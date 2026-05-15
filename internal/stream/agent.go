package stream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"DeepPacketAI/internal/capture"

	"github.com/google/gopacket/layers"
)

const (
	protoVersion  = "1"
	maxBatchSize  = 500
	batchInterval = 200 * time.Millisecond
	reconnectWait = 5 * time.Second
)

// AgentStreamer captures packets on a local interface and streams them to a
// central DeepPacketAI node over TCP (optionally TLS). It reconnects
// automatically on failure and supports:
//   - Pre-shared token authentication
//   - zlib compression (negotiated in handshake)
//   - Empty-batch heartbeats to keep the connection alive on quiet interfaces
//   - Outbound bandwidth throttling
//   - Hot-swap of the BPF filter at runtime (triggered by central)
type AgentStreamer struct {
	info          AgentInfo
	factory       capture.CaptureSourceFactory
	capCfg        capture.CaptureConfig
	currentFilter string
	central       string
	cfg           AgentConfig
	filterCh      chan string // receives new BPF filters from central
}

// NewAgentStreamer creates an AgentStreamer.
// factory and capCfg are used to (re-)open the capture source, allowing
// BPF filter hot-swap without restarting the process.
func NewAgentStreamer(
	info AgentInfo,
	factory capture.CaptureSourceFactory,
	capCfg capture.CaptureConfig,
	initialFilter string,
	centralAddr string,
	cfg AgentConfig,
) *AgentStreamer {
	return &AgentStreamer{
		info:          info,
		factory:       factory,
		capCfg:        capCfg,
		currentFilter: initialFilter,
		central:       centralAddr,
		cfg:           cfg,
		filterCh:      make(chan string, 4),
	}
}

// Run streams packets until ctx is cancelled, reconnecting after failures.
func (a *AgentStreamer) Run(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		if err := a.connect(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("stream/agent: disconnected from %s: %v — retry in %s",
				a.central, err, reconnectWait)
			select {
			case <-ctx.Done():
				return
			case <-time.After(reconnectWait):
			}
		}
	}
}

func (a *AgentStreamer) connect(ctx context.Context) error {
	// Open (or reopen) the capture source with the current BPF filter.
	sources, err := a.factory.CreateSources(a.info.Interface, a.currentFilter, 1, a.capCfg)
	if err != nil {
		return fmt.Errorf("open capture source: %w", err)
	}
	src := sources[0]
	defer src.Close()

	// Dial central — optionally wrapped in TLS.
	conn, err := a.dial()
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}
	log.Printf("stream/agent: connected to central %s (tls=%v)", a.central, a.cfg.UseTLS)

	// Handshake
	linkType := int(layers.LinkTypeEthernet)
	if lt, ok := src.Decoder().(layers.LinkType); ok {
		linkType = int(lt)
	}
	hs := Handshake{
		Version:     protoVersion,
		Agent:       a.info,
		Token:       a.cfg.Token,
		CanCompress: true,
		LinkType:    linkType,
	}
	if err := writeMsg(conn, hs); err != nil {
		return fmt.Errorf("handshake write: %w", err)
	}
	var ack HandshakeAck
	if err := readMsg(conn, &ack); err != nil {
		return fmt.Errorf("handshake ack: %w", err)
	}
	if !ack.OK {
		return fmt.Errorf("rejected by central: %s", ack.Message)
	}
	log.Printf("stream/agent: accepted — session_id=%s compress=%v", ack.SessionID, ack.UseCompress)

	useCompress := ack.UseCompress
	writeBatch := writeMsg
	if useCompress {
		writeBatch = writeMsgZlib
	}

	// maxBytesPS derived from cfg.MaxMbps (0 = unlimited)
	var maxBytesPS int64
	if a.cfg.MaxMbps > 0 {
		maxBytesPS = int64(a.cfg.MaxMbps * 1_000_000 / 8)
	}

	// Read control messages from central (filter updates) in a separate goroutine.
	// Central uses the same TCP connection in the opposite direction.
	ctrlErrCh := make(chan error, 1)
	go func() {
		for {
			var fu FilterUpdate
			if err := readMsg(conn, &fu); err != nil {
				ctrlErrCh <- err
				return
			}
			log.Printf("stream/agent: filter update → %q", fu.BPFFilter)
			select {
			case a.filterCh <- fu.BPFFilter:
			default:
			}
		}
	}()

	// Read packets from the capture source.
	pktCh := make(chan capture.RawPacket, 10_000)
	readErrCh := make(chan error, 1)
	go func() {
		for {
			pkt, err := src.ReadPacket()
			if err != nil {
				readErrCh <- err
				return
			}
			select {
			case pktCh <- pkt:
			default:
				// drop under backpressure
			}
		}
	}()

	var seq uint64
	var drops uint64
	batch := make([]RawPacketMsg, 0, maxBatchSize)
	ticker := time.NewTicker(batchInterval)
	heartbeat := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()
	defer heartbeat.Stop()

	// Token-bucket state for bandwidth throttle
	var tokenBucket int64
	bucketRefillAt := time.Now()

	flush := func(forceHeartbeat bool) error {
		if len(batch) == 0 && !forceHeartbeat {
			return nil
		}
		pb := PacketBatch{
			AgentID: a.info.ID,
			SeqNum:  seq,
			Drops:   drops,
			Packets: batch,
		}
		// measure serialised size for throttle (approximate with batch length)
		batchBytes := 0
		for _, p := range batch {
			batchBytes += len(p.Data)
		}

		if err := writeBatch(conn, pb); err != nil {
			return err
		}
		seq++
		drops = 0
		batch = batch[:0]

		// Bandwidth throttle: sleep to stay under maxBytesPS.
		if maxBytesPS > 0 && batchBytes > 0 {
			now := time.Now()
			elapsed := now.Sub(bucketRefillAt)
			bucketRefillAt = now
			refill := int64(float64(maxBytesPS) * elapsed.Seconds())
			tokenBucket += refill
			if tokenBucket > maxBytesPS {
				tokenBucket = maxBytesPS // cap to one second of burst
			}
			tokenBucket -= int64(batchBytes)
			if tokenBucket < 0 {
				sleepDur := time.Duration(-tokenBucket * int64(time.Second) / maxBytesPS)
				if sleepDur > 2*time.Second {
					sleepDur = 2 * time.Second // safety cap
				}
				time.Sleep(sleepDur)
				tokenBucket = 0
			}
		}
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			_ = flush(false)
			return nil

		case err := <-readErrCh:
			_ = flush(false)
			return fmt.Errorf("read source: %w", err)

		case err := <-ctrlErrCh:
			// Control channel broken — reconnect to get a fresh one.
			_ = flush(false)
			return fmt.Errorf("control channel: %w", err)

		case newFilter := <-a.filterCh:
			// BPF filter hot-swap: flush current batch then reconnect with new filter.
			_ = flush(false)
			a.currentFilter = newFilter
			log.Printf("stream/agent: applying new BPF filter %q — reconnecting", newFilter)
			return nil // Run() loop will call connect() again

		case pkt := <-pktCh:
			batch = append(batch, RawPacketMsg{
				TimestampNs:   pkt.CaptureInfo.Timestamp.UnixNano(),
				CaptureLength: pkt.CaptureInfo.CaptureLength,
				Length:        pkt.CaptureInfo.Length,
				LinkType:      linkType,
				Data:          pkt.Data,
			})
			if len(batch) >= maxBatchSize {
				if err := flush(false); err != nil {
					return fmt.Errorf("send batch: %w", err)
				}
			}

		case <-ticker.C:
			if err := flush(false); err != nil {
				return fmt.Errorf("flush: %w", err)
			}

		case <-heartbeat.C:
			// Send empty batch as heartbeat on quiet interfaces.
			if err := flush(true); err != nil {
				return fmt.Errorf("heartbeat: %w", err)
			}
		}
	}
}

// dial opens the TCP connection to central, optionally wrapped in TLS.
func (a *AgentStreamer) dial() (net.Conn, error) {
	if !a.cfg.UseTLS {
		return net.DialTimeout("tcp", a.central, 10*time.Second)
	}

	tlsCfg := &tls.Config{InsecureSkipVerify: a.cfg.TLSSkipVerify} //nolint:gosec
	if a.cfg.TLSCA != "" {
		caCert, err := os.ReadFile(a.cfg.TLSCA)
		if err != nil {
			return nil, fmt.Errorf("read TLS CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert from %s", a.cfg.TLSCA)
		}
		tlsCfg.RootCAs = pool
		tlsCfg.InsecureSkipVerify = false
	}
	return tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", a.central, tlsCfg)
}
