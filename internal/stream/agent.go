package stream

import (
	"context"
	"fmt"
	"log"
	"net"
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

// AgentStreamer reads packets from a local CaptureSource and streams them to
// a central DeepPacketAI node over TCP. It reconnects automatically on failure.
type AgentStreamer struct {
	info    AgentInfo
	src     capture.CaptureSource
	central string // host:port of central node
}

// NewAgentStreamer creates an AgentStreamer.
func NewAgentStreamer(info AgentInfo, src capture.CaptureSource, centralAddr string) *AgentStreamer {
	return &AgentStreamer{info: info, src: src, central: centralAddr}
}

// Run streams packets until ctx is cancelled. It reconnects to central after
// transient failures, so the capture continues across brief network outages.
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
	conn, err := net.DialTimeout("tcp", a.central, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	log.Printf("stream/agent: connected to central %s", a.central)

	// Determine link type from the source decoder
	linkType := int(layers.LinkTypeEthernet)
	if lt, ok := a.src.Decoder().(layers.LinkType); ok {
		linkType = int(lt)
	}

	// Handshake
	if err := writeMsg(conn, Handshake{Version: protoVersion, Agent: a.info}); err != nil {
		return fmt.Errorf("handshake write: %w", err)
	}
	var ack HandshakeAck
	if err := readMsg(conn, &ack); err != nil {
		return fmt.Errorf("handshake ack: %w", err)
	}
	if !ack.OK {
		return fmt.Errorf("rejected by central: %s", ack.Message)
	}
	log.Printf("stream/agent: accepted — session_id=%s", ack.SessionID)

	// Read packets from source in a goroutine so we can select on ctx too
	pktCh := make(chan capture.RawPacket, 2000)
	readErrCh := make(chan error, 1)
	go func() {
		for {
			pkt, err := a.src.ReadPacket()
			if err != nil {
				readErrCh <- err
				return
			}
			select {
			case pktCh <- pkt:
			default:
				// Drop packet under backpressure rather than blocking the reader
			}
		}
	}()

	var seq uint64
	batch := make([]RawPacketMsg, 0, maxBatchSize)
	ticker := time.NewTicker(batchInterval)
	defer ticker.Stop()

	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := writeMsg(conn, PacketBatch{AgentID: a.info.ID, SeqNum: seq, Packets: batch})
		seq++
		batch = batch[:0]
		return err
	}

	for {
		select {
		case <-ctx.Done():
			_ = flush()
			return nil
		case err := <-readErrCh:
			_ = flush()
			return fmt.Errorf("read source: %w", err)
		case pkt := <-pktCh:
			batch = append(batch, RawPacketMsg{
				TimestampNs:   pkt.CaptureInfo.Timestamp.UnixNano(),
				CaptureLength: pkt.CaptureInfo.CaptureLength,
				Length:        pkt.CaptureInfo.Length,
				LinkType:      linkType,
				Data:          pkt.Data,
			})
			if len(batch) >= maxBatchSize {
				if err := flush(); err != nil {
					return fmt.Errorf("send batch: %w", err)
				}
			}
		case <-ticker.C:
			if err := flush(); err != nil {
				return fmt.Errorf("send batch: %w", err)
			}
		}
	}
}
