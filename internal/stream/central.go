package stream

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"DeepPacketAI/internal/capture"

	"github.com/google/gopacket"
)

// CentralConfig holds optional configuration for the CentralReceiver.
type CentralConfig struct {
	Token   string // if non-empty, agents must present this token
	TLSCert string // path to TLS certificate PEM file
	TLSKey  string // path to TLS private key PEM file
}

// CentralReceiver listens for incoming agent TCP connections and feeds their
// packet streams into the local capture Engine for decode, analysis, and storage.
type CentralReceiver struct {
	engine   *capture.Engine
	registry *AgentRegistry
	cfg      CentralConfig
}

// NewCentralReceiver creates a CentralReceiver backed by the given Engine.
func NewCentralReceiver(engine *capture.Engine, cfg CentralConfig) *CentralReceiver {
	return &CentralReceiver{engine: engine, registry: NewAgentRegistry(), cfg: cfg}
}

// Registry returns the live agent registry.
func (c *CentralReceiver) Registry() *AgentRegistry {
	return c.registry
}

// Listen starts the TCP listener on addr and accepts agent connections in the
// background. If TLSCert+TLSKey are configured the listener is wrapped in TLS.
func (c *CentralReceiver) Listen(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("central listen %s: %w", addr, err)
	}

	if c.cfg.TLSCert != "" && c.cfg.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(c.cfg.TLSCert, c.cfg.TLSKey)
		if err != nil {
			ln.Close()
			return fmt.Errorf("central: load TLS cert/key: %w", err)
		}
		tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
		ln = tls.NewListener(ln, tlsCfg)
		log.Printf("stream/central: listening (TLS) on %s", addr)
	} else {
		log.Printf("stream/central: listening on %s", addr)
	}

	go c.registry.StartStalenessChecker(ctx)
	go c.accept(ln, ctx)
	return nil
}

func (c *CentralReceiver) accept(ln net.Listener, ctx context.Context) {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return // context cancelled — normal shutdown
			}
			log.Printf("stream/central: accept error: %v", err)
			return
		}
		go c.handleAgent(conn)
	}
}

func (c *CentralReceiver) handleAgent(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	log.Printf("stream/central: agent connected from %s", remote)

	var hs Handshake
	if err := readMsg(conn, &hs); err != nil {
		log.Printf("stream/central: handshake from %s: %v", remote, err)
		return
	}

	// Token authentication
	if c.cfg.Token != "" && hs.Token != c.cfg.Token {
		_ = writeMsg(conn, HandshakeAck{OK: false, Message: "invalid token"})
		log.Printf("stream/central: rejected %s — bad token", remote)
		return
	}

	session, pktCh, err := c.engine.StartVirtualCapture(hs.Agent.ID, hs.Agent.Hostname, hs.Agent.Interface, hs.LinkType)
	if err != nil {
		_ = writeMsg(conn, HandshakeAck{OK: false, Message: err.Error()})
		return
	}

	useCompress := hs.CanCompress
	ack := HandshakeAck{OK: true, SessionID: session.ID, UseCompress: useCompress}
	if err := writeMsg(conn, ack); err != nil {
		_, _ = c.engine.StopCapture(session.ID)
		return
	}

	readBatch := readMsg
	if useCompress {
		readBatch = readMsgZlib
	}

	log.Printf("stream/central: agent %s → session %s (agent=%s iface=%s compress=%v)",
		remote, session.ID, hs.Agent.ID, hs.Agent.Interface, useCompress)

	c.registry.register(AgentStatus{
		AgentID:     hs.Agent.ID,
		Hostname:    hs.Agent.Hostname,
		Interface:   hs.Agent.Interface,
		RemoteAddr:  remote,
		SessionID:   session.ID,
		ConnectedAt: time.Now(),
	})
	defer c.registry.unregister(hs.Agent.ID)

	// Goroutine: forward BPF filter updates from API → agent.
	filterCh := c.registry.FilterCh(hs.Agent.ID)
	go func() {
		for newFilter := range filterCh {
			fu := FilterUpdate{AgentID: hs.Agent.ID, BPFFilter: newFilter}
			if err := writeMsg(conn, fu); err != nil {
				log.Printf("stream/central: filter send to %s: %v", hs.Agent.ID, err)
				return
			}
			log.Printf("stream/central: sent filter update to %s: %q", hs.Agent.ID, newFilter)
		}
	}()

	// Receive packet batches until the agent disconnects.
	for {
		var batch PacketBatch
		if err := readBatch(conn, &batch); err != nil {
			if err == io.EOF {
				log.Printf("stream/central: agent %s (%s) disconnected cleanly", remote, hs.Agent.ID)
			} else {
				log.Printf("stream/central: read from %s: %v", remote, err)
			}
			break
		}

		batchBytes := 0
		dropped := 0
		for _, pm := range batch.Packets {
			batchBytes += pm.Length
			raw := capture.RawPacket{
				Data: pm.Data,
				CaptureInfo: gopacket.CaptureInfo{
					Timestamp:     timeFromNs(pm.TimestampNs),
					CaptureLength: pm.CaptureLength,
					Length:        pm.Length,
				},
			}
			select {
			case pktCh <- raw:
			default:
				dropped++
			}
		}
		c.registry.update(hs.Agent.ID, len(batch.Packets), batchBytes, dropped+int(batch.Drops))
	}

	_, _ = c.engine.StopCapture(session.ID)
	log.Printf("stream/central: session %s stopped", session.ID)
}

func timeFromNs(ns int64) time.Time {
	return time.Unix(0, ns)
}
