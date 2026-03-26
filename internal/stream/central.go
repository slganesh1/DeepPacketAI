package stream

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"DeepPacketAI/internal/capture"

	"github.com/google/gopacket"
)

// CentralReceiver listens for incoming agent TCP connections and feeds their
// packet streams into the local capture Engine for decode, analysis, and storage.
// The UI and API server run alongside the receiver — agents are transparent to them.
type CentralReceiver struct {
	engine *capture.Engine
}

// NewCentralReceiver creates a CentralReceiver backed by the given Engine.
func NewCentralReceiver(engine *capture.Engine) *CentralReceiver {
	return &CentralReceiver{engine: engine}
}

// Listen starts the TCP listener on addr (e.g. ":9090") and accepts agent
// connections in background goroutines. Returns once the listener is bound.
func (c *CentralReceiver) Listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("central listen %s: %w", addr, err)
	}
	log.Printf("stream/central: listening for agents on %s", addr)
	go c.accept(ln)
	return nil
}

func (c *CentralReceiver) accept(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
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

	session, pktCh, err := c.engine.StartVirtualCapture(hs.Agent.ID, hs.Agent.Interface)
	if err != nil {
		_ = writeMsg(conn, HandshakeAck{OK: false, Message: err.Error()})
		log.Printf("stream/central: start virtual capture for %s: %v", remote, err)
		return
	}

	if err := writeMsg(conn, HandshakeAck{OK: true, SessionID: session.ID}); err != nil {
		_, _ = c.engine.StopCapture(session.ID)
		return
	}

	log.Printf("stream/central: agent %s → session %s (agent=%s iface=%s)",
		remote, session.ID, hs.Agent.ID, hs.Agent.Interface)

	// Receive packet batches until the agent disconnects
	for {
		var batch PacketBatch
		if err := readMsg(conn, &batch); err != nil {
			if err == io.EOF {
				log.Printf("stream/central: agent %s (%s) disconnected cleanly", remote, hs.Agent.ID)
			} else {
				log.Printf("stream/central: read from %s: %v", remote, err)
			}
			break
		}

		for _, pm := range batch.Packets {
			raw := capture.RawPacket{
				Data: pm.Data,
				CaptureInfo: gopacket.CaptureInfo{
					Timestamp:     time.Unix(0, pm.TimestampNs),
					CaptureLength: pm.CaptureLength,
					Length:        pm.Length,
				},
			}
			select {
			case pktCh <- raw:
			default:
				// Engine overwhelmed: drop packet. Stats will show the gap.
			}
		}
	}

	// Agent gone — stop the virtual session and trigger analysis + storage
	_, _ = c.engine.StopCapture(session.ID)
	log.Printf("stream/central: session %s stopped, analysis queued", session.ID)
}
