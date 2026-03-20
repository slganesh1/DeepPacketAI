package reassembly

import (
	"net"
	"time"

	"DeepPacketAI/internal/domain"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

// WorkerAssembler wraps a gopacket reassembly.Assembler for use by a single
// pipeline worker. It is NOT safe for concurrent use.
type WorkerAssembler struct {
	pool      *reassembly.StreamPool
	assembler *reassembly.Assembler
}

// NewWorkerAssembler creates a new assembler backed by the given stream factory.
func NewWorkerAssembler(factory *StreamFactory) *WorkerAssembler {
	pool := reassembly.NewStreamPool(factory)
	assembler := reassembly.NewAssembler(pool)
	return &WorkerAssembler{
		pool:      pool,
		assembler: assembler,
	}
}

// ShouldReassemble returns true if the packet's ports match a protocol that
// should be reassembled (i.e., SelectFramer returns non-nil).
func ShouldReassemble(pkt *domain.Packet) bool {
	return SelectFramer(pkt.SrcPort, pkt.DstPort) != nil
}

// assemblerContext provides the timestamp for gopacket reassembly.
type assemblerContext struct {
	ci gopacket.CaptureInfo
}

func (ac *assemblerContext) GetCaptureInfo() gopacket.CaptureInfo {
	return ac.ci
}

// FeedPacket reconstructs the gopacket layers from a domain.Packet and feeds
// it into the reassembly engine.
func (wa *WorkerAssembler) FeedPacket(pkt *domain.Packet) {
	srcIP := net.ParseIP(pkt.SrcIP)
	dstIP := net.ParseIP(pkt.DstIP)
	if srcIP == nil || dstIP == nil {
		return
	}

	srcEP := layers.NewIPEndpoint(srcIP)
	dstEP := layers.NewIPEndpoint(dstIP)
	netFlow, _ := gopacket.FlowFromEndpoints(srcEP, dstEP)

	tcp := &layers.TCP{
		SrcPort:  layers.TCPPort(pkt.SrcPort),
		DstPort:  layers.TCPPort(pkt.DstPort),
		Seq:      pkt.TCPSeq,
		Ack:      pkt.TCPAck,
		SYN:      pkt.TCPFlags&0x02 != 0,
		FIN:      pkt.TCPFlags&0x01 != 0,
		RST:      pkt.TCPFlags&0x04 != 0,
		PSH:      pkt.TCPFlags&0x08 != 0,
		ACK:      pkt.TCPFlags&0x10 != 0,
		BaseLayer: layers.BaseLayer{Payload: pkt.Payload},
	}

	ts := pkt.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	wa.assembler.AssembleWithContext(netFlow, tcp, &assemblerContext{
		ci: gopacket.CaptureInfo{Timestamp: ts},
	})
}

// FlushAll flushes all pending streams, delivering any remaining data.
func (wa *WorkerAssembler) FlushAll() {
	wa.assembler.FlushAll()
}
