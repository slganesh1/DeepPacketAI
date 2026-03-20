package pipeline

import (
	"sync"
	"time"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/protocols"
	"DeepPacketAI/internal/reassembly"
)

// DecodeWorker processes packets through its own set of protocol decoders.
// Each worker has a dedicated input channel and its own decoder instances,
// ensuring thread safety without mutexes in the decoders themselves.
type DecodeWorker struct {
	id        int
	ch        chan *domain.Packet
	decoders  []protocols.Decoder
	wg        *sync.WaitGroup
	onPacket  func(pkt *domain.Packet) // optional per-packet callback
	assembler *reassembly.WorkerAssembler
}

// NewDecodeWorker creates a decode worker with its own channel and decoders.
func NewDecodeWorker(id int, decoders []protocols.Decoder, bufSize int, wg *sync.WaitGroup) *DecodeWorker {
	return &DecodeWorker{
		id:       id,
		ch:       make(chan *domain.Packet, bufSize),
		decoders: decoders,
		wg:       wg,
	}
}

// NewDecodeWorkerWithAssembler creates a decode worker with TCP reassembly support.
// All packets still go to decoders directly (preserving existing single-segment handling).
// Additionally, TCP streams on known protocol ports are reassembled, and complete
// messages are fed to decoders as synthetic packets (marked Reassembled=true).
func NewDecodeWorkerWithAssembler(id int, decoders []protocols.Decoder, bufSize int, wg *sync.WaitGroup) *DecodeWorker {
	w := &DecodeWorker{
		id:       id,
		ch:       make(chan *domain.Packet, bufSize),
		decoders: decoders,
		wg:       wg,
	}

	factory := &reassembly.StreamFactory{
		OnMessage: func(payload []byte, srcIP, dstIP string, srcPort, dstPort uint16, ts time.Time) {
			// Create a synthetic packet from the reassembled message
			pkt := &domain.Packet{
				SrcIP:       srcIP,
				DstIP:       dstIP,
				SrcPort:     srcPort,
				DstPort:     dstPort,
				Protocol:    "TCP",
				Payload:     payload,
				Timestamp:   ts,
				Reassembled: true,
			}
			for _, d := range decoders {
				d.HandlePacket(pkt)
			}
		},
	}
	w.assembler = reassembly.NewWorkerAssembler(factory)

	return w
}

// Run processes packets from the worker's channel until it is closed.
// All packets are always fed to decoders directly (preserving existing behavior).
// TCP packets on known protocol ports are additionally fed to the assembler,
// which produces reassembled complete messages that are also sent to decoders.
func (w *DecodeWorker) Run() {
	defer w.wg.Done()
	for pkt := range w.ch {
		// Always feed every packet to decoders (preserves pre-reassembly behavior)
		for _, d := range w.decoders {
			d.HandlePacket(pkt)
		}
		// Additionally feed TCP packets to the assembler for multi-segment reassembly.
		// The assembler callback will create synthetic Reassembled packets for decoders.
		if pkt.Protocol == "TCP" && w.assembler != nil && reassembly.ShouldReassemble(pkt) {
			annotateByPort(pkt)
			w.assembler.FeedPacket(pkt)
		}
		if w.onPacket != nil {
			w.onPacket(pkt)
		}
	}
	if w.assembler != nil {
		w.assembler.FlushAll()
	}
}

// Send submits a packet to this worker's channel.
func (w *DecodeWorker) Send(pkt *domain.Packet) {
	w.ch <- pkt
}

// Close closes the worker's input channel, signaling it to drain and exit.
func (w *DecodeWorker) Close() {
	close(w.ch)
}

// Flush collects flows from all of this worker's decoders.
func (w *DecodeWorker) Flush() []domain.Flow {
	var flows []domain.Flow
	for _, d := range w.decoders {
		flows = append(flows, d.Flush()...)
	}
	return flows
}

// annotateByPort sets AppProtocol on original TCP packets based on well-known ports.
// This is lightweight annotation for UI display of the original packet.
func annotateByPort(pkt *domain.Packet) {
	if pkt.AppProtocol != "" {
		return
	}
	if proto := portToProtocol(pkt.DstPort); proto != "" {
		pkt.AppProtocol = proto
		return
	}
	if proto := portToProtocol(pkt.SrcPort); proto != "" {
		pkt.AppProtocol = proto
	}
}

func portToProtocol(port uint16) string {
	switch port {
	case 5060, 5061:
		return "SIP"
	case 80, 8080, 8000, 8888, 3000:
		return "HTTP"
	case 443, 8443:
		return "HTTPS"
	case 993, 995, 465, 636:
		return "TLS"
	case 3868:
		return "Diameter"
	}
	return ""
}
