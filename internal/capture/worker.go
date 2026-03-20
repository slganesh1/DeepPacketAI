package capture

import (
	"log"
	"sync"
	"sync/atomic"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/metrics"
	"DeepPacketAI/internal/pipeline"
	"DeepPacketAI/internal/protocols"
	"DeepPacketAI/internal/ws"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// CaptureWorker runs a capture loop on a single CaptureSource with its own decoders.
type CaptureWorker struct {
	id           int
	source       CaptureSource
	firstDecoder gopacket.Decoder
	decoders     []protocols.StreamingDecoder
	session      *Session
	stats        *Stats
	hub          *ws.Hub
	frameGen     *uint64 // shared atomic counter across all workers
	wg           *sync.WaitGroup
}

// NewCaptureWorker creates a new capture worker.
func NewCaptureWorker(
	id int,
	source CaptureSource,
	decoders []protocols.StreamingDecoder,
	session *Session,
	stats *Stats,
	hub *ws.Hub,
	frameGen *uint64,
	wg *sync.WaitGroup,
) *CaptureWorker {
	return &CaptureWorker{
		id:           id,
		source:       source,
		firstDecoder: source.Decoder(),
		decoders:     decoders,
		session:      session,
		stats:        stats,
		hub:          hub,
		frameGen:     frameGen,
		wg:           wg,
	}
}

// Run starts the capture loop. It blocks until the session is stopped or the source returns an error.
func (w *CaptureWorker) Run() {
	defer w.wg.Done()

	log.Printf("worker %d: started, decoder=%v", w.id, w.firstDecoder)

	for {
		select {
		case <-w.session.StopCh():
			log.Printf("worker %d: stopped", w.id)
			return
		default:
		}

		raw, err := w.source.ReadPacket()
		if err != nil {
			// On transient errors, check if we should stop
			select {
			case <-w.session.StopCh():
				log.Printf("worker %d: stopped after read error", w.id)
				return
			default:
				continue
			}
		}

		frameNum := atomic.AddUint64(w.frameGen, 1)

		packet := gopacket.NewPacket(raw.Data, w.firstDecoder, gopacket.Default)
		// Apply capture info from the source
		packet.Metadata().Timestamp = raw.CaptureInfo.Timestamp
		packet.Metadata().CaptureLength = raw.CaptureInfo.CaptureLength
		packet.Metadata().Length = raw.CaptureInfo.Length

		pkt := extractPacketFromRaw(packet, frameNum)
		if pkt == nil {
			metrics.PacketsDropped.WithLabelValues("parse").Inc()
			continue
		}

		w.session.IncrementCounters(pkt.Length)

		proto := pkt.Protocol
		if pkt.AppProtocol != "" {
			proto = pkt.AppProtocol
		}
		w.stats.Record(proto, pkt.Length)

		// Prometheus counters for live capture
		metrics.PacketsTotal.WithLabelValues("live", pkt.Protocol).Inc()
		metrics.BytesTotal.WithLabelValues("live").Add(float64(pkt.Length))

		// Feed through per-worker decoders (not shared across workers)
		for _, sd := range w.decoders {
			if decoded := sd.HandlePacketLive(pkt); decoded != nil {
				pkt.AppProtocol = decoded.Protocol
				pkt.Summary = decoded.Summary
				pkt.Metadata = decoded.Metadata
				pkt.Errors = decoded.Errors

				if decoded.Protocol != "" {
					metrics.ProtocolPackets.WithLabelValues(decoded.Protocol).Inc()
				}

				if len(decoded.Errors) > 0 {
					for _, pe := range decoded.Errors {
						metrics.DecodeErrors.WithLabelValues(decoded.Protocol, pe.Title).Inc()
						w.hub.Broadcast(ws.Message{
							Type: ws.MsgAlert,
							Payload: map[string]any{
								"frame":       pkt.FrameNumber,
								"timestamp":   pkt.Timestamp,
								"severity":    pe.Severity,
								"protocol":    decoded.Protocol,
								"title":       pe.Title,
								"description": pe.Description,
								"src_ip":      pkt.SrcIP,
								"dst_ip":      pkt.DstIP,
							},
						})
					}
				}
			}
		}

		// Buffer packet for persistence (without RawPacket to save memory)
		buffered := &domain.Packet{
			Timestamp:   pkt.Timestamp,
			SrcIP:       pkt.SrcIP,
			DstIP:       pkt.DstIP,
			SrcPort:     pkt.SrcPort,
			DstPort:     pkt.DstPort,
			Protocol:    pkt.Protocol,
			FrameNumber: pkt.FrameNumber,
			Length:      pkt.Length,
			AppProtocol: pkt.AppProtocol,
			Summary:     pkt.Summary,
			Metadata:    pkt.Metadata,
			Errors:      pkt.Errors,
		}
		w.session.BufferPacket(buffered)

		w.hub.Broadcast(ws.Message{
			Type: ws.MsgPacket,
			Payload: map[string]any{
				"frame":        pkt.FrameNumber,
				"timestamp":    pkt.Timestamp,
				"src_ip":       pkt.SrcIP,
				"dst_ip":       pkt.DstIP,
				"src_port":     pkt.SrcPort,
				"dst_port":     pkt.DstPort,
				"protocol":     pkt.Protocol,
				"app_protocol": pkt.AppProtocol,
				"length":       pkt.Length,
				"summary":      pkt.Summary,
				"metadata":     pkt.Metadata,
				"errors":       pkt.Errors,
			},
		})
	}
}

// RunWithPool reads packets and submits them to a decode pool for parallel processing.
// Used when there is only 1 capture source (e.g., pcap on Windows/macOS) so that
// decoding can still be parallelized across multiple workers via flow-affinity routing.
func (w *CaptureWorker) RunWithPool(pool *pipeline.Pool) {
	defer w.wg.Done()
	defer pool.Close() // Close pool channels when reader exits; workers drain remaining packets

	log.Printf("worker %d: started with decode pool, decoder=%v", w.id, w.firstDecoder)

	for {
		select {
		case <-w.session.StopCh():
			log.Printf("worker %d: stopped", w.id)
			return
		default:
		}

		raw, err := w.source.ReadPacket()
		if err != nil {
			select {
			case <-w.session.StopCh():
				log.Printf("worker %d: stopped after read error", w.id)
				return
			default:
				continue
			}
		}

		frameNum := atomic.AddUint64(w.frameGen, 1)

		packet := gopacket.NewPacket(raw.Data, w.firstDecoder, gopacket.Default)
		packet.Metadata().Timestamp = raw.CaptureInfo.Timestamp
		packet.Metadata().CaptureLength = raw.CaptureInfo.CaptureLength
		packet.Metadata().Length = raw.CaptureInfo.Length

		pkt := extractPacketFromRaw(packet, frameNum)
		if pkt == nil {
			metrics.PacketsDropped.WithLabelValues("parse").Inc()
			continue
		}

		w.session.IncrementCounters(pkt.Length)

		proto := pkt.Protocol
		if pkt.AppProtocol != "" {
			proto = pkt.AppProtocol
		}
		w.stats.Record(proto, pkt.Length)

		metrics.PacketsTotal.WithLabelValues("live", pkt.Protocol).Inc()
		metrics.BytesTotal.WithLabelValues("live").Add(float64(pkt.Length))

		pool.Submit(pkt)
	}
}

// Flush collects flows from this worker's decoders.
func (w *CaptureWorker) Flush() []domain.Flow {
	var flows []domain.Flow
	for _, d := range w.decoders {
		flows = append(flows, d.Flush()...)
	}
	return flows
}

// extractPacketFromRaw extracts a domain.Packet from a decoded gopacket.Packet.
// This adds SCTP support that was missing from the original extractPacket.
func extractPacketFromRaw(packet gopacket.Packet, frameNum uint64) *domain.Packet {
	net := packet.NetworkLayer()
	if net == nil {
		return nil
	}

	var srcIP, dstIP string
	switch ip := net.(type) {
	case *layers.IPv4:
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	case *layers.IPv6:
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	default:
		return nil
	}

	var srcPort, dstPort uint16
	var proto string
	var payload []byte
	var tcpSeq, tcpAck uint32
	var tcpFlags uint16

	tr := packet.TransportLayer()
	if tr != nil {
		switch t := tr.(type) {
		case *layers.TCP:
			srcPort = uint16(t.SrcPort)
			dstPort = uint16(t.DstPort)
			proto = "TCP"
			payload = t.LayerPayload()
			tcpSeq = t.Seq
			tcpAck = t.Ack
			tcpFlags = tcpFlagsFromLayer(t)
		case *layers.UDP:
			srcPort = uint16(t.SrcPort)
			dstPort = uint16(t.DstPort)
			proto = "UDP"
			payload = t.LayerPayload()
		default:
			// Fall through to SCTP check below
		}
	}

	// Check for SCTP if no TCP/UDP was found
	if proto == "" {
		if sctp := packet.Layer(layers.LayerTypeSCTP); sctp != nil {
			sctpLayer := sctp.(*layers.SCTP)
			srcPort = uint16(sctpLayer.SrcPort)
			dstPort = uint16(sctpLayer.DstPort)
			proto = "SCTP"
			payload = sctpLayer.LayerPayload()
		} else {
			return nil
		}
	}

	return &domain.Packet{
		Timestamp:   packet.Metadata().Timestamp,
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     srcPort,
		DstPort:     dstPort,
		Protocol:    proto,
		Payload:     payload,
		FrameNumber: frameNum,
		Length:      len(packet.Data()),
		RawPacket:   packet.Data(),
		TCPSeq:      tcpSeq,
		TCPAck:      tcpAck,
		TCPFlags:    tcpFlags,
	}
}

func tcpFlagsFromLayer(t *layers.TCP) uint16 {
	var f uint16
	if t.SYN {
		f |= 0x02
	}
	if t.FIN {
		f |= 0x01
	}
	if t.RST {
		f |= 0x04
	}
	if t.PSH {
		f |= 0x08
	}
	if t.ACK {
		f |= 0x10
	}
	return f
}
