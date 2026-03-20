package rtp

import (
	"fmt"

	"DeepPacketAI/internal/domain"
)

type RTPDecoder struct {
	streams map[string]*RTPStream
}

func NewDecoder() *RTPDecoder {
	return &RTPDecoder{
		streams: make(map[string]*RTPStream),
	}
}

func (d *RTPDecoder) Name() string {
	return "rtp"
}

// Called for EVERY packet
func (d *RTPDecoder) HandlePacket(pkt *domain.Packet) {
	// RTP is UDP only
	if pkt.Protocol != "UDP" {
		return
	}

	// RTP header minimum size
	if len(pkt.Payload) < 12 {
		return
	}

	if !looksLikeRTP(pkt.Payload) {
		return
	}

	hdr := parseRTPHeader(pkt.Payload)
	if hdr == nil {
		return
	}

	key := streamKey(pkt, hdr.SSRC)

	stream, ok := d.streams[key]
	if !ok {
		stream = NewRTPStream(pkt, hdr)
		d.streams[key] = stream
	}

	stream.AddPacket(pkt, hdr)

	pkt.AppProtocol = "RTP"
	pkt.Summary = fmt.Sprintf("SSRC=0x%08x seq=%d pt=%d", hdr.SSRC, hdr.Sequence, hdr.Payload)
}

// Called ONCE at end of PCAP
func (d *RTPDecoder) Flush() []domain.Flow {
	var flows []domain.Flow

	for _, s := range d.streams {
		flows = append(flows, s.ToFlow())
	}

	return flows
}
