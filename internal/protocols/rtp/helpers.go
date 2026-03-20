package rtp

import (
	"fmt"

	"DeepPacketAI/internal/domain"
)

func looksLikeRTP(b []byte) bool {
	if len(b) < 12 {
		return false
	}
	return b[0]>>6 == 2
}

func streamKey(pkt *domain.Packet, ssrc uint32) string {
	return fmt.Sprintf(
		"%s:%d-%s:%d-%d",
		pkt.SrcIP,
		pkt.SrcPort,
		pkt.DstIP,
		pkt.DstPort,
		ssrc,
	)
}
