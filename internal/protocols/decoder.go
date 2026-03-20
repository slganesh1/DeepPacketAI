package protocols

import "DeepPacketAI/internal/domain"

// Decoder is the base interface for all protocol decoders.
// HandlePacket is called for every packet; Flush is called once at end of capture.
type Decoder interface {
	Name() string
	HandlePacket(pkt *domain.Packet)
	Flush() []domain.Flow
}

// DecodedPacket holds the result of real-time packet decoding.
type DecodedPacket struct {
	Packet   *domain.Packet
	Protocol string
	Summary  string
	Metadata map[string]any
	Errors   []domain.PacketError
}

// StreamingDecoder extends Decoder with real-time packet emission for live capture.
type StreamingDecoder interface {
	Decoder
	HandlePacketLive(pkt *domain.Packet) *DecodedPacket
}
