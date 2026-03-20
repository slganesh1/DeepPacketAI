package protocols

import "DeepPacketAI/internal/domain"

// StreamingWrapper wraps any Decoder to implement the StreamingDecoder interface.
// It calls HandlePacket and checks if the decoder claimed the packet by setting AppProtocol.
type StreamingWrapper struct {
	Decoder
}

func (w *StreamingWrapper) HandlePacketLive(pkt *domain.Packet) *DecodedPacket {
	oldProto := pkt.AppProtocol
	oldSummary := pkt.Summary

	w.HandlePacket(pkt)

	// If the decoder set AppProtocol, it recognized this packet
	if pkt.AppProtocol != "" && pkt.AppProtocol != oldProto {
		return &DecodedPacket{
			Packet:   pkt,
			Protocol: pkt.AppProtocol,
			Summary:  pkt.Summary,
			Metadata: pkt.Metadata,
			Errors:   pkt.Errors,
		}
	}

	// Restore if decoder didn't claim this packet
	pkt.AppProtocol = oldProto
	pkt.Summary = oldSummary
	return nil
}

// WrapAsStreaming wraps a Decoder as a StreamingDecoder.
// If it already implements StreamingDecoder, returns it as-is.
func WrapAsStreaming(d Decoder) StreamingDecoder {
	if sd, ok := d.(StreamingDecoder); ok {
		return sd
	}
	return &StreamingWrapper{Decoder: d}
}

// WrapAllStreaming wraps a slice of Decoders as StreamingDecoders.
func WrapAllStreaming(decoders []Decoder) []StreamingDecoder {
	result := make([]StreamingDecoder, len(decoders))
	for i, d := range decoders {
		result[i] = WrapAsStreaming(d)
	}
	return result
}
