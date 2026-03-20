package rtp

type RTPHeader struct {
	Version   uint8
	Payload   uint8
	Sequence  uint16
	Timestamp uint32
	SSRC      uint32
}

func parseRTPHeader(b []byte) *RTPHeader {
	if len(b) < 12 {
		return nil
	}

	v := b[0] >> 6
	if v != 2 {
		return nil
	}

	return &RTPHeader{
		Version:   v,
		Payload:   b[1] & 0x7F,
		Sequence:  uint16(b[2])<<8 | uint16(b[3]),
		Timestamp: uint32(b[4])<<24 | uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7]),
		SSRC:      uint32(b[8])<<24 | uint32(b[9])<<16 | uint32(b[10])<<8 | uint32(b[11]),
	}
}
