package capture

import (
	"github.com/google/gopacket"
)

// RawPacket holds raw packet data and capture metadata.
type RawPacket struct {
	Data        []byte
	CaptureInfo gopacket.CaptureInfo
}

// SourceStats holds kernel-level capture statistics.
type SourceStats struct {
	Received uint64
	Dropped  uint64
}

// CaptureSource is the interface for reading packets from a capture backend.
type CaptureSource interface {
	// ReadPacket blocks until the next packet is available or returns io.EOF.
	ReadPacket() (RawPacket, error)
	// Stats returns kernel-level receive/drop counters.
	Stats() SourceStats
	// Decoder returns the first-layer decoder for packet decoding.
	Decoder() gopacket.Decoder
	// Close releases resources associated with this source.
	Close() error
}

// CaptureSourceFactory creates one or more CaptureSource instances.
// AF_PACKET returns N sources (one per fanout worker); pcap returns 1.
type CaptureSourceFactory interface {
	CreateSources(iface, bpfFilter string, count int, cfg CaptureConfig) ([]CaptureSource, error)
}
