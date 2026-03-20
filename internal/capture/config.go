package capture

import "runtime"

// CaptureConfig holds configuration for the capture engine.
type CaptureConfig struct {
	WorkerCount        int    // number of parallel capture workers (default: min(NumCPU, 8))
	Snaplen            int    // max bytes captured per packet (default: 65535)
	RingBlockSize      int    // TPACKET_V3 block size in bytes (default: 4 MiB)
	RingBlockCount     int    // number of ring blocks per worker (default: 64 → 256 MiB ring)
	RingFrameSize      int    // TPACKET_V3 frame size in bytes (default: 64 KiB)
	FanoutGroup        uint16 // PACKET_FANOUT group ID (default: 0 = auto)
	UseAFPacket        bool   // prefer AF_PACKET on Linux (ignored on other platforms)
	PipelineBufferSize int    // per-worker channel buffer for decode pool (default: 4096)
}

// DefaultCaptureConfig returns a CaptureConfig with sensible defaults.
func DefaultCaptureConfig() CaptureConfig {
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	if workers < 1 {
		workers = 1
	}
	return CaptureConfig{
		WorkerCount:        workers,
		Snaplen:            65535,
		RingBlockSize:      1 << 22, // 4 MiB
		RingBlockCount:     64,      // 64 blocks → 256 MiB per worker
		RingFrameSize:      1 << 16, // 64 KiB
		FanoutGroup:        0,
		UseAFPacket:        true,
		PipelineBufferSize: 4096,
	}
}
