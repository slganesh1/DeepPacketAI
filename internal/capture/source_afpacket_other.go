//go:build !linux

package capture

import "fmt"

// AFPacketSourceFactory is a stub for non-Linux platforms.
type AFPacketSourceFactory struct{}

func (f *AFPacketSourceFactory) CreateSources(iface, bpfFilter string, count int, cfg CaptureConfig) ([]CaptureSource, error) {
	return nil, fmt.Errorf("AF_PACKET is not supported on this platform")
}
