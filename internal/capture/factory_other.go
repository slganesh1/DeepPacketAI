//go:build !linux

package capture

func selectFactory(_ CaptureConfig) CaptureSourceFactory {
	return &PcapSourceFactory{}
}
