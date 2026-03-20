//go:build linux

package capture

import "log"

func selectFactory(cfg CaptureConfig) CaptureSourceFactory {
	if cfg.UseAFPacket && afpacketAvailable() {
		log.Println("capture: using AF_PACKET backend")
		return &AFPacketSourceFactory{}
	}
	log.Println("capture: using pcap backend")
	return &PcapSourceFactory{}
}
