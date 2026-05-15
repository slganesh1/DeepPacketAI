//go:build linux

package capture

import "log"

// selectFactory picks the highest-performance available capture backend:
//
//	XDP  (AF_XDP + eBPF)  — Linux 5.10+, CAP_BPF, opt-in via UseXDP=true
//	     5–15× faster than AF_PACKET; zero-copy with supported NIC drivers.
//
//	AF_PACKET (TPACKET_V3) — Linux 3.x+, CAP_NET_RAW
//	     1–3 Mpps; default on Linux.
//
//	pcap                   — fallback (Windows / macOS / old kernels).
func selectFactory(cfg CaptureConfig) CaptureSourceFactory {
	if cfg.UseXDP && xdpAvailable() {
		log.Println("capture: using AF_XDP backend (eBPF, Linux 5.10+)")
		return &XDPSourceFactory{}
	}
	if cfg.UseAFPacket && afpacketAvailable() {
		log.Println("capture: using AF_PACKET backend (TPACKET_V3)")
		return &AFPacketSourceFactory{}
	}
	log.Println("capture: using pcap backend")
	return &PcapSourceFactory{}
}
