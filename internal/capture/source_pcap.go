package capture

import (
	"fmt"
	"io"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// PcapSource wraps a pcap handle into the CaptureSource interface.
type PcapSource struct {
	handle *pcap.Handle
}

func newPcapSource(handle *pcap.Handle) *PcapSource {
	return &PcapSource{
		handle: handle,
	}
}

func (p *PcapSource) ReadPacket() (RawPacket, error) {
	data, ci, err := p.handle.ReadPacketData()
	if err != nil {
		if err == io.EOF {
			return RawPacket{}, io.EOF
		}
		return RawPacket{}, err
	}
	return RawPacket{
		Data:        data,
		CaptureInfo: ci,
	}, nil
}

func (p *PcapSource) Stats() SourceStats {
	stats, err := p.handle.Stats()
	if err != nil {
		return SourceStats{}
	}
	return SourceStats{
		Received: uint64(stats.PacketsReceived),
		Dropped:  uint64(stats.PacketsDropped),
	}
}

func (p *PcapSource) Decoder() gopacket.Decoder {
	return p.handle.LinkType()
}

func (p *PcapSource) Close() error {
	p.handle.Close()
	return nil
}

// PcapSourceFactory creates a single PcapSource using pcap.OpenLive.
type PcapSourceFactory struct{}

func (f *PcapSourceFactory) CreateSources(iface, bpfFilter string, count int, cfg CaptureConfig) ([]CaptureSource, error) {
	handle, err := pcap.OpenLive(iface, int32(cfg.Snaplen), true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("pcap open live: %w", err)
	}

	if bpfFilter != "" {
		if err := handle.SetBPFFilter(bpfFilter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("pcap set bpf filter: %w", err)
		}
	}

	return []CaptureSource{newPcapSource(handle)}, nil
}
