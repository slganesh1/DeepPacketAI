package rtcp

import (
	"fmt"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"DeepPacketAI/internal/events"
	"DeepPacketAI/internal/correlation"
)

type RTCPDecoder struct {
	media *correlation.MediaRegistry
}

func New(media *correlation.MediaRegistry) *RTCPDecoder {
	return &RTCPDecoder{media: media}
}

func (d *RTCPDecoder) Name() string {
	return "rtcp"
}

func (d *RTCPDecoder) CanHandle(pkt gopacket.Packet) bool {
	udp := pkt.Layer(layers.LayerTypeUDP)
	if udp == nil {
		return false
	}

	payload := udp.(*layers.UDP).Payload
	return len(payload) > 0 && payload[1] >= 200 && payload[1] <= 204
}

func (d *RTCPDecoder) Handle(pkt gopacket.Packet) ([]events.Event, error) {

	udp := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
	ip4 := pkt.Layer(layers.LayerTypeIPv4)
	ip6 := pkt.Layer(layers.LayerTypeIPv6)

	var srcIP string
	if ip4 != nil {
		srcIP = ip4.(*layers.IPv4).SrcIP.String()
	} else if ip6 != nil {
		srcIP = ip6.(*layers.IPv6).SrcIP.String()
	}

	callID, ok := d.media.Match(srcIP, fmt.Sprintf("%d", udp.SrcPort))
	if !ok {
		return nil, nil
	}

	payload := udp.Payload
	rtcpType := payload[1]

	// We only care about Receiver Reports (201)
	if rtcpType != 201 {
		return nil, nil
	}

	fractionLost := payload[12]
	jitter := uint32(payload[16])<<24 |
		uint32(payload[17])<<16 |
		uint32(payload[18])<<8 |
		uint32(payload[19])

	return []events.Event{
		{
			Type:      events.EventRTCPReport,
			SessionID: callID,
			Timestamp: pkt.Metadata().Timestamp,
			Source:    "rtcp",
			Fields: map[string]string{
				"fraction_lost": strconv.Itoa(int(fractionLost)),
				"jitter":        strconv.Itoa(int(jitter)),
			},
		},
	}, nil
}
