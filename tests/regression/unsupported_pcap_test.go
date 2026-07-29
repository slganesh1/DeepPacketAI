package regression_test

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"DeepPacketAI/internal/execution"
)

// TestUnsupportedPCAP_ICMP verifies that a PCAP containing only ICMP packets
// (no TCP/UDP/SCTP) is fully analysed, not rejected: reader.go decodes ICMP
// packets (Type/Code mapped onto SrcPort/DstPort), and flowengine merges an
// echo request with its own reply into a single flow per host pair — needed
// for icmpFloodRule to do meaningful ICMP flood/ping-sweep detection. This
// used to be a "no supported traffic" rejection case before ICMP decoding was
// added; the behavior is now deliberately the opposite (see the pcapCount
// guard and comment in executor.go's runPCAP).
func TestUnsupportedPCAP_ICMP(t *testing.T) {
	t0 := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)

	frames := []pcapFrame{
		icmpFrame("10.0.0.1", "10.0.0.2", t0),
		icmpFrame("10.0.0.1", "10.0.0.2", t0.Add(time.Second)),
		icmpFrame("10.0.0.2", "10.0.0.1", t0.Add(2*time.Second)),
	}

	pcap := writeTempPCAP(t, frames)

	pipe := execution.NewPipeline(execution.BuiltinDecoderFactory)
	flows, packets, _, err := pipe.Run(pcap)

	if err != nil {
		t.Fatalf("pipeline returned unexpected error: %v", err)
	}
	if len(packets) != 3 {
		t.Errorf("expected 3 ICMP packets to be extracted, got %d", len(packets))
	}
	// All 3 frames use the same Type/Code (echo request) between the same
	// host pair, just with the two IPs swapped for the third — merges into
	// one flow per host pair regardless of which side is "src" in a given
	// packet (see flowengine.makeKey's ICMP special case).
	if len(flows) != 1 {
		t.Errorf("expected 1 merged ICMP flow, got %d", len(flows))
	}
	if len(flows) == 1 && flows[0].Type != "ICMP" {
		t.Errorf("expected flow type ICMP, got %q", flows[0].Type)
	}
}

// TestUnsupportedPCAP_EmptyFile verifies that an empty/header-only PCAP
// produces 0 flows and 0 packets without crashing.
func TestUnsupportedPCAP_EmptyFile(t *testing.T) {
	pcap := writeTempPCAP(t, nil) // write pcap header only, no packets

	pipe := execution.NewPipeline(execution.BuiltinDecoderFactory)
	flows, packets, _, err := pipe.Run(pcap)

	if err != nil {
		t.Fatalf("unexpected error on empty pcap: %v", err)
	}
	if len(packets) != 0 || len(flows) != 0 {
		t.Errorf("expected empty results, got flows=%d packets=%d", len(flows), len(packets))
	}
	t.Logf("empty PCAP handled gracefully: flows=%d packets=%d", len(flows), len(packets))
}

// TestUnsupportedPCAP_UnknownAppProtocol verifies that a PCAP with TCP/UDP
// carrying an unknown application protocol (e.g. MQTT on port 1883) is NOT
// rejected — the flowengine still produces generic TCP/UDP flow records.
func TestUnsupportedPCAP_UnknownAppProtocol(t *testing.T) {
	t0 := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)

	// MQTT CONNECT packet on port 1883 (not supported by any decoder)
	mqttConnect := []byte{
		0x10,                   // MQTT CONNECT fixed header
		0x2b,                   // remaining length
		0x00, 0x04, 'M', 'Q', 'T', 'T', // protocol name
		0x04,       // protocol level
		0x02,       // connect flags
		0x00, 0x3c, // keep-alive
		0x00, 0x06, 'c', 'l', 'i', 'e', 'n', 't', // client id
	}

	frames := []pcapFrame{
		tcpFrame("10.0.0.1", "10.0.0.2", 54321, 1883, true, false, false, false, 1000, 0, nil, t0),
		tcpFrame("10.0.0.2", "10.0.0.1", 1883, 54321, true, true, false, false, 5000, 1001, nil, t0.Add(time.Millisecond)),
		tcpFrame("10.0.0.1", "10.0.0.2", 54321, 1883, false, true, false, false, 1001, 5001, nil, t0.Add(2*time.Millisecond)),
		tcpFrame("10.0.0.1", "10.0.0.2", 54321, 1883, false, true, true, false, 1001, 5001, mqttConnect, t0.Add(3*time.Millisecond)),
	}

	pcap := writeTempPCAP(t, frames)

	pipe := execution.NewPipeline(execution.BuiltinDecoderFactory)
	flows, packets, _, err := pipe.Run(pcap)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(packets) == 0 {
		t.Error("expected packets to be extracted from TCP capture")
	}
	if len(flows) == 0 {
		t.Error("expected flowengine to produce generic TCP flows")
	}

	t.Logf("unknown app protocol handled: packets=%d, generic flows=%d (%s)",
		len(packets), len(flows), func() string {
			var types []string
			seen := map[string]bool{}
			for _, f := range flows {
				if !seen[string(f.Type)] {
					types = append(types, string(f.Type))
					seen[string(f.Type)] = true
				}
			}
			return strings.Join(types, ", ")
		}())

	// executor would NOT fail this job — packets > 0 means it proceeds normally
	if len(packets) > 0 {
		t.Logf("executor would complete this job (packets=%d > 0)", len(packets))
	}
}

// ─── ICMP frame builder ───────────────────────────────────────────────────────

func icmpFrame(srcIP, dstIP string, ts time.Time) pcapFrame {
	eth := &layers.Ethernet{
		SrcMAC:       mac1,
		DstMAC:       mac2,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
	}
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, icmp, gopacket.Payload([]byte("ping"))); err != nil {
		panic(fmt.Sprintf("serialize icmp: %v", err))
	}
	return pcapFrame{data: buf.Bytes(), ts: ts}
}
