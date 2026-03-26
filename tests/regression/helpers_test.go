// Package regression_test contains end-to-end PCAP regression tests that run
// the full decode → detect → correlate pipeline against synthetic captures.
//
// Generate/update golden files:
//
//	go test ./tests/regression/... -update
package regression_test

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"DeepPacketAI/internal/correlation"
	"DeepPacketAI/internal/detection"
	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/execution"
)

var update = flag.Bool("update", false, "regenerate golden files")

// ─── Snapshot ────────────────────────────────────────────────────────────────

// Snapshot captures the deterministic parts of a pipeline run for golden-file
// comparison.  Timestamps, IDs, and MOS scores are excluded to keep it stable.
type Snapshot struct {
	FlowCount   int      `json:"flow_count"`
	FlowTypes   []string `json:"flow_types"`    // sorted unique protocol names
	AlertCount  int      `json:"alert_count"`
	AlertTitles []string `json:"alert_titles"`  // sorted unique titles
	CallCount   int      `json:"call_count"`
}

func buildSnapshot(flows []domain.Flow, alerts []detection.Alert, calls []domain.Call) Snapshot {
	typeSet := map[string]bool{}
	for _, f := range flows {
		typeSet[string(f.Type)] = true
	}
	flowTypes := sortedKeys(typeSet)

	titleSet := map[string]bool{}
	for _, a := range alerts {
		titleSet[a.Title] = true
	}
	titles := sortedKeys(titleSet)

	return Snapshot{
		FlowCount:   len(flows),
		FlowTypes:   flowTypes,
		AlertCount:  len(alerts),
		AlertTitles: titles,
		CallCount:   len(calls),
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ─── Golden file helpers ──────────────────────────────────────────────────────

func goldenPath(name string) string {
	return filepath.Join("testdata", "golden", name+".json")
}

// assertGolden compares got against the stored golden file for name.
// With -update it writes the golden file and passes.
func assertGolden(t *testing.T, name string, got Snapshot) {
	t.Helper()
	path := goldenPath(name)

	if *update {
		data, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
		t.Logf("updated golden: %s", path)
		return
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Fatalf("golden file %q missing — run: go test ./tests/regression/... -update", path)
	}
	if err != nil {
		t.Fatalf("read golden %s: %v", path, err)
	}

	var want Snapshot
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatalf("parse golden %s: %v", path, err)
	}

	if got.FlowCount != want.FlowCount {
		t.Errorf("FlowCount: got %d, want %d", got.FlowCount, want.FlowCount)
	}
	if !equalStringSlice(got.FlowTypes, want.FlowTypes) {
		t.Errorf("FlowTypes:\n  got  %v\n  want %v", got.FlowTypes, want.FlowTypes)
	}
	if got.AlertCount != want.AlertCount {
		t.Errorf("AlertCount: got %d, want %d", got.AlertCount, want.AlertCount)
	}
	if !equalStringSlice(got.AlertTitles, want.AlertTitles) {
		t.Errorf("AlertTitles:\n  got  %v\n  want %v", got.AlertTitles, want.AlertTitles)
	}
	if got.CallCount != want.CallCount {
		t.Errorf("CallCount: got %d, want %d", got.CallCount, want.CallCount)
	}
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ─── Pipeline runner ──────────────────────────────────────────────────────────

// runPipeline runs the decode + detect + correlate pipeline on pcapPath and
// returns the resulting snapshot.
func runPipeline(t *testing.T, pcapPath string) Snapshot {
	t.Helper()
	pipe := execution.NewPipeline(execution.BuiltinDecoderFactory)
	flows, _, _, err := pipe.Run(pcapPath)
	if err != nil {
		t.Fatalf("pipeline error: %v", err)
	}

	alerts := detection.NewEngine().RunOnFlows(flows)
	calls := correlation.CorrelateSIPRTP(flows)

	snap := buildSnapshot(flows, alerts, calls)
	t.Logf("flows=%d types=%v alerts=%d calls=%d", snap.FlowCount, snap.FlowTypes, snap.AlertCount, snap.CallCount)
	return snap
}

// ─── PCAP builder ────────────────────────────────────────────────────────────

var (
	mac1 = net.HardwareAddr{0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01}
	mac2 = net.HardwareAddr{0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x02}
)

type pcapFrame struct {
	data []byte
	ts   time.Time
}

// writeTempPCAP serialises frames to a classic pcap file in t.TempDir() and
// returns the file path.
func writeTempPCAP(t *testing.T, frames []pcapFrame) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.pcap")
	if err != nil {
		t.Fatalf("create temp pcap: %v", err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}
	for _, fr := range frames {
		ci := gopacket.CaptureInfo{
			Timestamp:     fr.ts,
			CaptureLength: len(fr.data),
			Length:        len(fr.data),
		}
		if err := w.WritePacket(ci, fr.data); err != nil {
			t.Fatalf("write packet: %v", err)
		}
	}
	f.Close()
	return f.Name()
}

// udpFrame builds an Ethernet+IPv4+UDP frame with the given payload.
func udpFrame(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte, ts time.Time) pcapFrame {
	eth := &layers.Ethernet{
		SrcMAC:       mac1,
		DstMAC:       mac2,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		panic(fmt.Sprintf("serialize udp: %v", err))
	}
	return pcapFrame{data: buf.Bytes(), ts: ts}
}

// tcpFrame builds an Ethernet+IPv4+TCP frame with the given payload and flags.
func tcpFrame(srcIP, dstIP string, srcPort, dstPort uint16, syn, ack, psh, fin bool, seq, ackNum uint32, payload []byte, ts time.Time) pcapFrame {
	eth := &layers.Ethernet{
		SrcMAC:       mac1,
		DstMAC:       mac2,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		Ack:     ackNum,
		SYN:     syn,
		ACK:     ack,
		PSH:     psh,
		FIN:     fin,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		panic(fmt.Sprintf("serialize tcp: %v", err))
	}
	return pcapFrame{data: buf.Bytes(), ts: ts}
}

// ─── RTP helpers ─────────────────────────────────────────────────────────────

// rtpPayload builds a minimal RTP packet (12-byte header, 4-byte dummy audio).
// version=2, no padding/extension, CC=0, marker=0, payloadType=0 (PCMU).
func rtpPayload(seq uint16, rtpTS uint32, ssrc uint32) []byte {
	pkt := make([]byte, 16)
	pkt[0] = 0x80              // V=2, P=0, X=0, CC=0
	pkt[1] = 0x00              // M=0, PT=0 (PCMU)
	binary.BigEndian.PutUint16(pkt[2:4], seq)
	binary.BigEndian.PutUint32(pkt[4:8], rtpTS)
	binary.BigEndian.PutUint32(pkt[8:12], ssrc)
	// 4 bytes of dummy audio payload
	copy(pkt[12:], []byte{0xFF, 0xFF, 0xFF, 0xFF})
	return pkt
}

// ─── DNS helpers ─────────────────────────────────────────────────────────────

// dnsTunnelPayload builds a binary DNS query for name with query type A (1).
// name must be a valid dot-separated domain label string.
func dnsTunnelPayload(txID uint16, name string) []byte {
	// DNS header (12 bytes): ID + flags + counts
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], txID)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // standard query, RD=1
	binary.BigEndian.PutUint16(hdr[4:6], 1)       // QDCOUNT=1
	// ANCOUNT, NSCOUNT, ARCOUNT stay 0

	// Encode QNAME (length-prefixed labels)
	var qname []byte
	for _, label := range splitLabels(name) {
		qname = append(qname, byte(len(label)))
		qname = append(qname, []byte(label)...)
	}
	qname = append(qname, 0x00) // root label

	// QTYPE=A(1) + QCLASS=IN(1)
	qtype := []byte{0x00, 0x01, 0x00, 0x01}

	return append(append(hdr, qname...), qtype...)
}

func splitLabels(name string) []string {
	var labels []string
	start := 0
	for i, c := range name {
		if c == '.' {
			if i > start {
				labels = append(labels, name[start:i])
			}
			start = i + 1
		}
	}
	if start < len(name) {
		labels = append(labels, name[start:])
	}
	return labels
}
