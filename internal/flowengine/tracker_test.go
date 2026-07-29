package flowengine

import (
	"strings"
	"testing"
	"time"

	"DeepPacketAI/internal/domain"
)

func tcpPkt(srcIP string, srcPort uint16, dstIP string, dstPort uint16, flags uint16, ttl uint8, ipID uint16, ts time.Time) *domain.Packet {
	return &domain.Packet{
		Timestamp: ts,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  "TCP",
		TCPFlags:  flags,
		TTL:       ttl,
		IPID:      ipID,
	}
}

func TestRSTAuthenticity_GenuineClose(t *testing.T) {
	tr := NewTracker()
	base := time.Now()

	// SYN/ACK/data from the server, all at TTL 118 (its real, consistent path).
	tr.HandlePacket(tcpPkt("10.0.0.1", 51000, "10.0.0.2", 443, flagSYN, 64, 100, base))
	tr.HandlePacket(tcpPkt("10.0.0.2", 443, "10.0.0.1", 51000, flagSYN|flagACK, 118, 200, base.Add(time.Millisecond)))
	tr.HandlePacket(tcpPkt("10.0.0.1", 51000, "10.0.0.2", 443, flagACK, 64, 101, base.Add(2*time.Millisecond)))
	// Server closes with an RST at the same TTL (118) it's used all along.
	tr.HandlePacket(tcpPkt("10.0.0.2", 443, "10.0.0.1", 51000, flagRST|flagACK, 118, 250, base.Add(3*time.Millisecond)))

	flows := tr.Flush()
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	m := flows[0].Metrics
	if m["close_reason"] != "RST" {
		t.Fatalf("expected close_reason RST, got %v", m["close_reason"])
	}
	if m["rst_authenticity"] != "genuine" {
		t.Fatalf("expected rst_authenticity genuine, got %v (delta=%v)", m["rst_authenticity"], m["rst_ttl_delta"])
	}
}

func TestRSTAuthenticity_SuspiciousInjectedReset(t *testing.T) {
	tr := NewTracker()
	base := time.Now()

	// Server's real packets are all at TTL 118.
	tr.HandlePacket(tcpPkt("10.0.0.1", 51000, "10.0.0.2", 443, flagSYN, 64, 100, base))
	tr.HandlePacket(tcpPkt("10.0.0.2", 443, "10.0.0.1", 51000, flagSYN|flagACK, 118, 200, base.Add(time.Millisecond)))
	tr.HandlePacket(tcpPkt("10.0.0.1", 51000, "10.0.0.2", 443, flagACK, 64, 101, base.Add(2*time.Millisecond)))
	// A "server-sourced" RST arrives with TTL 46 (72 hops off — an off-path
	// injector, not the real server whose packets all showed TTL 118) and
	// IP-ID 0, consistent with a crude injection tool.
	tr.HandlePacket(tcpPkt("10.0.0.2", 443, "10.0.0.1", 51000, flagRST|flagACK, 46, 0, base.Add(3*time.Millisecond)))

	flows := tr.Flush()
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	m := flows[0].Metrics
	if m["rst_authenticity"] != "suspicious" {
		t.Fatalf("expected rst_authenticity suspicious, got %v", m["rst_authenticity"])
	}
	delta, _ := m["rst_ttl_delta"].(int)
	if delta != 72 {
		t.Fatalf("expected rst_ttl_delta 72, got %d", delta)
	}
	reason, _ := m["rst_authenticity_reason"].(string)
	if !strings.Contains(reason, "TTL") {
		t.Fatalf("expected reason to mention TTL, got %q", reason)
	}
	if !strings.Contains(reason, "IP-ID is 0") {
		t.Fatalf("expected reason to note the zero IP-ID as corroborating, got %q", reason)
	}
}

func TestRSTAuthenticity_SmallDeltaIsGenuine(t *testing.T) {
	tr := NewTracker()
	base := time.Now()

	tr.HandlePacket(tcpPkt("10.0.0.1", 51000, "10.0.0.2", 443, flagSYN, 64, 100, base))
	tr.HandlePacket(tcpPkt("10.0.0.2", 443, "10.0.0.1", 51000, flagSYN|flagACK, 118, 200, base.Add(time.Millisecond)))
	// RST at TTL 117 — a 1-hop difference, well within ordinary route noise.
	tr.HandlePacket(tcpPkt("10.0.0.2", 443, "10.0.0.1", 51000, flagRST|flagACK, 117, 201, base.Add(2*time.Millisecond)))

	flows := tr.Flush()
	m := flows[0].Metrics
	if m["rst_authenticity"] != "genuine" {
		t.Fatalf("expected small TTL delta to be classified genuine, got %v (delta=%v)", m["rst_authenticity"], m["rst_ttl_delta"])
	}
}

func TestRSTAuthenticity_UnknownWithoutBaseline(t *testing.T) {
	tr := NewTracker()
	base := time.Now()

	// The RST is the very first (and only) packet ever seen from the server
	// direction — no baseline TTL exists to compare against.
	tr.HandlePacket(tcpPkt("10.0.0.1", 51000, "10.0.0.2", 443, flagSYN, 64, 100, base))
	tr.HandlePacket(tcpPkt("10.0.0.2", 443, "10.0.0.1", 51000, flagRST|flagACK, 46, 0, base.Add(time.Millisecond)))

	flows := tr.Flush()
	m := flows[0].Metrics
	if m["rst_authenticity"] != "unknown" {
		t.Fatalf("expected rst_authenticity unknown without a baseline, got %v", m["rst_authenticity"])
	}
	if _, ok := m["rst_ttl_delta"]; ok {
		t.Fatalf("did not expect rst_ttl_delta to be set without a baseline")
	}
}

func TestRSTAuthenticity_AbsentOnFINClose(t *testing.T) {
	tr := NewTracker()
	base := time.Now()

	tr.HandlePacket(tcpPkt("10.0.0.1", 51000, "10.0.0.2", 443, flagSYN, 64, 100, base))
	tr.HandlePacket(tcpPkt("10.0.0.2", 443, "10.0.0.1", 51000, flagSYN|flagACK, 118, 200, base.Add(time.Millisecond)))
	tr.HandlePacket(tcpPkt("10.0.0.1", 51000, "10.0.0.2", 443, flagFIN|flagACK, 64, 101, base.Add(2*time.Millisecond)))

	flows := tr.Flush()
	m := flows[0].Metrics
	if m["close_reason"] != "FIN" {
		t.Fatalf("expected close_reason FIN, got %v", m["close_reason"])
	}
	if _, ok := m["rst_authenticity"]; ok {
		t.Fatalf("did not expect rst_authenticity on a FIN-closed flow, got %v", m["rst_authenticity"])
	}
}

func icmpPkt(srcIP, dstIP string, typeCode uint16, ts time.Time) *domain.Packet {
	return &domain.Packet{
		Timestamp: ts,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   typeCode >> 8,
		DstPort:   typeCode & 0xFF,
		Protocol:  "ICMP",
	}
}

// TestICMPRequestReplyMergeIntoOneFlow reproduces a real bug: pcap/reader.go
// maps ICMP Type/Code onto SrcPort/DstPort as a port stand-in so the generic
// flow tracker has something to key on, but an echo request (Type=8) and its
// own reply (Type=0) read as opposite "ports" — before the fix, makeKey's
// TCP/UDP-style canonicization treated request and reply as two unrelated
// flows instead of one ping/pong conversation.
func TestICMPRequestReplyMergeIntoOneFlow(t *testing.T) {
	tr := NewTracker()
	base := time.Now()

	const echoRequest = uint16(8) << 8 // Type=8, Code=0
	const echoReply = uint16(0) << 8   // Type=0, Code=0

	tr.HandlePacket(icmpPkt("10.0.0.1", "10.0.0.2", echoRequest, base))
	tr.HandlePacket(icmpPkt("10.0.0.2", "10.0.0.1", echoReply, base.Add(time.Millisecond)))
	tr.HandlePacket(icmpPkt("10.0.0.1", "10.0.0.2", echoRequest, base.Add(time.Second)))
	tr.HandlePacket(icmpPkt("10.0.0.2", "10.0.0.1", echoReply, base.Add(time.Second+time.Millisecond)))

	flows := tr.Flush()
	if len(flows) != 1 {
		t.Fatalf("expected 1 merged ICMP flow for the ping/pong conversation, got %d", len(flows))
	}
	if flows[0].Type != "ICMP" {
		t.Fatalf("expected flow type ICMP, got %q", flows[0].Type)
	}
	if flows[0].Metrics["packets"] != int64(4) {
		t.Fatalf("expected 4 packets in the merged flow, got %v", flows[0].Metrics["packets"])
	}
}

func TestICMPDifferentHostPairsStayDistinct(t *testing.T) {
	tr := NewTracker()
	base := time.Now()
	const echoRequest = uint16(8) << 8

	tr.HandlePacket(icmpPkt("10.0.0.1", "10.0.0.2", echoRequest, base))
	tr.HandlePacket(icmpPkt("10.0.0.1", "10.0.0.3", echoRequest, base.Add(time.Millisecond)))

	flows := tr.Flush()
	if len(flows) != 2 {
		t.Fatalf("expected 2 distinct ICMP flows for 2 different destination hosts, got %d", len(flows))
	}
}

func TestRSTAuthenticity_InjectorRSTIsNotItsOwnBaseline(t *testing.T) {
	tr := NewTracker()
	base := time.Now()

	// A completely off-path RST arrives as the very FIRST packet ever seen
	// from the server direction — before any genuine server packet. It must
	// not become its own baseline (which would trivially compare equal).
	tr.HandlePacket(tcpPkt("10.0.0.1", 51000, "10.0.0.2", 443, flagSYN, 64, 100, base))
	tr.HandlePacket(tcpPkt("10.0.0.2", 443, "10.0.0.1", 51000, flagRST|flagACK, 46, 0, base.Add(time.Millisecond)))
	// The real server's SYN-ACK never arrives (connection was killed by the
	// injected RST before it could) — so there is genuinely no baseline.

	flows := tr.Flush()
	m := flows[0].Metrics
	if m["rst_authenticity"] != "unknown" {
		t.Fatalf("expected unknown (no genuine baseline exists), got %v", m["rst_authenticity"])
	}
}
