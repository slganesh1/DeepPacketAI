package regression_test

import (
	"fmt"
	"testing"
	"time"
)

// TestDNSTunnel_Detection verifies that 12 DNS queries with long (>52-char)
// unique subdomains under the same base domain trigger the
// "DNS Tunneling" alert.
//
// Rule thresholds:
//   - totalQueries  >= 5   (we send 12)
//   - longQueries   >  3   (score +3; we make all 12 long)
//   - score         >= 3   → alert fires
func TestDNSTunnel_Detection(t *testing.T) {
	t0 := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)

	const (
		resolver = "10.0.0.1"
		dnsServer = "8.8.8.8"
		dnsPort   = uint16(53)
	)

	// Base domain: evil.com
	// Each subdomain is 50 chars → full name = 59 chars > 52
	subdomains := []string{
		"aGVsbG8td29ybGQtdGhpcy1pcy1hLXZlcnlsb25nc3ViZG9t",
		"dGVzdGluZzEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9wcXJz",
		"c29tZWxvbmdyYW5kb21kYXRhc3RyaW5nZm9yZG5zdHVubmVs",
		"YW5vdGhlcmxvbmdzdWJkb21haW5mb3J0ZXN0aW5ncHVycG9z",
		"ZW5jb2RlZHBheWxvYWRkYXRhYmFzZTY0dHVubmVsaW5naGVy",
		"ZGF0YXRyYW5zZmVydmlhZG5zdHVubmVsaW5ncHJvdG9jb2xs",
		"bG9uZ3N1YmRvbWFpbnN0cmluZ251bWJlcnNldmVudGVzdGluZ",
		"bG9uZ3N1YmRvbWFpbnN0cmluZ251bWJlcmVpZ2h0dGVzdGlu",
		"bG9uZ3N1YmRvbWFpbnN0cmluZ251bWJlcm5pbmV0ZXN0aW5n",
		"bG9uZ3N1YmRvbWFpbnN0cmluZ251bWJlcnRlbnRlc3Rpbmdh",
		"bG9uZ3N1YmRvbWFpbnN0cmluZ251bWJlcmVsZXZlbnRlc3Rp",
		"bG9uZ3N1YmRvbWFpbnN0cmluZ251bWJlcnR3ZWx2ZXRlc3Rp",
	}

	var frames []pcapFrame
	for i, sub := range subdomains {
		name := fmt.Sprintf("%s.evil.com", sub)
		payload := dnsTunnelPayload(uint16(i+1), name)
		ts := t0.Add(time.Duration(i) * 100 * time.Millisecond)
		frames = append(frames, udpFrame(resolver, dnsServer, 10000+uint16(i), dnsPort, payload, ts))
	}

	pcap := writeTempPCAP(t, frames)
	snap := runPipeline(t, pcap)

	// Verify DNS Tunneling alert is present regardless of golden state
	hasTunnel := false
	for _, title := range snap.AlertTitles {
		if len(title) >= 12 && title[:12] == "DNS Tunnelin" {
			hasTunnel = true
			break
		}
	}
	if !hasTunnel {
		t.Errorf("expected DNS Tunneling alert, got alerts: %v", snap.AlertTitles)
	}

	assertGolden(t, "dns_tunnel", snap)
}

// TestDNSDGA_Detection sends DNS queries for high-entropy, long labels that
// resemble DGA (Domain Generation Algorithm) patterns.
func TestDNSDGA_Detection(t *testing.T) {
	t0 := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)

	const (
		resolver  = "10.0.0.1"
		dnsServer = "8.8.8.8"
		dnsPort   = uint16(53)
	)

	// High-entropy looking DGA-style domains (each ≥16 chars, high Shannon entropy)
	domains := []string{
		"xk3mq9p2r7n5t8y.ru",
		"z9w4s6h1c0v3b8q.ru",
		"n2f7r5t9m3k6p1w.ru",
		"b8h3q7y5s2n9r4t.ru",
		"w6p1m4f8k3z7n2s.ru",
	}

	var frames []pcapFrame
	for i, name := range domains {
		payload := dnsTunnelPayload(uint16(i+100), name)
		ts := t0.Add(time.Duration(i) * 200 * time.Millisecond)
		frames = append(frames, udpFrame(resolver, dnsServer, 20000+uint16(i), dnsPort, payload, ts))
	}

	pcap := writeTempPCAP(t, frames)
	snap := runPipeline(t, pcap)
	assertGolden(t, "dns_dga", snap)
}
