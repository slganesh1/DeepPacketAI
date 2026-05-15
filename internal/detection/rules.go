package detection

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// BuiltinRules returns the default set of detection rules (24 total).
func BuiltinRules() []Rule {
	return []Rule{
		// Existing protocol-specific rules (8)
		sipErrorRule(),
		rtpLossRule(),
		rtpJitterRule(),
		dnsErrorRule(),
		diameterErrorRule(),
		gtpFailureRule(),
		pfcpFailureRule(),
		oneWayAudioRule(),

		// Category 1: Volume-based (5)
		packetVolumeSpike(),
		largePacketRule(),
		packetFloodRule(),
		synFloodRule(),
		icmpFloodRule(),

		// Category 2: Protocol/Port (2)
		unusualPortRule(),
		protocolMismatchRule(),

		// Category 3: Source/Destination (2)
		sourceFanOutRule(),
		trafficConcentrationRule(),

		// Category 4: Behavioral/Content (3)
		repeatedFailureRule(),
		sipRegisterFloodRule(),
		dnsQueryFloodRule(),

		// Category 5: Temporal (2)
		longDurationFlowRule(),
		trafficBurstRule(),

		// Category 6: Improved Jitter (1)
		jitterVarianceRule(),

		// Category 7: Latency & QoS (3)
		dnsSlowResponseRule(),
		sipSlowSetupRule(),
		qosDegradationRule(),

		// Category 8: Security (4 existing)
		sipBruteForceRule(),
		dnsTunnelingRule(),
		voipCallDropRule(),
		tlsDowngradeRule(),

		// Category 9: Advanced VoIP Security (3)
		sipOptionsScanRule(),
		sipInviteFloodRule(),
		sipCallHijackRule(),

		// Category 10: Advanced DNS Security (2)
		dnsDGADetectionRule(),
		dnsFastFluxRule(),

		// Category 11: Advanced TLS Security (3)
		tlsWeakCipherRule(),
		tlsJA3AlertRule(),
		tlsSelfSignedCertRule(),
	}
}

// ─── Existing Rules ─────────────────────────────────────────────────────────

func sipErrorRule() Rule {
	return Rule{
		Name:     "SIP Error Responses",
		Protocol: "SIP",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert
			for _, f := range ctx.Flows {
				if f.Type != "SIP" {
					continue
				}
				resp, _ := f.Metrics["response"].(string)
				if len(resp) >= 3 && (resp[0] == '4' || resp[0] == '5' || resp[0] == '6') {
					severity := SeverityWarning
					if resp[0] == '5' || resp[0] == '6' {
						severity = SeverityError
					}
					alerts = append(alerts, Alert{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						Severity:    severity,
						Protocol:    "SIP",
						Title:       fmt.Sprintf("SIP Error: %s", resp),
						Description: fmt.Sprintf("SIP call %s received error response %s", f.FlowID, resp),
						FlowID:      f.FlowID,
					})
				}
			}
			return alerts
		},
	}
}

func rtpLossRule() Rule {
	return Rule{
		Name:     "RTP Packet Loss",
		Protocol: "RTP",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert
			for _, f := range ctx.Flows {
				if f.Type != "RTP" {
					continue
				}
				pktCount, _ := f.Metrics["packet_count"].(int)
				seqGap, _ := f.Metrics["max_seq_gap"].(int)
				if pktCount > 0 && seqGap > 0 {
					lossPct := float64(seqGap) / float64(pktCount) * 100
					if lossPct > 5 {
						severity := SeverityWarning
						if lossPct > 15 {
							severity = SeverityError
						}
						alerts = append(alerts, Alert{
							ID:          uuid.New().String(),
							Timestamp:   time.Now(),
							Severity:    severity,
							Protocol:    "RTP",
							Title:       fmt.Sprintf("High Packet Loss (%.1f%%)", lossPct),
							Description: fmt.Sprintf("RTP stream %s has %.1f%% packet loss (%d gaps in %d packets)", f.FlowID, lossPct, seqGap, pktCount),
							FlowID:      f.FlowID,
						})
					}
				}
			}
			return alerts
		},
	}
}

func rtpJitterRule() Rule {
	return Rule{
		Name:     "RTP High Jitter",
		Protocol: "RTP",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert
			for _, f := range ctx.Flows {
				if f.Type != "RTP" {
					continue
				}
				jitter := getFloat64Metric(f.Metrics, "jitter_ms")
				if jitter > 30 {
					severity := SeverityWarning
					if jitter > 100 {
						severity = SeverityError
					}
					alerts = append(alerts, Alert{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						Severity:    severity,
						Protocol:    "RTP",
						Title:       fmt.Sprintf("High Jitter (%.1fms)", jitter),
						Description: fmt.Sprintf("RTP stream %s has jitter of %.1fms", f.FlowID, jitter),
						FlowID:      f.FlowID,
					})
				}
			}
			return alerts
		},
	}
}

func dnsErrorRule() Rule {
	return Rule{
		Name:     "DNS Errors",
		Protocol: "DNS",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert
			for _, f := range ctx.Flows {
				if f.Type != "DNS" {
					continue
				}
				isErr, _ := f.Metrics["is_error"].(bool)
				if !isErr {
					continue
				}
				errType, _ := f.Metrics["error_type"].(string)
				name, _ := f.Metrics["query_name"].(string)
				severity := SeverityWarning
				if errType == "SERVFAIL" {
					severity = SeverityError
				}
				alerts = append(alerts, Alert{
					ID:          uuid.New().String(),
					Timestamp:   time.Now(),
					Severity:    severity,
					Protocol:    "DNS",
					Title:       fmt.Sprintf("DNS %s: %s", errType, name),
					Description: fmt.Sprintf("DNS lookup for %s returned %s", name, errType),
					FlowID:      f.FlowID,
				})
			}
			return alerts
		},
	}
}

func diameterErrorRule() Rule {
	return Rule{
		Name:     "Diameter Non-Success",
		Protocol: "Diameter",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert
			for _, f := range ctx.Flows {
				if f.Type != "Diameter" {
					continue
				}
				isErr, _ := f.Metrics["is_error"].(bool)
				if !isErr {
					continue
				}
				cmd, _ := f.Metrics["command"].(string)
				rc, _ := f.Metrics["result_code"].(uint32)
				alerts = append(alerts, Alert{
					ID:          uuid.New().String(),
					Timestamp:   time.Now(),
					Severity:    SeverityError,
					Protocol:    "Diameter",
					Title:       fmt.Sprintf("Diameter %s Failed (RC=%d)", cmd, rc),
					Description: fmt.Sprintf("Diameter %s returned result code %d", cmd, rc),
					FlowID:      f.FlowID,
				})
			}
			return alerts
		},
	}
}

func gtpFailureRule() Rule {
	return Rule{
		Name:     "GTP Failures",
		Protocol: "GTP",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert
			for _, f := range ctx.Flows {
				if f.Type != "GTP" {
					continue
				}
				isErr, _ := f.Metrics["is_error"].(bool)
				if !isErr {
					continue
				}
				msgType, _ := f.Metrics["message_type"].(string)
				cause, _ := f.Metrics["cause_code"].(uint8)
				alerts = append(alerts, Alert{
					ID:          uuid.New().String(),
					Timestamp:   time.Now(),
					Severity:    SeverityError,
					Protocol:    "GTP",
					Title:       fmt.Sprintf("GTP %s Failed (Cause=%d)", msgType, cause),
					Description: fmt.Sprintf("GTP %s failed with cause %d", msgType, cause),
					FlowID:      f.FlowID,
				})
			}
			return alerts
		},
	}
}

func pfcpFailureRule() Rule {
	return Rule{
		Name:     "PFCP Failures",
		Protocol: "PFCP",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert
			for _, f := range ctx.Flows {
				if f.Type != "PFCP" {
					continue
				}
				isErr, _ := f.Metrics["is_error"].(bool)
				if !isErr {
					continue
				}
				msgType, _ := f.Metrics["message_type"].(string)
				cause, _ := f.Metrics["cause_code"].(uint8)
				alerts = append(alerts, Alert{
					ID:          uuid.New().String(),
					Timestamp:   time.Now(),
					Severity:    SeverityError,
					Protocol:    "PFCP",
					Title:       fmt.Sprintf("PFCP %s Failed (Cause=%d)", msgType, cause),
					Description: fmt.Sprintf("PFCP %s failed with cause %d", msgType, cause),
					FlowID:      f.FlowID,
				})
			}
			return alerts
		},
	}
}

func oneWayAudioRule() Rule {
	return Rule{
		Name:     "One-Way Audio",
		Protocol: "RTP",
		Check: func(ctx *RuleContext) []Alert {
			type stream struct {
				src, dst string
				count    int
			}
			var streams []stream
			for _, f := range ctx.Flows {
				if f.Type != "RTP" {
					continue
				}
				count, _ := f.Metrics["packet_count"].(int)
				streams = append(streams, stream{src: f.SrcIP, dst: f.DstIP, count: count})
			}

			var alerts []Alert
			for i, s1 := range streams {
				hasReverse := false
				for j, s2 := range streams {
					if i != j && s1.src == s2.dst && s1.dst == s2.src && s2.count > 10 {
						hasReverse = true
						break
					}
				}
				if !hasReverse && s1.count > 50 {
					alerts = append(alerts, Alert{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						Severity:    SeverityWarning,
						Protocol:    "RTP",
						Title:       "Possible One-Way Audio",
						Description: fmt.Sprintf("RTP stream %s -> %s has %d packets but no return stream detected", s1.src, s1.dst, s1.count),
					})
				}
			}
			return alerts
		},
	}
}

// ─── Category 1: Volume-based ───────────────────────────────────────────────

func packetVolumeSpike() Rule {
	return Rule{
		Name:     "Packet Volume Spike",
		Protocol: "ALL",
		Check: func(ctx *RuleContext) []Alert {
			if ctx.Aggregates == nil || ctx.Aggregates.TotalFlows == 0 {
				return nil
			}
			avgPackets := float64(ctx.Aggregates.TotalPackets) / float64(ctx.Aggregates.TotalFlows)

			var alerts []Alert
			for _, f := range ctx.Flows {
				pktCount := getIntMetric(f.Metrics, "packet_count")
				if pktCount < 500 {
					continue
				}
				if avgPackets > 0 && float64(pktCount) > avgPackets*10 {
					alerts = append(alerts, Alert{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						Severity:    SeverityWarning,
						Protocol:    f.Type,
						Title:       fmt.Sprintf("Packet Volume Spike (%d pkts)", pktCount),
						Description: fmt.Sprintf("%s flow %s has %d packets (avg %.0f), >10x average", f.Type, f.FlowID, pktCount, avgPackets),
						FlowID:      f.FlowID,
					})
				}
			}
			return alerts
		},
	}
}

func largePacketRule() Rule {
	// Protocol-specific maximum expected packet sizes (bytes)
	maxExpected := map[string]int{
		"RTP":  400,
		"DNS":  512,
		"SIP":  4000,
	}

	return Rule{
		Name:     "Oversized Packets",
		Protocol: "ALL",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert
			for _, f := range ctx.Flows {
				limit, ok := maxExpected[f.Type]
				if !ok {
					continue
				}
				maxSize := getIntMetric(f.Metrics, "max_packet_size")
				if maxSize > limit {
					alerts = append(alerts, Alert{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						Severity:    SeverityWarning,
						Protocol:    f.Type,
						Title:       fmt.Sprintf("Oversized %s Packet (%d bytes)", f.Type, maxSize),
						Description: fmt.Sprintf("%s flow %s has packets up to %d bytes (expected max %d)", f.Type, f.FlowID, maxSize, limit),
						FlowID:      f.FlowID,
					})
				}
			}
			return alerts
		},
	}
}

func packetFloodRule() Rule {
	return Rule{
		Name:     "Packet Flood",
		Protocol: "ALL",
		Check: func(ctx *RuleContext) []Alert {
			if ctx.Aggregates == nil || ctx.Aggregates.TotalPackets < 1000 {
				return nil
			}
			var alerts []Alert
			for srcIP, count := range ctx.Aggregates.PacketsPerSrcIP {
				ratio := float64(count) / float64(ctx.Aggregates.TotalPackets)
				if ratio > 0.80 && count >= 1000 {
					alerts = append(alerts, Alert{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						Severity:    SeverityError,
						Protocol:    "ALL",
						Title:       fmt.Sprintf("Packet Flood from %s", srcIP),
						Description: fmt.Sprintf("Source %s contributes %d packets (%.0f%% of total %d)", srcIP, count, ratio*100, ctx.Aggregates.TotalPackets),
					})
				}
			}
			return alerts
		},
	}
}

// synFloodRule detects TCP SYN flood attacks — many half-open connections from
// a single source, indicating the attacker is sending SYN packets without
// completing the three-way handshake.
func synFloodRule() Rule {
	return Rule{
		Name:     "TCP SYN Flood",
		Protocol: "TCP",
		Check: func(ctx *RuleContext) []Alert {
			if ctx.Aggregates == nil {
				return nil
			}
			var alerts []Alert
			for srcIP, synCount := range ctx.Aggregates.SYNOnlyFlowsPerSrcIP {
				if synCount < 20 {
					continue
				}
				severity := SeverityWarning
				if synCount >= 100 {
					severity = SeverityCritical
				} else if synCount >= 50 {
					severity = SeverityError
				}
				alerts = append(alerts, Alert{
					ID:        uuid.New().String(),
					Timestamp: time.Now(),
					Severity:  severity,
					Protocol:  "TCP",
					Title:     fmt.Sprintf("TCP SYN Flood: %s (%d half-open connections)", srcIP, synCount),
					Description: fmt.Sprintf(
						"Source %s opened %d TCP connections that never completed the handshake (SYN sent, ACK never received) — possible SYN flood DoS attack",
						srcIP, synCount,
					),
					Metadata: map[string]any{
						"src_ip":          srcIP,
						"syn_only_flows":  synCount,
						"attack_type":     "syn_flood",
					},
				})
			}
			return alerts
		},
	}
}

// icmpFloodRule detects ICMP flood attacks — a high volume of ICMP flows from
// a single source, indicating a ping flood or ICMP-based DoS.
func icmpFloodRule() Rule {
	return Rule{
		Name:     "ICMP Flood",
		Protocol: "ICMP",
		Check: func(ctx *RuleContext) []Alert {
			if ctx.Aggregates == nil {
				return nil
			}
			var alerts []Alert
			for srcIP, icmpCount := range ctx.Aggregates.ICMPFlowsPerSrcIP {
				if icmpCount < 50 {
					continue
				}
				severity := SeverityWarning
				if icmpCount >= 500 {
					severity = SeverityCritical
				} else if icmpCount >= 200 {
					severity = SeverityError
				}
				alerts = append(alerts, Alert{
					ID:        uuid.New().String(),
					Timestamp: time.Now(),
					Severity:  severity,
					Protocol:  "ICMP",
					Title:     fmt.Sprintf("ICMP Flood: %s (%d ICMP flows)", srcIP, icmpCount),
					Description: fmt.Sprintf(
						"Source %s generated %d ICMP flows — possible ping flood or ICMP-based DoS attack",
						srcIP, icmpCount,
					),
					Metadata: map[string]any{
						"src_ip":      srcIP,
						"icmp_flows":  icmpCount,
						"attack_type": "icmp_flood",
					},
				})
			}
			return alerts
		},
	}
}

// ─── Category 2: Protocol/Port ──────────────────────────────────────────────

// standardPorts maps protocol types to their well-known ports.
var standardPorts = map[string][]uint16{
	"SIP":      {5060, 5061},
	"DNS":      {53},
	"Diameter": {3868},
	"GTP":      {2123, 2152},
	"PFCP":     {8805},
}

func unusualPortRule() Rule {
	return Rule{
		Name:     "Unusual Port",
		Protocol: "ALL",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert
			for _, f := range ctx.Flows {
				ports, ok := standardPorts[f.Type]
				if !ok {
					continue
				}
				srcMatch := false
				dstMatch := false
				for _, p := range ports {
					if f.SrcPort == p {
						srcMatch = true
					}
					if f.DstPort == p {
						dstMatch = true
					}
				}
				if !srcMatch && !dstMatch {
					alerts = append(alerts, Alert{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						Severity:    SeverityWarning,
						Protocol:    f.Type,
						Title:       fmt.Sprintf("Unusual %s Port (%d -> %d)", f.Type, f.SrcPort, f.DstPort),
						Description: fmt.Sprintf("%s flow %s uses non-standard ports %d -> %d (expected %v)", f.Type, f.FlowID, f.SrcPort, f.DstPort, ports),
						FlowID:      f.FlowID,
					})
				}
			}
			return alerts
		},
	}
}

// portToProtocol maps well-known ports to expected protocol types.
var portToProtocol = map[uint16]string{
	5060: "SIP",
	5061: "SIP",
	53:   "DNS",
	3868: "Diameter",
	2123: "GTP",
	2152: "GTP",
	8805: "PFCP",
}

func protocolMismatchRule() Rule {
	return Rule{
		Name:     "Protocol Mismatch",
		Protocol: "ALL",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert
			for _, f := range ctx.Flows {
				// Check if either port implies a specific protocol
				expectedBySrc, srcHas := portToProtocol[f.SrcPort]
				expectedByDst, dstHas := portToProtocol[f.DstPort]

				if srcHas && expectedBySrc != f.Type {
					alerts = append(alerts, Alert{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						Severity:    SeverityError,
						Protocol:    f.Type,
						Title:       fmt.Sprintf("Protocol Mismatch (port %d)", f.SrcPort),
						Description: fmt.Sprintf("Flow %s on port %d is %s but expected %s", f.FlowID, f.SrcPort, f.Type, expectedBySrc),
						FlowID:      f.FlowID,
					})
				}
				if dstHas && expectedByDst != f.Type {
					alerts = append(alerts, Alert{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						Severity:    SeverityError,
						Protocol:    f.Type,
						Title:       fmt.Sprintf("Protocol Mismatch (port %d)", f.DstPort),
						Description: fmt.Sprintf("Flow %s on port %d is %s but expected %s", f.FlowID, f.DstPort, f.Type, expectedByDst),
						FlowID:      f.FlowID,
					})
				}
			}
			return alerts
		},
	}
}

// ─── Category 3: Source/Destination ─────────────────────────────────────────

func sourceFanOutRule() Rule {
	return Rule{
		Name:     "Source Fan-Out (Scanning)",
		Protocol: "ALL",
		Check: func(ctx *RuleContext) []Alert {
			if ctx.Aggregates == nil {
				return nil
			}
			var alerts []Alert
			for srcIP, dests := range ctx.Aggregates.DestinationsPerSrc {
				count := len(dests)
				if count >= 20 {
					severity := SeverityWarning
					if count >= 50 {
						severity = SeverityError
					}
					alerts = append(alerts, Alert{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						Severity:    severity,
						Protocol:    "ALL",
						Title:       fmt.Sprintf("Source Fan-Out: %s (%d destinations)", srcIP, count),
						Description: fmt.Sprintf("Source %s communicates with %d unique destinations, possible scanning activity", srcIP, count),
					})
				}
			}
			return alerts
		},
	}
}

func trafficConcentrationRule() Rule {
	return Rule{
		Name:     "Traffic Concentration",
		Protocol: "ALL",
		Check: func(ctx *RuleContext) []Alert {
			if ctx.Aggregates == nil || ctx.Aggregates.TotalFlows < 10 {
				return nil
			}
			threshold := float64(ctx.Aggregates.TotalFlows) * 0.5
			var alerts []Alert

			// Check source IPs
			for ip, count := range ctx.Aggregates.FlowsPerSrcIP {
				if float64(count) > threshold {
					alerts = append(alerts, Alert{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						Severity:    SeverityWarning,
						Protocol:    "ALL",
						Title:       fmt.Sprintf("Traffic Concentration: %s (source)", ip),
						Description: fmt.Sprintf("Source %s appears in %d of %d flows (%.0f%%)", ip, count, ctx.Aggregates.TotalFlows, float64(count)/float64(ctx.Aggregates.TotalFlows)*100),
					})
				}
			}

			// Check destination IPs
			for ip, count := range ctx.Aggregates.FlowsPerDstIP {
				if float64(count) > threshold {
					alerts = append(alerts, Alert{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						Severity:    SeverityWarning,
						Protocol:    "ALL",
						Title:       fmt.Sprintf("Traffic Concentration: %s (destination)", ip),
						Description: fmt.Sprintf("Destination %s appears in %d of %d flows (%.0f%%)", ip, count, ctx.Aggregates.TotalFlows, float64(count)/float64(ctx.Aggregates.TotalFlows)*100),
					})
				}
			}
			return alerts
		},
	}
}

// ─── Category 4: Behavioral/Content ─────────────────────────────────────────

func repeatedFailureRule() Rule {
	return Rule{
		Name:     "Repeated Failures",
		Protocol: "ALL",
		Check: func(ctx *RuleContext) []Alert {
			if ctx.Aggregates == nil {
				return nil
			}
			var alerts []Alert
			for key, count := range ctx.Aggregates.ErrorCounts {
				if count >= 5 {
					severity := SeverityWarning
					if count >= 20 {
						severity = SeverityError
					}
					alerts = append(alerts, Alert{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						Severity:    severity,
						Protocol:    "ALL",
						Title:       fmt.Sprintf("Repeated Failures: %s (%d times)", key, count),
						Description: fmt.Sprintf("Error pattern %s occurred %d times across flows", key, count),
					})
				}
			}
			return alerts
		},
	}
}

func sipRegisterFloodRule() Rule {
	return Rule{
		Name:     "SIP REGISTER Flood",
		Protocol: "SIP",
		Check: func(ctx *RuleContext) []Alert {
			if ctx.Aggregates == nil {
				return nil
			}
			count := ctx.Aggregates.SIPMethodCounts["REGISTER"]
			if count < 20 {
				return nil
			}
			severity := SeverityWarning
			if count >= 50 {
				severity = SeverityError
			}
			return []Alert{{
				ID:          uuid.New().String(),
				Timestamp:   time.Now(),
				Severity:    severity,
				Protocol:    "SIP",
				Title:       fmt.Sprintf("SIP REGISTER Flood (%d requests)", count),
				Description: fmt.Sprintf("Detected %d SIP REGISTER requests, possible registration flood attack", count),
			}}
		},
	}
}

func dnsQueryFloodRule() Rule {
	return Rule{
		Name:     "DNS Query Flood",
		Protocol: "DNS",
		Check: func(ctx *RuleContext) []Alert {
			if ctx.Aggregates == nil {
				return nil
			}
			var alerts []Alert
			for domain, count := range ctx.Aggregates.DNSQueryCounts {
				if count >= 20 {
					severity := SeverityWarning
					if count >= 50 {
						severity = SeverityError
					}
					alerts = append(alerts, Alert{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						Severity:    severity,
						Protocol:    "DNS",
						Title:       fmt.Sprintf("DNS Query Flood: %s (%d queries)", domain, count),
						Description: fmt.Sprintf("Domain %s queried %d times, possible DNS flood or amplification", domain, count),
					})
				}
			}
			return alerts
		},
	}
}

// ─── Category 5: Temporal ───────────────────────────────────────────────────

func longDurationFlowRule() Rule {
	// Protocol-specific maximum expected flow durations
	maxDuration := map[string]time.Duration{
		"DNS":      30 * time.Second,
		"Diameter": 5 * time.Minute,
		"PFCP":     5 * time.Minute,
		"GTP":      10 * time.Minute,
		"RTP":      2 * time.Hour,
		"SIP":      2 * time.Hour,
	}

	return Rule{
		Name:     "Long Duration Flow",
		Protocol: "ALL",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert
			for _, f := range ctx.Flows {
				limit, ok := maxDuration[f.Type]
				if !ok {
					continue
				}
				duration := f.EndTime.Sub(f.StartTime)
				if duration > limit {
					alerts = append(alerts, Alert{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						Severity:    SeverityWarning,
						Protocol:    f.Type,
						Title:       fmt.Sprintf("Long Duration %s Flow (%.0fs)", f.Type, duration.Seconds()),
						Description: fmt.Sprintf("%s flow %s lasted %.0f seconds (max expected %.0fs)", f.Type, f.FlowID, duration.Seconds(), limit.Seconds()),
						FlowID:      f.FlowID,
					})
				}
			}
			return alerts
		},
	}
}

func trafficBurstRule() Rule {
	return Rule{
		Name:     "Traffic Burst",
		Protocol: "ALL",
		Check: func(ctx *RuleContext) []Alert {
			if ctx.Aggregates == nil || ctx.Aggregates.TotalFlows < 10 {
				return nil
			}

			// Bucket flows by second using their start time
			buckets := make(map[int64]int)
			for _, f := range ctx.Flows {
				if f.StartTime.IsZero() {
					continue
				}
				sec := f.StartTime.Unix()
				buckets[sec]++
			}

			if len(buckets) == 0 {
				return nil
			}

			// Compute average rate per second
			total := 0
			for _, count := range buckets {
				total += count
			}
			avg := float64(total) / float64(len(buckets))

			var alerts []Alert
			for sec, count := range buckets {
				if avg > 0 && float64(count) > avg*5 {
					t := time.Unix(sec, 0)
					alerts = append(alerts, Alert{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						Severity:    SeverityWarning,
						Protocol:    "ALL",
						Title:       fmt.Sprintf("Traffic Burst (%d flows/sec)", count),
						Description: fmt.Sprintf("At %s: %d flows started (avg %.1f/sec), >5x average rate", t.Format(time.RFC3339), count, avg),
					})
				}
			}
			return alerts
		},
	}
}

// ─── Category 6: Improved Jitter ────────────────────────────────────────────

func jitterVarianceRule() Rule {
	return Rule{
		Name:     "RTP Jitter Variance",
		Protocol: "RTP",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert
			for _, f := range ctx.Flows {
				if f.Type != "RTP" {
					continue
				}
				jitterMin := getFloat64Metric(f.Metrics, "jitter_min_ms")
				jitterMax := getFloat64Metric(f.Metrics, "jitter_max_ms")
				jitterAvg := getFloat64Metric(f.Metrics, "jitter_avg_ms")

				spread := jitterMax - jitterMin
				if jitterAvg > 0 && spread > jitterAvg*3 && spread > 50 {
					severity := SeverityWarning
					if spread > 200 {
						severity = SeverityError
					}
					alerts = append(alerts, Alert{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						Severity:    severity,
						Protocol:    "RTP",
						Title:       fmt.Sprintf("High Jitter Variance (%.1fms spread)", spread),
						Description: fmt.Sprintf("RTP stream %s has jitter spread %.1fms (min=%.1f, max=%.1f, avg=%.1f)", f.FlowID, spread, jitterMin, jitterMax, jitterAvg),
						FlowID:      f.FlowID,
					})
				}
			}
			return alerts
		},
	}
}

// ─── Category 7: Latency & QoS ─────────────────────────────────────────────

func dnsSlowResponseRule() Rule {
	return Rule{
		Name:     "DNS Slow Response",
		Protocol: "DNS",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert
			for _, f := range ctx.Flows {
				if f.Type != "DNS" {
					continue
				}
				latency := getFloat64Metric(f.Metrics, "latency_ms")
				if latency > 500 {
					severity := SeverityWarning
					if latency > 2000 {
						severity = SeverityError
					}
					name, _ := f.Metrics["query_name"].(string)
					alerts = append(alerts, Alert{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						Severity:    severity,
						Protocol:    "DNS",
						Title:       fmt.Sprintf("Slow DNS Response (%.0fms)", latency),
						Description: fmt.Sprintf("DNS query for %s took %.0fms (flow %s)", name, latency, f.FlowID),
						FlowID:      f.FlowID,
					})
				}
			}
			return alerts
		},
	}
}

func sipSlowSetupRule() Rule {
	return Rule{
		Name:     "SIP Slow Setup",
		Protocol: "SIP",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert
			for _, f := range ctx.Flows {
				if f.Type != "SIP" {
					continue
				}
				setupLatency := getFloat64Metric(f.Metrics, "setup_latency_ms")
				if setupLatency > 3000 {
					severity := SeverityWarning
					if setupLatency > 10000 {
						severity = SeverityError
					}
					alerts = append(alerts, Alert{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						Severity:    severity,
						Protocol:    "SIP",
						Title:       fmt.Sprintf("Slow SIP Setup (%.1fs)", setupLatency/1000),
						Description: fmt.Sprintf("SIP call %s took %.1fs from INVITE to 200 OK", f.FlowID, setupLatency/1000),
						FlowID:      f.FlowID,
					})
				}
			}
			return alerts
		},
	}
}

func qosDegradationRule() Rule {
	return Rule{
		Name:     "QoS Degradation",
		Protocol: "RTP",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert
			for _, f := range ctx.Flows {
				if f.Type != "RTP" {
					continue
				}
				jitter := getFloat64Metric(f.Metrics, "jitter_ms")
				pktCount := getIntMetric(f.Metrics, "packet_count")
				seqGap := getIntMetric(f.Metrics, "max_seq_gap")
				if pktCount == 0 {
					continue
				}
				lossPct := float64(seqGap) / float64(pktCount) * 100

				// Estimate MOS from jitter + loss (no latency measurement for RTP)
				R := 94.2 - lossPct*2.5 - jitter*0.1
				if R < 0 {
					R = 0
				}
				if R > 100 {
					R = 100
				}
				mos := 1.0 + 0.035*R + R*(R-60)*(100-R)*7e-6

				if mos < 3.6 {
					severity := SeverityWarning
					if mos < 2.6 {
						severity = SeverityError
					}
					alerts = append(alerts, Alert{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						Severity:    severity,
						Protocol:    "RTP",
						Title:       fmt.Sprintf("QoS Degradation (est. MOS %.1f)", mos),
						Description: fmt.Sprintf("RTP stream %s: estimated MOS %.2f (loss=%.1f%%, jitter=%.1fms)", f.FlowID, mos, lossPct, jitter),
						FlowID:      f.FlowID,
					})
				}
			}
			return alerts
		},
	}
}

// ─── Category 8: Security ────────────────────────────────────────────────────

// sipBruteForceRule detects SIP registration brute-force attacks.
// Fires when the same source IP accumulates ≥5 SIP 401 Unauthorized responses.
func sipBruteForceRule() Rule {
	return Rule{
		Name:     "SIP Registration Brute Force",
		Protocol: "SIP",
		Check: func(ctx *RuleContext) []Alert {
			if ctx.Aggregates == nil {
				return nil
			}
			var alerts []Alert
			for srcIP, count401 := range ctx.Aggregates.SIP401PerSrcIP {
				if count401 < 5 {
					continue
				}
				regCount := ctx.Aggregates.SIPRegisterPerSrcIP[srcIP]
				severity := SeverityWarning
				if count401 >= 20 {
					severity = SeverityCritical
				} else if count401 >= 10 {
					severity = SeverityError
				}
				alerts = append(alerts, Alert{
					ID:        uuid.New().String(),
					Timestamp: time.Now(),
					Severity:  severity,
					Protocol:  "SIP",
					Title:     fmt.Sprintf("SIP Brute Force: %s (%d × 401)", srcIP, count401),
					Description: fmt.Sprintf(
						"Source %s received %d SIP 401 Unauthorized responses (%d REGISTER attempts) — credential brute-force attack",
						srcIP, count401, regCount,
					),
					Metadata: map[string]any{
						"src_ip":         srcIP,
						"count_401":      count401,
						"count_register": regCount,
						"attack_type":    "sip_brute_force",
					},
				})
			}
			return alerts
		},
	}
}

// dnsTunnelingRule detects DNS tunneling via long subdomains, TXT abuse, and high subdomain entropy.
func dnsTunnelingRule() Rule {
	return Rule{
		Name:     "DNS Tunneling",
		Protocol: "DNS",
		Check: func(ctx *RuleContext) []Alert {
			type domainStat struct {
				longQueries   int
				txtQueries    int
				nxdomainCount int
				totalQueries  int
				uniqueLabels  map[string]bool
			}
			stats := make(map[string]*domainStat)

			for _, f := range ctx.Flows {
				if f.Type != "DNS" {
					continue
				}
				name, _ := f.Metrics["query_name"].(string)
				qtype, _ := f.Metrics["query_type"].(string)
				rcode, _ := f.Metrics["reply_code"].(string)

				base := dnsTunnelingBaseDomain(name)
				if base == "" {
					continue
				}
				if stats[base] == nil {
					stats[base] = &domainStat{uniqueLabels: make(map[string]bool)}
				}
				st := stats[base]
				st.totalQueries++
				if len(name) > 52 {
					st.longQueries++
				}
				if qtype == "TXT" || qtype == "NULL" {
					st.txtQueries++
				}
				if rcode == "NXDOMAIN" {
					st.nxdomainCount++
				}
				if idx := strings.Index(name, "."); idx > 0 {
					st.uniqueLabels[name[:idx]] = true
				}
			}

			var alerts []Alert
			for base, st := range stats {
				if st.totalQueries < 5 {
					continue
				}
				score := 0
				var reasons []string

				if st.longQueries > 3 {
					score += 3
					reasons = append(reasons, fmt.Sprintf("%d long subdomains (>52 chars)", st.longQueries))
				}
				if st.txtQueries > 2 {
					score += 2
					reasons = append(reasons, fmt.Sprintf("%d TXT/NULL queries", st.txtQueries))
				}
				uniqueRatio := float64(len(st.uniqueLabels)) / float64(st.totalQueries)
				if uniqueRatio > 0.8 && st.totalQueries >= 10 {
					score += 3
					reasons = append(reasons, fmt.Sprintf("%.0f%% unique subdomains (high entropy)", uniqueRatio*100))
				}
				if st.nxdomainCount > 5 {
					score += 2
					reasons = append(reasons, fmt.Sprintf("%d NXDOMAIN responses", st.nxdomainCount))
				}
				if score < 3 {
					continue
				}
				severity := SeverityWarning
				if score >= 6 {
					severity = SeverityCritical
				} else if score >= 4 {
					severity = SeverityError
				}
				alerts = append(alerts, Alert{
					ID:        uuid.New().String(),
					Timestamp: time.Now(),
					Severity:  severity,
					Protocol:  "DNS",
					Title:     fmt.Sprintf("DNS Tunneling: %s (score=%d)", base, score),
					Description: fmt.Sprintf(
						"Domain %s shows DNS tunneling indicators: %s",
						base, strings.Join(reasons, "; "),
					),
					Metadata: map[string]any{
						"base_domain":    base,
						"long_queries":   st.longQueries,
						"txt_queries":    st.txtQueries,
						"unique_labels":  len(st.uniqueLabels),
						"total_queries":  st.totalQueries,
						"nxdomain_count": st.nxdomainCount,
						"tunnel_score":   score,
					},
				})
			}
			return alerts
		},
	}
}

func dnsTunnelingBaseDomain(name string) string {
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return name
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// voipCallDropRule detects abruptly terminated VoIP calls and failed call setups.
func voipCallDropRule() Rule {
	return Rule{
		Name:     "VoIP Call Drop",
		Protocol: "SIP",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert
			for _, f := range ctx.Flows {
				if f.Type != "SIP" {
					continue
				}

				// Short-lived sessions terminated with BYE or CANCEL
				endType, _ := f.Metrics["end_type"].(string)
				dur := f.EndTime.Sub(f.StartTime)
				if (endType == "BYE" || endType == "CANCEL") && dur > 0 && dur < 30*time.Second {
					alerts = append(alerts, Alert{
						ID:        uuid.New().String(),
						Timestamp: time.Now(),
						Severity:  SeverityWarning,
						Protocol:  "SIP",
						Title:     fmt.Sprintf("VoIP Call Drop (%.1fs)", dur.Seconds()),
						Description: fmt.Sprintf(
							"SIP call %s terminated with %s after %.1fs — possible call drop or failed handoff",
							f.FlowID, endType, dur.Seconds(),
						),
						FlowID: f.FlowID,
						Metadata: map[string]any{
							"end_type":    endType,
							"duration_ms": dur.Milliseconds(),
						},
					})
				}

				// Response codes indicating call failure
				resp, _ := f.Metrics["response"].(string)
				dropReasons := map[string]string{
					"480": "Temporarily Unavailable",
					"486": "Busy Here",
					"487": "Request Cancelled",
					"503": "Service Unavailable",
					"504": "Server Timeout",
				}
				if reason, ok := dropReasons[resp]; ok {
					alerts = append(alerts, Alert{
						ID:        uuid.New().String(),
						Timestamp: time.Now(),
						Severity:  SeverityWarning,
						Protocol:  "SIP",
						Title:     fmt.Sprintf("VoIP Call Drop: %s (%s)", reason, resp),
						Description: fmt.Sprintf(
							"SIP call %s returned %s (%s) — call not established",
							f.FlowID, resp, reason,
						),
						FlowID: f.FlowID,
						Metadata: map[string]any{"sip_response": resp, "reason": reason},
					})
				}
			}
			return alerts
		},
	}
}

// tlsDowngradeRule detects deprecated TLS versions (SSLv3, TLSv1.0, TLSv1.1).
func tlsDowngradeRule() Rule {
	insecure := map[string]bool{
		"SSLv3":   true,
		"TLSv1.0": true,
		"TLSv1.1": true,
	}
	vulnMap := map[string]string{
		"SSLv3":   "POODLE",
		"TLSv1.0": "BEAST/POODLE",
		"TLSv1.1": "deprecated — IETF RFC 8996",
	}

	return Rule{
		Name:     "TLS Downgrade",
		Protocol: "TLS",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert
			for _, f := range ctx.Flows {
				if f.Type != "TLS" {
					continue
				}
				version, _ := f.Metrics["tls_version"].(string)
				if !insecure[version] {
					continue
				}
				severity := SeverityWarning
				if version == "SSLv3" {
					severity = SeverityCritical
				} else if version == "TLSv1.0" {
					severity = SeverityError
				}
				vuln := vulnMap[version]
				alerts = append(alerts, Alert{
					ID:        uuid.New().String(),
					Timestamp: time.Now(),
					Severity:  severity,
					Protocol:  "TLS",
					Title:     fmt.Sprintf("TLS Downgrade: %s (%s)", version, vuln),
					Description: fmt.Sprintf(
						"Flow %s uses deprecated %s between %s:%d ↔ %s:%d — %s",
						f.FlowID, version, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, vuln,
					),
					FlowID: f.FlowID,
					Metadata: map[string]any{
						"tls_version": version,
						"src_ip":      f.SrcIP,
						"dst_ip":      f.DstIP,
						"src_port":    f.SrcPort,
						"dst_port":    f.DstPort,
						"attack":      vuln,
					},
				})
			}
			return alerts
		},
	}
}
