package detection

import (
	"crypto/md5"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ─── Category 9: Advanced VoIP Security ─────────────────────────────────────

// sipOptionsScanRule detects SIP OPTIONS scanning — probing to enumerate SIP endpoints.
func sipOptionsScanRule() Rule {
	return Rule{
		Name:     "SIP OPTIONS Scanning",
		Protocol: "SIP",
		Check: func(ctx *RuleContext) []Alert {
			if ctx.Aggregates == nil {
				return nil
			}
			var alerts []Alert
			for srcIP, optCount := range ctx.Aggregates.SIPOptionsPerSrcIP {
				if optCount < 10 {
					continue
				}
				uniqueDests := len(ctx.Aggregates.DestinationsPerSrc[srcIP])
				if uniqueDests < 5 {
					continue
				}
				severity := SeverityWarning
				if optCount >= 50 || uniqueDests >= 20 {
					severity = SeverityError
				}
				alerts = append(alerts, Alert{
					ID:        uuid.New().String(),
					Timestamp: time.Now(),
					Severity:  severity,
					Protocol:  "SIP",
					Title:     fmt.Sprintf("SIP Endpoint Scanning: %s (%d OPTIONS)", srcIP, optCount),
					Description: fmt.Sprintf(
						"Source %s sent %d SIP OPTIONS probes to %d distinct destinations — active SIP endpoint enumeration",
						srcIP, optCount, uniqueDests,
					),
					Metadata: map[string]any{
						"src_ip":        srcIP,
						"options_count": optCount,
						"unique_dests":  uniqueDests,
						"attack_type":   "sip_scanning",
					},
				})
			}
			return alerts
		},
	}
}

// sipInviteFloodRule detects SIP INVITE flooding — mass call attempts, toll fraud.
func sipInviteFloodRule() Rule {
	return Rule{
		Name:     "SIP INVITE Flood / Toll Fraud",
		Protocol: "SIP",
		Check: func(ctx *RuleContext) []Alert {
			if ctx.Aggregates == nil {
				return nil
			}
			var alerts []Alert
			for srcIP, inviteCount := range ctx.Aggregates.SIPInvitePerSrcIP {
				if inviteCount < 15 {
					continue
				}
				uniqueDests := len(ctx.Aggregates.DestinationsPerSrc[srcIP])
				severity := SeverityWarning
				attackType := "sip_invite_flood"
				desc := fmt.Sprintf("Source %s sent %d SIP INVITE requests to %d destinations", srcIP, inviteCount, uniqueDests)

				if uniqueDests >= 10 {
					severity = SeverityCritical
					attackType = "toll_fraud"
					desc += " — suspected toll fraud (mass outbound calling)"
				} else if inviteCount >= 50 {
					severity = SeverityError
					desc += " — possible SIP DoS / call flood"
				}

				alerts = append(alerts, Alert{
					ID:        uuid.New().String(),
					Timestamp: time.Now(),
					Severity:  severity,
					Protocol:  "SIP",
					Title:     fmt.Sprintf("SIP INVITE Flood: %s (%d INVITEs)", srcIP, inviteCount),
					Description: desc,
					Metadata: map[string]any{
						"src_ip":       srcIP,
						"invite_count": inviteCount,
						"unique_dests": uniqueDests,
						"attack_type":  attackType,
					},
				})
			}
			return alerts
		},
	}
}

// sipCallHijackRule detects potential SIP call hijacking — BYE/CANCEL from an IP
// that was not part of the original call setup.
func sipCallHijackRule() Rule {
	return Rule{
		Name:     "SIP Call Hijack",
		Protocol: "SIP",
		Check: func(ctx *RuleContext) []Alert {
			type callPair struct{ src, dst string }
			established := make(map[string]callPair)
			var byeFlows []FlowSummary

			for _, f := range ctx.Flows {
				if f.Type != "SIP" {
					continue
				}
				method, _ := f.Metrics["method"].(string)
				resp, _ := f.Metrics["response"].(string)
				if method == "INVITE" && (resp == "200" || resp == "") {
					established[f.FlowID] = callPair{f.SrcIP, f.DstIP}
				}
				if method == "BYE" || method == "CANCEL" {
					byeFlows = append(byeFlows, f)
				}
			}

			var alerts []Alert
			for _, bye := range byeFlows {
				pair, ok := established[bye.FlowID]
				if !ok {
					continue
				}
				if bye.SrcIP != pair.src && bye.SrcIP != pair.dst {
					method, _ := bye.Metrics["method"].(string)
					alerts = append(alerts, Alert{
						ID:        uuid.New().String(),
						Timestamp: time.Now(),
						Severity:  SeverityCritical,
						Protocol:  "SIP",
						Title:     fmt.Sprintf("SIP Call Hijack: %s from unexpected IP %s", method, bye.SrcIP),
						Description: fmt.Sprintf(
							"SIP %s for call %s sent from %s — not a participant (original: %s ↔ %s)",
							method, bye.FlowID, bye.SrcIP, pair.src, pair.dst,
						),
						FlowID: bye.FlowID,
						Metadata: map[string]any{
							"hijack_ip":    bye.SrcIP,
							"original_src": pair.src,
							"original_dst": pair.dst,
							"method":       method,
							"attack_type":  "sip_call_hijack",
						},
					})
				}
			}
			return alerts
		},
	}
}

// ─── Category 10: Advanced DNS Security ─────────────────────────────────────

var knownSuspiciousTLDs = map[string]bool{
	"xyz": true, "top": true, "club": true, "gq": true, "cf": true,
	"ga": true, "ml": true, "tk": true, "pw": true, "work": true,
	"click": true, "download": true, "stream": true, "zip": true, "mov": true,
}

func shannonEntropy(s string) float64 {
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	n := float64(len(s))
	h := 0.0
	for _, count := range freq {
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

// dnsDGADetectionRule detects likely DGA or C2 domains via Shannon entropy and TLD analysis.
func dnsDGADetectionRule() Rule {
	return Rule{
		Name:     "DNS DGA / C2 Domain",
		Protocol: "DNS",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert
			for _, f := range ctx.Flows {
				if f.Type != "DNS" {
					continue
				}
				name, _ := f.Metrics["query_name"].(string)
				if name == "" || len(name) < 8 {
					continue
				}
				parts := strings.Split(name, ".")
				if len(parts) < 2 {
					continue
				}
				label := parts[0]
				tld := parts[len(parts)-1]

				entropy := shannonEntropy(label)
				isSuspiciousTLD := knownSuspiciousTLDs[strings.ToLower(tld)]
				isHighEntropy := entropy >= 3.5
				queryCount := ctx.Aggregates.DNSQueryCounts[name]

				score := 0
				var reasons []string
				if isHighEntropy {
					score += 3
					reasons = append(reasons, fmt.Sprintf("high entropy label (%.2f bits)", entropy))
				}
				if isSuspiciousTLD {
					score += 2
					reasons = append(reasons, fmt.Sprintf("suspicious TLD (.%s)", tld))
				}
				if len(label) >= 16 {
					score++
					reasons = append(reasons, fmt.Sprintf("long label (%d chars)", len(label)))
				}
				if queryCount <= 2 {
					score++
					reasons = append(reasons, "queried only once (DGA pattern)")
				}
				if score < 3 {
					continue
				}
				severity := SeverityWarning
				if score >= 5 {
					severity = SeverityCritical
				} else if score >= 4 {
					severity = SeverityError
				}
				alerts = append(alerts, Alert{
					ID:        uuid.New().String(),
					Timestamp: time.Now(),
					Severity:  severity,
					Protocol:  "DNS",
					Title:     fmt.Sprintf("Suspected DGA/C2 Domain: %s", name),
					Description: fmt.Sprintf(
						"Domain %s shows DGA/C2 indicators (score=%d): %s",
						name, score, strings.Join(reasons, "; "),
					),
					FlowID: f.FlowID,
					Metadata: map[string]any{
						"domain":      name,
						"label":       label,
						"entropy":     entropy,
						"tld":         tld,
						"dga_score":   score,
						"query_count": queryCount,
						"attack_type": "dns_c2",
					},
				})
			}
			return alerts
		},
	}
}

// dnsFastFluxRule detects fast-flux DNS — many different IPs for the same domain.
func dnsFastFluxRule() Rule {
	return Rule{
		Name:     "DNS Fast-Flux",
		Protocol: "DNS",
		Check: func(ctx *RuleContext) []Alert {
			if ctx.Aggregates == nil {
				return nil
			}
			var alerts []Alert
			for domain, ipSet := range ctx.Aggregates.DNSAnswerIPsPerDomain {
				uniqueIPs := len(ipSet)
				if uniqueIPs < 5 {
					continue
				}
				severity := SeverityWarning
				if uniqueIPs >= 15 {
					severity = SeverityCritical
				} else if uniqueIPs >= 8 {
					severity = SeverityError
				}
				sample := make([]string, 0, 5)
				for ip := range ipSet {
					sample = append(sample, ip)
					if len(sample) >= 5 {
						break
					}
				}
				alerts = append(alerts, Alert{
					ID:        uuid.New().String(),
					Timestamp: time.Now(),
					Severity:  severity,
					Protocol:  "DNS",
					Title:     fmt.Sprintf("DNS Fast-Flux: %s (%d IPs)", domain, uniqueIPs),
					Description: fmt.Sprintf(
						"Domain %s resolved to %d different IPs — fast-flux botnet C2 pattern. Sample: %s",
						domain, uniqueIPs, strings.Join(sample, ", "),
					),
					Metadata: map[string]any{
						"domain":      domain,
						"unique_ips":  uniqueIPs,
						"sample_ips":  sample,
						"attack_type": "dns_fast_flux",
					},
				})
			}
			return alerts
		},
	}
}

// ─── Category 11: Advanced TLS Security ─────────────────────────────────────

var brokenCipherFragments = []string{
	"NULL", "EXPORT", "ANON", "RC4", "_DES_", "3DES", "RC2", "IDEA", "KRB5",
}

// tlsWeakCipherRule detects negotiated ciphers lacking forward secrecy or using broken algorithms.
func tlsWeakCipherRule() Rule {
	return Rule{
		Name:     "TLS Weak Cipher",
		Protocol: "TLS",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert
			for _, f := range ctx.Flows {
				if f.Type != "TLS" {
					continue
				}
				cipher, _ := f.Metrics["cipher_suite"].(string)
				if cipher == "" {
					continue
				}
				upper := strings.ToUpper(cipher)

				var matched []string
				for _, frag := range brokenCipherFragments {
					if strings.Contains(upper, strings.ToUpper(frag)) {
						matched = append(matched, frag)
					}
				}
				noFS := !strings.Contains(upper, "ECDHE") && !strings.Contains(upper, "DHE")
				if len(matched) == 0 && !noFS {
					continue
				}

				var severity, title, desc string
				if len(matched) > 0 {
					severity = SeverityCritical
					title = fmt.Sprintf("Broken Cipher: %s", cipher)
					desc = fmt.Sprintf(
						"TLS flow %s (%s:%d→%s:%d) negotiated broken cipher %s — algorithms: %s",
						f.FlowID, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, cipher, strings.Join(matched, ", "),
					)
				} else {
					severity = SeverityWarning
					title = fmt.Sprintf("No Forward Secrecy: %s", cipher)
					desc = fmt.Sprintf(
						"TLS flow %s (%s:%d→%s:%d) uses %s — no forward secrecy (RSA key exchange only)",
						f.FlowID, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, cipher,
					)
				}
				alerts = append(alerts, Alert{
					ID:          uuid.New().String(),
					Timestamp:   time.Now(),
					Severity:    severity,
					Protocol:    "TLS",
					Title:       title,
					Description: desc,
					FlowID:      f.FlowID,
					Metadata: map[string]any{
						"cipher_suite":        cipher,
						"has_forward_secrecy": !noFS,
						"weak_algorithms":     matched,
						"src_ip":              f.SrcIP,
						"dst_ip":              f.DstIP,
						"attack_type":         "weak_cipher",
					},
				})
			}
			return alerts
		},
	}
}

// knownMaliciousJA3 maps documented malicious JA3 fingerprints to their associated malware.
var knownMaliciousJA3 = map[string]string{
	"e7d705a3286e19ea42f587b344ee6865": "Mirai botnet C2",
	"6734f37431670b3ab4292b8f60f29984": "Trickbot malware",
	"a0e9f5d64349fb13191bc781f81f42e1": "CobaltStrike Beacon (default)",
	"72a589da586844d7f0818ce684948eea": "CobaltStrike Beacon (variant)",
	"b386946a5a44d1ddcc843bc75336dfce": "Metasploit Framework",
	"de350869b8c85de67a350c8d186f11e6": "Dridex banking trojan",
	"6bea65232d2734571b057466a576d801": "Agent Tesla",
}

// tlsJA3AlertRule computes JA3 fingerprints and alerts on known malicious hashes.
func tlsJA3AlertRule() Rule {
	return Rule{
		Name:     "TLS JA3 Fingerprint",
		Protocol: "TLS",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert
			for _, f := range ctx.Flows {
				if f.Type != "TLS" {
					continue
				}
				ja3Hash, _ := f.Metrics["ja3_hash"].(string)
				ja3Str, _ := f.Metrics["ja3_string"].(string)
				if ja3Hash == "" {
					version, _ := f.Metrics["tls_version"].(string)
					cipher, _ := f.Metrics["cipher_suite"].(string)
					if version == "" && cipher == "" {
						continue
					}
					input := fmt.Sprintf("%s|%s", version, cipher)
					h := md5.Sum([]byte(input))
					ja3Hash = fmt.Sprintf("%x", h)
					ja3Str = input
				}

				malwareName, isMalicious := knownMaliciousJA3[ja3Hash]
				if !isMalicious {
					continue
				}
				sni, _ := f.Metrics["sni"].(string)
				shortHash := ja3Hash
				if len(ja3Hash) > 8 {
					shortHash = ja3Hash[:8] + "..."
				}
				alerts = append(alerts, Alert{
					ID:        uuid.New().String(),
					Timestamp: time.Now(),
					Severity:  SeverityCritical,
					Protocol:  "TLS",
					Title:     fmt.Sprintf("Malicious JA3: %s (%s)", shortHash, malwareName),
					Description: fmt.Sprintf(
						"TLS flow %s (%s→%s SNI=%q) matches known malicious JA3 %s — %s",
						f.FlowID, f.SrcIP, f.DstIP, sni, ja3Hash, malwareName,
					),
					FlowID: f.FlowID,
					Metadata: map[string]any{
						"ja3_hash":    ja3Hash,
						"ja3_string":  ja3Str,
						"malware":     malwareName,
						"src_ip":      f.SrcIP,
						"dst_ip":      f.DstIP,
						"sni":         sni,
						"attack_type": "malicious_ja3",
					},
				})
			}
			return alerts
		},
	}
}

// tlsSelfSignedCertRule detects TLS connections using self-signed certificates.
func tlsSelfSignedCertRule() Rule {
	return Rule{
		Name:     "TLS Self-Signed Certificate",
		Protocol: "TLS",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert
			for _, f := range ctx.Flows {
				if f.Type != "TLS" {
					continue
				}
				selfSigned, _ := f.Metrics["cert_self_signed"].(bool)
				if !selfSigned {
					continue
				}
				subject, _ := f.Metrics["cert_subject"].(string)
				issuer, _ := f.Metrics["cert_issuer"].(string)
				sni, _ := f.Metrics["sni"].(string)

				// Skip local/internal domains
				if strings.HasSuffix(sni, ".local") || strings.HasSuffix(sni, ".internal") ||
					strings.HasSuffix(sni, ".lan") {
					continue
				}

				severity := SeverityWarning
				if f.DstPort == 443 || f.DstPort == 8443 {
					severity = SeverityError
				}
				alerts = append(alerts, Alert{
					ID:        uuid.New().String(),
					Timestamp: time.Now(),
					Severity:  severity,
					Protocol:  "TLS",
					Title:     fmt.Sprintf("Self-Signed Cert: %s (%s)", sni, f.DstIP),
					Description: fmt.Sprintf(
						"TLS connection to %s (%s:%d) presents a self-signed certificate (Subject=%q) — possible MITM proxy or malware C2",
						sni, f.DstIP, f.DstPort, subject,
					),
					FlowID: f.FlowID,
					Metadata: map[string]any{
						"cert_subject": subject,
						"cert_issuer":  issuer,
						"sni":          sni,
						"dst_ip":       f.DstIP,
						"dst_port":     f.DstPort,
						"attack_type":  "self_signed_cert",
					},
				})
			}
			return alerts
		},
	}
}
