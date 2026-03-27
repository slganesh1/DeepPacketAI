package detection

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Builtin5GCRules returns detection rules specific to 5G Core network protocols.
func Builtin5GCRules() []Rule {
	return []Rule{
		nasAuthFailureStormRule(),
		pduSessionFloodRule(),
		pfcpDropActionAnomalyRule(),
		sbiErrorRateRule(),
		gtpTunnelFloodRule(),
		nfRegistrationStormRule(),
	}
}

// nasAuthFailureStormRule detects repeated NAS authentication failures from a single UE.
// Threshold: auth_failures > 10 from the same UE → critical alert.
func nasAuthFailureStormRule() Rule {
	return Rule{
		Name:     "NAS Auth Failure Storm",
		Protocol: "NAS5G",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert

			// Group auth failures by source IP (UE)
			authFailsByUE := make(map[string]int)
			for _, f := range ctx.Flows {
				if f.Type != "NAS5G" {
					continue
				}
				authFails := getIntMetric(f.Metrics, "auth_failures")
				if authFails > 0 {
					authFailsByUE[f.SrcIP] += authFails
				}
				// Also count individual auth failure messages
				if msgType, ok := f.Metrics["message_type"].(string); ok {
					if msgType == "Authentication Failure" || msgType == "Authentication Reject" {
						authFailsByUE[f.SrcIP]++
					}
				}
			}

			for ueIP, count := range authFailsByUE {
				if count > 10 {
					alerts = append(alerts, Alert{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						Severity:    SeverityCritical,
						Protocol:    "NAS5G",
						Title:       "NAS Authentication Failure Storm",
						Description: fmt.Sprintf("UE %s has %d authentication failures — possible SIM cloning, DoS, or brute force attack", ueIP, count),
						Metadata: map[string]any{
							"ue_ip":         ueIP,
							"auth_failures": count,
							"threshold":     10,
						},
					})
				}
			}

			return alerts
		},
	}
}

// pduSessionFloodRule detects a high rate of PDU session establishment requests.
// Threshold: > 100 PDU session establishment requests → warning.
func pduSessionFloodRule() Rule {
	return Rule{
		Name:     "PDU Session Flood",
		Protocol: "NAS5G",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert

			pduEstablishCount := 0
			for _, f := range ctx.Flows {
				if f.Type != "NAS5G" {
					continue
				}
				proc, _ := f.Metrics["procedure"].(string)
				msgType, _ := f.Metrics["message_type"].(string)
				if proc == "PDUSessionEstablishment" && msgType == "PDU Session Establishment Request" {
					pduEstablishCount++
				}
			}

			if pduEstablishCount > 100 {
				alerts = append(alerts, Alert{
					ID:          uuid.New().String(),
					Timestamp:   time.Now(),
					Severity:    SeverityWarning,
					Protocol:    "NAS5G",
					Title:       "PDU Session Establishment Flood",
					Description: fmt.Sprintf("%d PDU session establishment requests detected — possible session flood or misconfigured UE", pduEstablishCount),
					Metadata: map[string]any{
						"pdu_session_requests": pduEstablishCount,
						"threshold":            100,
					},
				})
			}

			return alerts
		},
	}
}

// pfcpDropActionAnomalyRule detects when a high proportion of PFCP sessions have DROP action.
// Threshold: DROP action > 50% of FAR sessions → warning.
func pfcpDropActionAnomalyRule() Rule {
	return Rule{
		Name:     "PFCP Session Anomaly",
		Protocol: "PFCP",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert

			totalPFCP := 0
			dropCount := 0

			for _, f := range ctx.Flows {
				if f.Type != "PFCP" {
					continue
				}
				totalPFCP++
				action, _ := f.Metrics["apply_action"].(string)
				if action != "" {
					// Check if DROP is part of the action string
					hasDrop := false
					for i := 0; i+3 < len(action); i++ {
						if action[i:i+4] == "DROP" {
							hasDrop = true
							break
						}
					}
					if !hasDrop && len(action) == 4 && action == "DROP" {
						hasDrop = true
					}
					if hasDrop {
						dropCount++
					}
				}
			}

			if totalPFCP > 0 && dropCount*2 > totalPFCP {
				pct := (dropCount * 100) / totalPFCP
				alerts = append(alerts, Alert{
					ID:          uuid.New().String(),
					Timestamp:   time.Now(),
					Severity:    SeverityWarning,
					Protocol:    "PFCP",
					Title:       "PFCP High DROP Action Rate",
					Description: fmt.Sprintf("%d%% of PFCP sessions (%d/%d) have DROP action — possible misconfiguration or traffic blocking policy", pct, dropCount, totalPFCP),
					Metadata: map[string]any{
						"drop_count":  dropCount,
						"total_pfcp":  totalPFCP,
						"drop_pct":    pct,
						"threshold":   50,
					},
				})
			}

			return alerts
		},
	}
}

// sbiErrorRateRule detects high 5xx error rates on the 3GPP SBI (HTTP/2).
// Threshold: 5xx responses > 20% of total SBI calls → warning.
func sbiErrorRateRule() Rule {
	return Rule{
		Name:     "SBI Error Rate",
		Protocol: "HTTP2",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert

			totalSBI := 0
			errorCount := 0

			for _, f := range ctx.Flows {
				if f.Type != "HTTP2" && f.Type != "SBI" {
					continue
				}
				isSBI, _ := f.Metrics["is_sbi"].(bool)
				if !isSBI {
					continue
				}
				totalSBI++

				statusCode, _ := f.Metrics["status_code"].(string)
				if len(statusCode) > 0 && statusCode[0] == '5' {
					errorCount++
				}

				// Also check error_count metric
				errCnt := getIntMetric(f.Metrics, "error_count")
				if errCnt > 0 {
					errorCount += errCnt
				}
			}

			if totalSBI > 0 && errorCount*5 > totalSBI {
				pct := (errorCount * 100) / totalSBI
				alerts = append(alerts, Alert{
					ID:          uuid.New().String(),
					Timestamp:   time.Now(),
					Severity:    SeverityWarning,
					Protocol:    "HTTP2",
					Title:       "SBI High 5xx Error Rate",
					Description: fmt.Sprintf("%d%% of SBI calls (%d/%d) returned 5xx errors — possible NF overload or configuration issue", pct, errorCount, totalSBI),
					Metadata: map[string]any{
						"error_count": errorCount,
						"total_sbi":   totalSBI,
						"error_pct":   pct,
						"threshold":   20,
					},
				})
			}

			return alerts
		},
	}
}

// gtpTunnelFloodRule detects an abnormally large number of unique GTP tunnels (TEIDs).
// Threshold: unique TEID count > 10000 → warning.
func gtpTunnelFloodRule() Rule {
	return Rule{
		Name:     "GTP-U Tunnel Flood",
		Protocol: "GTP",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert

			uniqueTEIDs := make(map[uint32]bool)
			for _, f := range ctx.Flows {
				if f.Type != "GTP" && f.Type != "GTPU" {
					continue
				}
				if teidVal, ok := f.Metrics["teid"]; ok {
					switch v := teidVal.(type) {
					case uint32:
						uniqueTEIDs[v] = true
					case int:
						uniqueTEIDs[uint32(v)] = true
					case uint64:
						uniqueTEIDs[uint32(v)] = true
					}
				}
			}

			teidCount := len(uniqueTEIDs)
			if teidCount > 10000 {
				alerts = append(alerts, Alert{
					ID:          uuid.New().String(),
					Timestamp:   time.Now(),
					Severity:    SeverityWarning,
					Protocol:    "GTP",
					Title:       "GTP-U Tunnel Flood",
					Description: fmt.Sprintf("%d unique GTP tunnels (TEIDs) detected — possible tunnel exhaustion or attack", teidCount),
					Metadata: map[string]any{
						"unique_teids": teidCount,
						"threshold":    10000,
					},
				})
			}

			return alerts
		},
	}
}

// nfRegistrationStormRule detects excessive NF registration calls to the NRF.
// Threshold: NRF registration calls > 50 → warning.
func nfRegistrationStormRule() Rule {
	return Rule{
		Name:     "NF Registration Storm",
		Protocol: "HTTP2",
		Check: func(ctx *RuleContext) []Alert {
			var alerts []Alert

			nrfRegCount := 0
			for _, f := range ctx.Flows {
				if f.Type != "HTTP2" && f.Type != "SBI" {
					continue
				}
				nfType, _ := f.Metrics["nf_type"].(string)
				service, _ := f.Metrics["service_name"].(string)
				method, _ := f.Metrics["method"].(string)

				if nfType == "NRF" && service == "nnrf-nfm" &&
					(method == "PUT" || method == "POST") {
					nrfRegCount++
				}
			}

			if nrfRegCount > 50 {
				alerts = append(alerts, Alert{
					ID:          uuid.New().String(),
					Timestamp:   time.Now(),
					Severity:    SeverityWarning,
					Protocol:    "HTTP2",
					Title:       "NF Registration Storm",
					Description: fmt.Sprintf("%d NF registration calls to NRF detected — possible NF registration loop or attack", nrfRegCount),
					Metadata: map[string]any{
						"nrf_registrations": nrfRegCount,
						"threshold":         50,
					},
				})
			}

			return alerts
		},
	}
}
