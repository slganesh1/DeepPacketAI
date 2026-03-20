package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"DeepPacketAI/internal/domain"
)

// TelecomAnalysis holds the LLM's security assessment of a single telecom session.
type TelecomAnalysis struct {
	SessionID   string   `json:"session_id"`
	Threats     []string `json:"threats"`
	Anomalies   []string `json:"anomalies"`
	Frauds      []string `json:"frauds"`
	Suggestions []string `json:"suggestions"`
	Summary     string   `json:"summary"`
	RawResponse string   `json:"raw_response"`
}

// TrafficAnalysis holds the LLM's holistic assessment of all captured traffic.
type TrafficAnalysis struct {
	Anomalies   []string `json:"anomalies"`
	Threats     []string `json:"threats"`
	Frauds      []string `json:"frauds"`
	Summary     string   `json:"summary"`
	RawResponse string   `json:"raw_response"`
}

// TrafficStats carries aggregate counters for AI analysis.
type TrafficStats struct {
	TotalFlows       int
	TotalPackets     int
	Window           string
	SIPFlows         int
	RTPFlows         int
	DNSFlows         int
	GTPFlows         int
	NGAPFlows        int
	TLSFlows         int
	SIP401Count      int
	SIPRegisterCount int
	DNSQueryCount    int
	DiameterErrors   int
}

// AnalyzeTelecomSession sends a full 5G/4G call trace to the LLM for threat and fraud detection.
// Returns nil, nil if there are no events to analyze.
func AnalyzeTelecomSession(ctx context.Context, provider LLMProvider, session domain.TelecomSession) (*TelecomAnalysis, error) {
	if len(session.Events) == 0 {
		return nil, nil
	}

	var evLines []string
	for _, ev := range session.Events {
		evLines = append(evLines, fmt.Sprintf(
			"[%s] %s %s: %s  src=%s dst=%s",
			ev.Timestamp.Format("15:04:05.000"),
			ev.Protocol, ev.Step, ev.Summary,
			ev.SrcIP, ev.DstIP,
		))
	}

	prompt := fmt.Sprintf(`Analyze this 5G/4G telecom call trace for security threats, fraud, and protocol anomalies.

## Session
Session-ID : %s
IMSI       : %s   MSISDN: %s   UE-IP: %s   APN: %s
SIP-Call-ID: %s   From: %s   To: %s
Duration   : %s → %s
MOS        : %.2f   Quality: %s
Layers     : NGAP=%v GTP-C=%v GTP-U=%v SIP=%v RTP=%v Diameter=%v   Complete=%v

## Event Timeline (%d events)
%s

## Instructions
Respond with ONLY this JSON (no markdown, no explanation outside the JSON):
{
  "threats":     ["<specific threat if found, else empty array>"],
  "anomalies":   ["<protocol anomaly if found, else empty array>"],
  "frauds":      ["<fraud indicator if found, else empty array>"],
  "suggestions": ["<actionable recommendation>"],
  "summary":     "<2-3 sentence plain-English summary>"
}

Detection focus:
- SIP brute force: repeated 401 from same source → credential attack
- SIP toll fraud: INVITE to premium/international numbers, unexpected APN routing
- Session hijacking: IMSI/TEID mismatch across layers, unexpected re-REGISTER
- GTP abuse: TEID reuse, missing PFCP session before GTP-U traffic
- RTP anomalies: media before SIP 200 OK, wrong codec, no RTCP
- Timing: unusually fast (<50ms) or slow (>10s) signalling steps
- Missing layers: GTP-U without GTP-C → possible injection`,
		session.SessionID, session.IMSI, session.MSISDN, session.UEIP, session.APN,
		session.SIPCallID, session.SIPFrom, session.SIPTo,
		session.StartTime.Format("15:04:05"), session.EndTime.Format("15:04:05"),
		session.MOS, session.Quality,
		session.HasNGAP, session.HasGTPC, session.HasGTPU, session.HasSIP, session.HasRTP, session.HasDiameter,
		session.IsComplete,
		len(session.Events), strings.Join(evLines, "\n"),
	)

	resp, err := provider.Complete(ctx, CompletionRequest{
		Messages:     []Message{{Role: "user", Content: prompt}},
		MaxTokens:    1500,
		Temperature:  0.1,
		SystemPrompt: `You are a telecom security expert specializing in 5G/4G network threat detection. Analyze SIP, GTP, RTP, Diameter, NGAP, and PFCP protocol traces to identify attacks, fraud, and anomalies. Always respond with the exact JSON format requested — no markdown, no extra text.`,
	})
	if err != nil {
		return nil, fmt.Errorf("LLM session analysis: %w", err)
	}

	result := &TelecomAnalysis{
		SessionID:   session.SessionID,
		RawResponse: resp.Content,
	}
	parseJSONAnalysis(resp.Content, result)
	return result, nil
}

// AnalyzeTrafficAnomalies sends aggregate traffic statistics and rule-based alerts to the LLM
// to find patterns rules may have missed — coordinated attacks, fraud campaigns, etc.
func AnalyzeTrafficAnomalies(ctx context.Context, provider LLMProvider, alerts []AlertSummary, stats TrafficStats) (*TrafficAnalysis, error) {
	var alertLines []string
	for _, a := range alerts {
		alertLines = append(alertLines, fmt.Sprintf("[%s][%s] %s — %s", a.Severity, a.Protocol, a.Title, a.Description))
	}
	alertBlock := strings.Join(alertLines, "\n")
	if len(alertLines) == 0 {
		alertBlock = "(none)"
	}

	prompt := fmt.Sprintf(`You are analyzing telecom network traffic. Below are statistics and rule-based alerts.
Identify coordinated attacks, fraud campaigns, and anomalies that individual rules may have missed.

## Traffic Statistics
Total flows   : %d    Total packets: %d    Capture window: %s
SIP=%d  RTP=%d  DNS=%d  GTP=%d  NGAP=%d  TLS=%d
SIP-401s=%d  SIP-REGISTER=%d  DNS-queries=%d  Diameter-errors=%d

## Rule-Based Alerts (%d)
%s

## Instructions
Respond with ONLY this JSON:
{
  "anomalies": ["<traffic pattern anomaly>"],
  "threats":   ["<specific threat or attack>"],
  "frauds":    ["<fraud indicator>"],
  "summary":   "<2-3 sentence summary>"
}

Look for:
- Coordinated multi-protocol attacks (SIP flood + DNS flood simultaneously)
- Toll fraud campaigns (many short calls to premium numbers)
- SIM swap indicators (IMSI seen on multiple base stations simultaneously)
- Signalling storms (repeated failed GTP/PFCP sessions)
- Data exfiltration (high DNS volume, large TLS records, unexpected GTP tunnel endpoints)
- Authentication bypass (success after many failures from same source)`,
		stats.TotalFlows, stats.TotalPackets, stats.Window,
		stats.SIPFlows, stats.RTPFlows, stats.DNSFlows, stats.GTPFlows, stats.NGAPFlows, stats.TLSFlows,
		stats.SIP401Count, stats.SIPRegisterCount, stats.DNSQueryCount, stats.DiameterErrors,
		len(alertLines), alertBlock,
	)

	resp, err := provider.Complete(ctx, CompletionRequest{
		Messages:     []Message{{Role: "user", Content: prompt}},
		MaxTokens:    1200,
		Temperature:  0.1,
		SystemPrompt: `You are a telecom security analyst. Identify threats and anomalies in network traffic. Respond in the exact JSON format requested — no markdown, no extra text.`,
	})
	if err != nil {
		return nil, fmt.Errorf("LLM traffic analysis: %w", err)
	}

	result := &TrafficAnalysis{RawResponse: resp.Content}
	var parsed struct {
		Anomalies []string `json:"anomalies"`
		Threats   []string `json:"threats"`
		Frauds    []string `json:"frauds"`
		Summary   string   `json:"summary"`
	}
	raw := resp.Content
	if s, e := strings.Index(raw, "{"), strings.LastIndex(raw, "}"); s >= 0 && e > s {
		_ = json.Unmarshal([]byte(raw[s:e+1]), &parsed)
	}
	result.Anomalies = parsed.Anomalies
	result.Threats = parsed.Threats
	result.Frauds = parsed.Frauds
	result.Summary = parsed.Summary
	return result, nil
}

// parseJSONAnalysis extracts JSON fields from LLM response into a TelecomAnalysis.
func parseJSONAnalysis(raw string, out *TelecomAnalysis) {
	s := strings.Index(raw, "{")
	e := strings.LastIndex(raw, "}")
	if s < 0 || e <= s {
		return
	}
	var parsed struct {
		Threats     []string `json:"threats"`
		Anomalies   []string `json:"anomalies"`
		Frauds      []string `json:"frauds"`
		Suggestions []string `json:"suggestions"`
		Summary     string   `json:"summary"`
	}
	if err := json.Unmarshal([]byte(raw[s:e+1]), &parsed); err != nil {
		return
	}
	out.Threats = parsed.Threats
	out.Anomalies = parsed.Anomalies
	out.Frauds = parsed.Frauds
	out.Suggestions = parsed.Suggestions
	out.Summary = parsed.Summary
}
