package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// LiveCaptureStats is a snapshot of live capture metrics sent to the AI
// for periodic real-time analysis during an active capture session.
type LiveCaptureStats struct {
	ElapsedSecs    int
	TotalPackets   uint64
	TotalBytes     uint64
	PacketsPerSec  uint64
	BytesPerSec    uint64
	ProtocolCounts map[string]uint64 // e.g. {"SIP":120,"RTP":450,"DNS":30}
}

// RealtimeInsight is the AI's analysis of a live capture window.
type RealtimeInsight struct {
	Summary   string   `json:"summary"`
	Anomalies []string `json:"anomalies"`
	Threats   []string `json:"threats"`
	Frauds    []string `json:"frauds"`
}

// AnalyzeRealtimeCapture sends a 30-second live capture snapshot to the AI
// and returns a brief insight. Designed to be called periodically during capture.
func AnalyzeRealtimeCapture(ctx context.Context, provider LLMProvider, stats LiveCaptureStats) (*RealtimeInsight, error) {
	// Build protocol distribution block
	var protoLines []string
	for proto, count := range stats.ProtocolCounts {
		if count > 0 {
			protoLines = append(protoLines, fmt.Sprintf("  %-12s %d packets", proto, count))
		}
	}
	protoBlock := strings.Join(protoLines, "\n")
	if protoBlock == "" {
		protoBlock = "  (no protocol data yet)"
	}

	throughputKbps := stats.BytesPerSec * 8 / 1000

	prompt := fmt.Sprintf(`You are monitoring live network traffic. Analyze this 30-second capture window and identify anything noteworthy.

## Capture Window
Elapsed     : %ds
Total packets: %d   Total bytes: %s
Current rate : %d pkt/s   %d Kbps

## Protocol Breakdown (last 30s)
%s

## Instructions
Respond with ONLY this JSON (no markdown, no extra text):
{
  "anomalies": ["<unusual traffic pattern, if any — else empty array>"],
  "threats":   ["<security concern, if any — else empty array>"],
  "frauds":    ["<fraud indicator, if any — else empty array>"],
  "summary":   "<1-2 sentence plain-English summary of what is happening right now>"
}

Focus on:
- Sudden protocol spikes or unexpected ratios
- High SIP error rates (many 401/403/486 responses)
- Unusual DNS query volumes
- SIP REGISTER floods (possible brute-force)
- RTP without SIP signalling (possible injection)
- Traffic volumes that seem anomalous for the elapsed time
- Return empty arrays if nothing notable — do not invent issues`,
		stats.ElapsedSecs,
		stats.TotalPackets,
		formatBytesAI(stats.TotalBytes),
		stats.PacketsPerSec,   // %d
		throughputKbps,        // %d
		protoBlock,
	)

	resp, err := provider.Complete(ctx, CompletionRequest{
		Messages:     []Message{{Role: "user", Content: prompt}},
		MaxTokens:    400,
		Temperature:  0.1,
		SystemPrompt: `You are a real-time network traffic analyst. Identify anomalies and threats in live packet capture data. Be concise. Return only the requested JSON.`,
	})
	if err != nil {
		return nil, fmt.Errorf("realtime AI: %w", err)
	}

	result := &RealtimeInsight{}
	raw := resp.Content
	if s, e := strings.Index(raw, "{"), strings.LastIndex(raw, "}"); s >= 0 && e > s {
		_ = json.Unmarshal([]byte(raw[s:e+1]), result)
	}
	if result.Summary == "" {
		result.Summary = strings.TrimSpace(raw)
	}
	return result, nil
}

func formatBytesAI(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
