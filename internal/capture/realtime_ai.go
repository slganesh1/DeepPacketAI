package capture

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	"DeepPacketAI/internal/ai"
	"DeepPacketAI/internal/ws"
)

// realtimeAnalysisInterval is how often (in statsLoop ticks) the AI is called.
// At 1 tick/second this equals 30 seconds.
const realtimeAnalysisInterval = 30

// realtimeAnalysis sends a live capture snapshot to the AI and broadcasts
// the resulting insight over WebSocket. It is a no-op when no AI provider
// is configured or when the previous analysis is still running.
//
// running is an atomic flag (0=idle, 1=in-progress) shared across calls to
// prevent concurrent AI requests for the same session.
func (e *Engine) realtimeAnalysis(session *Session, stats *Stats, elapsedSecs int, running *int32) {
	if e.aiRegistry == nil {
		return
	}
	provider, ok := e.aiRegistry.Active()
	if !ok {
		return
	}

	// Skip if a previous analysis is still running
	if !atomic.CompareAndSwapInt32(running, 0, 1) {
		return
	}
	defer atomic.StoreInt32(running, 0)

	snap := stats.Snapshot()
	if snap.TotalPackets == 0 {
		return
	}

	aiStats := ai.LiveCaptureStats{
		ElapsedSecs:   elapsedSecs,
		TotalPackets:  snap.TotalPackets,
		TotalBytes:    snap.TotalBytes,
		PacketsPerSec: snap.PacketsPerSec,
		BytesPerSec:   snap.BytesPerSec,
		ProtocolCounts: snap.ProtocolCounts,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	insight, err := ai.AnalyzeRealtimeCapture(ctx, provider, aiStats)
	if err != nil {
		log.Printf("realtime AI [session=%s]: %v", session.ID, err)
		return
	}

	// Determine severity from the AI's findings
	severity := "info"
	if len(insight.Threats) > 0 || len(insight.Frauds) > 0 {
		severity = "critical"
	} else if len(insight.Anomalies) > 0 {
		severity = "warning"
	}

	// Only broadcast if there's something meaningful to say
	if insight.Summary == "" {
		return
	}

	e.hub.Broadcast(ws.Message{
		Type: ws.MsgAIInsight,
		Payload: map[string]any{
			"session_id":  session.ID,
			"timestamp":   time.Now().Format("15:04:05"),
			"severity":    severity,
			"summary":     insight.Summary,
			"anomalies":   insight.Anomalies,
			"threats":     insight.Threats,
			"frauds":      insight.Frauds,
			"elapsed_secs": elapsedSecs,
			"total_packets": snap.TotalPackets,
		},
	})
}
