package analysis

import (
	"log"

	"DeepPacketAI/internal/domain"
)

func AnalyzeCall(call *domain.Call) {
	log.Printf("ANALYZE CALLED for %s", call.CallID)

	analyzeHold(call)
	analyzeEndType(call)
	analyzeRootCause(call)
	assignConfidence(call)

	log.Printf(
		"ANALYZE RESULT %s endType=%s root=%s conf=%.2f",
		call.CallID,
		call.EndType,
		call.RootCause,
		call.Confidence,
	)
}

func analyzeHold(call *domain.Call) {
	dir, _ := call.SIPMetrics["direction"].(string)

	if dir == "sendonly" || dir == "inactive" {
		call.IsOnHold = true
	} else {
		call.IsOnHold = false
	}
}

func analyzeEndType(call *domain.Call) {
	call.EndType = "normal"

	if len(call.RTPLegs) == 0 {
		call.EndType = "abnormal"
	}
}

func analyzeRootCause(call *domain.Call) {
	if call.IsOnHold {
		call.RootCause = "user_hold"
		return
	}

	if len(call.RTPLegs) == 0 {
		call.RootCause = "no_media"
		return
	}

	if call.MOS > 0 && call.MOS < 2.6 {
		// Examine the worst leg to determine primary cause
		for _, leg := range call.RTPLegs {
			jitter := getFloat64(leg, "jitter_ms")
			pktCount := getInt(leg, "packet_count")
			seqGap := getInt(leg, "max_seq_gap")
			lossPct := 0.0
			if pktCount > 0 {
				lossPct = float64(seqGap) / float64(pktCount) * 100
			}
			if lossPct > 10 {
				call.RootCause = "high_packet_loss"
				return
			}
			if jitter > 100 {
				call.RootCause = "excessive_jitter"
				return
			}
		}
		call.RootCause = "media_quality" // fallback
		return
	}

	call.RootCause = "normal_release"
}

func assignConfidence(call *domain.Call) {
	switch call.RootCause {
	case "user_hold":
		call.Confidence = 0.95
	case "high_packet_loss", "excessive_jitter":
		call.Confidence = 0.9
	case "media_quality":
		call.Confidence = 0.85
	case "no_media":
		call.Confidence = 0.8
	case "normal_release":
		call.Confidence = 0.9
	default:
		call.Confidence = 0.7
	}
}

// getFloat64 safely extracts a float64 from a metrics map.
func getFloat64(m map[string]any, key string) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	if v, ok := m[key].(int); ok {
		return float64(v)
	}
	return 0
}

// getInt safely extracts an int from a metrics map.
func getInt(m map[string]any, key string) int {
	if v, ok := m[key].(int); ok {
		return v
	}
	return 0
}
