package analysis

import "fmt"

// SLAVerdict classifies a flow's quality level.
type SLAVerdict string

const (
	SLAGood       SLAVerdict = "good"
	SLAAcceptable SLAVerdict = "acceptable"
	SLAPoor       SLAVerdict = "poor"
	SLACritical   SLAVerdict = "critical"
)

// SLAResult holds the verdict, composite score (0–100), and human-readable details.
type SLAResult struct {
	Verdict SLAVerdict `json:"verdict"`
	Score   int        `json:"score"`   // 100 = perfect, 0 = unusable
	Details []string   `json:"details"`
}

// ClassifyTCP rates a TCP flow using RTT and retransmission rate.
// rttMs: effective RTT in milliseconds (0 = unknown)
// retransPct: retransmission percentage (0–100)
func ClassifyTCP(rttMs, retransPct float64) SLAResult {
	score := 100
	var details []string

	// RTT penalty (max 40 points): 0ms=0, 500ms=40
	if rttMs > 0 {
		rttPenalty := min(int(rttMs/500*40), 40)
		score -= rttPenalty
		switch {
		case rttMs <= 100:
			details = append(details, fmt.Sprintf("RTT %.1fms (good)", rttMs))
		case rttMs <= 300:
			details = append(details, fmt.Sprintf("RTT %.1fms (acceptable)", rttMs))
		case rttMs <= 500:
			details = append(details, fmt.Sprintf("RTT %.1fms (poor)", rttMs))
		default:
			details = append(details, fmt.Sprintf("RTT %.1fms (critical)", rttMs))
		}
	}

	// Retransmission penalty. Scales 0→30 points across 0-3% (unchanged from
	// before), matching the "poor" text boundary below. Beyond 3% — already
	// labeled "critical" in the details text — the penalty keeps climbing
	// instead of capping at 30: real captures show retransmission rates well
	// past 30% (e.g. after fixing the reassembled-packet double-counting bug
	// that previously inflated these numbers), and a flat 30-point ceiling
	// meant any such flow scored 70 ("acceptable") whenever RTT was
	// unmeasured — a "critical"-by-its-own-text flow could never actually
	// reach a poor/critical verdict from retransmission severity alone.
	if retransPct > 0 {
		var retransPenalty int
		if retransPct <= 3 {
			retransPenalty = int(retransPct / 3 * 30)
		} else {
			retransPenalty = min(30+int((retransPct-3)/3*20), 90)
		}
		score -= retransPenalty
		switch {
		case retransPct <= 0.1:
			details = append(details, fmt.Sprintf("retrans %.2f%% (good)", retransPct))
		case retransPct <= 1:
			details = append(details, fmt.Sprintf("retrans %.2f%% (acceptable)", retransPct))
		case retransPct <= 3:
			details = append(details, fmt.Sprintf("retrans %.2f%% (poor)", retransPct))
		default:
			details = append(details, fmt.Sprintf("retrans %.2f%% (critical)", retransPct))
		}
	}

	score = max(score, 0)

	verdict := verdictFromScore(score)
	return SLAResult{Verdict: verdict, Score: score, Details: details}
}

// ClassifyRTP rates an RTP stream using jitter and packet loss.
// Thresholds from ITU-T G.1010 conversational voice class.
// jitterMs: running average jitter in ms
// lossPct: packet loss percentage (0–100)
func ClassifyRTP(jitterMs, lossPct float64) SLAResult {
	score := 100
	var details []string

	// Jitter penalty (max 40 points): 0ms=0, 100ms=40
	if jitterMs > 0 {
		jitterPenalty := min(int(jitterMs/100*40), 40)
		score -= jitterPenalty
		switch {
		case jitterMs <= 30:
			details = append(details, fmt.Sprintf("jitter %.1fms (good)", jitterMs))
		case jitterMs <= 50:
			details = append(details, fmt.Sprintf("jitter %.1fms (acceptable)", jitterMs))
		case jitterMs <= 100:
			details = append(details, fmt.Sprintf("jitter %.1fms (poor)", jitterMs))
		default:
			details = append(details, fmt.Sprintf("jitter %.1fms (critical)", jitterMs))
		}
	}

	// Loss penalty (max 60 points): 0%=0, 5%=60
	if lossPct > 0 {
		lossPenalty := min(int(lossPct/5*60), 60)
		score -= lossPenalty
		switch {
		case lossPct <= 1:
			details = append(details, fmt.Sprintf("loss %.2f%% (good)", lossPct))
		case lossPct <= 3:
			details = append(details, fmt.Sprintf("loss %.2f%% (acceptable)", lossPct))
		case lossPct <= 5:
			details = append(details, fmt.Sprintf("loss %.2f%% (poor)", lossPct))
		default:
			details = append(details, fmt.Sprintf("loss %.2f%% (critical)", lossPct))
		}
	}

	score = max(score, 0)

	verdict := verdictFromScore(score)
	return SLAResult{Verdict: verdict, Score: score, Details: details}
}

// ClassifyUDP classifies a generic UDP flow (no RTT/loss measurable at transport layer).
func ClassifyUDP() SLAResult {
	return SLAResult{Verdict: SLAGood, Score: 100, Details: []string{"UDP flow (no RTT measurement)"}}
}

func verdictFromScore(score int) SLAVerdict {
	switch {
	case score >= 80:
		return SLAGood
	case score >= 60:
		return SLAAcceptable
	case score >= 40:
		return SLAPoor
	default:
		return SLACritical
	}
}
