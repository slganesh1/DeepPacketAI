package analysis

import "testing"

func TestClassifyTCP_NoDegradation(t *testing.T) {
	r := ClassifyTCP(0, 0)
	if r.Score != 100 || r.Verdict != SLAGood {
		t.Fatalf("got score=%d verdict=%s, want 100/good", r.Score, r.Verdict)
	}
}

func TestClassifyTCP_RetransAt3PercentBoundaryUnchanged(t *testing.T) {
	// 3% is the pre-existing "poor" text boundary; penalty at exactly this
	// point must stay 30 (unchanged) so behavior below it is not disturbed.
	r := ClassifyTCP(0, 3)
	if r.Score != 70 {
		t.Fatalf("got score=%d, want 70 (30-point penalty unchanged at the 3%% boundary)", r.Score)
	}
}

// TestClassifyTCP_SevereRetransReachesCriticalVerdict reproduces the real bug:
// with the old flat 30-point cap, any retransmission rate >=3% scored exactly
//70 ("acceptable") whenever RTT was unmeasured — so a flow with 38%
// retransmission (seen in real captures) was indistinguishable from one with
// barely 3%, despite its own detail text calling it "critical".
func TestClassifyTCP_SevereRetransReachesCriticalVerdict(t *testing.T) {
	r := ClassifyTCP(0, 38.46)
	if r.Verdict != SLACritical {
		t.Fatalf("got verdict=%s score=%d, want critical for 38%% retransmission", r.Verdict, r.Score)
	}
	if r.Score >= 40 {
		t.Fatalf("expected score below the critical threshold (40), got %d", r.Score)
	}
}

func TestClassifyTCP_ModerateSevereRetransReachesPoor(t *testing.T) {
	// 6% retransmission (already "critical" by the text bands) with no RTT
	// signal should land in poor/critical, not acceptable.
	r := ClassifyTCP(0, 6)
	if r.Verdict == SLAGood || r.Verdict == SLAAcceptable {
		t.Fatalf("got verdict=%s score=%d for 6%% retransmission, want poor or worse", r.Verdict, r.Score)
	}
}

func TestClassifyTCP_RetransPenaltyMonotonic(t *testing.T) {
	// Higher retransmission must never score better than lower retransmission.
	prevScore := 101
	for _, pct := range []float64{0, 1, 2, 3, 6, 9, 12, 20, 38, 60, 100} {
		r := ClassifyTCP(0, pct)
		if r.Score > prevScore {
			t.Fatalf("retrans %.0f%%: score %d is higher than a lower retransmission rate's score %d", pct, r.Score, prevScore)
		}
		prevScore = r.Score
	}
}

func TestClassifyTCP_ScoreNeverNegative(t *testing.T) {
	r := ClassifyTCP(10000, 100)
	if r.Score < 0 {
		t.Fatalf("got negative score %d", r.Score)
	}
}

func TestClassifyUDP(t *testing.T) {
	r := ClassifyUDP()
	if r.Verdict != SLAGood || r.Score != 100 {
		t.Fatalf("got verdict=%s score=%d, want good/100", r.Verdict, r.Score)
	}
}
