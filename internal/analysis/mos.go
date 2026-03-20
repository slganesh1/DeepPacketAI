package analysis

import "math"

// ComputeMOS calculates MOS using a simplified E-Model
// Inputs:
//   packetLossPct: 0–100
//   jitterMs: milliseconds
//   latencyMs: one-way delay in milliseconds
func ComputeMOS(packetLossPct float64, jitterMs float64, latencyMs float64) float64 {
	// Base R factor (G.711-like)
	R := 94.2

	// Packet loss impairment
	R -= packetLossPct * 2.5

	// Jitter impairment (simplified)
	R -= jitterMs * 0.1

	// One-way delay impairment (simplified ITU-T G.107)
	// Delays under 177.3ms have minimal impact; above that, impact grows quadratically
	if latencyMs > 177.3 {
		R -= 0.024*latencyMs + 0.11*(latencyMs-177.3)
	}

	// Clamp R
	if R < 0 {
		R = 0
	}
	if R > 100 {
		R = 100
	}

	// Convert R to MOS (ITU-T G.107)
	mos := 1.0 + 0.035*R + R*(R-60)*(100-R)*7e-6

	// Clamp MOS
	if mos < 1.0 {
		mos = 1.0
	}
	if mos > 4.5 {
		mos = 4.5
	}

	return math.Round(mos*1000) / 1000 // 3 decimals
}

func QualityFromMOS(mos float64) string {
	switch {
	case mos >= 4.0:
		return "excellent"
	case mos >= 3.6:
		return "good"
	case mos >= 3.1:
		return "fair"
	case mos >= 2.6:
		return "poor"
	default:
		return "bad"
	}
}
