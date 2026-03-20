package analytics

import (
	"strconv"
	"strings"
	"time"

	"DeepPacketAI/internal/domain"
)

func normalizeQuality(q string) string {
	return strings.ToLower(strings.TrimSpace(q))
}

// Report is a comprehensive analysis report for a PCAP or capture session.
type Report struct {
	GeneratedAt       time.Time            `json:"generated_at"`
	Duration          float64              `json:"duration_seconds"`
	TotalFlows        int                  `json:"total_flows"`
	TotalCalls        int                  `json:"total_calls"`
	ProtocolBreakdown map[string]int       `json:"protocol_breakdown"`
	KPIs              KPIReport            `json:"kpis"`
	TopIssues         []Issue              `json:"top_issues"`
	CallSummary       CallSummaryStats     `json:"call_summary"`
	ProtocolStats     []ProtocolStatDetail `json:"protocol_stats"`
	RootCauseCounts   map[string]int       `json:"root_cause_counts,omitempty"`
}

// Issue represents a detected problem in the network traffic.
type Issue struct {
	Severity    string `json:"severity"`
	Protocol    string `json:"protocol"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Count       int    `json:"count"`
}

// CallSummaryStats summarizes SIP call statistics.
type CallSummaryStats struct {
	TotalCalls    int     `json:"total_calls"`
	SuccessRate   float64 `json:"success_rate"`
	AvgMOS        float64 `json:"avg_mos"`
	AvgDuration   float64 `json:"avg_duration_sec"`
	DroppedCalls  int     `json:"dropped_calls"`
	QualityGood   int     `json:"quality_good"`
	QualityFair   int     `json:"quality_fair"`
	QualityPoor   int     `json:"quality_poor"`
	QualityFailed int     `json:"quality_failed"`
}

// ProtocolStatDetail provides per-protocol statistics.
type ProtocolStatDetail struct {
	Protocol    string  `json:"protocol"`
	FlowCount   int     `json:"flow_count"`
	SuccessRate float64 `json:"success_rate"`
	ErrorCount  int     `json:"error_count"`
}

// GenerateReport produces a full analysis report from flows and calls.
func GenerateReport(flows []domain.Flow, calls []domain.Call) Report {
	report := Report{
		GeneratedAt:       time.Now(),
		TotalFlows:        len(flows),
		TotalCalls:        len(calls),
		ProtocolBreakdown: make(map[string]int),
	}

	// Compute time range
	var earliest, latest time.Time
	for _, f := range flows {
		if earliest.IsZero() || (!f.StartTime.IsZero() && f.StartTime.Before(earliest)) {
			earliest = f.StartTime
		}
		if f.EndTime.After(latest) {
			latest = f.EndTime
		}
	}
	if !earliest.IsZero() && !latest.IsZero() {
		report.Duration = latest.Sub(earliest).Seconds()
	}

	// Protocol breakdown
	for _, f := range flows {
		report.ProtocolBreakdown[string(f.Type)]++
	}

	// KPIs
	report.KPIs = ComputeKPIs(flows, calls)

	// Call summary
	report.CallSummary = computeCallSummary(calls)

	// Protocol stats
	report.ProtocolStats = computeProtocolStats(flows)

	// Root cause counts
	report.RootCauseCounts = computeRootCauseCounts(calls)

	return report
}

func computeCallSummary(calls []domain.Call) CallSummaryStats {
	stats := CallSummaryStats{
		TotalCalls: len(calls),
	}

	if len(calls) == 0 {
		return stats
	}

	totalMOS := 0.0
	mosCount := 0
	totalDuration := 0.0
	durCount := 0

	for _, c := range calls {
		switch normalizeQuality(c.Quality) {
		case "good", "excellent":
			stats.QualityGood++
		case "fair":
			stats.QualityFair++
		case "poor", "bad":
			stats.QualityPoor++
		default:
			stats.QualityFailed++
		}

		if c.EndType == "abnormal" || c.EndType == "dropped" {
			stats.DroppedCalls++
		}

		if c.MOS > 0 {
			totalMOS += c.MOS
			mosCount++
		}

		if !c.StartTime.IsZero() && !c.EndTime.IsZero() {
			dur := c.EndTime.Sub(c.StartTime).Seconds()
			if dur > 0 {
				totalDuration += dur
				durCount++
			}
		}
	}

	if mosCount > 0 {
		stats.AvgMOS = round2(totalMOS / float64(mosCount))
	}
	if durCount > 0 {
		stats.AvgDuration = round2(totalDuration / float64(durCount))
	}

	successful := stats.TotalCalls - stats.QualityFailed
	if stats.TotalCalls > 0 {
		stats.SuccessRate = round2(float64(successful) / float64(stats.TotalCalls) * 100)
	}

	return stats
}

func computeProtocolStats(flows []domain.Flow) []ProtocolStatDetail {
	type protoCounter struct {
		total  int
		errors int
	}
	counters := make(map[string]*protoCounter)

	for _, f := range flows {
		proto := string(f.Type)
		c, ok := counters[proto]
		if !ok {
			c = &protoCounter{}
			counters[proto] = c
		}
		c.total++

		// Check for error indicators in metrics
		if hasError(f) {
			c.errors++
		}
	}

	var stats []ProtocolStatDetail
	for proto, c := range counters {
		successRate := 100.0
		if c.total > 0 {
			successRate = round2(float64(c.total-c.errors) / float64(c.total) * 100)
		}
		stats = append(stats, ProtocolStatDetail{
			Protocol:    proto,
			FlowCount:   c.total,
			SuccessRate: successRate,
			ErrorCount:  c.errors,
		})
	}

	return stats
}

func hasError(f domain.Flow) bool {
	if f.Metrics == nil {
		return false
	}

	// SIP/HTTP error responses via integer status_code
	if statusCode, ok := f.Metrics["status_code"].(int); ok && statusCode >= 400 {
		return true
	}
	// status_code may come back as float64 from JSON unmarshaling
	if statusCode, ok := f.Metrics["status_code"].(float64); ok && int(statusCode) >= 400 {
		return true
	}

	// SIP error responses via "response" string (e.g. "SIP/2.0 404 Not Found")
	if resp, ok := f.Metrics["response"].(string); ok && resp != "" {
		if code := parseSIPStatusCode(resp); code >= 400 {
			return true
		}
	}

	// DNS errors (decoder stores "reply_code")
	if rcode, ok := f.Metrics["reply_code"].(string); ok {
		if rcode == "SERVFAIL" || rcode == "NXDOMAIN" || rcode == "REFUSED" || rcode == "FORMERR" {
			return true
		}
	}
	// Also check is_error flag set by DNS decoder
	if isErr, ok := f.Metrics["is_error"].(bool); ok && isErr {
		return true
	}

	// Diameter non-success
	if rc, ok := f.Metrics["result_code"].(uint32); ok {
		if rc < 2001 || rc > 2002 {
			return true
		}
	}
	if rc, ok := f.Metrics["result_code"].(float64); ok {
		code := int(rc)
		if code < 2001 || code > 2002 {
			return true
		}
	}

	return false
}

func computeRootCauseCounts(calls []domain.Call) map[string]int {
	counts := make(map[string]int)
	for _, c := range calls {
		rc := c.RootCause
		if rc == "" {
			rc = "unknown"
		}
		counts[rc]++
	}
	if len(counts) == 0 {
		return nil
	}
	return counts
}

// parseSIPStatusCode extracts the numeric status code from a SIP response line
// like "SIP/2.0 404 Not Found" and returns it, or 0 if parsing fails.
func parseSIPStatusCode(response string) int {
	// Expected format: "SIP/2.0 <code> <reason>"
	parts := strings.SplitN(response, " ", 3)
	if len(parts) < 2 {
		return 0
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0
	}
	return code
}
