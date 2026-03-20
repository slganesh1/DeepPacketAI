package analytics

import (
	"math"
	"time"

	"DeepPacketAI/internal/domain"
)

// KPI represents a key performance indicator.
type KPI struct {
	Name        string  `json:"name"`
	Value       float64 `json:"value"`
	Unit        string  `json:"unit"`
	Description string  `json:"description"`
	Status      string  `json:"status"` // "good", "warning", "critical"
}

// KPIReport contains all computed KPIs.
type KPIReport struct {
	GeneratedAt time.Time `json:"generated_at"`
	KPIs        []KPI     `json:"kpis"`
}

// ComputeKPIs computes telecom KPIs from flows and calls.
func ComputeKPIs(flows []domain.Flow, calls []domain.Call) KPIReport {
	report := KPIReport{
		GeneratedAt: time.Now(),
	}

	// 1. Call Setup Success Rate (CSSR)
	report.KPIs = append(report.KPIs, computeCSSR(calls))

	// 2. Call Drop Rate
	report.KPIs = append(report.KPIs, computeCallDropRate(calls))

	// 3. Average MOS
	report.KPIs = append(report.KPIs, computeAvgMOS(calls))

	// 4. Average Call Setup Time
	report.KPIs = append(report.KPIs, computeAvgSetupTime(flows))

	// 5. DNS Resolution Success Rate
	report.KPIs = append(report.KPIs, computeDNSSuccessRate(flows))

	// 6. DNS Average Resolution Time
	report.KPIs = append(report.KPIs, computeDNSAvgTime(flows))

	// 7. Diameter Auth Success Rate
	report.KPIs = append(report.KPIs, computeDiameterSuccessRate(flows))

	// 8. GTP Tunnel Success Rate
	report.KPIs = append(report.KPIs, computeGTPSuccessRate(flows))

	// 9. PFCP Session Success Rate
	report.KPIs = append(report.KPIs, computePFCPSuccessRate(flows))

	// 10. Protocol Distribution
	report.KPIs = append(report.KPIs, computeProtocolCount(flows))

	return report
}

func computeCSSR(calls []domain.Call) KPI {
	if len(calls) == 0 {
		return KPI{Name: "CSSR", Value: 0, Unit: "%", Description: "Call Setup Success Rate", Status: "warning"}
	}

	successful := 0
	for _, c := range calls {
		if c.Quality != "" && c.Quality != "Failed" {
			successful++
		}
	}

	rate := float64(successful) / float64(len(calls)) * 100
	status := "good"
	if rate < 95 {
		status = "warning"
	}
	if rate < 90 {
		status = "critical"
	}

	return KPI{Name: "CSSR", Value: round2(rate), Unit: "%", Description: "Call Setup Success Rate", Status: status}
}

func computeCallDropRate(calls []domain.Call) KPI {
	if len(calls) == 0 {
		return KPI{Name: "Call Drop Rate", Value: 0, Unit: "%", Description: "Percentage of calls dropped unexpectedly", Status: "good"}
	}

	dropped := 0
	for _, c := range calls {
		if c.EndType == "abnormal" || c.EndType == "dropped" {
			dropped++
		}
	}

	rate := float64(dropped) / float64(len(calls)) * 100
	status := "good"
	if rate > 2 {
		status = "warning"
	}
	if rate > 5 {
		status = "critical"
	}

	return KPI{Name: "Call Drop Rate", Value: round2(rate), Unit: "%", Description: "Percentage of calls dropped unexpectedly", Status: status}
}

func computeAvgMOS(calls []domain.Call) KPI {
	if len(calls) == 0 {
		return KPI{Name: "Average MOS", Value: 0, Unit: "", Description: "Mean Opinion Score (1-5 scale)", Status: "warning"}
	}

	total := 0.0
	count := 0
	for _, c := range calls {
		if c.MOS > 0 {
			total += c.MOS
			count++
		}
	}

	if count == 0 {
		return KPI{Name: "Average MOS", Value: 0, Unit: "", Description: "Mean Opinion Score (1-5 scale)", Status: "warning"}
	}

	avg := total / float64(count)
	status := "good"
	if avg < 3.5 {
		status = "warning"
	}
	if avg < 3.0 {
		status = "critical"
	}

	return KPI{Name: "Average MOS", Value: round2(avg), Unit: "", Description: "Mean Opinion Score (1-5 scale)", Status: status}
}

func computeAvgSetupTime(flows []domain.Flow) KPI {
	var setupTimes []float64

	for _, f := range flows {
		if f.Type != domain.FlowSIP {
			continue
		}
		// Use the setup_latency_ms already computed by the SIP decoder
		// (time from INVITE to first 200 OK)
		if latencyMs, ok := f.Metrics["setup_latency_ms"].(float64); ok && latencyMs > 0 {
			setupTimes = append(setupTimes, latencyMs/1000.0)
		}
	}

	if len(setupTimes) == 0 {
		return KPI{Name: "Avg Setup Time", Value: 0, Unit: "sec", Description: "Average call setup time", Status: "good"}
	}

	total := 0.0
	for _, t := range setupTimes {
		total += t
	}
	avg := total / float64(len(setupTimes))

	status := "good"
	if avg > 3 {
		status = "warning"
	}
	if avg > 6 {
		status = "critical"
	}

	return KPI{Name: "Avg Setup Time", Value: round2(avg), Unit: "sec", Description: "Average call setup time", Status: status}
}

func computeDNSSuccessRate(flows []domain.Flow) KPI {
	total := 0
	success := 0

	for _, f := range flows {
		if f.Type != domain.FlowDNS {
			continue
		}
		total++
		rcode, _ := f.Metrics["reply_code"].(string)
		if rcode == "NOERROR" || rcode == "" {
			success++
		}
	}

	if total == 0 {
		return KPI{Name: "DNS Success Rate", Value: 100, Unit: "%", Description: "DNS query success rate", Status: "good"}
	}

	rate := float64(success) / float64(total) * 100
	status := "good"
	if rate < 98 {
		status = "warning"
	}
	if rate < 95 {
		status = "critical"
	}

	return KPI{Name: "DNS Success Rate", Value: round2(rate), Unit: "%", Description: "DNS query success rate", Status: status}
}

func computeDNSAvgTime(flows []domain.Flow) KPI {
	var times []float64

	for _, f := range flows {
		if f.Type != domain.FlowDNS {
			continue
		}
		if respTime, ok := f.Metrics["latency_ms"].(float64); ok && respTime > 0 {
			times = append(times, respTime)
		}
		if respTime, ok := f.Metrics["latency_ms"].(int); ok && respTime > 0 {
			times = append(times, float64(respTime))
		}
	}

	if len(times) == 0 {
		return KPI{Name: "DNS Avg Latency", Value: 0, Unit: "ms", Description: "Average DNS resolution time", Status: "good"}
	}

	total := 0.0
	for _, t := range times {
		total += t
	}
	avg := total / float64(len(times))

	status := "good"
	if avg > 100 {
		status = "warning"
	}
	if avg > 500 {
		status = "critical"
	}

	return KPI{Name: "DNS Avg Latency", Value: round2(avg), Unit: "ms", Description: "Average DNS resolution time", Status: status}
}

func computeDiameterSuccessRate(flows []domain.Flow) KPI {
	total := 0
	success := 0

	for _, f := range flows {
		if f.Type != domain.FlowDiameter {
			continue
		}
		resultCode, ok := f.Metrics["result_code"].(uint32)
		if !ok {
			continue
		}
		total++
		if resultCode >= 2001 && resultCode <= 2002 {
			success++
		}
	}

	if total == 0 {
		return KPI{Name: "Diameter Success Rate", Value: 100, Unit: "%", Description: "Diameter auth/accounting success rate", Status: "good"}
	}

	rate := float64(success) / float64(total) * 100
	status := "good"
	if rate < 98 {
		status = "warning"
	}
	if rate < 95 {
		status = "critical"
	}

	return KPI{Name: "Diameter Success Rate", Value: round2(rate), Unit: "%", Description: "Diameter auth/accounting success rate", Status: status}
}

func computeGTPSuccessRate(flows []domain.Flow) KPI {
	total := 0
	success := 0

	for _, f := range flows {
		if f.Type != domain.FlowGTP {
			continue
		}
		total++
		cause, _ := f.Metrics["cause"].(string)
		if cause == "" || cause == "Request Accepted" {
			success++
		}
	}

	if total == 0 {
		return KPI{Name: "GTP Success Rate", Value: 100, Unit: "%", Description: "GTP tunnel establishment success rate", Status: "good"}
	}

	rate := float64(success) / float64(total) * 100
	status := "good"
	if rate < 98 {
		status = "warning"
	}
	if rate < 95 {
		status = "critical"
	}

	return KPI{Name: "GTP Success Rate", Value: round2(rate), Unit: "%", Description: "GTP tunnel establishment success rate", Status: status}
}

func computePFCPSuccessRate(flows []domain.Flow) KPI {
	total := 0
	success := 0

	for _, f := range flows {
		if f.Type != domain.FlowPFCP {
			continue
		}
		total++
		cause, _ := f.Metrics["cause"].(string)
		if cause == "" || cause == "Request accepted" {
			success++
		}
	}

	if total == 0 {
		return KPI{Name: "PFCP Success Rate", Value: 100, Unit: "%", Description: "PFCP session success rate", Status: "good"}
	}

	rate := float64(success) / float64(total) * 100
	status := "good"
	if rate < 98 {
		status = "warning"
	}
	if rate < 95 {
		status = "critical"
	}

	return KPI{Name: "PFCP Success Rate", Value: round2(rate), Unit: "%", Description: "PFCP session success rate", Status: status}
}

func computeProtocolCount(flows []domain.Flow) KPI {
	protos := make(map[domain.FlowType]bool)
	for _, f := range flows {
		protos[f.Type] = true
	}
	return KPI{
		Name:        "Active Protocols",
		Value:       float64(len(protos)),
		Unit:        "",
		Description: "Number of distinct protocols detected",
		Status:      "good",
	}
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}
