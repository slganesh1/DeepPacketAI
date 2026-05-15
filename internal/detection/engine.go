package detection

import (
	"fmt"
	"log"
	"strings"
	"sync"

	"DeepPacketAI/internal/domain"
)

// Engine orchestrates detection rules against flows and packets.
type Engine struct {
	rules  []Rule
	alerts []Alert
	mu     sync.Mutex
}

// NewEngine creates a detection engine with default rules.
func NewEngine() *Engine {
	return &Engine{
		rules: BuiltinRules(),
	}
}

// NewEngineWithRules creates a detection engine with the provided rules.
// Pass plugin.Detection.ActiveRules() to use the plugin-managed rule set.
func NewEngineWithRules(rules []Rule) *Engine {
	return &Engine{
		rules: rules,
	}
}

// RunOnFlows evaluates all rules against the given flows.
func (e *Engine) RunOnFlows(flows []domain.Flow) []Alert {
	ctx := &RuleContext{}

	// Build FlowSummary list
	for _, f := range flows {
		ctx.Flows = append(ctx.Flows, FlowSummary{
			FlowID:    f.FlowID,
			Type:      string(f.Type),
			Metrics:   f.Metrics,
			SrcIP:     f.SrcIP,
			DstIP:     f.DstIP,
			SrcPort:   f.SrcPort,
			DstPort:   f.DstPort,
			StartTime: f.StartTime,
			EndTime:   f.EndTime,
		})
	}

	// Compute aggregate statistics in a single pass
	ctx.Aggregates = computeAggregates(ctx.Flows)

	var allAlerts []Alert
	for _, rule := range e.rules {
		alerts := rule.Check(ctx)
		if len(alerts) > 0 {
			log.Printf("[detection] %s: %d alerts", rule.Name, len(alerts))
			allAlerts = append(allAlerts, alerts...)
		}
	}

	e.mu.Lock()
	e.alerts = append(e.alerts, allAlerts...)
	e.mu.Unlock()

	return allAlerts
}

// computeAggregates builds cross-flow statistics in a single pass.
func computeAggregates(flows []FlowSummary) *AggregateStats {
	agg := &AggregateStats{
		FlowCountByType:    make(map[string]int),
		PacketCountByType:  make(map[string]int),
		FlowsPerSrcIP:     make(map[string]int),
		FlowsPerDstIP:     make(map[string]int),
		DestinationsPerSrc: make(map[string]map[string]bool),
		PacketsPerSrcIP:    make(map[string]int),
		SIPMethodCounts:    make(map[string]int),
		SIPResponseCounts:  make(map[string]int),
		DNSQueryCounts:     make(map[string]int),
		DiameterCmdCounts:  make(map[string]int),
		ErrorCounts:        make(map[string]int),
	}
	agg.SIP401PerSrcIP = make(map[string]int)
	agg.SIPRegisterPerSrcIP = make(map[string]int)
	agg.SIPOptionsPerSrcIP = make(map[string]int)
	agg.SIPInvitePerSrcIP = make(map[string]int)
	agg.DNSAnswerIPsPerDomain = make(map[string]map[string]bool)
	agg.SYNOnlyFlowsPerSrcIP = make(map[string]int)
	agg.ICMPFlowsPerSrcIP = make(map[string]int)

	agg.TotalFlows = len(flows)

	for _, f := range flows {
		// --- Volume ---
		agg.FlowCountByType[f.Type]++

		pktCount := getIntMetric(f.Metrics, "packet_count")
		agg.PacketCountByType[f.Type] += pktCount
		agg.TotalPackets += pktCount

		// --- Source/Destination ---
		agg.FlowsPerSrcIP[f.SrcIP]++
		agg.FlowsPerDstIP[f.DstIP]++
		agg.PacketsPerSrcIP[f.SrcIP] += pktCount

		if agg.DestinationsPerSrc[f.SrcIP] == nil {
			agg.DestinationsPerSrc[f.SrcIP] = make(map[string]bool)
		}
		agg.DestinationsPerSrc[f.SrcIP][f.DstIP] = true

		// --- Temporal ---
		if !f.StartTime.IsZero() {
			if agg.EarliestStart.IsZero() || f.StartTime.Before(agg.EarliestStart) {
				agg.EarliestStart = f.StartTime
			}
		}
		if !f.EndTime.IsZero() {
			if agg.LatestEnd.IsZero() || f.EndTime.After(agg.LatestEnd) {
				agg.LatestEnd = f.EndTime
			}
		}

		// --- Behavioral: SIP ---
		if f.Type == "SIP" {
			if method, ok := f.Metrics["method"].(string); ok {
				agg.SIPMethodCounts[method]++
				switch method {
				case "REGISTER":
					agg.SIPRegisterPerSrcIP[f.SrcIP]++
				case "OPTIONS":
					agg.SIPOptionsPerSrcIP[f.SrcIP]++
				case "INVITE":
					agg.SIPInvitePerSrcIP[f.SrcIP]++
				}
			}
			if resp, ok := f.Metrics["response"].(string); ok && resp != "" {
				agg.SIPResponseCounts[resp]++
				if resp == "401" {
					agg.SIP401PerSrcIP[f.SrcIP]++
				}
			}
		}

		// --- Behavioral: DoS ---
		if f.Type == "TCP" {
			flags, _ := f.Metrics["tcp_flags"].(string)
			// SYN-only: SYN seen but ACK never received → half-open connection (SYN flood)
			if strings.Contains(flags, "SYN") && !strings.Contains(flags, "ACK") {
				agg.SYNOnlyFlowsPerSrcIP[f.SrcIP]++
			}
		}
		// ICMP flows: FlowID format is "flow-src:port-dst:port-PROTO"
		if strings.HasSuffix(f.FlowID, "-ICMP") || strings.HasSuffix(f.FlowID, "-ICMPv6") {
			agg.ICMPFlowsPerSrcIP[f.SrcIP]++
		}

		// --- Behavioral: DNS ---
		if f.Type == "DNS" {
			if name, ok := f.Metrics["query_name"].(string); ok {
				agg.DNSQueryCounts[name]++
			}
			// Track resolved IPs per domain for fast-flux detection
			if answers, ok := f.Metrics["answers"].([]string); ok {
				base := dnsDomainBase(f.Metrics)
				if base != "" {
					if agg.DNSAnswerIPsPerDomain[base] == nil {
						agg.DNSAnswerIPsPerDomain[base] = make(map[string]bool)
					}
					for _, a := range answers {
						agg.DNSAnswerIPsPerDomain[base][a] = true
					}
				}
			}
		}

		// --- Behavioral: Diameter ---
		if f.Type == "Diameter" {
			if cmd, ok := f.Metrics["command"].(string); ok {
				agg.DiameterCmdCounts[cmd]++
			}
		}

		// --- Error tracking ---
		isErr, _ := f.Metrics["is_error"].(bool)
		if isErr {
			errType, _ := f.Metrics["error_type"].(string)
			key := fmt.Sprintf("%s:%s", f.Type, errType)
			agg.ErrorCounts[key]++
		}
	}

	if !agg.EarliestStart.IsZero() && !agg.LatestEnd.IsZero() {
		agg.CaptureWindow = agg.LatestEnd.Sub(agg.EarliestStart)
	}

	return agg
}

// getIntMetric safely extracts an int from a metrics map.
func getIntMetric(m map[string]any, key string) int {
	if v, ok := m[key].(int); ok {
		return v
	}
	return 0
}

// GetAlerts returns all accumulated alerts.
func (e *Engine) GetAlerts() []Alert {
	e.mu.Lock()
	defer e.mu.Unlock()
	result := make([]Alert, len(e.alerts))
	copy(result, e.alerts)
	return result
}

// ClearAlerts clears all accumulated alerts.
func (e *Engine) ClearAlerts() {
	e.mu.Lock()
	e.alerts = nil
	e.mu.Unlock()
}

// getFloat64Metric safely extracts a float64 from a metrics map.
func getFloat64Metric(m map[string]any, key string) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	if v, ok := m[key].(int); ok {
		return float64(v)
	}
	return 0
}

// dnsDomainBase returns the eTLD+1 from a DNS flow's query_name metric.
func dnsDomainBase(m map[string]any) string {
	name, _ := m["query_name"].(string)
	if name == "" {
		return ""
	}
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return name
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
