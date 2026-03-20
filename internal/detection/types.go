package detection

import "time"

// Severity levels for alerts.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityError    = "error"
	SeverityCritical = "critical"
)

// Alert represents a detected issue.
type Alert struct {
	ID          string         `json:"id"`
	Timestamp   time.Time      `json:"timestamp"`
	Severity    string         `json:"severity"`
	Protocol    string         `json:"protocol"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	PacketRef   uint64         `json:"packet_ref,omitempty"`
	FlowID      string         `json:"flow_id,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// Rule defines a detection rule.
type Rule struct {
	Name     string
	Protocol string
	Check    func(ctx *RuleContext) []Alert
}

// RuleContext provides data for rule evaluation.
type RuleContext struct {
	Flows      []FlowSummary
	Alerts     []Alert
	Aggregates *AggregateStats
}

// FlowSummary is a simplified flow for rule evaluation.
type FlowSummary struct {
	FlowID    string
	Type      string
	Metrics   map[string]any
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	StartTime time.Time
	EndTime   time.Time
}

// AggregateStats holds cross-flow statistics computed once and shared across all rules.
type AggregateStats struct {
	// Volume
	TotalFlows      int
	TotalPackets    int
	FlowCountByType map[string]int
	PacketCountByType map[string]int

	// Source/Destination
	FlowsPerSrcIP     map[string]int
	FlowsPerDstIP     map[string]int
	DestinationsPerSrc map[string]map[string]bool
	PacketsPerSrcIP    map[string]int

	// Temporal
	EarliestStart time.Time
	LatestEnd     time.Time
	CaptureWindow time.Duration

	// Behavioral — SIP
	SIPMethodCounts   map[string]int
	SIPResponseCounts map[string]int

	// Behavioral — SIP per-source (brute force detection)
	SIP401PerSrcIP      map[string]int
	SIPRegisterPerSrcIP map[string]int
	SIPOptionsPerSrcIP  map[string]int // for OPTIONS scanning detection
	SIPInvitePerSrcIP   map[string]int // for INVITE flood / toll fraud detection

	// Behavioral — DNS
	DNSQueryCounts       map[string]int
	DNSAnswerIPsPerDomain map[string]map[string]bool // domain → set of resolved IPs (fast-flux)

	// Behavioral — Diameter
	DiameterCmdCounts map[string]int

	// Error tracking: key = "protocol:error_type"
	ErrorCounts map[string]int
}
