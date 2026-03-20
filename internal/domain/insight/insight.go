package insight

// Type classifies an insight.
type Type string

const (
	TypeAnomaly    Type = "anomaly"
	TypeThreat     Type = "threat"
	TypeFraud      Type = "fraud"
	TypePerformance Type = "performance"
)

// Severity indicates how critical the insight is.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Insight is an AI-generated or rule-derived analytical finding.
type Insight struct {
	ID          string   `json:"id"`
	CallID      string   `json:"call_id"`
	Type        Type     `json:"type"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Embedding   []float32 `json:"embedding,omitempty"`
}
