package detection

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ConditionField enumerates the aggregate/flow fields a user rule can test.
// Supported fields:
//
//	total_flows          — total number of decoded flows
//	total_packets        — total packet count across all flows
//	flow_count.PROTO     — flow count for a specific protocol (e.g. flow_count.SIP)
//	error_count.KEY      — error count for a specific key (e.g. error_count.SIP:)
//	sip_401_max          — highest 401-response count from any single source IP
//	sip_register_max     — highest REGISTER count from any single source IP
//	sip_invite_max       — highest INVITE count from any single source IP
//	sip_options_max      — highest OPTIONS count from any single source IP
//	source_fan_out_max   — highest number of unique destinations from any single source IP
//	dns_query_max        — highest DNS query count for any single domain
//	capture_window_secs  — length of the capture window in seconds
type ConditionField = string

// Operator is a comparison operator.
type Operator = string

const (
	OpGT  Operator = ">"
	OpGTE Operator = ">="
	OpLT  Operator = "<"
	OpLTE Operator = "<="
	OpEQ  Operator = "=="
	OpNEQ Operator = "!="
)

// Condition is a single threshold test.
type Condition struct {
	Field    ConditionField `json:"field"`
	Operator Operator       `json:"operator"`
	Value    float64        `json:"value"`
}

// RuleCondition describes the full condition set for a user rule.
// Match "any" fires when at least one condition is true.
// Match "all" fires only when every condition is true.
type RuleCondition struct {
	Conditions []Condition `json:"conditions"`
	Match      string      `json:"match"` // "any" | "all"
}

// extractField resolves a ConditionField to a numeric value from AggregateStats.
func extractField(field string, agg *AggregateStats) (float64, error) {
	switch {
	case field == "total_flows":
		return float64(agg.TotalFlows), nil
	case field == "total_packets":
		return float64(agg.TotalPackets), nil
	case field == "capture_window_secs":
		return agg.CaptureWindow.Seconds(), nil
	case field == "sip_401_max":
		return float64(maxIntMap(agg.SIP401PerSrcIP)), nil
	case field == "sip_register_max":
		return float64(maxIntMap(agg.SIPRegisterPerSrcIP)), nil
	case field == "sip_invite_max":
		return float64(maxIntMap(agg.SIPInvitePerSrcIP)), nil
	case field == "sip_options_max":
		return float64(maxIntMap(agg.SIPOptionsPerSrcIP)), nil
	case field == "source_fan_out_max":
		return float64(maxDestinations(agg.DestinationsPerSrc)), nil
	case field == "dns_query_max":
		return float64(maxIntMap(agg.DNSQueryCounts)), nil
	case strings.HasPrefix(field, "flow_count."):
		proto := strings.TrimPrefix(field, "flow_count.")
		return float64(agg.FlowCountByType[proto]), nil
	case strings.HasPrefix(field, "error_count."):
		key := strings.TrimPrefix(field, "error_count.")
		return float64(agg.ErrorCounts[key]), nil
	default:
		return 0, fmt.Errorf("unknown field %q", field)
	}
}

// evaluate tests a single Condition against AggregateStats.
func evaluate(c Condition, agg *AggregateStats) (bool, error) {
	actual, err := extractField(c.Field, agg)
	if err != nil {
		return false, err
	}
	switch c.Operator {
	case OpGT:
		return actual > c.Value, nil
	case OpGTE:
		return actual >= c.Value, nil
	case OpLT:
		return actual < c.Value, nil
	case OpLTE:
		return actual <= c.Value, nil
	case OpEQ:
		return actual == c.Value, nil
	case OpNEQ:
		return actual != c.Value, nil
	default:
		return false, fmt.Errorf("unknown operator %q", c.Operator)
	}
}

// UserRuleFromJSON builds a detection.Rule from a stored UserDetectionRule record.
// id / name / description / severity / conditionJSON come from storage.
func UserRuleFromJSON(id int64, name, description, protocol, severity, conditionJSON string) (Rule, error) {
	var rc RuleCondition
	if err := json.Unmarshal([]byte(conditionJSON), &rc); err != nil {
		return Rule{}, fmt.Errorf("rule %q: bad condition JSON: %w", name, err)
	}
	if len(rc.Conditions) == 0 {
		return Rule{}, fmt.Errorf("rule %q: no conditions defined", name)
	}
	if rc.Match == "" {
		rc.Match = "any"
	}

	ruleName := fmt.Sprintf("user:%d:%s", id, name)
	ruleProtocol := protocol
	ruleSeverity := severity
	ruleDesc := description
	if ruleDesc == "" {
		ruleDesc = buildAutoDescription(rc)
	}

	rule := Rule{
		Name:     ruleName,
		Protocol: ruleProtocol,
		Check: func(ctx *RuleContext) []Alert {
			if ctx.Aggregates == nil {
				return nil
			}

			matched := false
			var failedFields []string

			for _, cond := range rc.Conditions {
				ok, err := evaluate(cond, ctx.Aggregates)
				if err != nil {
					continue // skip unknown fields gracefully
				}
				if ok {
					if rc.Match == "any" {
						matched = true
						break
					}
					// "all" — keep checking
				} else {
					failedFields = append(failedFields, cond.Field)
					if rc.Match == "all" {
						matched = false
						break
					}
				}
			}

			// For "all" mode: matched only if no failures
			if rc.Match == "all" {
				matched = len(failedFields) == 0
			}

			if !matched {
				return nil
			}

			return []Alert{{
				ID:          uuid.NewString(),
				Timestamp:   time.Now(),
				Severity:    ruleSeverity,
				Protocol:    ruleProtocol,
				Title:       name,
				Description: ruleDesc,
				Metadata:    map[string]any{"user_rule_id": id, "match": rc.Match},
			}}
		},
	}
	return rule, nil
}

// buildAutoDescription constructs a human-readable description from conditions.
func buildAutoDescription(rc RuleCondition) string {
	parts := make([]string, 0, len(rc.Conditions))
	for _, c := range rc.Conditions {
		parts = append(parts, fmt.Sprintf("%s %s %.0f", c.Field, c.Operator, c.Value))
	}
	return strings.Join(parts, fmt.Sprintf(" %s ", rc.Match))
}

// maxIntMap returns the maximum value in an int map, or 0 if empty.
func maxIntMap(m map[string]int) int {
	max := 0
	for _, v := range m {
		if v > max {
			max = v
		}
	}
	return max
}

// maxDestinations returns the highest unique-destination count across all source IPs.
func maxDestinations(m map[string]map[string]bool) int {
	max := 0
	for _, dsts := range m {
		if len(dsts) > max {
			max = len(dsts)
		}
	}
	return max
}
