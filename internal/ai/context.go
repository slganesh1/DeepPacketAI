package ai

import (
	"fmt"
	"strings"
)

// PacketContext is used to build context from selected packets for LLM consumption.
type PacketContext struct {
	Packets []PacketSummary `json:"packets"`
	Flows   []FlowSummary   `json:"flows,omitempty"`
	Alerts  []AlertSummary  `json:"alerts,omitempty"`
}

// PacketSummary is a simplified packet for LLM context.
type PacketSummary struct {
	FrameNumber uint64 `json:"frame_number"`
	Timestamp   string `json:"timestamp"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	Protocol    string `json:"protocol"`
	Summary     string `json:"summary"`
}

// FlowSummary is a simplified flow for LLM context.
type FlowSummary struct {
	FlowID   string         `json:"flow_id"`
	Type     string         `json:"type"`
	Metrics  map[string]any `json:"metrics,omitempty"`
}

// AlertSummary is a simplified alert for LLM context.
type AlertSummary struct {
	Severity    string `json:"severity"`
	Protocol    string `json:"protocol"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// BuildContextString formats packet context for LLM consumption.
func BuildContextString(ctx PacketContext) string {
	var sb strings.Builder

	if len(ctx.Packets) > 0 {
		sb.WriteString("## Selected Packets\n\n")
		for _, p := range ctx.Packets {
			sb.WriteString(fmt.Sprintf("Frame #%d [%s] %s:%s -> %s [%s]\n",
				p.FrameNumber, p.Timestamp, p.SrcIP, p.Protocol, p.DstIP, p.Summary))
		}
		sb.WriteString("\n")
	}

	if len(ctx.Alerts) > 0 {
		sb.WriteString("## Detected Issues\n\n")
		for _, a := range ctx.Alerts {
			sb.WriteString(fmt.Sprintf("- [%s] %s: %s - %s\n", a.Severity, a.Protocol, a.Title, a.Description))
		}
		sb.WriteString("\n")
	}

	if len(ctx.Flows) > 0 {
		sb.WriteString("## Related Flows\n\n")
		for _, f := range ctx.Flows {
			sb.WriteString(fmt.Sprintf("- %s (%s): %v\n", f.FlowID, f.Type, f.Metrics))
		}
	}

	return sb.String()
}

// MaxPacketsForContext is the maximum number of packets to include in LLM context.
const MaxPacketsForContext = 50
