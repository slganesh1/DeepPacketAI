package detection

import "testing"

func gtpFlow(id string, srcIP string, srcPort, dstPort uint16) FlowSummary {
	return FlowSummary{
		FlowID:  id,
		Type:    "GTP",
		SrcIP:   srcIP,
		DstIP:   "10.9.9.9",
		SrcPort: srcPort,
		DstPort: dstPort,
	}
}

// TestUnusualPortRule_DedupesTunneledConversation reproduces the real bug:
// GTP (and similarly PFCP) flows are tracked one-per-message/transaction
// rather than one-per-tunnel, so a long-lived tunnel using a non-standard
// port throughout its life used to raise one "Unusual GTP Port" alert per
// message — hundreds or thousands of alerts for a single noisy tunnel.
func TestUnusualPortRule_DedupesTunneledConversation(t *testing.T) {
	rule := unusualPortRule()

	var flows []FlowSummary
	for i := 0; i < 500; i++ {
		// Same 5-tuple every time (one long-lived tunnel), non-standard port 9999.
		flows = append(flows, gtpFlow("gtp-msg", "10.0.0.1", 9999, 9999))
	}

	alerts := rule.Check(&RuleContext{Flows: flows})
	if len(alerts) != 1 {
		t.Fatalf("expected exactly 1 deduplicated alert for 500 messages on the same tunnel, got %d", len(alerts))
	}
	count, _ := alerts[0].Metadata["occurrence_count"].(int)
	if count != 500 {
		t.Fatalf("expected occurrence_count 500, got %v", alerts[0].Metadata["occurrence_count"])
	}
}

func TestUnusualPortRule_DistinctTunnelsGetSeparateAlerts(t *testing.T) {
	rule := unusualPortRule()

	flows := []FlowSummary{
		gtpFlow("gtp-1", "10.0.0.1", 9999, 9999),
		gtpFlow("gtp-2", "10.0.0.1", 9999, 9999), // same tunnel as gtp-1 -> dedup
		gtpFlow("gtp-3", "10.0.0.2", 8888, 8888), // different 5-tuple -> separate alert
	}

	alerts := rule.Check(&RuleContext{Flows: flows})
	if len(alerts) != 2 {
		t.Fatalf("expected 2 alerts (one per distinct 5-tuple), got %d", len(alerts))
	}
}

func TestUnusualPortRule_StandardPortNotFlagged(t *testing.T) {
	rule := unusualPortRule()

	flows := []FlowSummary{
		gtpFlow("gtp-std", "10.0.0.1", 2123, 2123), // standard GTP-C port
	}

	alerts := rule.Check(&RuleContext{Flows: flows})
	if len(alerts) != 0 {
		t.Fatalf("expected 0 alerts for a standard-port GTP flow, got %d", len(alerts))
	}
}
