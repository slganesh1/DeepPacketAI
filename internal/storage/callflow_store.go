package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

// CallFlowEvent represents a single event in a call flow ladder diagram.
type CallFlowEvent struct {
	ID        int64          `json:"id"`
	EntityID  string         `json:"entity_id"`
	Timestamp string         `json:"timestamp"`
	Protocol  string         `json:"protocol"`
	EventType string         `json:"event_type"`
	Summary   string         `json:"summary"`
	SrcIP     string         `json:"src_ip"`
	DstIP     string         `json:"dst_ip"`
	SrcPort   int            `json:"src_port"`
	DstPort   int            `json:"dst_port"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// CallFlowResult contains the call flow data for rendering a ladder diagram.
type CallFlowResult struct {
	EntityID     string          `json:"entity_id"`
	Participants []string        `json:"participants"`
	Events       []CallFlowEvent `json:"events"`
}

// GetCallFlow retrieves ordered events for an entity (call) and its participants.
func (s *SQLiteStore) GetCallFlow(entityID string) (*CallFlowResult, error) {
	ctx, cancel := queryCtx()
	defer cancel()
	db := s.DB()

	result := &CallFlowResult{
		EntityID: entityID,
	}

	// Get all flows for this entity (call ID)
	rows, err := db.QueryContext(ctx, `
		SELECT src_ip, dst_ip, src_port, dst_port, type, start_time, end_time, metrics
		FROM flows
		WHERE flow_id LIKE ? OR flow_id = ?
		ORDER BY start_time ASC
	`, entityID+"%", entityID)
	if err != nil {
		return nil, fmt.Errorf("query flows: %w", err)
	}
	defer rows.Close()

	participants := make(map[string]bool)

	for rows.Next() {
		var srcIP, dstIP, protocol, startTime string
		var endTime sql.NullString
		var srcPort, dstPort int
		var metricsJSON sql.NullString

		if err := rows.Scan(&srcIP, &dstIP, &srcPort, &dstPort, &protocol, &startTime, &endTime, &metricsJSON); err != nil {
			continue
		}

		participants[srcIP] = true
		participants[dstIP] = true

		var metadata map[string]any
		if metricsJSON.Valid {
			json.Unmarshal([]byte(metricsJSON.String), &metadata)
		}

		summary := protocol
		if method, ok := metadata["method"].(string); ok {
			summary = fmt.Sprintf("%s %s", protocol, method)
		}
		if procName, ok := metadata["procedure_name"].(string); ok {
			summary = fmt.Sprintf("%s %s", protocol, procName)
		}
		if cmdName, ok := metadata["command_name"].(string); ok {
			summary = fmt.Sprintf("%s %s", protocol, cmdName)
		}

		event := CallFlowEvent{
			EntityID:  entityID,
			Timestamp: startTime,
			Protocol:  protocol,
			EventType: summary,
			Summary:   summary,
			SrcIP:     srcIP,
			DstIP:     dstIP,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Metadata:  metadata,
		}

		result.Events = append(result.Events, event)
	}

	for p := range participants {
		result.Participants = append(result.Participants, p)
	}

	// Also get events from protocol_events table
	eventRows, err := db.QueryContext(ctx, `
		SELECT id, timestamp, severity, protocol, title, description
		FROM protocol_events
		WHERE description LIKE ?
		ORDER BY timestamp ASC
	`, "%"+entityID+"%")
	if err == nil {
		defer eventRows.Close()
		for eventRows.Next() {
			var id int64
			var ts, severity, proto, title, desc string
			if err := eventRows.Scan(&id, &ts, &severity, &proto, &title, &desc); err != nil {
				continue
			}
			result.Events = append(result.Events, CallFlowEvent{
				ID:        id,
				EntityID:  entityID,
				Timestamp: ts,
				Protocol:  proto,
				EventType: title,
				Summary:   fmt.Sprintf("[%s] %s", severity, title),
			})
		}
	}

	return result, nil
}
