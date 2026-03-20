package storage

import (
	"encoding/json"
	"errors"
	"time"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/web/api"
)

// GetEntityWithRTPLegs fetches an entity and its RTP legs in a single
// store call, eliminating the N+1 pattern from the handler.
func (s *SQLiteStore) GetEntityWithRTPLegs(callID string) (*api.EntityItem, []map[string]any, error) {
	entity, err := s.GetEntityByCallID(callID)
	if err != nil {
		return nil, nil, err
	}
	legs, err := s.GetRTPLegsForCall(callID)
	if err != nil {
		return entity, nil, nil // degrade gracefully
	}
	return entity, legs, nil
}

func (s *SQLiteStore) GetCallByID(callID string) (*domain.Call, error) {
	ctx, cancel := queryCtx()
	defer cancel()
	row := s.db.QueryRowContext(ctx, `
		SELECT
			call_id,
			start_time,
			end_time,
			mos,
			quality,
			root_cause,
			confidence,
			is_on_hold,
			end_type
		FROM calls
		WHERE call_id = ?
	`, callID)

	var c domain.Call

	if err := row.Scan(
		&c.CallID,
		&c.StartTime,
		&c.EndTime,
		&c.MOS,
		&c.Quality,
		&c.RootCause,
		&c.Confidence,
		&c.IsOnHold,
		&c.EndType,
	); err != nil {
		return nil, errors.New("entity not found")
	}

	// RTP legs are already in memory today.
	// For now, leave empty; later we persist RTP legs table.
	c.RTPLegs = []map[string]any{}

	return &c, nil
}

func (s *SQLiteStore) GetRTPLegsForCall(callID string) ([]map[string]any, error) {
	ctx, cancel := queryCtx()
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			src_ip, src_port,
			dst_ip, dst_port,
			ssrc,
			packet_count,
			jitter_ms,
			max_seq_gap,
			start_time,
			end_time
		FROM rtp_legs
		WHERE call_id = ?
	`, callID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var legs []map[string]any

	for rows.Next() {
	var (
		srcIP      string
		srcPort    int
		dstIP      string
		dstPort    int
		ssrc       uint32
		packetCnt  int
		jitterMs   int
		maxSeqGap  int
		startTime  string
		endTime    string
	)

	if err := rows.Scan(
		&srcIP,
		&srcPort,
		&dstIP,
		&dstPort,
		&ssrc,
		&packetCnt,
		&jitterMs,
		&maxSeqGap,
		&startTime,
		&endTime,
	); err != nil {
		return nil, err
	}

	leg := map[string]any{
		"src_ip":        srcIP,
		"src_port":      srcPort,
		"dst_ip":        dstIP,
		"dst_port":      dstPort,
		"ssrc":          ssrc,
		"packet_count":  packetCnt,
		"jitter_ms":     jitterMs,
		"max_seq_gap":   maxSeqGap,
		"start_time":    startTime,
		"end_time":      endTime,
	}

	legs = append(legs, leg)
}


	return legs, nil
}

func (s *SQLiteStore) GetEntityByCallID(callID string) (*api.EntityItem, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	query := `
	SELECT
		call_id,
		start_time,
		end_time,
		mos,
		quality,
		root_cause,
		confidence
	FROM calls
	WHERE call_id = ?
	`

	var (
		id         string
		startStr   string
		endStr     string
		mos        float64
		quality    string
		rootCause  string
		confidence float64
	)

	err := s.db.QueryRowContext(ctx, query, callID).Scan(
		&id,
		&startStr,
		&endStr,
		&mos,
		&quality,
		&rootCause,
		&confidence,
	)
	if err != nil {
		return nil, err
	}

	startTime, _ := time.Parse(time.RFC3339, startStr)
	endTime, _ := time.Parse(time.RFC3339, endStr)

	entity := api.EntityItem{
		EntityID:   "call:" + id,
		EntityType: "call",
		Protocols:  []string{"sip", "rtp"},
		StartTime:  startTime,
		EndTime:    endTime,
		Summary: api.EntitySummary{
			MOS:        mos,
			Quality:    quality,
			RootCause:  rootCause,
			Confidence: confidence,
		},
	}

	return &entity, nil
}

// GetSIPFlowMetrics returns the metrics map for a SIP flow matching the given call ID.
func (s *SQLiteStore) GetSIPFlowMetrics(callID string) (map[string]any, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	var metricsJSON string
	err := s.db.QueryRowContext(ctx,
		`SELECT metrics FROM flows WHERE flow_id = ? AND type = 'SIP' LIMIT 1`,
		callID,
	).Scan(&metricsJSON)
	if err != nil {
		return nil, err
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(metricsJSON), &m); err != nil {
		return nil, err
	}
	return m, nil
}
