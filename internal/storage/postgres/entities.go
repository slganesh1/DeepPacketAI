package postgres

import (
	"encoding/json"
	"fmt"
	"time"

	"DeepPacketAI/internal/storage"
	"DeepPacketAI/internal/web/api"
)

func (s *PostgresStore) ListCallEntities(
	jobID *int64,
	quality *string,
	rootCause *string,
	limit int,
	offset int,
) ([]api.EntityItem, int, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	where := "WHERE 1=1"
	args := []any{}
	argIdx := 1

	if jobID != nil {
		where += fmt.Sprintf(" AND job_id = $%d", argIdx)
		args = append(args, *jobID)
		argIdx++
	}
	if quality != nil {
		where += fmt.Sprintf(" AND quality = $%d", argIdx)
		args = append(args, *quality)
		argIdx++
	}
	if rootCause != nil {
		where += fmt.Sprintf(" AND root_cause = $%d", argIdx)
		args = append(args, *rootCause)
		argIdx++
	}

	var total int
	countQuery := "SELECT COUNT(*) FROM calls " + where
	if err := s.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `
		SELECT call_id, start_time, end_time, mos, quality, root_cause, confidence
		FROM calls ` + where + `
		ORDER BY start_time DESC
		LIMIT $` + fmt.Sprintf("%d", argIdx) + ` OFFSET $` + fmt.Sprintf("%d", argIdx+1)

	args = append(args, limit, offset)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []api.EntityItem
	for rows.Next() {
		var (
			callID    string
			startTime time.Time
			endTime   time.Time
			mos       float64
			qual      *string
			root      *string
			conf      float64
		)

		if err := rows.Scan(&callID, &startTime, &endTime, &mos, &qual, &root, &conf); err != nil {
			return nil, 0, err
		}

		qualStr := ""
		if qual != nil {
			qualStr = *qual
		}
		rootStr := ""
		if root != nil {
			rootStr = *root
		}

		items = append(items, api.EntityItem{
			EntityID:   "call:" + callID,
			EntityType: "call",
			Protocols:  []string{"sip", "rtp"},
			StartTime:  startTime,
			EndTime:    endTime,
			Summary: api.EntitySummary{
				MOS:        mos,
				Quality:    qualStr,
				RootCause:  rootStr,
				Confidence: conf,
			},
		})
	}

	return items, total, nil
}

func (s *PostgresStore) GetEntityWithRTPLegs(callID string) (*api.EntityItem, []map[string]any, error) {
	entity, err := s.GetEntityByCallID(callID)
	if err != nil {
		return nil, nil, err
	}
	legs, err := s.GetRTPLegsForCall(callID)
	if err != nil {
		return entity, nil, nil
	}
	return entity, legs, nil
}

func (s *PostgresStore) GetEntityByCallID(callID string) (*api.EntityItem, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	var (
		id         string
		startTime  time.Time
		endTime    time.Time
		mos        float64
		quality    *string
		rootCause  *string
		confidence float64
	)

	err := s.pool.QueryRow(ctx, `
		SELECT call_id, start_time, end_time, mos, quality, root_cause, confidence
		FROM calls WHERE call_id = $1
	`, callID).Scan(&id, &startTime, &endTime, &mos, &quality, &rootCause, &confidence)
	if err != nil {
		return nil, err
	}

	qualStr := ""
	if quality != nil {
		qualStr = *quality
	}
	rootStr := ""
	if rootCause != nil {
		rootStr = *rootCause
	}

	entity := api.EntityItem{
		EntityID:   "call:" + id,
		EntityType: "call",
		Protocols:  []string{"sip", "rtp"},
		StartTime:  startTime,
		EndTime:    endTime,
		Summary: api.EntitySummary{
			MOS:        mos,
			Quality:    qualStr,
			RootCause:  rootStr,
			Confidence: confidence,
		},
	}

	return &entity, nil
}

func (s *PostgresStore) ListEntitiesForJob(jobID int64, limit int, quality string) ([]api.EntityItem, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	query := `
		SELECT call_id, start_time, end_time, mos, quality, root_cause, confidence
		FROM calls WHERE job_id = $1
	`
	args := []any{jobID}
	argIdx := 2

	if quality != "" {
		query += fmt.Sprintf(" AND quality = $%d", argIdx)
		args = append(args, quality)
		argIdx++
	}

	query += " ORDER BY start_time"

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, limit)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entities := []api.EntityItem{}
	for rows.Next() {
		var (
			callID    string
			startTime time.Time
			endTime   time.Time
			mos       float64
			qual      *string
			root      *string
			conf      float64
		)

		if err := rows.Scan(&callID, &startTime, &endTime, &mos, &qual, &root, &conf); err != nil {
			return nil, err
		}

		qualStr := ""
		if qual != nil {
			qualStr = *qual
		}
		rootStr := ""
		if root != nil {
			rootStr = *root
		}

		entities = append(entities, api.EntityItem{
			EntityID:   "call:" + callID,
			EntityType: "call",
			Protocols:  []string{"sip", "rtp"},
			StartTime:  startTime,
			EndTime:    endTime,
			Summary: api.EntitySummary{
				MOS:        mos,
				Quality:    qualStr,
				RootCause:  rootStr,
				Confidence: conf,
			},
		})
	}

	return entities, nil
}

func (s *PostgresStore) GetMetricsForCall(callID string) (*api.EntityMetrics, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	rows, err := s.pool.Query(ctx, `
		SELECT start_time, jitter_ms, packet_count
		FROM rtp_legs WHERE call_id = $1
		ORDER BY start_time
	`, callID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	jitter := []api.MetricPoint{}
	packets := []api.MetricPoint{}

	for rows.Next() {
		var (
			startTime   time.Time
			jitterMs    int
			packetCount int
		)

		if err := rows.Scan(&startTime, &jitterMs, &packetCount); err != nil {
			return nil, err
		}

		jitter = append(jitter, api.MetricPoint{
			Timestamp: startTime,
			Value:     float64(jitterMs),
		})
		packets = append(packets, api.MetricPoint{
			Timestamp: startTime,
			Value:     float64(packetCount),
		})
	}

	var (
		endTime time.Time
		mos     float64
	)
	_ = s.pool.QueryRow(ctx, `SELECT end_time, mos FROM calls WHERE call_id = $1`, callID).Scan(&endTime, &mos)

	metrics := map[string][]api.MetricPoint{}

	if len(jitter) > 0 {
		metrics["jitter_ms"] = jitter
	}
	if len(packets) > 0 {
		metrics["packet_count"] = packets
	}
	if mos > 0 {
		metrics["mos"] = []api.MetricPoint{
			{Timestamp: endTime, Value: mos},
		}
	}

	return &api.EntityMetrics{
		EntityID: "call:" + callID,
		Metrics:  metrics,
	}, nil
}

func (s *PostgresStore) GetEventsForCall(callID string) ([]api.TimelineEvent, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	rows, err := s.pool.Query(ctx, `
		SELECT start_time, src_ip, dst_ip, metrics
		FROM flows
		WHERE type = 'sip'
		  AND metrics::text LIKE $1
		ORDER BY start_time
	`, "%"+callID+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := []api.TimelineEvent{}
	for rows.Next() {
		var (
			startTime time.Time
			srcIP     string
			dstIP     string
			metrics   []byte
		)

		if err := rows.Scan(&startTime, &srcIP, &dstIP, &metrics); err != nil {
			return nil, err
		}

		var m map[string]any
		_ = json.Unmarshal(metrics, &m)

		method, _ := m["method"].(string)
		dir := "out"
		if m["direction"] == "in" {
			dir = "in"
		}

		events = append(events, api.TimelineEvent{
			Timestamp: startTime,
			Protocol:  "sip",
			Method:    method,
			Direction: dir,
			Src:       srcIP,
			Dst:       dstIP,
			Details:   m,
		})
	}

	return events, nil
}

func (s *PostgresStore) GetCallFlow(entityID string) (*storage.CallFlowResult, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	result := &storage.CallFlowResult{
		EntityID: entityID,
	}

	rows, err := s.pool.Query(ctx, `
		SELECT src_ip, dst_ip, src_port, dst_port, type, start_time, end_time, metrics
		FROM flows
		WHERE flow_id LIKE $1 OR flow_id = $2
		ORDER BY start_time ASC
	`, entityID+"%", entityID)
	if err != nil {
		return nil, fmt.Errorf("query flows: %w", err)
	}
	defer rows.Close()

	participants := make(map[string]bool)

	for rows.Next() {
		var srcIP, dstIP, protocol string
		var srcPort, dstPort int
		var startTime time.Time
		var endTime *time.Time
		var metricsJSON []byte

		if err := rows.Scan(&srcIP, &dstIP, &srcPort, &dstPort, &protocol, &startTime, &endTime, &metricsJSON); err != nil {
			continue
		}

		participants[srcIP] = true
		participants[dstIP] = true

		var metadata map[string]any
		if len(metricsJSON) > 0 {
			json.Unmarshal(metricsJSON, &metadata)
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

		event := storage.CallFlowEvent{
			EntityID:  entityID,
			Timestamp: startTime.Format(time.RFC3339),
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
	eventRows, err := s.pool.Query(ctx, `
		SELECT id, timestamp, severity, protocol, title, description
		FROM protocol_events
		WHERE description LIKE $1
		ORDER BY timestamp ASC
	`, "%"+entityID+"%")
	if err == nil {
		defer eventRows.Close()
		for eventRows.Next() {
			var id int64
			var ts time.Time
			var severity, proto, title, desc string
			if err := eventRows.Scan(&id, &ts, &severity, &proto, &title, &desc); err != nil {
				continue
			}
			result.Events = append(result.Events, storage.CallFlowEvent{
				ID:        id,
				EntityID:  entityID,
				Timestamp: ts.Format(time.RFC3339),
				Protocol:  proto,
				EventType: title,
				Summary:   fmt.Sprintf("[%s] %s", severity, title),
			})
		}
	}

	return result, nil
}

func (s *PostgresStore) GetProtocolCounts(jobID *int64) ([]map[string]any, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	query := "SELECT app_protocol, COUNT(*) as count FROM packets WHERE app_protocol != ''"
	args := []any{}
	argIdx := 1

	if jobID != nil {
		query += fmt.Sprintf(" AND job_id = $%d", argIdx)
		args = append(args, *jobID)
		argIdx++
	}
	_ = argIdx

	query += " GROUP BY app_protocol ORDER BY count DESC"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []map[string]any
	for rows.Next() {
		var proto string
		var count int64
		if err := rows.Scan(&proto, &count); err != nil {
			continue
		}
		result = append(result, map[string]any{"protocol": proto, "count": count})
	}
	return result, nil
}

func (s *PostgresStore) GetTopTalkers(jobID *int64, limit int) ([]map[string]any, error) {
	if limit <= 0 {
		limit = 10
	}

	ctx, cancel := queryCtx()
	defer cancel()

	query := fmt.Sprintf(`
		SELECT ip, SUM(count) as total FROM (
			SELECT src_ip as ip, COUNT(*) as count FROM packets GROUP BY src_ip
			UNION ALL
			SELECT dst_ip as ip, COUNT(*) as count FROM packets GROUP BY dst_ip
		) t GROUP BY ip ORDER BY total DESC LIMIT %d`, limit)

	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []map[string]any
	for rows.Next() {
		var ip string
		var total int64
		if err := rows.Scan(&ip, &total); err != nil {
			continue
		}
		result = append(result, map[string]any{"ip": ip, "count": total})
	}
	return result, nil
}
