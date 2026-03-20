package storage

import (
	"time"

	"DeepPacketAI/internal/web/api"
)

func (s *SQLiteStore) GetMetricsForCall(callID string) (*api.EntityMetrics, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx, `
	SELECT
		start_time,
		jitter_ms,
		packet_count
	FROM rtp_legs
	WHERE call_id = ?
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
			startStr    string
			jitterMs    int
			packetCount int
		)

		if err := rows.Scan(&startStr, &jitterMs, &packetCount); err != nil {
			return nil, err
		}

		ts, _ := time.Parse(time.RFC3339, startStr)

		jitter = append(jitter, api.MetricPoint{
			Timestamp: ts,
			Value:     float64(jitterMs),
		})

		packets = append(packets, api.MetricPoint{
			Timestamp: ts,
			Value:     float64(packetCount),
		})
	}

	// MOS is call-level → single point at end_time
	var (
		endStr string
		mos    float64
	)

	_ = s.db.QueryRowContext(ctx, `
	SELECT end_time, mos
	FROM calls
	WHERE call_id = ?
	`, callID).Scan(&endStr, &mos)

	endTs, _ := time.Parse(time.RFC3339, endStr)

	metrics := map[string][]api.MetricPoint{}

	if len(jitter) > 0 {
		metrics["jitter_ms"] = jitter
	}
	if len(packets) > 0 {
		metrics["packet_count"] = packets
	}
	if mos > 0 {
		metrics["mos"] = []api.MetricPoint{
			{Timestamp: endTs, Value: mos},
		}
	}

	return &api.EntityMetrics{
		EntityID: "call:" + callID,
		Metrics:  metrics,
	}, nil
}
