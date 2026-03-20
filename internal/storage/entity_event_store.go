package storage

import (
	"encoding/json"
	"time"

	"DeepPacketAI/internal/web/api"
)

func (s *SQLiteStore) GetEventsForCall(callID string) ([]api.TimelineEvent, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx, `
	SELECT
		start_time,
		src_ip,
		dst_ip,
		metrics
	FROM flows
	WHERE type = 'sip'
	  AND metrics LIKE ?
	ORDER BY start_time
	`, "%"+callID+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := []api.TimelineEvent{}

	for rows.Next() {
		var (
			startStr string
			srcIP    string
			dstIP    string
			metrics  string
		)

		if err := rows.Scan(&startStr, &srcIP, &dstIP, &metrics); err != nil {
			return nil, err
		}

		ts, _ := time.Parse(time.RFC3339, startStr)

		var m map[string]any
		_ = json.Unmarshal([]byte(metrics), &m)

		method, _ := m["method"].(string)
		dir := "out"
		if m["direction"] == "in" {
			dir = "in"
		}

		events = append(events, api.TimelineEvent{
			Timestamp: ts,
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
