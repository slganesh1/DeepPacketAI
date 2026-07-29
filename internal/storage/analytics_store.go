package storage

import (
	"encoding/json"
	"time"

	"DeepPacketAI/internal/domain"
)

// sqliteTimeLayouts are the formats a start_time/end_time column may contain.
// mattn/go-sqlite3 writes time.Time values using its own default layout
// ("2006-01-02 15:04:05.999999999-07:00" — space-separated, not RFC3339's
// "T"), so a plain time.Parse(time.RFC3339, ...) fails silently on every
// value that driver wrote and falls back to the zero time. Try the actual
// driver format first, then RFC3339 for forward/other-source compatibility.
var sqliteTimeLayouts = []string{
	"2006-01-02 15:04:05.999999999-07:00",
	time.RFC3339,
	"2006-01-02 15:04:05.999999999",
	"2006-01-02T15:04:05.999999999",
}

// parseSQLiteTime parses a start_time/end_time string stored by any of the
// layouts above, returning the zero time only if the string itself is empty
// or truly unparseable in every known format.
func parseSQLiteTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range sqliteTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// GetAllFlows retrieves all flows from the database.
func (s *SQLiteStore) GetAllFlows() ([]domain.Flow, error) {
	ctx, cancel := queryCtx()
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `
		SELECT flow_id, type, src_ip, dst_ip, src_port, dst_port, start_time, end_time, metrics
		FROM flows
		ORDER BY start_time ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var flows []domain.Flow
	for rows.Next() {
		var f domain.Flow
		var flowType string
		var startTime, endTime string
		var srcPort, dstPort int
		var metricsJSON *string

		if err := rows.Scan(&f.FlowID, &flowType, &f.SrcIP, &f.DstIP, &srcPort, &dstPort, &startTime, &endTime, &metricsJSON); err != nil {
			continue
		}

		f.Type = domain.FlowType(flowType)
		f.SrcPort = uint16(srcPort)
		f.DstPort = uint16(dstPort)
		f.StartTime = parseSQLiteTime(startTime)
		f.EndTime = parseSQLiteTime(endTime)

		if metricsJSON != nil && *metricsJSON != "" {
			var m map[string]any
			if err := json.Unmarshal([]byte(*metricsJSON), &m); err == nil {
				f.Metrics = m
			}
		}

		flows = append(flows, f)
	}

	return flows, nil
}

// GetFlowsByJob retrieves all flows for a specific job.
func (s *SQLiteStore) GetFlowsByJob(jobID int64) ([]domain.Flow, error) {
	ctx, cancel := queryCtx()
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `
		SELECT flow_id, type, src_ip, dst_ip, src_port, dst_port, start_time, end_time, metrics
		FROM flows
		WHERE job_id = ?
		ORDER BY start_time ASC
	`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var flows []domain.Flow
	for rows.Next() {
		var f domain.Flow
		var flowType string
		var startTime, endTime string
		var srcPort, dstPort int
		var metricsJSON *string

		if err := rows.Scan(&f.FlowID, &flowType, &f.SrcIP, &f.DstIP, &srcPort, &dstPort, &startTime, &endTime, &metricsJSON); err != nil {
			continue
		}

		f.Type = domain.FlowType(flowType)
		f.SrcPort = uint16(srcPort)
		f.DstPort = uint16(dstPort)
		f.StartTime = parseSQLiteTime(startTime)
		f.EndTime = parseSQLiteTime(endTime)

		if metricsJSON != nil && *metricsJSON != "" {
			var m map[string]any
			if err := json.Unmarshal([]byte(*metricsJSON), &m); err == nil {
				f.Metrics = m
			}
		}

		flows = append(flows, f)
	}

	return flows, nil
}

// GetCallsByJob retrieves all calls for a specific job.
func (s *SQLiteStore) GetCallsByJob(jobID int64) ([]domain.Call, error) {
	ctx, cancel := queryCtx()
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `
		SELECT call_id, start_time, end_time, from_uri, to_uri,
		       mos, quality, is_on_hold, end_type, root_cause, confidence
		FROM calls
		WHERE job_id = ?
		ORDER BY start_time ASC
	`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var calls []domain.Call
	for rows.Next() {
		var c domain.Call
		var startTime, endTime string
		var fromURI, toURI *string
		var isOnHold bool

		if err := rows.Scan(
			&c.CallID, &startTime, &endTime,
			&fromURI, &toURI,
			&c.MOS, &c.Quality, &isOnHold,
			&c.EndType, &c.RootCause, &c.Confidence,
		); err != nil {
			continue
		}

		c.StartTime = parseSQLiteTime(startTime)
		c.EndTime = parseSQLiteTime(endTime)
		c.IsOnHold = isOnHold

		if fromURI != nil || toURI != nil {
			c.SIPMetrics = map[string]any{}
			if fromURI != nil {
				c.SIPMetrics["from"] = *fromURI
			}
			if toURI != nil {
				c.SIPMetrics["to"] = *toURI
			}
		}

		calls = append(calls, c)
	}

	return calls, nil
}

// GetAllCalls retrieves all calls from the database.
func (s *SQLiteStore) GetAllCalls() ([]domain.Call, error) {
	ctx, cancel := queryCtx()
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `
		SELECT call_id, start_time, end_time, from_uri, to_uri,
		       mos, quality, is_on_hold, end_type, root_cause, confidence
		FROM calls
		ORDER BY start_time ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var calls []domain.Call
	for rows.Next() {
		var c domain.Call
		var startTime, endTime string
		var fromURI, toURI *string
		var isOnHold bool

		if err := rows.Scan(
			&c.CallID, &startTime, &endTime,
			&fromURI, &toURI,
			&c.MOS, &c.Quality, &isOnHold,
			&c.EndType, &c.RootCause, &c.Confidence,
		); err != nil {
			continue
		}

		c.StartTime = parseSQLiteTime(startTime)
		c.EndTime = parseSQLiteTime(endTime)
		c.IsOnHold = isOnHold

		if fromURI != nil || toURI != nil {
			c.SIPMetrics = map[string]any{}
			if fromURI != nil {
				c.SIPMetrics["from"] = *fromURI
			}
			if toURI != nil {
				c.SIPMetrics["to"] = *toURI
			}
		}

		calls = append(calls, c)
	}

	return calls, nil
}
