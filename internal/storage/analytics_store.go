package storage

import (
	"encoding/json"
	"time"

	"DeepPacketAI/internal/domain"
)

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
		f.StartTime, _ = time.Parse(time.RFC3339, startTime)
		f.EndTime, _ = time.Parse(time.RFC3339, endTime)

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
		f.StartTime, _ = time.Parse(time.RFC3339, startTime)
		f.EndTime, _ = time.Parse(time.RFC3339, endTime)

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

		c.StartTime, _ = time.Parse(time.RFC3339, startTime)
		c.EndTime, _ = time.Parse(time.RFC3339, endTime)
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

		c.StartTime, _ = time.Parse(time.RFC3339, startTime)
		c.EndTime, _ = time.Parse(time.RFC3339, endTime)
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
