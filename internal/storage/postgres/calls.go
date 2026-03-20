package postgres

import (
	"errors"
	"time"

	"DeepPacketAI/internal/domain"
)

func (s *PostgresStore) StoreCalls(jobID int64, calls []domain.Call) error {
	if len(calls) == 0 {
		return nil
	}

	ctx, cancel := writeCtx()
	defer cancel()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	for _, c := range calls {
		duration := int(c.EndTime.Sub(c.StartTime).Seconds())

		fromURI, _ := c.SIPMetrics["from"].(string)
		toURI, _ := c.SIPMetrics["to"].(string)

		_, err := tx.Exec(ctx, `
			INSERT INTO calls (
				job_id, call_id,
				start_time, end_time, duration_sec,
				from_uri, to_uri,
				packet_count, jitter_ms, max_seq_gap,
				mos, quality,
				is_on_hold, end_type, root_cause, confidence
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
			ON CONFLICT (job_id, call_id) DO NOTHING
		`,
			jobID, c.CallID,
			c.StartTime, c.EndTime, duration,
			nullStrPG(fromURI), nullStrPG(toURI),
			0, 0, 0,
			c.MOS, nullStrPG(c.Quality),
			c.IsOnHold, nullStrPG(c.EndType), nullStrPG(c.RootCause), c.Confidence,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (s *PostgresStore) StoreRTPLegs(jobID int64, calls []domain.Call) error {
	ctx, cancel := writeCtx()
	defer cancel()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	for _, call := range calls {
		for _, leg := range call.RTPLegs {
			_, err := tx.Exec(ctx, `
				INSERT INTO rtp_legs (
					job_id, call_id,
					src_ip, src_port, dst_ip, dst_port,
					ssrc, packet_count, jitter_ms, max_seq_gap,
					start_time, end_time
				) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			`,
				jobID, call.CallID,
				leg["src_ip"], leg["src_port"], leg["dst_ip"], leg["dst_port"],
				leg["ssrc"], leg["packet_count"], leg["jitter_ms"], leg["max_seq_gap"],
				leg["start_time"], leg["end_time"],
			)
			if err != nil {
				return err
			}
		}
	}

	return tx.Commit(ctx)
}

func (s *PostgresStore) GetAllCalls() ([]domain.Call, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	rows, err := s.pool.Query(ctx, `
		SELECT call_id, start_time, end_time, from_uri, to_uri,
		       mos, quality, is_on_hold, end_type, root_cause, confidence
		FROM calls
		ORDER BY start_time ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanPGCalls(rows)
}

func (s *PostgresStore) GetCallsByJob(jobID int64) ([]domain.Call, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	rows, err := s.pool.Query(ctx, `
		SELECT call_id, start_time, end_time, from_uri, to_uri,
		       mos, quality, is_on_hold, end_type, root_cause, confidence
		FROM calls WHERE job_id = $1
		ORDER BY start_time ASC
	`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanPGCalls(rows)
}

func (s *PostgresStore) GetCallByID(callID string) (*domain.Call, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	var c domain.Call
	var startTime, endTime time.Time
	var fromURI, toURI, quality, endType, rootCause *string
	var isOnHold bool

	err := s.pool.QueryRow(ctx, `
		SELECT call_id, start_time, end_time, from_uri, to_uri,
		       mos, quality, is_on_hold, end_type, root_cause, confidence
		FROM calls WHERE call_id = $1
	`, callID).Scan(
		&c.CallID, &startTime, &endTime,
		&fromURI, &toURI,
		&c.MOS, &quality, &isOnHold,
		&endType, &rootCause, &c.Confidence,
	)
	if err != nil {
		return nil, errors.New("entity not found")
	}

	c.StartTime = startTime
	c.EndTime = endTime
	c.IsOnHold = isOnHold
	if quality != nil {
		c.Quality = *quality
	}
	if endType != nil {
		c.EndType = *endType
	}
	if rootCause != nil {
		c.RootCause = *rootCause
	}

	if fromURI != nil || toURI != nil {
		c.SIPMetrics = map[string]any{}
		if fromURI != nil {
			c.SIPMetrics["from"] = *fromURI
		}
		if toURI != nil {
			c.SIPMetrics["to"] = *toURI
		}
	}

	c.RTPLegs = []map[string]any{}
	return &c, nil
}

func (s *PostgresStore) GetRTPLegsForCall(callID string) ([]map[string]any, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	rows, err := s.pool.Query(ctx, `
		SELECT src_ip, src_port, dst_ip, dst_port,
		       ssrc, packet_count, jitter_ms, max_seq_gap,
		       start_time, end_time
		FROM rtp_legs WHERE call_id = $1
	`, callID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var legs []map[string]any

	for rows.Next() {
		var (
			srcIP, dstIP     string
			srcPort, dstPort int
			ssrc             int64
			packetCnt        int
			jitterMs         int
			maxSeqGap        int
			startTime        *time.Time
			endTime          *time.Time
		)

		if err := rows.Scan(&srcIP, &srcPort, &dstIP, &dstPort,
			&ssrc, &packetCnt, &jitterMs, &maxSeqGap,
			&startTime, &endTime); err != nil {
			return nil, err
		}

		var startStr, endStr string
		if startTime != nil {
			startStr = startTime.Format(time.RFC3339)
		}
		if endTime != nil {
			endStr = endTime.Format(time.RFC3339)
		}

		legs = append(legs, map[string]any{
			"src_ip":       srcIP,
			"src_port":     srcPort,
			"dst_ip":       dstIP,
			"dst_port":     dstPort,
			"ssrc":         ssrc,
			"packet_count": packetCnt,
			"jitter_ms":    jitterMs,
			"max_seq_gap":  maxSeqGap,
			"start_time":   startStr,
			"end_time":     endStr,
		})
	}

	return legs, nil
}

func scanPGCalls(rows pgRows) ([]domain.Call, error) {
	var calls []domain.Call

	for rows.Next() {
		var c domain.Call
		var startTime, endTime time.Time
		var fromURI, toURI, quality, endType, rootCause *string
		var isOnHold bool

		if err := rows.Scan(
			&c.CallID, &startTime, &endTime,
			&fromURI, &toURI,
			&c.MOS, &quality, &isOnHold,
			&endType, &rootCause, &c.Confidence,
		); err != nil {
			continue
		}

		c.StartTime = startTime
		c.EndTime = endTime
		c.IsOnHold = isOnHold
		if quality != nil {
			c.Quality = *quality
		}
		if endType != nil {
			c.EndType = *endType
		}
		if rootCause != nil {
			c.RootCause = *rootCause
		}

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
