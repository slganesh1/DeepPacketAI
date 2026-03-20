package postgres

import (
	"fmt"
	"time"

	"DeepPacketAI/internal/storage"
)

func (s *PostgresStore) StoreCaptureSession(rec storage.CaptureSessionRecord) error {
	ctx, cancel := writeCtx()
	defer cancel()

	startedAt, err := time.Parse(time.RFC3339, rec.StartedAt)
	if err != nil {
		startedAt = time.Now()
	}

	var stoppedAt *time.Time
	if rec.StoppedAt != "" {
		t, err := time.Parse(time.RFC3339, rec.StoppedAt)
		if err == nil {
			stoppedAt = &t
		}
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO capture_sessions (id, interface_name, bpf_filter, status, started_at, stopped_at, packet_count, byte_count)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (id) DO UPDATE SET
			status=EXCLUDED.status,
			stopped_at=EXCLUDED.stopped_at,
			packet_count=EXCLUDED.packet_count,
			byte_count=EXCLUDED.byte_count
	`, rec.ID, rec.InterfaceName, rec.BPFFilter, rec.Status, startedAt, stoppedAt, rec.PacketCount, rec.ByteCount)
	return err
}

func (s *PostgresStore) QueryCaptureSessions() ([]storage.CaptureSessionRecord, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	rows, err := s.pool.Query(ctx,
		"SELECT id, interface_name, bpf_filter, status, started_at, stopped_at, packet_count, byte_count FROM capture_sessions ORDER BY started_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []storage.CaptureSessionRecord
	for rows.Next() {
		var r storage.CaptureSessionRecord
		var startedAt time.Time
		var stoppedAt *time.Time

		if err := rows.Scan(&r.ID, &r.InterfaceName, &r.BPFFilter, &r.Status, &startedAt, &stoppedAt, &r.PacketCount, &r.ByteCount); err != nil {
			return nil, err
		}
		r.StartedAt = startedAt.Format(time.RFC3339)
		if stoppedAt != nil {
			r.StoppedAt = stoppedAt.Format(time.RFC3339)
		}
		sessions = append(sessions, r)
	}

	return sessions, nil
}

func (s *PostgresStore) StoreTrafficStats(records []storage.TrafficStatsRecord) error {
	if len(records) == 0 {
		return nil
	}

	ctx, cancel := writeCtx()
	defer cancel()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	for _, r := range records {
		ts, err := time.Parse(time.RFC3339, r.Timestamp)
		if err != nil {
			ts = time.Now()
		}

		var protoJSON []byte
		if r.ProtocolCountsJSON != "" {
			protoJSON = []byte(r.ProtocolCountsJSON)
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO traffic_stats (job_id, session_id, timestamp, interval_sec, packets_per_sec, bytes_per_sec, protocol_counts_json)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, r.JobID, nullStrPG(r.SessionID), ts, r.IntervalSec, r.PacketsPerSec, r.BytesPerSec, protoJSON)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (s *PostgresStore) QueryTrafficStats(sessionID string, limit int) ([]storage.TrafficStatsRecord, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	query := "SELECT id, job_id, session_id, timestamp, interval_sec, packets_per_sec, bytes_per_sec, protocol_counts_json FROM traffic_stats WHERE session_id = $1 ORDER BY timestamp DESC"
	args := []any{sessionID}

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT $2")
		args = append(args, limit)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []storage.TrafficStatsRecord
	for rows.Next() {
		var r storage.TrafficStatsRecord
		var jobID *int64
		var sessID *string
		var ts time.Time
		var protoJSON []byte

		if err := rows.Scan(&r.ID, &jobID, &sessID, &ts, &r.IntervalSec, &r.PacketsPerSec, &r.BytesPerSec, &protoJSON); err != nil {
			return nil, err
		}
		r.JobID = jobID
		r.Timestamp = ts.Format(time.RFC3339)
		if sessID != nil {
			r.SessionID = *sessID
		}
		if len(protoJSON) > 0 {
			r.ProtocolCountsJSON = string(protoJSON)
		}
		records = append(records, r)
	}

	return records, nil
}
