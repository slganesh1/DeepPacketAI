package storage

// TrafficStatsRecord represents a time-series stats record.
type TrafficStatsRecord struct {
	ID                 int64  `json:"id"`
	JobID              *int64 `json:"job_id,omitempty"`
	SessionID          string `json:"session_id,omitempty"`
	Timestamp          string `json:"timestamp"`
	IntervalSec        int    `json:"interval_sec"`
	PacketsPerSec      int    `json:"packets_per_sec"`
	BytesPerSec        int    `json:"bytes_per_sec"`
	ProtocolCountsJSON string `json:"protocol_counts_json,omitempty"`
}

// StoreTrafficStats stores traffic stats records.
func (s *SQLiteStore) StoreTrafficStats(records []TrafficStatsRecord) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO traffic_stats (job_id, session_id, timestamp, interval_sec, packets_per_sec, bytes_per_sec, protocol_counts_json)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range records {
		_, err := stmt.Exec(r.JobID, r.SessionID, r.Timestamp, r.IntervalSec, r.PacketsPerSec, r.BytesPerSec, r.ProtocolCountsJSON)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// QueryTrafficStats returns traffic stats for a session, or the most recent
// records across all sessions when sessionID is empty.
func (s *SQLiteStore) QueryTrafficStats(sessionID string, limit int) ([]TrafficStatsRecord, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	var query string
	var args []any

	if sessionID != "" {
		query = "SELECT id, job_id, session_id, timestamp, interval_sec, packets_per_sec, bytes_per_sec, protocol_counts_json FROM traffic_stats WHERE session_id = ? ORDER BY id ASC"
		args = []any{sessionID}
	} else {
		// Fetch the most recent N records (DESC), then reverse to chronological order for chart rendering
		query = "SELECT id, job_id, session_id, timestamp, interval_sec, packets_per_sec, bytes_per_sec, protocol_counts_json FROM traffic_stats ORDER BY id DESC"
	}

	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []TrafficStatsRecord
	for rows.Next() {
		var r TrafficStatsRecord
		var jobID *int64
		var sessionID, protoJSON *string
		if err := rows.Scan(&r.ID, &jobID, &sessionID, &r.Timestamp, &r.IntervalSec, &r.PacketsPerSec, &r.BytesPerSec, &protoJSON); err != nil {
			return nil, err
		}
		r.JobID = jobID
		if sessionID != nil {
			r.SessionID = *sessionID
		}
		if protoJSON != nil {
			r.ProtocolCountsJSON = *protoJSON
		}
		records = append(records, r)
	}

	return records, nil
}
