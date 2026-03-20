package postgres

import (
	"fmt"
	"strings"
	"time"

	"DeepPacketAI/internal/storage"
)

func (s *PostgresStore) StoreEvents(events []storage.EventRecord) error {
	if len(events) == 0 {
		return nil
	}

	ctx, cancel := writeCtx()
	defer cancel()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	for _, e := range events {
		ts, err := time.Parse(time.RFC3339, e.Timestamp)
		if err != nil {
			ts = time.Now()
		}

		var metaJSON []byte
		if e.MetadataJSON != "" {
			metaJSON = []byte(e.MetadataJSON)
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO protocol_events (job_id, session_id, packet_id, timestamp, severity, protocol, title, description, metadata_json)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`, e.JobID, nullStrPG(e.SessionID), e.PacketID, ts, e.Severity, e.Protocol, e.Title, e.Description, metaJSON)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (s *PostgresStore) QueryEvents(filters map[string]string, limit int) ([]storage.EventRecord, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	query := "SELECT id, job_id, session_id, packet_id, timestamp, severity, protocol, title, description, metadata_json FROM protocol_events"

	var conditions []string
	var args []any
	argIdx := 1

	if v, ok := filters["severity"]; ok {
		conditions = append(conditions, fmt.Sprintf("severity = $%d", argIdx))
		args = append(args, v)
		argIdx++
	}
	if v, ok := filters["protocol"]; ok {
		conditions = append(conditions, fmt.Sprintf("protocol = $%d", argIdx))
		args = append(args, v)
		argIdx++
	}
	if v, ok := filters["job_id"]; ok {
		conditions = append(conditions, fmt.Sprintf("job_id = $%d", argIdx))
		args = append(args, v)
		argIdx++
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	query += " ORDER BY timestamp DESC"

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, limit)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []storage.EventRecord
	for rows.Next() {
		var e storage.EventRecord
		var jobID, packetID *int64
		var sessionID *string
		var ts time.Time
		var metaJSON []byte

		if err := rows.Scan(&e.ID, &jobID, &sessionID, &packetID, &ts, &e.Severity, &e.Protocol, &e.Title, &e.Description, &metaJSON); err != nil {
			return nil, err
		}
		e.Timestamp = ts.Format(time.RFC3339)
		e.JobID = jobID
		e.PacketID = packetID
		if sessionID != nil {
			e.SessionID = *sessionID
		}
		if len(metaJSON) > 0 {
			e.MetadataJSON = string(metaJSON)
		}
		events = append(events, e)
	}

	return events, nil
}
