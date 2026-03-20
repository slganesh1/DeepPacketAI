package storage

import (
	"fmt"
	"strings"
)

// EventRecord represents a stored protocol event/alert.
type EventRecord struct {
	ID           int64  `json:"id"`
	JobID        *int64 `json:"job_id,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
	PacketID     *int64 `json:"packet_id,omitempty"`
	Timestamp    string `json:"timestamp"`
	Severity     string `json:"severity"`
	Protocol     string `json:"protocol"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	MetadataJSON string `json:"metadata_json,omitempty"`
}

// StoreEvents stores protocol events/alerts.
func (s *SQLiteStore) StoreEvents(events []EventRecord) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO protocol_events (job_id, session_id, packet_id, timestamp, severity, protocol, title, description, metadata_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range events {
		_, err := stmt.Exec(e.JobID, e.SessionID, e.PacketID, e.Timestamp, e.Severity, e.Protocol, e.Title, e.Description, e.MetadataJSON)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// QueryEvents returns events with optional filtering.
func (s *SQLiteStore) QueryEvents(filters map[string]string, limit int) ([]EventRecord, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	query := "SELECT id, job_id, session_id, packet_id, timestamp, severity, protocol, title, description, metadata_json FROM protocol_events"

	var conditions []string
	var args []any

	if v, ok := filters["severity"]; ok {
		conditions = append(conditions, "severity = ?")
		args = append(args, v)
	}
	if v, ok := filters["protocol"]; ok {
		conditions = append(conditions, "protocol = ?")
		args = append(args, v)
	}
	if v, ok := filters["job_id"]; ok {
		conditions = append(conditions, "job_id = ?")
		args = append(args, v)
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	query += " ORDER BY timestamp DESC"

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []EventRecord
	for rows.Next() {
		var e EventRecord
		var jobID, packetID *int64
		var sessionID, metaJSON *string
		if err := rows.Scan(&e.ID, &jobID, &sessionID, &packetID, &e.Timestamp, &e.Severity, &e.Protocol, &e.Title, &e.Description, &metaJSON); err != nil {
			return nil, err
		}
		e.JobID = jobID
		e.PacketID = packetID
		if sessionID != nil {
			e.SessionID = *sessionID
		}
		if metaJSON != nil {
			e.MetadataJSON = *metaJSON
		}
		events = append(events, e)
	}

	return events, nil
}
