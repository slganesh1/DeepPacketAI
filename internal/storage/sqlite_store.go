package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"DeepPacketAI/internal/domain"
)

// queryTimeout is the default timeout for database queries.
const queryTimeout = 10 * time.Second

// writeTimeout is the default timeout for database writes.
const writeTimeout = 30 * time.Second

// queryCtx returns a context with the standard query timeout.
func queryCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), queryTimeout)
}

// writeCtx returns a context with the standard write timeout.
func writeCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), writeTimeout)
}

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLite(path string) (*SQLiteStore, error) {
	// Resolve absolute path to avoid duplicate DB confusion
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	log.Println("SQLite DB path:", absPath)

	db, err := sql.Open("sqlite3", absPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}

	// SQLite only supports one writer at a time; serialise writes
	// through a single connection to avoid SQLITE_BUSY errors.
	db.SetMaxOpenConns(1)

	// Enable WAL mode and performance pragmas
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA foreign_keys=ON",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("pragma %s: %w", p, err)
		}
	}

	// Run versioned migrations
	if err := runMigrations(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrations: %w", err)
	}

	store := &SQLiteStore{
		db: db,
	}

	return store, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// DB returns the underlying sql.DB for direct queries.
func (s *SQLiteStore) DB() *sql.DB {
	return s.db
}

func (s *SQLiteStore) CreateJob(jobID int64, pcap string) error {
	ctx, cancel := writeCtx()
	defer cancel()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO jobs (id, pcap_path, status, started_at) VALUES (?, ?, 'running', datetime('now'))`,
		jobID, pcap,
	)
	return err
}

func (s *SQLiteStore) FailJob(jobID int64, reason string) error {
	ctx, cancel := writeCtx()
	defer cancel()
	_, err := s.db.ExecContext(ctx,
		`UPDATE jobs SET status='failed', error=? WHERE id=?`,
		reason, jobID,
	)
	return err
}

func (s *SQLiteStore) CompleteJob(jobID int64) error {
	ctx, cancel := writeCtx()
	defer cancel()
	_, err := s.db.ExecContext(ctx,
		`UPDATE jobs SET status='completed', completed_at=datetime('now') WHERE id=?`,
		jobID,
	)
	return err
}

// ClearJobData removes all flows, calls, rtp_legs, events, and packets for a job
// so that it can be re-analyzed from the original PCAP.
func (s *SQLiteStore) ClearJobData(jobID int64) error {
	ctx, cancel := writeCtx()
	defer cancel()
	tables := []string{"flows", "calls", "rtp_legs", "events", "packets"}
	for _, t := range tables {
		if _, err := s.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE job_id = ?", t), jobID); err != nil {
			// Table might not exist yet — ignore
			log.Printf("ClearJobData: skipping table %s: %v", t, err)
		}
	}
	// Reset job status
	_, err := s.db.ExecContext(ctx, `UPDATE jobs SET status='running', completed_at=NULL, error=NULL WHERE id=?`, jobID)
	return err
}

func (s *SQLiteStore) StoreCalls(jobID int64, calls []domain.Call) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT OR IGNORE INTO calls (
			job_id, call_id,
			start_time, end_time, duration_sec,
			from_uri, to_uri,
			packet_count, jitter_ms, max_seq_gap,
			mos, quality,
			is_on_hold, end_type, root_cause, confidence
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, c := range calls {
		duration := int(c.EndTime.Sub(c.StartTime).Seconds())

		var packetCount, jitterMs, maxSeqGap int

		fromURI, _ := c.SIPMetrics["from"].(string)
		toURI, _ := c.SIPMetrics["to"].(string)

		_, err := stmt.Exec(
			jobID,
			c.CallID,
			c.StartTime,
			c.EndTime,
			duration,
			fromURI,
			toURI,
			packetCount,
			jitterMs,
			maxSeqGap,
			c.MOS,
			c.Quality,
			c.IsOnHold,
			c.EndType,
			c.RootCause,
			c.Confidence,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *SQLiteStore) GetProtocolCounts(jobID *int64) ([]map[string]any, error) {
	query := "SELECT app_protocol, COUNT(*) as count FROM packets WHERE app_protocol != ''"
	args := []any{}
	if jobID != nil {
		query += " AND job_id = ?"
		args = append(args, *jobID)
	}
	query += " GROUP BY app_protocol ORDER BY count DESC"

	ctx, cancel := queryCtx()
	defer cancel()
	rows, err := s.db.QueryContext(ctx, query, args...)
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

func (s *SQLiteStore) GetTopTalkers(jobID *int64, limit int) ([]map[string]any, error) {
	if limit <= 0 {
		limit = 10
	}
	ctx, cancel := queryCtx()
	defer cancel()
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT ip, SUM(count) as total FROM (
			SELECT src_ip as ip, COUNT(*) as count FROM packets GROUP BY src_ip
			UNION ALL
			SELECT dst_ip as ip, COUNT(*) as count FROM packets GROUP BY dst_ip
		) GROUP BY ip ORDER BY total DESC LIMIT %d`, limit))
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

func (s *SQLiteStore) StoreFlows(jobID int64, flows []domain.Flow) error {
	for _, f := range flows {
		var metricsJSON *string
		if f.Metrics != nil {
			b, err := json.Marshal(f.Metrics)
			if err == nil {
				s := string(b)
				metricsJSON = &s
			}
		}

		_, err := s.db.Exec(
			`INSERT INTO flows (job_id, flow_id, type, src_ip, dst_ip, src_port, dst_port, start_time, end_time, metrics)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			jobID, f.FlowID, f.Type, f.SrcIP, f.DstIP, f.SrcPort, f.DstPort, f.StartTime, f.EndTime, metricsJSON,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

