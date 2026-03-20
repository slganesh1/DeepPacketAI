package postgres

import (
	"fmt"
	"time"

	"DeepPacketAI/internal/web/api"
)

func (s *PostgresStore) CreateJob(jobID int64, pcap string) error {
	ctx, cancel := writeCtx()
	defer cancel()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO jobs (id, pcap_path, status, started_at) VALUES ($1, $2, 'running', NOW())`,
		jobID, pcap,
	)
	return err
}

func (s *PostgresStore) FailJob(jobID int64, reason string) error {
	ctx, cancel := writeCtx()
	defer cancel()
	_, err := s.pool.Exec(ctx,
		`UPDATE jobs SET status='failed', error=$1 WHERE id=$2`,
		reason, jobID,
	)
	return err
}

func (s *PostgresStore) CompleteJob(jobID int64) error {
	ctx, cancel := writeCtx()
	defer cancel()
	_, err := s.pool.Exec(ctx,
		`UPDATE jobs SET status='completed', completed_at=NOW() WHERE id=$1`,
		jobID,
	)
	return err
}

func (s *PostgresStore) ClearJobData(jobID int64) error {
	ctx, cancel := writeCtx()
	defer cancel()
	tables := []string{"flows", "calls", "rtp_legs", "protocol_events", "packets"}
	for _, t := range tables {
		if _, err := s.pool.Exec(ctx, fmt.Sprintf("DELETE FROM %s WHERE job_id = $1", t), jobID); err != nil {
			// ignore errors for tables that might not exist yet
			_ = err
		}
	}
	_, err := s.pool.Exec(ctx, `UPDATE jobs SET status='running', completed_at=NULL, error=NULL WHERE id=$1`, jobID)
	return err
}

func (s *PostgresStore) GetJob(jobID int64) (*api.JobItem, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	var j api.JobItem
	var startedAt time.Time
	var completedAt *time.Time
	var errStr *string

	err := s.pool.QueryRow(ctx, `
		SELECT id, pcap_path, status,
		       COALESCE(started_at, NOW()),
		       completed_at,
		       COALESCE(error, '')
		FROM jobs WHERE id = $1
	`, jobID).Scan(&j.JobID, &j.PCAPPath, &j.Status, &startedAt, &completedAt, &j.Error)
	if err != nil {
		return nil, err
	}
	_ = errStr

	j.StartedAt = startedAt
	j.CompletedAt = completedAt

	return &j, nil
}

func (s *PostgresStore) ListJobs(limit int, status string) ([]api.JobItem, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	query := `
		SELECT id, pcap_path, status,
		       COALESCE(started_at, NOW()),
		       completed_at,
		       COALESCE(error, '')
		FROM jobs
	`
	args := []any{}
	argIdx := 1

	if status != "" {
		query += fmt.Sprintf(" WHERE status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}

	query += " ORDER BY id DESC"

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, limit)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []api.JobItem
	for rows.Next() {
		var j api.JobItem
		var startedAt time.Time
		var completedAt *time.Time

		if err := rows.Scan(&j.JobID, &j.PCAPPath, &j.Status, &startedAt, &completedAt, &j.Error); err != nil {
			return nil, err
		}

		j.StartedAt = startedAt
		j.CompletedAt = completedAt
		jobs = append(jobs, j)
	}

	return jobs, nil
}
