package storage

import (
	"time"

	"DeepPacketAI/internal/web/api"
)

func (s *SQLiteStore) GetJob(jobID int64) (*api.JobItem, error) {
	ctx, cancel := queryCtx()
	defer cancel()
	row := s.db.QueryRowContext(ctx, `
		SELECT
			id,
			pcap_path,
			status,
			COALESCE(started_at, CURRENT_TIMESTAMP),
			completed_at,
			IFNULL(error, '')
		FROM jobs
		WHERE id = ?
	`, jobID)

	var (
		startedAtStr   string
		completedAtStr *string
	)
	var j api.JobItem

	if err := row.Scan(
		&j.JobID,
		&j.PCAPPath,
		&j.Status,
		&startedAtStr,
		&completedAtStr,
		&j.Error,
	); err != nil {
		return nil, err
	}

	j.StartedAt, _ = time.Parse("2006-01-02 15:04:05", startedAtStr)
	if completedAtStr != nil {
		t, err := time.Parse("2006-01-02 15:04:05", *completedAtStr)
		if err == nil {
			j.CompletedAt = &t
		}
	}

	return &j, nil
}

func (s *SQLiteStore) ListJobs(limit int, status string) ([]api.JobItem, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	query := `
	SELECT
		id,
		pcap_path,
		status,
		COALESCE(started_at, CURRENT_TIMESTAMP),
		completed_at,
		IFNULL(error, '')
	FROM jobs
	`
	args := []any{}

	if status != "" {
		query += " WHERE status = ?"
		args = append(args, status)
	}

	query += " ORDER BY id DESC"

	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []api.JobItem

	for rows.Next() {
		var (
			startedAtStr   string
			completedAtStr *string
		)

		var j api.JobItem

		if err := rows.Scan(
			&j.JobID,
			&j.PCAPPath,
			&j.Status,
			&startedAtStr,
			&completedAtStr,
			&j.Error,
		); err != nil {
			return nil, err
		}

		// Parse started_at
		j.StartedAt, _ = time.Parse("2006-01-02 15:04:05", startedAtStr)

		// Parse completed_at if present
		if completedAtStr != nil {
			t, err := time.Parse("2006-01-02 15:04:05", *completedAtStr)
			if err == nil {
				j.CompletedAt = &t
			}
		}

		jobs = append(jobs, j)
	}

	return jobs, nil
}
