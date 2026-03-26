package storage

// AlertTarget represents a notification destination (Slack, webhook, email).
type AlertTarget struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`         // "slack" | "webhook" | "email"
	URL         string `json:"url"`          // webhook/Slack URL or SMTP host
	ConfigJSON  string `json:"config_json"`  // extra config (SMTP auth, headers, etc.)
	Enabled     bool   `json:"enabled"`
	MinSeverity string `json:"min_severity"` // "info" | "warning" | "critical"
	CreatedAt   string `json:"created_at"`
}

// CreateAlertTarget inserts a new alert target and returns its auto-generated ID.
func (s *SQLiteStore) CreateAlertTarget(t AlertTarget) (int64, error) {
	ctx, cancel := writeCtx()
	defer cancel()

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO alert_targets (name, type, url, config_json, enabled, min_severity)
		VALUES (?, ?, ?, ?, ?, ?)`,
		t.Name, t.Type, t.URL, t.ConfigJSON, boolInt(t.Enabled), t.MinSeverity,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateAlertTarget overwrites all fields of an existing target (identified by ID).
func (s *SQLiteStore) UpdateAlertTarget(t AlertTarget) error {
	ctx, cancel := writeCtx()
	defer cancel()

	_, err := s.db.ExecContext(ctx, `
		UPDATE alert_targets
		SET name=?, type=?, url=?, config_json=?, enabled=?, min_severity=?
		WHERE id=?`,
		t.Name, t.Type, t.URL, t.ConfigJSON, boolInt(t.Enabled), t.MinSeverity, t.ID,
	)
	return err
}

// DeleteAlertTarget removes an alert target by ID.
func (s *SQLiteStore) DeleteAlertTarget(id int64) error {
	ctx, cancel := writeCtx()
	defer cancel()

	_, err := s.db.ExecContext(ctx, `DELETE FROM alert_targets WHERE id=?`, id)
	return err
}

// GetAlertTarget retrieves a single alert target by ID.
func (s *SQLiteStore) GetAlertTarget(id int64) (*AlertTarget, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, type, url, config_json, enabled, min_severity, created_at
		FROM alert_targets WHERE id=?`, id)
	return scanAlertTarget(row)
}

// ListAlertTargets returns all alert targets ordered by id.
func (s *SQLiteStore) ListAlertTargets() ([]AlertTarget, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, type, url, config_json, enabled, min_severity, created_at
		FROM alert_targets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []AlertTarget
	for rows.Next() {
		t, err := scanAlertTarget(rows)
		if err != nil {
			return nil, err
		}
		targets = append(targets, *t)
	}
	return targets, nil
}

// scanner is a common interface satisfied by *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanAlertTarget(s scanner) (*AlertTarget, error) {
	var t AlertTarget
	var enabled int
	if err := s.Scan(&t.ID, &t.Name, &t.Type, &t.URL, &t.ConfigJSON, &enabled, &t.MinSeverity, &t.CreatedAt); err != nil {
		return nil, err
	}
	t.Enabled = enabled != 0
	return &t, nil
}

// boolInt converts a bool to 1/0 for SQLite storage.
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
