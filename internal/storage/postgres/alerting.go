package postgres

import (
	"DeepPacketAI/internal/storage"
)

func (s *PostgresStore) CreateAlertTarget(t storage.AlertTarget) (int64, error) {
	ctx, cancel := writeCtx()
	defer cancel()

	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO alert_targets (name, type, url, config_json, enabled, min_severity)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		t.Name, t.Type, t.URL, t.ConfigJSON, t.Enabled, t.MinSeverity,
	).Scan(&id)
	return id, err
}

func (s *PostgresStore) UpdateAlertTarget(t storage.AlertTarget) error {
	ctx, cancel := writeCtx()
	defer cancel()

	_, err := s.pool.Exec(ctx, `
		UPDATE alert_targets
		SET name=$1, type=$2, url=$3, config_json=$4, enabled=$5, min_severity=$6
		WHERE id=$7`,
		t.Name, t.Type, t.URL, t.ConfigJSON, t.Enabled, t.MinSeverity, t.ID,
	)
	return err
}

func (s *PostgresStore) DeleteAlertTarget(id int64) error {
	ctx, cancel := writeCtx()
	defer cancel()

	_, err := s.pool.Exec(ctx, `DELETE FROM alert_targets WHERE id=$1`, id)
	return err
}

func (s *PostgresStore) GetAlertTarget(id int64) (*storage.AlertTarget, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	var t storage.AlertTarget
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, type, url, config_json, enabled, min_severity, created_at
		FROM alert_targets WHERE id=$1`, id).
		Scan(&t.ID, &t.Name, &t.Type, &t.URL, &t.ConfigJSON, &t.Enabled, &t.MinSeverity, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *PostgresStore) ListAlertTargets() ([]storage.AlertTarget, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	rows, err := s.pool.Query(ctx, `
		SELECT id, name, type, url, config_json, enabled, min_severity, created_at
		FROM alert_targets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []storage.AlertTarget
	for rows.Next() {
		var t storage.AlertTarget
		if err := rows.Scan(&t.ID, &t.Name, &t.Type, &t.URL, &t.ConfigJSON, &t.Enabled, &t.MinSeverity, &t.CreatedAt); err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, nil
}
