package postgres

import (
	"DeepPacketAI/internal/storage"
)

func (s *PostgresStore) CreateUserRule(r storage.UserDetectionRule) (int64, error) {
	ctx, cancel := writeCtx()
	defer cancel()
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO user_detection_rules (name, description, protocol, severity, condition_json, enabled)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		r.Name, r.Description, r.Protocol, r.Severity, r.ConditionJSON, r.Enabled,
	).Scan(&id)
	return id, err
}

func (s *PostgresStore) UpdateUserRule(r storage.UserDetectionRule) error {
	ctx, cancel := writeCtx()
	defer cancel()
	_, err := s.pool.Exec(ctx, `
		UPDATE user_detection_rules
		SET name=$1, description=$2, protocol=$3, severity=$4, condition_json=$5, enabled=$6
		WHERE id=$7`,
		r.Name, r.Description, r.Protocol, r.Severity, r.ConditionJSON, r.Enabled, r.ID,
	)
	return err
}

func (s *PostgresStore) DeleteUserRule(id int64) error {
	ctx, cancel := writeCtx()
	defer cancel()
	_, err := s.pool.Exec(ctx, `DELETE FROM user_detection_rules WHERE id=$1`, id)
	return err
}

func (s *PostgresStore) GetUserRule(id int64) (*storage.UserDetectionRule, error) {
	ctx, cancel := queryCtx()
	defer cancel()
	var r storage.UserDetectionRule
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, description, protocol, severity, condition_json, enabled, created_at
		FROM user_detection_rules WHERE id=$1`, id).
		Scan(&r.ID, &r.Name, &r.Description, &r.Protocol, &r.Severity, &r.ConditionJSON, &r.Enabled, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *PostgresStore) ListUserRules() ([]storage.UserDetectionRule, error) {
	ctx, cancel := queryCtx()
	defer cancel()
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, description, protocol, severity, condition_json, enabled, created_at
		FROM user_detection_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []storage.UserDetectionRule
	for rows.Next() {
		var r storage.UserDetectionRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.Protocol, &r.Severity,
			&r.ConditionJSON, &r.Enabled, &r.CreatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}
