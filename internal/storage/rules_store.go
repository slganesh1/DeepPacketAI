package storage

// UserDetectionRule is a user-defined detection rule stored in the database.
// The ConditionJSON field holds a serialised RuleCondition (see internal/detection/user_rules.go).
type UserDetectionRule struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	Protocol      string `json:"protocol"`    // "ANY", "SIP", "DNS", "RTP", …
	Severity      string `json:"severity"`    // "info" | "warning" | "error" | "critical"
	ConditionJSON string `json:"condition_json"`
	Enabled       bool   `json:"enabled"`
	CreatedAt     string `json:"created_at"`
}

// CreateUserRule inserts a new user detection rule and returns its ID.
func (s *SQLiteStore) CreateUserRule(r UserDetectionRule) (int64, error) {
	ctx, cancel := writeCtx()
	defer cancel()

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO user_detection_rules (name, description, protocol, severity, condition_json, enabled)
		VALUES (?, ?, ?, ?, ?, ?)`,
		r.Name, r.Description, r.Protocol, r.Severity, r.ConditionJSON, boolInt(r.Enabled),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateUserRule overwrites all editable fields of a rule.
func (s *SQLiteStore) UpdateUserRule(r UserDetectionRule) error {
	ctx, cancel := writeCtx()
	defer cancel()

	_, err := s.db.ExecContext(ctx, `
		UPDATE user_detection_rules
		SET name=?, description=?, protocol=?, severity=?, condition_json=?, enabled=?
		WHERE id=?`,
		r.Name, r.Description, r.Protocol, r.Severity, r.ConditionJSON, boolInt(r.Enabled), r.ID,
	)
	return err
}

// DeleteUserRule removes a rule by ID.
func (s *SQLiteStore) DeleteUserRule(id int64) error {
	ctx, cancel := writeCtx()
	defer cancel()
	_, err := s.db.ExecContext(ctx, `DELETE FROM user_detection_rules WHERE id=?`, id)
	return err
}

// GetUserRule returns a single rule by ID.
func (s *SQLiteStore) GetUserRule(id int64) (*UserDetectionRule, error) {
	ctx, cancel := queryCtx()
	defer cancel()
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, description, protocol, severity, condition_json, enabled, created_at
		FROM user_detection_rules WHERE id=?`, id)
	return scanUserRule(row)
}

// ListUserRules returns all user rules ordered by id.
func (s *SQLiteStore) ListUserRules() ([]UserDetectionRule, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, description, protocol, severity, condition_json, enabled, created_at
		FROM user_detection_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []UserDetectionRule
	for rows.Next() {
		r, err := scanUserRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, *r)
	}
	return rules, nil
}

func scanUserRule(s scanner) (*UserDetectionRule, error) {
	var r UserDetectionRule
	var enabled int
	if err := s.Scan(&r.ID, &r.Name, &r.Description, &r.Protocol, &r.Severity,
		&r.ConditionJSON, &enabled, &r.CreatedAt); err != nil {
		return nil, err
	}
	r.Enabled = enabled != 0
	return &r, nil
}
