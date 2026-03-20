package storage

// CaptureSessionRecord represents a stored capture session.
type CaptureSessionRecord struct {
	ID            string `json:"id"`
	InterfaceName string `json:"interface_name"`
	BPFFilter     string `json:"bpf_filter"`
	Status        string `json:"status"`
	StartedAt     string `json:"started_at"`
	StoppedAt     string `json:"stopped_at,omitempty"`
	PacketCount   int64  `json:"packet_count"`
	ByteCount     int64  `json:"byte_count"`
}

// StoreCaptureSession stores a capture session record.
func (s *SQLiteStore) StoreCaptureSession(rec CaptureSessionRecord) error {
	ctx, cancel := writeCtx()
	defer cancel()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO capture_sessions (id, interface_name, bpf_filter, status, started_at, stopped_at, packet_count, byte_count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			status=excluded.status,
			stopped_at=excluded.stopped_at,
			packet_count=excluded.packet_count,
			byte_count=excluded.byte_count
	`, rec.ID, rec.InterfaceName, rec.BPFFilter, rec.Status, rec.StartedAt, rec.StoppedAt, rec.PacketCount, rec.ByteCount)
	return err
}

// QueryCaptureSessions returns all capture sessions.
func (s *SQLiteStore) QueryCaptureSessions() ([]CaptureSessionRecord, error) {
	ctx, cancel := queryCtx()
	defer cancel()
	rows, err := s.db.QueryContext(ctx, "SELECT id, interface_name, bpf_filter, status, started_at, stopped_at, packet_count, byte_count FROM capture_sessions ORDER BY started_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []CaptureSessionRecord
	for rows.Next() {
		var r CaptureSessionRecord
		var stoppedAt *string
		if err := rows.Scan(&r.ID, &r.InterfaceName, &r.BPFFilter, &r.Status, &r.StartedAt, &stoppedAt, &r.PacketCount, &r.ByteCount); err != nil {
			return nil, err
		}
		if stoppedAt != nil {
			r.StoppedAt = *stoppedAt
		}
		sessions = append(sessions, r)
	}

	return sessions, nil
}
