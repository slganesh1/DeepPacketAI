package postgres

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"DeepPacketAI/internal/domain"
)

func (s *PostgresStore) StoreTelecomSessions(jobID int64, sessions []domain.TelecomSession) error {
	if len(sessions) == 0 {
		return nil
	}

	ctx, cancel := writeCtx()
	defer cancel()

	for _, sess := range sessions {
		layersJSON, err := marshalLayers(sess)
		if err != nil {
			log.Printf("postgres telecom_store: marshal layers for %s: %v", sess.SessionID, err)
			layersJSON = []byte("{}")
		}

		eventsJSON, err := json.Marshal(sess.Events)
		if err != nil {
			log.Printf("postgres telecom_store: marshal events for %s: %v", sess.SessionID, err)
			eventsJSON = []byte("[]")
		}

		var startTime, endTime *time.Time
		if !sess.StartTime.IsZero() {
			t := sess.StartTime
			startTime = &t
		}
		if !sess.EndTime.IsZero() {
			t := sess.EndTime
			endTime = &t
		}

		_, err = s.pool.Exec(ctx, `
			INSERT INTO telecom_sessions (
				job_id, session_id,
				imsi, msisdn, apn, ue_ip,
				sip_call_id, sip_from, sip_to,
				start_time, end_time,
				mos, quality,
				has_ngap, has_gtpc, has_pfcp, has_gtpu, has_sip, has_rtp, has_diameter, is_complete,
				layers, events
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)
			ON CONFLICT (job_id, session_id) DO UPDATE SET
				imsi=EXCLUDED.imsi, msisdn=EXCLUDED.msisdn, apn=EXCLUDED.apn, ue_ip=EXCLUDED.ue_ip,
				sip_call_id=EXCLUDED.sip_call_id, sip_from=EXCLUDED.sip_from, sip_to=EXCLUDED.sip_to,
				start_time=EXCLUDED.start_time, end_time=EXCLUDED.end_time,
				mos=EXCLUDED.mos, quality=EXCLUDED.quality,
				has_ngap=EXCLUDED.has_ngap, has_gtpc=EXCLUDED.has_gtpc, has_pfcp=EXCLUDED.has_pfcp,
				has_gtpu=EXCLUDED.has_gtpu, has_sip=EXCLUDED.has_sip, has_rtp=EXCLUDED.has_rtp,
				has_diameter=EXCLUDED.has_diameter, is_complete=EXCLUDED.is_complete,
				layers=EXCLUDED.layers, events=EXCLUDED.events
		`,
			jobID, sess.SessionID,
			nullStrPG(sess.IMSI), nullStrPG(sess.MSISDN), nullStrPG(sess.APN), nullStrPG(sess.UEIP),
			nullStrPG(sess.SIPCallID), nullStrPG(sess.SIPFrom), nullStrPG(sess.SIPTo),
			startTime, endTime,
			sess.MOS, nullStrPG(sess.Quality),
			sess.HasNGAP, sess.HasGTPC, sess.HasPFCP, sess.HasGTPU, sess.HasSIP, sess.HasRTP, sess.HasDiameter, sess.IsComplete,
			layersJSON, eventsJSON,
		)
		if err != nil {
			return fmt.Errorf("insert telecom session %s: %w", sess.SessionID, err)
		}
	}
	return nil
}

func (s *PostgresStore) ListTelecomSessions(jobID int64) ([]domain.TelecomSession, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	rows, err := s.pool.Query(ctx, `
		SELECT session_id, imsi, msisdn, apn, ue_ip,
		       sip_call_id, sip_from, sip_to,
		       start_time, end_time, mos, quality,
		       has_ngap, has_gtpc, has_pfcp, has_gtpu, has_sip, has_rtp, has_diameter, is_complete,
		       layers, events
		FROM telecom_sessions WHERE job_id = $1
		ORDER BY start_time ASC
	`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanPGTelecomSessions(rows)
}

func (s *PostgresStore) GetTelecomSession(jobID int64, sessionID string) (*domain.TelecomSession, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	rows, err := s.pool.Query(ctx, `
		SELECT session_id, imsi, msisdn, apn, ue_ip,
		       sip_call_id, sip_from, sip_to,
		       start_time, end_time, mos, quality,
		       has_ngap, has_gtpc, has_pfcp, has_gtpu, has_sip, has_rtp, has_diameter, is_complete,
		       layers, events
		FROM telecom_sessions WHERE job_id = $1 AND session_id = $2
		LIMIT 1
	`, jobID, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sessions, err := scanPGTelecomSessions(rows)
	if err != nil {
		return nil, err
	}
	if len(sessions) == 0 {
		return nil, nil
	}
	return &sessions[0], nil
}

func (s *PostgresStore) ListAllTelecomSessions() ([]domain.TelecomSession, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	rows, err := s.pool.Query(ctx, `
		SELECT session_id, imsi, msisdn, apn, ue_ip,
		       sip_call_id, sip_from, sip_to,
		       start_time, end_time, mos, quality,
		       has_ngap, has_gtpc, has_pfcp, has_gtpu, has_sip, has_rtp, has_diameter, is_complete,
		       layers, events
		FROM telecom_sessions
		ORDER BY job_id DESC, start_time ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanPGTelecomSessions(rows)
}

// pgRows is a minimal interface for rows from pgxpool.
type pgRows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

func scanPGTelecomSessions(rows pgRows) ([]domain.TelecomSession, error) {
	var sessions []domain.TelecomSession

	for rows.Next() {
		var (
			sess      domain.TelecomSession
			startTime *time.Time
			endTime   *time.Time
			layersRaw []byte
			eventsRaw []byte
		)

		err := rows.Scan(
			&sess.SessionID, &sess.IMSI, &sess.MSISDN, &sess.APN, &sess.UEIP,
			&sess.SIPCallID, &sess.SIPFrom, &sess.SIPTo,
			&startTime, &endTime,
			&sess.MOS, &sess.Quality,
			&sess.HasNGAP, &sess.HasGTPC, &sess.HasPFCP, &sess.HasGTPU, &sess.HasSIP, &sess.HasRTP, &sess.HasDiameter, &sess.IsComplete,
			&layersRaw, &eventsRaw,
		)
		if err != nil {
			return nil, err
		}

		if startTime != nil {
			sess.StartTime = *startTime
		}
		if endTime != nil {
			sess.EndTime = *endTime
		}

		if len(eventsRaw) > 0 {
			_ = json.Unmarshal(eventsRaw, &sess.Events)
		}

		sessions = append(sessions, sess)
	}

	return sessions, rows.Err()
}

func marshalLayers(sess domain.TelecomSession) ([]byte, error) {
	layers := map[string]interface{}{
		"ngap":        sess.NGAP,
		"gtp_control": sess.GTPControl,
		"pfcp":        sess.PFCP,
		"gtp_user":    sess.GTPUser,
		"sip":         sess.SIP,
		"rtp":         sess.RTP,
		"diameter":    sess.Diameter,
		"teids":       sess.TEIDs,
		"seids":       sess.SEIDs,
	}
	return json.Marshal(layers)
}

func nullStrPG(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
