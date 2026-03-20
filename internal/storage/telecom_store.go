package storage

import (
	"encoding/json"
	"fmt"
	"log"

	"DeepPacketAI/internal/domain"
)

// StoreTelecomSessions persists a slice of TelecomSession records for a job.
func (s *SQLiteStore) StoreTelecomSessions(jobID int64, sessions []domain.TelecomSession) error {
	if len(sessions) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO telecom_sessions (
			job_id, session_id,
			imsi, msisdn, apn, ue_ip,
			sip_call_id, sip_from, sip_to,
			start_time, end_time,
			mos, quality,
			has_ngap, has_gtpc, has_pfcp, has_gtpu, has_sip, has_rtp, has_diameter, is_complete,
			layers_json, events_json,
			rat_type, serving_network, location, pdn_type, ue_state,
			teids_json, bearer_teids_json, lifecycle_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, sess := range sessions {
		layersJSON, err := marshalLayers(sess)
		if err != nil {
			log.Printf("telecom_store: marshal layers for %s: %v", sess.SessionID, err)
			layersJSON = []byte("{}")
		}

		eventsJSON, err := json.Marshal(sess.Events)
		if err != nil {
			log.Printf("telecom_store: marshal events for %s: %v", sess.SessionID, err)
			eventsJSON = []byte("[]")
		}

		teidJSON, _ := json.Marshal(sess.TEIDs)
		bearerTEIDJSON, _ := json.Marshal(sess.BearerTEIDs)
		lifecycleJSON, _ := json.Marshal(sess.Lifecycle)

		var startStr, endStr string
		if !sess.StartTime.IsZero() {
			startStr = sess.StartTime.UTC().Format("2006-01-02T15:04:05.999Z")
		}
		if !sess.EndTime.IsZero() {
			endStr = sess.EndTime.UTC().Format("2006-01-02T15:04:05.999Z")
		}

		_, err = stmt.Exec(
			jobID, sess.SessionID,
			nullStr(sess.IMSI), nullStr(sess.MSISDN), nullStr(sess.APN), nullStr(sess.UEIP),
			nullStr(sess.SIPCallID), nullStr(sess.SIPFrom), nullStr(sess.SIPTo),
			nullStr(startStr), nullStr(endStr),
			sess.MOS, nullStr(sess.Quality),
			sess.HasNGAP, sess.HasGTPC, sess.HasPFCP, sess.HasGTPU, sess.HasSIP, sess.HasRTP, sess.HasDiameter, sess.IsComplete,
			string(layersJSON), string(eventsJSON),
			nullStr(sess.RATType), nullStr(sess.ServingNetwork), nullStr(sess.Location), nullStr(sess.PDNType), nullStr(string(sess.UEState)),
			string(teidJSON), string(bearerTEIDJSON), string(lifecycleJSON),
		)
		if err != nil {
			return fmt.Errorf("insert telecom session %s: %w", sess.SessionID, err)
		}
	}

	return tx.Commit()
}

const selectTelecomCols = `
	SELECT session_id, imsi, msisdn, apn, ue_ip,
	       sip_call_id, sip_from, sip_to,
	       start_time, end_time, mos, quality,
	       has_ngap, has_gtpc, has_pfcp, has_gtpu, has_sip, has_rtp, has_diameter, is_complete,
	       layers_json, events_json,
	       rat_type, serving_network, location, pdn_type, ue_state,
	       teids_json, bearer_teids_json, lifecycle_json
`

// ListTelecomSessions returns all telecom sessions for a job.
func (s *SQLiteStore) ListTelecomSessions(jobID int64) ([]domain.TelecomSession, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		selectTelecomCols+`FROM telecom_sessions WHERE job_id = ? ORDER BY start_time ASC`,
		jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanTelecomSessions(rows)
}

// GetTelecomSession returns one telecom session by its session_id under a job.
func (s *SQLiteStore) GetTelecomSession(jobID int64, sessionID string) (*domain.TelecomSession, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		selectTelecomCols+`FROM telecom_sessions WHERE job_id = ? AND session_id = ? LIMIT 1`,
		jobID, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sessions, err := scanTelecomSessions(rows)
	if err != nil {
		return nil, err
	}
	if len(sessions) == 0 {
		return nil, nil
	}
	return &sessions[0], nil
}

// ListAllTelecomSessions returns telecom sessions across all jobs (latest job wins on dup session_id).
func (s *SQLiteStore) ListAllTelecomSessions() ([]domain.TelecomSession, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		selectTelecomCols+`FROM telecom_sessions ORDER BY job_id DESC, start_time ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanTelecomSessions(rows)
}

// ---- helpers ----

func nullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
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

func scanTelecomSessions(rows interface {
	Next() bool
	Scan(...interface{}) error
	Err() error
}) ([]domain.TelecomSession, error) {
	var sessions []domain.TelecomSession

	for rows.Next() {
		var (
			sess                                    domain.TelecomSession
			imsi, msisdn, apn, ueip                *string
			sipCallID, sipFrom, sipTo               *string
			startStr, endStr                        *string
			mos                                     *float64
			quality                                 *string
			layersJSON, eventsJSON                  *string
			ratType, servingNetwork, location       *string
			pdnType, ueState                        *string
			teidJSON, bearerTEIDJSON, lifecycleJSON *string
		)

		err := rows.Scan(
			&sess.SessionID, &imsi, &msisdn, &apn, &ueip,
			&sipCallID, &sipFrom, &sipTo,
			&startStr, &endStr,
			&mos, &quality,
			&sess.HasNGAP, &sess.HasGTPC, &sess.HasPFCP, &sess.HasGTPU, &sess.HasSIP, &sess.HasRTP, &sess.HasDiameter, &sess.IsComplete,
			&layersJSON, &eventsJSON,
			&ratType, &servingNetwork, &location, &pdnType, &ueState,
			&teidJSON, &bearerTEIDJSON, &lifecycleJSON,
		)
		if err != nil {
			return nil, err
		}

		if imsi != nil {
			sess.IMSI = *imsi
		}
		if msisdn != nil {
			sess.MSISDN = *msisdn
		}
		if apn != nil {
			sess.APN = *apn
		}
		if ueip != nil {
			sess.UEIP = *ueip
		}
		if sipCallID != nil {
			sess.SIPCallID = *sipCallID
		}
		if sipFrom != nil {
			sess.SIPFrom = *sipFrom
		}
		if sipTo != nil {
			sess.SIPTo = *sipTo
		}
		if mos != nil {
			sess.MOS = *mos
		}
		if quality != nil {
			sess.Quality = *quality
		}
		if ratType != nil {
			sess.RATType = *ratType
		}
		if servingNetwork != nil {
			sess.ServingNetwork = *servingNetwork
		}
		if location != nil {
			sess.Location = *location
		}
		if pdnType != nil {
			sess.PDNType = *pdnType
		}
		if ueState != nil {
			sess.UEState = domain.UEState(*ueState)
		}

		if startStr != nil {
			_ = json.Unmarshal([]byte(`"`+*startStr+`"`), &sess.StartTime)
		}
		if endStr != nil {
			_ = json.Unmarshal([]byte(`"`+*endStr+`"`), &sess.EndTime)
		}

		if eventsJSON != nil && *eventsJSON != "" && *eventsJSON != "null" {
			_ = json.Unmarshal([]byte(*eventsJSON), &sess.Events)
		}
		if teidJSON != nil && *teidJSON != "" && *teidJSON != "null" {
			_ = json.Unmarshal([]byte(*teidJSON), &sess.TEIDs)
		}
		if bearerTEIDJSON != nil && *bearerTEIDJSON != "" && *bearerTEIDJSON != "null" {
			_ = json.Unmarshal([]byte(*bearerTEIDJSON), &sess.BearerTEIDs)
		}
		if lifecycleJSON != nil && *lifecycleJSON != "" && *lifecycleJSON != "null" {
			_ = json.Unmarshal([]byte(*lifecycleJSON), &sess.Lifecycle)
		}

		sessions = append(sessions, sess)
	}

	return sessions, rows.Err()
}
