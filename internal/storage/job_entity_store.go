package storage

import (
	"DeepPacketAI/internal/web/api"
)

func (s *SQLiteStore) ListEntitiesForJob(
	jobID int64,
	limit int,
	quality string,
) ([]api.EntityItem, error) {

	query := `
	SELECT
		call_id,
		start_time,
		end_time,
		mos,
		quality,
		root_cause,
		confidence
	FROM calls
	WHERE job_id = ?
	`
	args := []any{jobID}

	if quality != "" {
		query += " AND quality = ?"
		args = append(args, quality)
	}

	query += " ORDER BY start_time"

	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	ctx, cancel := queryCtx()
	defer cancel()
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entities := []api.EntityItem{}

	for rows.Next() {
		var (
			callID     string
			startStr   string
			endStr     string
			mos        float64
			qual       string
			rootCause  string
			confidence float64
		)

		if err := rows.Scan(
			&callID,
			&startStr,
			&endStr,
			&mos,
			&qual,
			&rootCause,
			&confidence,
		); err != nil {
			return nil, err
		}

		startTime := parseSQLiteTime(startStr)
		endTime := parseSQLiteTime(endStr)


		entities = append(entities, api.EntityItem{
			EntityID:   "call:" + callID,
			EntityType: "call",
			Protocols:  []string{"sip", "rtp"},
			StartTime:  startTime,
			EndTime:    endTime,
			Summary: api.EntitySummary{
				MOS:        mos,
				Quality:    qual,
				RootCause:  rootCause,
				Confidence: confidence,
			},
		})
	}

	return entities, nil
}
