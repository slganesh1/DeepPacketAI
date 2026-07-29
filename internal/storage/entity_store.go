package storage

import (
	//"database/sql"
   "time"
	"DeepPacketAI/internal/web/api"
)

func (s *SQLiteStore) ListCallEntities(
	jobID *int64,
	quality *string,
	rootCause *string,
	limit int,
	offset int,
) ([]api.EntityItem, int, error) {

	where := "WHERE 1=1"
	args := []any{}

	if jobID != nil {
		where += " AND job_id = ?"
		args = append(args, *jobID)
	}
	if quality != nil {
		where += " AND quality = ?"
		args = append(args, *quality)
	}
	if rootCause != nil {
		where += " AND root_cause = ?"
		args = append(args, *rootCause)
	}

	ctx, cancel := queryCtx()
	defer cancel()

	// total count
	var total int
	countQuery := "SELECT COUNT(*) FROM calls " + where
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

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
	` + where + `
		ORDER BY start_time DESC
		LIMIT ? OFFSET ?
	`

	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []api.EntityItem

	for rows.Next() {
		var (
			callID     string
			startTime  string
			endTime    string
			mos        float64
			qualityVal string
			root       string
			conf       float64
		)

		if err := rows.Scan(
			&callID,
			&startTime,
			&endTime,
			&mos,
			&qualityVal,
			&root,
			&conf,
		); err != nil {
			return nil, 0, err
		}

		items = append(items, api.EntityItem{
			EntityID:   "call:" + callID,
			EntityType: "call",
			Protocols:  []string{"sip", "rtp"},
			StartTime:  mustParseTime(startTime),
			EndTime:    mustParseTime(endTime),
			Summary: api.EntitySummary{
				MOS:        mos,
				Quality:    qualityVal,
				RootCause:  root,
				Confidence: conf,
			},
		})
	}

	return items, total, nil
}



func mustParseTime(s string) time.Time {
	return parseSQLiteTime(s)
}
