package storage

import "DeepPacketAI/internal/domain"

func (s *SQLiteStore) StoreRTPLegs(jobID int64, calls []domain.Call) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO rtp_legs (
			job_id,
			call_id,
			src_ip, src_port,
			dst_ip, dst_port,
			ssrc,
			packet_count,
			jitter_ms,
			max_seq_gap,
			start_time,
			end_time
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, call := range calls {
		for _, leg := range call.RTPLegs {

			_, err := stmt.Exec(
				jobID,
				call.CallID,

				leg["src_ip"],
				leg["src_port"],
				leg["dst_ip"],
				leg["dst_port"],

				leg["ssrc"],
				leg["packet_count"],
				leg["jitter_ms"],
				leg["max_seq_gap"],

				leg["start_time"],
				leg["end_time"],
			)
			if err != nil {
				return err
			}
		}
	}

	return tx.Commit()
}
