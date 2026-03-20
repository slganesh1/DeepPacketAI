package postgres

import (
	"encoding/json"
	"time"

	"DeepPacketAI/internal/domain"
)

func (s *PostgresStore) StoreFlows(jobID int64, flows []domain.Flow) error {
	if len(flows) == 0 {
		return nil
	}

	ctx, cancel := writeCtx()
	defer cancel()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	for _, f := range flows {
		var metricsJSON []byte
		if f.Metrics != nil {
			metricsJSON, _ = json.Marshal(f.Metrics)
		}

		_, err := tx.Exec(ctx, `
			INSERT INTO flows (job_id, flow_id, type, src_ip, dst_ip, src_port, dst_port, start_time, end_time, metrics)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		`, jobID, f.FlowID, string(f.Type), f.SrcIP, f.DstIP, f.SrcPort, f.DstPort, f.StartTime, f.EndTime, metricsJSON)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (s *PostgresStore) GetAllFlows() ([]domain.Flow, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	rows, err := s.pool.Query(ctx, `
		SELECT flow_id, type, src_ip, dst_ip, src_port, dst_port, start_time, end_time, metrics
		FROM flows ORDER BY start_time ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanPGFlows(rows)
}

func (s *PostgresStore) GetFlowsByJob(jobID int64) ([]domain.Flow, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	rows, err := s.pool.Query(ctx, `
		SELECT flow_id, type, src_ip, dst_ip, src_port, dst_port, start_time, end_time, metrics
		FROM flows WHERE job_id = $1 ORDER BY start_time ASC
	`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanPGFlows(rows)
}

func (s *PostgresStore) GetSIPFlowMetrics(callID string) (map[string]any, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	var metricsJSON []byte
	err := s.pool.QueryRow(ctx,
		`SELECT metrics FROM flows WHERE flow_id = $1 AND type = 'SIP' LIMIT 1`,
		callID,
	).Scan(&metricsJSON)
	if err != nil {
		return nil, err
	}

	var m map[string]any
	if err := json.Unmarshal(metricsJSON, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func scanPGFlows(rows pgRows) ([]domain.Flow, error) {
	var flows []domain.Flow

	for rows.Next() {
		var f domain.Flow
		var flowType string
		var startTime, endTime time.Time
		var srcPort, dstPort int
		var metricsJSON []byte

		if err := rows.Scan(&f.FlowID, &flowType, &f.SrcIP, &f.DstIP, &srcPort, &dstPort, &startTime, &endTime, &metricsJSON); err != nil {
			continue
		}

		f.Type = domain.FlowType(flowType)
		f.SrcPort = uint16(srcPort)
		f.DstPort = uint16(dstPort)
		f.StartTime = startTime
		f.EndTime = endTime

		if len(metricsJSON) > 0 {
			var m map[string]any
			if err := json.Unmarshal(metricsJSON, &m); err == nil {
				f.Metrics = m
			}
		}

		flows = append(flows, f)
	}

	return flows, nil
}
