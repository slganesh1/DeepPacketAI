package postgres

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/storage"
)

func (s *PostgresStore) StorePackets(jobID int64, sessionID string, packets []*domain.Packet) error {
	if len(packets) == 0 {
		return nil
	}

	ctx, cancel := writeCtx()
	defer cancel()

	rows := make([][]any, 0, len(packets))
	for _, pkt := range packets {
		var metaJSON, errJSON []byte
		if pkt.Metadata != nil {
			metaJSON, _ = json.Marshal(pkt.Metadata)
		}
		if len(pkt.Errors) > 0 {
			errJSON, _ = json.Marshal(pkt.Errors)
		}

		rows = append(rows, []any{
			jobID, sessionID, pkt.FrameNumber,
			pkt.Timestamp,
			pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort,
			pkt.Protocol, pkt.AppProtocol, pkt.Length, pkt.Summary,
			metaJSON, errJSON,
		})
	}

	_, err := s.pool.CopyFrom(ctx,
		pgx.Identifier{"packets"},
		[]string{"job_id", "session_id", "frame_number", "timestamp", "src_ip", "dst_ip",
			"src_port", "dst_port", "protocol", "app_protocol", "length", "summary",
			"metadata_json", "errors_json"},
		pgx.CopyFromRows(rows),
	)
	return err
}

func (s *PostgresStore) StorePacketsBatch(packets []storage.PacketRecord) error {
	if len(packets) == 0 {
		return nil
	}

	ctx, cancel := writeCtx()
	defer cancel()

	rows := make([][]any, 0, len(packets))
	for _, p := range packets {
		ts, err := time.Parse(time.RFC3339Nano, p.Timestamp)
		if err != nil {
			ts = time.Now()
		}
		rows = append(rows, []any{
			p.JobID, p.SessionID, p.FrameNumber,
			ts,
			p.SrcIP, p.DstIP, p.SrcPort, p.DstPort,
			p.Protocol, p.AppProtocol, p.Length, p.Summary,
			[]byte(p.MetadataJSON), []byte(p.ErrorsJSON),
		})
	}

	_, err := s.pool.CopyFrom(ctx,
		pgx.Identifier{"packets"},
		[]string{"job_id", "session_id", "frame_number", "timestamp", "src_ip", "dst_ip",
			"src_port", "dst_port", "protocol", "app_protocol", "length", "summary",
			"metadata_json", "errors_json"},
		pgx.CopyFromRows(rows),
	)
	return err
}

func (s *PostgresStore) QueryPackets(filters map[string]string, limit, offset int) ([]storage.PacketRecord, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	query := "SELECT id, job_id, session_id, frame_number, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, app_protocol, length, summary, metadata_json, errors_json FROM packets"

	var conditions []string
	var args []any
	argIdx := 1

	if v, ok := filters["job_id"]; ok {
		conditions = append(conditions, fmt.Sprintf("job_id = $%d", argIdx))
		args = append(args, v)
		argIdx++
	}
	if v, ok := filters["protocol"]; ok {
		conditions = append(conditions, fmt.Sprintf("app_protocol = $%d", argIdx))
		args = append(args, v)
		argIdx++
	}
	if v, ok := filters["src_ip"]; ok {
		conditions = append(conditions, fmt.Sprintf("src_ip = $%d", argIdx))
		args = append(args, v)
		argIdx++
	}
	if v, ok := filters["dst_ip"]; ok {
		conditions = append(conditions, fmt.Sprintf("dst_ip = $%d", argIdx))
		args = append(args, v)
		argIdx++
	}
	if v, ok := filters["session_id"]; ok {
		conditions = append(conditions, fmt.Sprintf("session_id = $%d", argIdx))
		args = append(args, v)
		argIdx++
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	query += " ORDER BY frame_number ASC"

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, limit)
		argIdx++
	}
	if offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, offset)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var packets []storage.PacketRecord
	for rows.Next() {
		var p storage.PacketRecord
		var sessionID *string
		var ts time.Time
		var metaJSON, errJSON []byte

		if err := rows.Scan(&p.ID, &p.JobID, &sessionID, &p.FrameNumber, &ts,
			&p.SrcIP, &p.DstIP, &p.SrcPort, &p.DstPort,
			&p.Protocol, &p.AppProtocol, &p.Length, &p.Summary,
			&metaJSON, &errJSON); err != nil {
			return nil, err
		}
		p.Timestamp = ts.Format(time.RFC3339Nano)
		if sessionID != nil {
			p.SessionID = *sessionID
		}
		if len(metaJSON) > 0 {
			p.MetadataJSON = string(metaJSON)
		}
		if len(errJSON) > 0 {
			p.ErrorsJSON = string(errJSON)
		}
		packets = append(packets, p)
	}

	return packets, nil
}

func (s *PostgresStore) GetPacketByID(id int64) (*storage.PacketRecord, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	var p storage.PacketRecord
	var sessionID *string
	var ts time.Time
	var metaJSON, errJSON []byte

	err := s.pool.QueryRow(ctx,
		"SELECT id, job_id, session_id, frame_number, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, app_protocol, length, summary, metadata_json, errors_json FROM packets WHERE id = $1",
		id,
	).Scan(&p.ID, &p.JobID, &sessionID, &p.FrameNumber, &ts,
		&p.SrcIP, &p.DstIP, &p.SrcPort, &p.DstPort,
		&p.Protocol, &p.AppProtocol, &p.Length, &p.Summary,
		&metaJSON, &errJSON)
	if err != nil {
		return nil, err
	}
	p.Timestamp = ts.Format(time.RFC3339Nano)
	if sessionID != nil {
		p.SessionID = *sessionID
	}
	if len(metaJSON) > 0 {
		p.MetadataJSON = string(metaJSON)
	}
	if len(errJSON) > 0 {
		p.ErrorsJSON = string(errJSON)
	}
	return &p, nil
}

func (s *PostgresStore) GetPacketCount(filters map[string]string) (int64, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	query := "SELECT COUNT(*) FROM packets"
	var conditions []string
	var args []any
	argIdx := 1

	if v, ok := filters["job_id"]; ok {
		conditions = append(conditions, fmt.Sprintf("job_id = $%d", argIdx))
		args = append(args, v)
		argIdx++
	}
	if v, ok := filters["protocol"]; ok {
		conditions = append(conditions, fmt.Sprintf("app_protocol = $%d", argIdx))
		args = append(args, v)
		argIdx++
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	_ = argIdx
	var count int64
	err := s.pool.QueryRow(ctx, query, args...).Scan(&count)
	return count, err
}
