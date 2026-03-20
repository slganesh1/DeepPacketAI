package storage

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"DeepPacketAI/internal/domain"
)

// PacketRecord represents a stored packet.
type PacketRecord struct {
	ID           int64  `json:"id"`
	JobID        int64  `json:"job_id"`
	SessionID    string `json:"session_id"`
	FrameNumber  int64  `json:"frame_number"`
	Timestamp    string `json:"timestamp"`
	SrcIP        string `json:"src_ip"`
	DstIP        string `json:"dst_ip"`
	SrcPort      int    `json:"src_port"`
	DstPort      int    `json:"dst_port"`
	Protocol     string `json:"protocol"`
	AppProtocol  string `json:"app_protocol"`
	Length       int    `json:"length"`
	Summary      string `json:"summary"`
	MetadataJSON string `json:"metadata_json,omitempty"`
	ErrorsJSON   string `json:"errors_json,omitempty"`
	RawPacket    []byte `json:"-"` // raw frame bytes; not sent in list responses
}

// StorePacketsBatch stores packets in a batch transaction.
func (s *SQLiteStore) StorePacketsBatch(packets []PacketRecord) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO packets (job_id, session_id, frame_number, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, app_protocol, length, summary, metadata_json, errors_json, raw_packet)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, p := range packets {
		_, err := stmt.Exec(p.JobID, p.SessionID, p.FrameNumber, p.Timestamp, p.SrcIP, p.DstIP, p.SrcPort, p.DstPort, p.Protocol, p.AppProtocol, p.Length, p.Summary, p.MetadataJSON, p.ErrorsJSON, p.RawPacket)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// QueryPackets returns packets with optional filtering.
func (s *SQLiteStore) QueryPackets(filters map[string]string, limit, offset int) ([]PacketRecord, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	query := "SELECT id, job_id, session_id, frame_number, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, app_protocol, length, summary, metadata_json, errors_json, raw_packet FROM packets"

	var conditions []string
	var args []any

	if v, ok := filters["job_id"]; ok {
		conditions = append(conditions, "job_id = ?")
		args = append(args, v)
	}
	if v, ok := filters["protocol"]; ok {
		conditions = append(conditions, "app_protocol = ?")
		args = append(args, v)
	}
	if v, ok := filters["src_ip"]; ok {
		conditions = append(conditions, "src_ip = ?")
		args = append(args, v)
	}
	if v, ok := filters["dst_ip"]; ok {
		conditions = append(conditions, "dst_ip = ?")
		args = append(args, v)
	}
	if v, ok := filters["session_id"]; ok {
		conditions = append(conditions, "session_id = ?")
		args = append(args, v)
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	query += " ORDER BY frame_number ASC"

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	if offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var packets []PacketRecord
	for rows.Next() {
		var p PacketRecord
		var sessionID, metaJSON, errJSON *string
		if err := rows.Scan(&p.ID, &p.JobID, &sessionID, &p.FrameNumber, &p.Timestamp, &p.SrcIP, &p.DstIP, &p.SrcPort, &p.DstPort, &p.Protocol, &p.AppProtocol, &p.Length, &p.Summary, &metaJSON, &errJSON, &p.RawPacket); err != nil {
			return nil, err
		}
		if sessionID != nil {
			p.SessionID = *sessionID
		}
		if metaJSON != nil {
			p.MetadataJSON = *metaJSON
		}
		if errJSON != nil {
			p.ErrorsJSON = *errJSON
		}
		packets = append(packets, p)
	}

	return packets, nil
}

// GetPacketByID returns a single packet with full metadata and raw bytes.
func (s *SQLiteStore) GetPacketByID(id int64) (*PacketRecord, error) {
	ctx, cancel := queryCtx()
	defer cancel()
	var p PacketRecord
	var sessionID, metaJSON, errJSON *string
	err := s.db.QueryRowContext(ctx,
		"SELECT id, job_id, session_id, frame_number, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, app_protocol, length, summary, metadata_json, errors_json, raw_packet FROM packets WHERE id = ?",
		id,
	).Scan(&p.ID, &p.JobID, &sessionID, &p.FrameNumber, &p.Timestamp, &p.SrcIP, &p.DstIP, &p.SrcPort, &p.DstPort, &p.Protocol, &p.AppProtocol, &p.Length, &p.Summary, &metaJSON, &errJSON, &p.RawPacket)
	if err != nil {
		return nil, err
	}
	if sessionID != nil {
		p.SessionID = *sessionID
	}
	if metaJSON != nil {
		p.MetadataJSON = *metaJSON
	}
	if errJSON != nil {
		p.ErrorsJSON = *errJSON
	}
	return &p, nil
}

// GetPacketCount returns the total number of packets matching filters.
func (s *SQLiteStore) GetPacketCount(filters map[string]string) (int64, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	query := "SELECT COUNT(*) FROM packets"
	var conditions []string
	var args []any

	if v, ok := filters["job_id"]; ok {
		conditions = append(conditions, "job_id = ?")
		args = append(args, v)
	}
	if v, ok := filters["protocol"]; ok {
		conditions = append(conditions, "app_protocol = ?")
		args = append(args, v)
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	var count int64
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

// StorePackets converts domain packets and stores them in batch.
func (s *SQLiteStore) StorePackets(jobID int64, sessionID string, packets []*domain.Packet) error {
	if len(packets) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO packets (job_id, session_id, frame_number, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, app_protocol, length, summary, metadata_json, errors_json, raw_packet)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, pkt := range packets {
		var metaJSON, errJSON string
		if pkt.Metadata != nil {
			b, _ := json.Marshal(pkt.Metadata)
			metaJSON = string(b)
		}
		if len(pkt.Errors) > 0 {
			b, _ := json.Marshal(pkt.Errors)
			errJSON = string(b)
		}

		_, err := stmt.Exec(
			jobID, sessionID, pkt.FrameNumber,
			pkt.Timestamp.Format(time.RFC3339Nano),
			pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort,
			pkt.Protocol, pkt.AppProtocol, pkt.Length, pkt.Summary,
			metaJSON, errJSON, pkt.RawPacket,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// helper to marshal any to JSON string
func ToJSON(v any) string {
	data, _ := json.Marshal(v)
	return string(data)
}
