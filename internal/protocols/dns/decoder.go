package dns

import (
	"encoding/binary"
	"fmt"
	"strings"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/dpi"
	"DeepPacketAI/internal/protocols"
)

// Decoder decodes DNS query/response packets.
type Decoder struct {
	transactions map[uint16]*Transaction // keyed by txID
	completed    []*Transaction
}

func NewDecoder() *Decoder {
	return &Decoder{
		transactions: make(map[uint16]*Transaction),
	}
}

func (d *Decoder) Name() string { return "dns" }

func (d *Decoder) HandlePacket(pkt *domain.Packet) {
	if len(pkt.Payload) < 12 {
		return
	}
	if !isDNSPort(pkt.SrcPort, pkt.DstPort) && !dpi.IsDNS(pkt.Payload) {
		return
	}

	d.parseDNS(pkt)
}

func (d *Decoder) HandlePacketLive(pkt *domain.Packet) *protocols.DecodedPacket {
	if len(pkt.Payload) < 12 {
		return nil
	}
	if !isDNSPort(pkt.SrcPort, pkt.DstPort) && !dpi.IsDNS(pkt.Payload) {
		return nil
	}

	tx := d.parseDNS(pkt)
	if tx == nil {
		return nil
	}

	summary := fmt.Sprintf("DNS %s %s", tx.QueryType, tx.QueryName)
	if tx.HasReply {
		summary = fmt.Sprintf("DNS %s %s -> %s", tx.ReplyCode, tx.QueryName, strings.Join(tx.Answers, ", "))
	}

	return &protocols.DecodedPacket{
		Packet:   pkt,
		Protocol: "DNS",
		Summary:  summary,
		Metadata: map[string]any{
			"query_name": tx.QueryName,
			"query_type": tx.QueryType,
			"reply_code": tx.ReplyCode,
			"answers":    tx.Answers,
		},
		Errors: DetectErrors(tx),
	}
}

func (d *Decoder) Flush() []domain.Flow {
	var flows []domain.Flow

	// Complete remaining pending queries as timeouts
	for _, tx := range d.transactions {
		tx.IsError = true
		tx.ErrorType = "TIMEOUT"
		d.completed = append(d.completed, tx)
	}

	for _, tx := range d.completed {
		metrics := map[string]any{
			"query_name": tx.QueryName,
			"query_type": tx.QueryType,
			"reply_code": tx.ReplyCode,
			"answers":    tx.Answers,
			"latency_ms": tx.Latency,
			"is_error":   tx.IsError,
			"error_type": tx.ErrorType,
		}

		flows = append(flows, domain.Flow{
			FlowID:    fmt.Sprintf("dns-%d-%s", tx.TxID, tx.QueryName),
			Type:      domain.FlowDNS,
			SrcIP:     tx.SrcIP,
			DstIP:     tx.DstIP,
			SrcPort:   tx.SrcPort,
			DstPort:   tx.DstPort,
			StartTime: tx.QueryTime,
			EndTime:   tx.ReplyTime,
			Metrics:   metrics,
		})
	}

	return flows
}

func (d *Decoder) parseDNS(pkt *domain.Packet) *Transaction {
	payload := pkt.Payload
	txID := binary.BigEndian.Uint16(payload[0:2])
	flags := binary.BigEndian.Uint16(payload[2:4])
	isResponse := (flags & 0x8000) != 0
	rcode := uint8(flags & 0x000F)

	if !isResponse {
		// Query
		name, qtype := parseQuestion(payload)
		tx := &Transaction{
			TxID:      txID,
			QueryName: name,
			QueryType: qtype,
			SrcIP:     pkt.SrcIP,
			DstIP:     pkt.DstIP,
			SrcPort:   pkt.SrcPort,
			DstPort:   pkt.DstPort,
			QueryTime: pkt.Timestamp,
		}
		d.transactions[txID] = tx
		pkt.AppProtocol = "DNS"
		pkt.Summary = fmt.Sprintf("Query %s %s", qtype, name)
		return tx
	}

	// Response
	tx, ok := d.transactions[txID]
	if !ok {
		// Response without matching query
		name, qtype := parseQuestion(payload)
		tx = &Transaction{
			TxID:      txID,
			QueryName: name,
			QueryType: qtype,
			SrcIP:     pkt.DstIP,
			DstIP:     pkt.SrcIP,
			SrcPort:   pkt.DstPort,
			DstPort:   pkt.SrcPort,
			QueryTime: pkt.Timestamp,
		}
	}

	tx.HasReply = true
	tx.ReplyTime = pkt.Timestamp
	tx.Latency = float64(tx.ReplyTime.Sub(tx.QueryTime).Microseconds()) / 1000.0

	rcodeStr, ok := ResponseCodes[rcode]
	if !ok {
		rcodeStr = fmt.Sprintf("RCODE_%d", rcode)
	}
	tx.ReplyCode = rcodeStr

	if rcode != 0 {
		tx.IsError = true
		tx.ErrorType = rcodeStr
	}

	// Parse answer records
	tx.Answers = parseAnswers(payload)

	delete(d.transactions, txID)
	d.completed = append(d.completed, tx)

	pkt.AppProtocol = "DNS"
	pkt.Summary = fmt.Sprintf("Response %s %s [%s]", tx.QueryType, tx.QueryName, rcodeStr)

	return tx
}

func isDNSPort(src, dst uint16) bool {
	return src == 53 || dst == 53 || src == 5353 || dst == 5353
}

func parseQuestion(payload []byte) (string, string) {
	if len(payload) < 13 {
		return "", ""
	}

	offset := 12
	var parts []string

	for offset < len(payload) {
		length := int(payload[offset])
		if length == 0 {
			offset++
			break
		}
		offset++
		if offset+length > len(payload) {
			break
		}
		label := payload[offset : offset+length]
		// Skip if label contains non-printable bytes (binary/garbled data)
		if !isValidDNSLabel(label) {
			return "", ""
		}
		parts = append(parts, string(label))
		offset += length
	}

	name := strings.Join(parts, ".")

	qtype := ""
	if offset+2 <= len(payload) {
		qtypeCode := binary.BigEndian.Uint16(payload[offset : offset+2])
		if t, ok := RecordTypes[qtypeCode]; ok {
			qtype = t
		} else {
			qtype = fmt.Sprintf("TYPE%d", qtypeCode)
		}
	}

	return name, qtype
}

func parseAnswers(payload []byte) []string {
	if len(payload) < 12 {
		return nil
	}

	anCount := binary.BigEndian.Uint16(payload[6:8])
	if anCount == 0 {
		return nil
	}

	// Skip header (12 bytes) + question section
	offset := 12
	// Skip question name
	for offset < len(payload) {
		length := int(payload[offset])
		if length == 0 {
			offset++
			break
		}
		if length >= 0xC0 {
			offset += 2
			break
		}
		offset += 1 + length
	}
	// Skip QTYPE + QCLASS
	offset += 4

	var answers []string
	for i := 0; i < int(anCount) && offset < len(payload); i++ {
		// Skip name (might be pointer)
		if offset >= len(payload) {
			break
		}
		if payload[offset] >= 0xC0 {
			offset += 2
		} else {
			for offset < len(payload) {
				l := int(payload[offset])
				if l == 0 {
					offset++
					break
				}
				offset += 1 + l
			}
		}

		if offset+10 > len(payload) {
			break
		}

		rtype := binary.BigEndian.Uint16(payload[offset : offset+2])
		rdLength := binary.BigEndian.Uint16(payload[offset+8 : offset+10])
		offset += 10

		if offset+int(rdLength) > len(payload) {
			break
		}

		switch rtype {
		case 1: // A record
			if rdLength == 4 {
				answers = append(answers, fmt.Sprintf("%d.%d.%d.%d",
					payload[offset], payload[offset+1], payload[offset+2], payload[offset+3]))
			}
		case 28: // AAAA record
			if rdLength == 16 {
				answers = append(answers, fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
					binary.BigEndian.Uint16(payload[offset:offset+2]),
					binary.BigEndian.Uint16(payload[offset+2:offset+4]),
					binary.BigEndian.Uint16(payload[offset+4:offset+6]),
					binary.BigEndian.Uint16(payload[offset+6:offset+8]),
					binary.BigEndian.Uint16(payload[offset+8:offset+10]),
					binary.BigEndian.Uint16(payload[offset+10:offset+12]),
					binary.BigEndian.Uint16(payload[offset+12:offset+14]),
					binary.BigEndian.Uint16(payload[offset+14:offset+16])))
			}
		case 5: // CNAME
			name := decodeName(payload, offset)
			if name != "" {
				answers = append(answers, name)
			}
		}

		offset += int(rdLength)
	}

	return answers
}

func decodeName(payload []byte, offset int) string {
	var parts []string
	seen := make(map[int]bool)

	for offset < len(payload) {
		if seen[offset] {
			break
		}
		seen[offset] = true

		length := int(payload[offset])
		if length == 0 {
			break
		}
		if length >= 0xC0 {
			if offset+1 >= len(payload) {
				break
			}
			ptr := int(binary.BigEndian.Uint16(payload[offset:offset+2]) & 0x3FFF)
			return strings.Join(parts, ".") + "." + decodeName(payload, ptr)
		}
		offset++
		if offset+length > len(payload) {
			break
		}
		parts = append(parts, string(payload[offset:offset+length]))
		offset += length
	}

	return strings.Join(parts, ".")
}

// isValidDNSLabel returns true if all bytes in the label are printable ASCII
// (letters, digits, hyphens, underscores). Rejects binary/garbled data.
func isValidDNSLabel(label []byte) bool {
	for _, b := range label {
		if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
			(b >= '0' && b <= '9') || b == '-' || b == '_') {
			return false
		}
	}
	return true
}

// Ensure Decoder implements StreamingDecoder.
var _ protocols.StreamingDecoder = (*Decoder)(nil)
