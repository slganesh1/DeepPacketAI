package pfcp

import (
	"encoding/binary"
	"fmt"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/protocols"
)

// Decoder decodes PFCP protocol messages (3GPP TS 29.244).
type Decoder struct {
	messages []pfcpRecord
}

type pfcpRecord struct {
	Header    PFCPHeader
	MsgName   string
	CauseCode uint8
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	IsError   bool
}

func NewDecoder() *Decoder {
	return &Decoder{}
}

func (d *Decoder) Name() string { return "pfcp" }

func (d *Decoder) HandlePacket(pkt *domain.Packet) {
	if pkt.SrcPort != 8805 && pkt.DstPort != 8805 {
		return
	}
	if pkt.Protocol != "UDP" {
		return
	}
	if len(pkt.Payload) < 8 {
		return
	}

	d.parsePFCP(pkt)
}

func (d *Decoder) HandlePacketLive(pkt *domain.Packet) *protocols.DecodedPacket {
	if pkt.SrcPort != 8805 && pkt.DstPort != 8805 {
		return nil
	}
	if pkt.Protocol != "UDP" {
		return nil
	}
	if len(pkt.Payload) < 8 {
		return nil
	}

	rec := d.parsePFCP(pkt)
	if rec == nil {
		return nil
	}

	summary := rec.MsgName
	if rec.Header.HasSEID {
		summary += fmt.Sprintf(" SEID=0x%016x", rec.Header.SEID)
	}
	if rec.CauseCode != 0 {
		causeName := CauseValues[rec.CauseCode]
		if causeName == "" {
			causeName = fmt.Sprintf("Cause_%d", rec.CauseCode)
		}
		summary += " [" + causeName + "]"
	}

	var errs []domain.PacketError
	if rec.IsError {
		causeName := CauseValues[rec.CauseCode]
		errs = append(errs, domain.PacketError{
			Code:        fmt.Sprintf("PFCP_%d", rec.CauseCode),
			Title:       "PFCP " + rec.MsgName + " Failed",
			Description: fmt.Sprintf("Cause: %s (%d)", causeName, rec.CauseCode),
			Severity:    "error",
		})
	}

	return &protocols.DecodedPacket{
		Packet:   pkt,
		Protocol: "PFCP",
		Summary:  summary,
		Metadata: map[string]any{
			"message_type": rec.MsgName,
			"seid":         rec.Header.SEID,
			"sequence":     rec.Header.SequenceNo,
			"cause_code":   rec.CauseCode,
		},
		Errors: errs,
	}
}

func (d *Decoder) Flush() []domain.Flow {
	var flows []domain.Flow

	for _, rec := range d.messages {
		flows = append(flows, domain.Flow{
			FlowID:  fmt.Sprintf("pfcp-%d-%d", rec.Header.SEID, rec.Header.SequenceNo),
			Type:    domain.FlowPFCP,
			SrcIP:   rec.SrcIP,
			DstIP:   rec.DstIP,
			SrcPort: rec.SrcPort,
			DstPort: rec.DstPort,
			Metrics: map[string]any{
				"message_type": rec.MsgName,
				"seid":         rec.Header.SEID,
				"cause_code":   rec.CauseCode,
				"is_error":     rec.IsError,
			},
		})
	}

	return flows
}

func (d *Decoder) parsePFCP(pkt *domain.Packet) *pfcpRecord {
	payload := pkt.Payload

	version := (payload[0] >> 5) & 0x07
	if version != 1 {
		return nil
	}

	seidPresent := (payload[0] & 0x01) != 0
	msgType := payload[1]
	msgLen := binary.BigEndian.Uint16(payload[2:4])

	hdr := PFCPHeader{
		Version:     version,
		MessageType: msgType,
		Length:      msgLen,
		HasSEID:     seidPresent,
	}

	var dataOffset int
	if seidPresent {
		if len(payload) < 16 {
			return nil
		}
		hdr.SEID = binary.BigEndian.Uint64(payload[4:12])
		hdr.SequenceNo = uint32(payload[12])<<16 | uint32(payload[13])<<8 | uint32(payload[14])
		dataOffset = 16
	} else {
		if len(payload) < 8 {
			return nil
		}
		hdr.SequenceNo = uint32(payload[4])<<16 | uint32(payload[5])<<8 | uint32(payload[6])
		dataOffset = 8
	}

	msgName := MessageTypes[msgType]
	if msgName == "" {
		msgName = fmt.Sprintf("PFCP_Type_%d", msgType)
	}

	// Extract cause IE from response messages
	var causeCode uint8
	if dataOffset < len(payload) {
		causeCode = extractPFCPCause(payload[dataOffset:])
	}

	isError := causeCode != 0 && causeCode != 1

	pkt.AppProtocol = "PFCP"
	pkt.Summary = msgName
	if hdr.HasSEID {
		pkt.Summary += fmt.Sprintf(" SEID=0x%016x", hdr.SEID)
	}

	rec := &pfcpRecord{
		Header:    hdr,
		MsgName:   msgName,
		CauseCode: causeCode,
		SrcIP:     pkt.SrcIP,
		DstIP:     pkt.DstIP,
		SrcPort:   pkt.SrcPort,
		DstPort:   pkt.DstPort,
		IsError:   isError,
	}

	d.messages = append(d.messages, *rec)
	return rec
}

// extractPFCPCause scans IEs for Cause IE (type 19).
func extractPFCPCause(data []byte) uint8 {
	offset := 0
	for offset+4 <= len(data) {
		ieType := binary.BigEndian.Uint16(data[offset : offset+2])
		ieLen := binary.BigEndian.Uint16(data[offset+2 : offset+4])

		if ieType == 19 && ieLen >= 1 && offset+4 < len(data) {
			return data[offset+4]
		}

		offset += 4 + int(ieLen)
	}
	return 0
}

var _ protocols.StreamingDecoder = (*Decoder)(nil)
