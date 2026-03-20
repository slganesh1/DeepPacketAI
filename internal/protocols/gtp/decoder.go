package gtp

import (
	"encoding/binary"
	"fmt"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/dpi"
	"DeepPacketAI/internal/protocols"
)

// Decoder decodes GTP-C and GTP-U packets.
type Decoder struct {
	transactions map[uint16]*gtpTransaction
	completed    []*gtpTransaction
}

type gtpTransaction struct {
	ID         string
	TEID       uint32
	MsgType    string
	SrcIP      string
	DstIP      string
	SrcPort    uint16
	DstPort    uint16
	CauseCode  uint8
	SeqNo      uint16
	IsGTPU     bool
	HasReply   bool
	IsError    bool
	Timestamp  interface{}
	IMSI       string
	MSISDN     string
	APN        string
	IEs        *GTPv2IESet // Full parsed IEs for GTPv2-C
}

func NewDecoder() *Decoder {
	return &Decoder{
		transactions: make(map[uint16]*gtpTransaction),
	}
}

func (d *Decoder) Name() string { return "gtp" }

func (d *Decoder) HandlePacket(pkt *domain.Packet) {
	if pkt.Protocol != "UDP" {
		return
	}
	if len(pkt.Payload) < 8 {
		return
	}
	if !isGTPPort(pkt.SrcPort, pkt.DstPort) && !dpi.IsGTP(pkt.Payload) {
		return
	}

	d.parseGTP(pkt)
}

func (d *Decoder) HandlePacketLive(pkt *domain.Packet) *protocols.DecodedPacket {
	if pkt.Protocol != "UDP" {
		return nil
	}
	if len(pkt.Payload) < 8 {
		return nil
	}
	if !isGTPPort(pkt.SrcPort, pkt.DstPort) && !dpi.IsGTP(pkt.Payload) {
		return nil
	}

	hdr, causeCode := d.parseGTP(pkt)
	if hdr == nil {
		return nil
	}

	msgType := MessageTypes[hdr.MessageType]
	if msgType == "" {
		msgType = fmt.Sprintf("Type_%d", hdr.MessageType)
	}

	proto := "GTP-C"
	if hdr.IsGTPU {
		proto = "GTP-U"
	}

	summary := fmt.Sprintf("%s TEID=0x%08x", msgType, hdr.TEID)
	metadata := map[string]any{
		"version":      hdr.Version,
		"message_type": msgType,
		"teid":         hdr.TEID,
		"sequence":     hdr.SequenceNo,
		"is_gtpu":      hdr.IsGTPU,
	}

	// Add parsed IE data from the transaction we just created
	if len(d.completed) > 0 {
		lastTx := d.completed[len(d.completed)-1]
		if lastTx.IEs != nil {
			for k, v := range lastTx.IEs.ToMetrics() {
				metadata[k] = v
			}
			if lastTx.IMSI != "" {
				summary += " IMSI=" + lastTx.IMSI
			}
		} else {
			// Fallback for GTPv1
			if lastTx.IMSI != "" {
				metadata["imsi"] = lastTx.IMSI
				summary += " IMSI=" + lastTx.IMSI
			}
			if lastTx.MSISDN != "" {
				metadata["msisdn"] = lastTx.MSISDN
			}
			if lastTx.APN != "" {
				metadata["apn"] = lastTx.APN
			}
		}
	}

	return &protocols.DecodedPacket{
		Packet:   pkt,
		Protocol: proto,
		Summary:  summary,
		Metadata: metadata,
		Errors:   DetectErrors(hdr, causeCode),
	}
}

func (d *Decoder) Flush() []domain.Flow {
	var flows []domain.Flow

	for _, tx := range d.completed {
		flowType := domain.FlowGTP
		metrics := map[string]any{
			"message_type": tx.MsgType,
			"teid":         tx.TEID,
			"is_gtpu":      tx.IsGTPU,
			"is_error":     tx.IsError,
			"cause_code":   tx.CauseCode,
		}

		// Merge comprehensive IE metrics for GTPv2-C
		if tx.IEs != nil {
			for k, v := range tx.IEs.ToMetrics() {
				metrics[k] = v
			}
		} else {
			// Fallback for GTPv1 (no full IE parser)
			if tx.IMSI != "" {
				metrics["imsi"] = tx.IMSI
			}
			if tx.MSISDN != "" {
				metrics["msisdn"] = tx.MSISDN
			}
			if tx.APN != "" {
				metrics["apn"] = tx.APN
			}
		}

		flows = append(flows, domain.Flow{
			FlowID:  tx.ID,
			Type:    flowType,
			SrcIP:   tx.SrcIP,
			DstIP:   tx.DstIP,
			SrcPort: tx.SrcPort,
			DstPort: tx.DstPort,
			Metrics: metrics,
		})
	}

	return flows
}

func (d *Decoder) parseGTP(pkt *domain.Packet) (*GTPHeader, uint8) {
	payload := pkt.Payload
	version := (payload[0] >> 5) & 0x07
	msgType := payload[1]
	length := binary.BigEndian.Uint16(payload[2:4])

	hdr := &GTPHeader{
		Version:     version,
		MessageType: msgType,
		Length:      length,
	}

	var headerSize int
	switch version {
	case 1:
		if len(payload) < 8 {
			return nil, 0
		}
		hdr.TEID = binary.BigEndian.Uint32(payload[4:8])
		headerSize = 8

		// Check for optional fields (S, E, PN flags)
		flags := payload[0]
		if flags&0x07 != 0 && len(payload) >= 12 {
			hdr.SequenceNo = binary.BigEndian.Uint16(payload[8:10])
			headerSize = 12
		}

		hdr.IsGTPU = (pkt.SrcPort == 2152 || pkt.DstPort == 2152)

	case 2:
		// GTPv2-C
		if len(payload) < 8 {
			return nil, 0
		}
		teidPresent := (payload[0] & 0x08) != 0
		if teidPresent {
			if len(payload) < 12 {
				return nil, 0
			}
			hdr.TEID = binary.BigEndian.Uint32(payload[4:8])
			hdr.SequenceNo = uint16(payload[9])<<8 | uint16(payload[10])
			headerSize = 12
		} else {
			hdr.SequenceNo = uint16(payload[5])<<8 | uint16(payload[6])
			headerSize = 8
		}

	default:
		return nil, 0
	}

	// Extract cause code from response messages
	var causeCode uint8
	if headerSize < len(payload) {
		causeCode = extractCauseCode(payload[headerSize:], version)
	}

	// Parse IEs — skip for GTP-U
	var imsi, msisdn, apn string
	var ies *GTPv2IESet
	isGTPU := (pkt.SrcPort == 2152 || pkt.DstPort == 2152)
	if !isGTPU && headerSize < len(payload) {
		if version == 2 {
			ies = ParseGTPv2IEs(payload[headerSize:])
			imsi = ies.IMSI
			msisdn = ies.MSISDN
			apn = ies.APN
		} else {
			imsi, msisdn, apn = extractSubscriberIEs(payload[headerSize:], version)
		}
	}

	msgTypeName := MessageTypes[msgType]
	if msgTypeName == "" {
		msgTypeName = fmt.Sprintf("Type_%d", msgType)
	}

	proto := "GTP-C"
	if hdr.IsGTPU {
		proto = "GTP-U"
	}

	pkt.AppProtocol = proto
	pkt.Summary = fmt.Sprintf("%s TEID=0x%08x", msgTypeName, hdr.TEID)
	if imsi != "" {
		pkt.Summary += " IMSI=" + imsi
	}
	if ies != nil {
		if ies.APN != "" {
			pkt.Summary += " APN=" + ies.APN
		}
		if len(ies.Bearers) > 0 && ies.Bearers[0].QCI > 0 {
			pkt.Summary += fmt.Sprintf(" QCI=%d", ies.Bearers[0].QCI)
		}
	}

	tx := &gtpTransaction{
		ID:        fmt.Sprintf("gtp-%d-%d", hdr.TEID, pkt.FrameNumber),
		TEID:      hdr.TEID,
		MsgType:   msgTypeName,
		SrcIP:     pkt.SrcIP,
		DstIP:     pkt.DstIP,
		SrcPort:   pkt.SrcPort,
		DstPort:   pkt.DstPort,
		CauseCode: causeCode,
		SeqNo:     hdr.SequenceNo,
		IsGTPU:    hdr.IsGTPU,
		IsError:   causeCode != 0 && causeCode != 16,
		Timestamp: pkt.Timestamp,
		IMSI:      imsi,
		MSISDN:    msisdn,
		APN:       apn,
		IEs:       ies,
	}

	d.completed = append(d.completed, tx)

	return hdr, causeCode
}

func extractCauseCode(data []byte, version uint8) uint8 {
	if version == 2 {
		// GTPv2: scan IEs for Cause IE (type 2)
		offset := 0
		for offset+4 <= len(data) {
			ieType := data[offset]
			ieLen := binary.BigEndian.Uint16(data[offset+1 : offset+3])
			if ieType == 2 && int(ieLen) >= 1 && offset+4 < len(data) {
				return data[offset+4]
			}
			offset += 4 + int(ieLen)
		}
	} else if version == 1 {
		// GTPv1: scan TLV IEs for Cause IE (type 1, TV format, 1 byte)
		if len(data) >= 2 && data[0] == 1 {
			return data[1]
		}
	}
	return 0
}

func isGTPPort(src, dst uint16) bool {
	return src == 2123 || dst == 2123 || src == 2152 || dst == 2152
}

var _ protocols.StreamingDecoder = (*Decoder)(nil)
