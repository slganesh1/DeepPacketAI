package pfcp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/protocols"
)

// Decoder decodes PFCP protocol messages (3GPP TS 29.244).
type Decoder struct {
	messages []pfcpRecord
}

type pfcpRecord struct {
	Header     PFCPHeader
	MsgName    string
	CauseCode  uint8
	SrcIP      string
	DstIP      string
	SrcPort    uint16
	DstPort    uint16
	IsError    bool
	NodeID     string
	LocalSEID  uint64
	RemoteSEID uint64
	UEIP       string
	DNN        string
	UPFeatures []string
	PDRCount   int
	FARCount   int
	URRCount   int
	QERCount   int
	ApplyAction string
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
	if rec.NodeID != "" {
		summary += " Node=" + rec.NodeID
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

	metadata := map[string]any{
		"message_type": rec.MsgName,
		"seid":         rec.Header.SEID,
		"sequence":     rec.Header.SequenceNo,
		"cause_code":   rec.CauseCode,
		"node_id":      rec.NodeID,
		"ue_ip":        rec.UEIP,
		"dnn":          rec.DNN,
		"pdr_count":    rec.PDRCount,
		"far_count":    rec.FARCount,
		"urr_count":    rec.URRCount,
		"qer_count":    rec.QERCount,
		"apply_action": rec.ApplyAction,
		"upf_features": rec.UPFeatures,
	}

	return &protocols.DecodedPacket{
		Packet:   pkt,
		Protocol: "PFCP",
		Summary:  summary,
		Metadata: metadata,
		Errors:   errs,
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
				"node_id":      rec.NodeID,
				"local_seid":   rec.LocalSEID,
				"remote_seid":  rec.RemoteSEID,
				"ue_ip":        rec.UEIP,
				"dnn":          rec.DNN,
				"upf_features": strings.Join(rec.UPFeatures, ","),
				"pdr_count":    rec.PDRCount,
				"far_count":    rec.FARCount,
				"urr_count":    rec.URRCount,
				"qer_count":    rec.QERCount,
				"apply_action": rec.ApplyAction,
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

	rec := &pfcpRecord{
		Header:  hdr,
		MsgName: msgName,
		SrcIP:   pkt.SrcIP,
		DstIP:   pkt.DstIP,
		SrcPort: pkt.SrcPort,
		DstPort: pkt.DstPort,
	}

	// Parse all IEs from the message body
	if dataOffset < len(payload) {
		parsePFCPIEs(payload[dataOffset:], rec)
	}

	rec.IsError = rec.CauseCode != 0 && rec.CauseCode != 1

	pkt.AppProtocol = "PFCP"
	pkt.Summary = msgName
	if hdr.HasSEID {
		pkt.Summary += fmt.Sprintf(" SEID=0x%016x", hdr.SEID)
	}

	d.messages = append(d.messages, *rec)
	return rec
}

// parsePFCPIEs iterates over the IE list and extracts known IE types.
func parsePFCPIEs(data []byte, rec *pfcpRecord) {
	offset := 0
	for offset+4 <= len(data) {
		ieType := binary.BigEndian.Uint16(data[offset : offset+2])
		ieLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		ieEnd := offset + 4 + ieLen

		if ieEnd > len(data) {
			ieEnd = len(data)
		}

		ieValue := data[offset+4 : ieEnd]

		switch ieType {
		case 19: // Cause
			if len(ieValue) >= 1 {
				rec.CauseCode = ieValue[0]
			}

		case 60: // Node ID
			parseNodeID(ieValue, rec)

		case 57: // F-SEID
			parseFSEID(ieValue, rec)

		case 93: // UE IP Address
			parseUEIPAddress(ieValue, rec)

		case 22: // Network Instance (DNN/APN)
			if len(ieValue) > 0 {
				rec.DNN = string(ieValue)
			}

		case 43: // UP Function Features
			parseUPFFeatures(ieValue, rec)

		case 1: // Create PDR (grouped IE)
			rec.PDRCount++
			parseGroupedIE(ieValue, rec, ieType)

		case 3: // Create FAR (grouped IE)
			rec.FARCount++
			parseGroupedIE(ieValue, rec, ieType)

		case 6: // Create URR (grouped IE)
			rec.URRCount++

		case 7: // Create QER (grouped IE)
			rec.QERCount++

		case 44: // Apply Action
			if len(ieValue) >= 1 {
				rec.ApplyAction = decodeApplyAction(ieValue[0])
			}
		}

		offset += 4 + ieLen
	}
}

// parseGroupedIE parses nested IEs within a grouped IE (Create PDR, Create FAR, etc.)
func parseGroupedIE(data []byte, rec *pfcpRecord, parentType uint16) {
	offset := 0
	for offset+4 <= len(data) {
		ieType := binary.BigEndian.Uint16(data[offset : offset+2])
		ieLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		ieEnd := offset + 4 + ieLen
		if ieEnd > len(data) {
			ieEnd = len(data)
		}
		ieValue := data[offset+4 : ieEnd]

		switch ieType {
		case 44: // Apply Action
			if len(ieValue) >= 1 {
				rec.ApplyAction = decodeApplyAction(ieValue[0])
			}
		case 93: // UE IP Address
			parseUEIPAddress(ieValue, rec)
		case 22: // Network Instance
			if len(ieValue) > 0 && rec.DNN == "" {
				rec.DNN = string(ieValue)
			}
		case 20: // Source Interface
			// 0=Access, 1=Core, 2=SGi-LAN/N6-LAN, 3=CP-function, 4=LI function
			// Just parse — could add to metrics later
		case 2: // PDI (grouped within Create PDR)
			parseGroupedIE(ieValue, rec, 2)
		case 4: // Forwarding Parameters (grouped within Create FAR)
			parseGroupedIE(ieValue, rec, 4)
		}

		offset += 4 + ieLen
	}
}

// parseNodeID extracts the Node ID IE (type 60).
func parseNodeID(data []byte, rec *pfcpRecord) {
	if len(data) < 1 {
		return
	}
	nodeIDType := data[0] & 0x0F
	switch nodeIDType {
	case 0: // IPv4
		if len(data) >= 5 {
			rec.NodeID = net.IP(data[1:5]).String()
		}
	case 1: // IPv6
		if len(data) >= 17 {
			rec.NodeID = net.IP(data[1:17]).String()
		}
	case 2: // FQDN
		if len(data) > 1 {
			rec.NodeID = decodeFQDN(data[1:])
		}
	}
}

// parseFSEID extracts the F-SEID IE (type 57).
func parseFSEID(data []byte, rec *pfcpRecord) {
	if len(data) < 9 {
		return
	}
	flags := data[0]
	seid := binary.BigEndian.Uint64(data[1:9])

	// Determine whether this is local or remote SEID based on context
	if rec.LocalSEID == 0 {
		rec.LocalSEID = seid
	} else {
		rec.RemoteSEID = seid
	}

	offset := 9
	hasV4 := (flags & 0x02) != 0
	hasV6 := (flags & 0x01) != 0

	if hasV4 && offset+4 <= len(data) {
		// IPv4 address available but not separately stored
		_ = net.IP(data[offset : offset+4]).String()
		offset += 4
	}
	if hasV6 && offset+16 <= len(data) {
		_ = net.IP(data[offset : offset+16]).String()
	}
	_ = seid
}

// parseUEIPAddress extracts the UE IP Address IE (type 93).
func parseUEIPAddress(data []byte, rec *pfcpRecord) {
	if len(data) < 1 {
		return
	}
	flags := data[0]
	hasV4 := (flags & 0x02) != 0
	hasV6 := (flags & 0x01) != 0

	offset := 1
	if hasV4 && offset+4 <= len(data) {
		rec.UEIP = net.IP(data[offset : offset+4]).String()
		offset += 4
	}
	if hasV6 && offset+16 <= len(data) && rec.UEIP == "" {
		rec.UEIP = net.IP(data[offset : offset+16]).String()
	}
}

// parseUPFFeatures extracts the UP Function Features IE (type 43).
func parseUPFFeatures(data []byte, rec *pfcpRecord) {
	if len(data) < 2 {
		return
	}
	features := binary.BigEndian.Uint16(data[0:2])
	featureNames := []string{
		"BUCP", "DDND", "DLBD", "TRST", "FTUP", "PFDM", "HEEU", "TREU",
		"EMPU", "PDIU", "UDBC", "QUOAC", "TRACE", "FRRT", "PFDE", "",
	}
	for i, name := range featureNames {
		if name != "" && (features>>uint(i))&1 == 1 {
			rec.UPFeatures = append(rec.UPFeatures, name)
		}
	}
}

// decodeApplyAction decodes the Apply Action IE flags byte.
func decodeApplyAction(flags uint8) string {
	var actions []string
	if flags&0x01 != 0 {
		actions = append(actions, "DROP")
	}
	if flags&0x02 != 0 {
		actions = append(actions, "FORW")
	}
	if flags&0x04 != 0 {
		actions = append(actions, "BUFF")
	}
	if flags&0x08 != 0 {
		actions = append(actions, "NOCP")
	}
	if flags&0x10 != 0 {
		actions = append(actions, "DUPL")
	}
	if len(actions) == 0 {
		return fmt.Sprintf("0x%02x", flags)
	}
	return strings.Join(actions, "+")
}

// decodeFQDN decodes a length-label encoded FQDN from PFCP Node ID.
func decodeFQDN(data []byte) string {
	var parts []string
	i := 0
	for i < len(data) {
		l := int(data[i])
		if l == 0 {
			break
		}
		i++
		if i+l > len(data) {
			break
		}
		parts = append(parts, string(data[i:i+l]))
		i += l
	}
	return strings.Join(parts, ".")
}

// extractPFCPCause scans IEs for Cause IE (type 19). Kept for backward compatibility.
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
