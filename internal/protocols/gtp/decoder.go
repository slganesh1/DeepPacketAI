package gtp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/dpi"
	"DeepPacketAI/internal/protocols"
)

// Decoder decodes GTP-C and GTP-U packets.
type Decoder struct {
	transactions map[uint16]*gtpTransaction
	completed    []*gtpTransaction
	tunnelCount  int
}

type gtpTransaction struct {
	ID               string
	TEID             uint32
	MsgType          string
	SrcIP            string
	DstIP            string
	SrcPort          uint16
	DstPort          uint16
	CauseCode        uint8
	SeqNo            uint16
	IsGTPU           bool
	HasReply         bool
	IsError          bool
	Timestamp        interface{}
	IMSI             string
	MSISDN           string
	APN              string
	IEs              *GTPv2IESet // Full parsed IEs for GTPv2-C
	// Inner packet fields (GTP-U only)
	InnerSrcIP       string
	InnerDstIP       string
	InnerProtocol    string
	InnerSrcPort     uint16
	InnerDstPort     uint16
	InnerPacketCount int
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

		// Add inner packet info for GTP-U
		if lastTx.IsGTPU {
			if lastTx.InnerSrcIP != "" {
				metadata["inner_src_ip"] = lastTx.InnerSrcIP
				metadata["inner_dst_ip"] = lastTx.InnerDstIP
				metadata["inner_protocol"] = lastTx.InnerProtocol
				summary += fmt.Sprintf(" Inner:%s->%s(%s)", lastTx.InnerSrcIP, lastTx.InnerDstIP, lastTx.InnerProtocol)
			}
			if lastTx.InnerSrcPort != 0 {
				metadata["inner_src_port"] = lastTx.InnerSrcPort
				metadata["inner_dst_port"] = lastTx.InnerDstPort
			}
			metadata["tunnel_count"] = d.tunnelCount
			metadata["inner_packet_count"] = lastTx.InnerPacketCount
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
		if tx.IsGTPU {
			flowType = domain.FlowGTPU
		}
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

		// Add inner packet info for GTP-U
		if tx.IsGTPU {
			metrics["inner_src_ip"] = tx.InnerSrcIP
			metrics["inner_dst_ip"] = tx.InnerDstIP
			metrics["inner_protocol"] = tx.InnerProtocol
			metrics["inner_src_port"] = tx.InnerSrcPort
			metrics["inner_dst_port"] = tx.InnerDstPort
			metrics["tunnel_count"] = d.tunnelCount
			metrics["inner_packet_count"] = tx.InnerPacketCount
		}

		ts, _ := tx.Timestamp.(time.Time)

		flows = append(flows, domain.Flow{
			FlowID:    tx.ID,
			Type:      flowType,
			SrcIP:     tx.SrcIP,
			DstIP:     tx.DstIP,
			SrcPort:   tx.SrcPort,
			DstPort:   tx.DstPort,
			StartTime: ts,
			EndTime:   ts,
			Metrics:   metrics,
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

	// Parse inner IP packet for GTP-U G-PDU (message type 0xFF)
	if isGTPU && msgType == 0xFF && headerSize < len(payload) {
		innerPayload := payload[headerSize:]
		parseInnerPacket(innerPayload, tx)
		if tx.InnerSrcIP != "" {
			d.tunnelCount++
			tx.InnerPacketCount = 1
		}
	}

	d.completed = append(d.completed, tx)

	return hdr, causeCode
}

// parseInnerPacket parses the inner IP packet encapsulated in a GTP-U G-PDU.
func parseInnerPacket(data []byte, tx *gtpTransaction) {
	if len(data) < 1 {
		return
	}

	version := (data[0] >> 4) & 0x0F

	switch version {
	case 4: // IPv4
		parseInnerIPv4(data, tx)
	case 6: // IPv6
		parseInnerIPv6(data, tx)
	}
}

// parseInnerIPv4 parses the inner IPv4 packet.
func parseInnerIPv4(data []byte, tx *gtpTransaction) {
	if len(data) < 20 {
		return
	}

	ihl := int(data[0]&0x0F) * 4
	if ihl < 20 || ihl > len(data) {
		return
	}

	tx.InnerSrcIP = net.IP(data[12:16]).String()
	tx.InnerDstIP = net.IP(data[16:20]).String()

	protocol := data[9]
	tx.InnerProtocol = innerProtocolName(protocol)

	if ihl < len(data) {
		parseInnerTransport(protocol, data[ihl:], tx)
	}
}

// parseInnerIPv6 parses the inner IPv6 packet.
func parseInnerIPv6(data []byte, tx *gtpTransaction) {
	if len(data) < 40 {
		return
	}

	tx.InnerSrcIP = net.IP(data[8:24]).String()
	tx.InnerDstIP = net.IP(data[24:40]).String()

	nextHeader := data[6]
	tx.InnerProtocol = innerProtocolName(nextHeader)

	if len(data) > 40 {
		parseInnerTransport(nextHeader, data[40:], tx)
	}
}

// parseInnerTransport parses TCP/UDP/SCTP port information from the inner transport layer.
func parseInnerTransport(protocol uint8, data []byte, tx *gtpTransaction) {
	switch protocol {
	case 6: // TCP
		if len(data) >= 4 {
			tx.InnerSrcPort = binary.BigEndian.Uint16(data[0:2])
			tx.InnerDstPort = binary.BigEndian.Uint16(data[2:4])
		}
	case 17: // UDP
		if len(data) >= 4 {
			tx.InnerSrcPort = binary.BigEndian.Uint16(data[0:2])
			tx.InnerDstPort = binary.BigEndian.Uint16(data[2:4])
		}
	case 132: // SCTP
		if len(data) >= 4 {
			tx.InnerSrcPort = binary.BigEndian.Uint16(data[0:2])
			tx.InnerDstPort = binary.BigEndian.Uint16(data[2:4])
		}
	}
}

// innerProtocolName returns the protocol name for an IP protocol number.
func innerProtocolName(proto uint8) string {
	switch proto {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 41:
		return "IPv6"
	case 58:
		return "ICMPv6"
	case 132:
		return "SCTP"
	default:
		return fmt.Sprintf("Proto_%d", proto)
	}
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
