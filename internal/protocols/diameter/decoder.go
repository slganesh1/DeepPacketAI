package diameter

import (
	"encoding/binary"
	"fmt"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/dpi"
	"DeepPacketAI/internal/protocols"
)

// Decoder decodes Diameter protocol messages (RFC 6733).
type Decoder struct {
	messages []*DiameterMessage
}

func NewDecoder() *Decoder {
	return &Decoder{}
}

func (d *Decoder) Name() string { return "diameter" }

func (d *Decoder) HandlePacket(pkt *domain.Packet) {
	if len(pkt.Payload) < 20 {
		return
	}
	if !isDiameterPort(pkt.SrcPort, pkt.DstPort) && !dpi.IsDiameter(pkt.Payload) {
		return
	}

	d.parseDiameter(pkt)
}

func (d *Decoder) HandlePacketLive(pkt *domain.Packet) *protocols.DecodedPacket {
	if len(pkt.Payload) < 20 {
		return nil
	}
	if !isDiameterPort(pkt.SrcPort, pkt.DstPort) && !dpi.IsDiameter(pkt.Payload) {
		return nil
	}

	msg := d.parseDiameter(pkt)
	if msg == nil {
		return nil
	}

	direction := "Request"
	if !msg.Header.IsRequest {
		direction = "Answer"
	}

	summary := fmt.Sprintf("%s %s", msg.CommandName, direction)
	if msg.SessionID != "" {
		summary += " [" + truncate(msg.SessionID, 40) + "]"
	}
	if !msg.Header.IsRequest && msg.ResultCode != 0 {
		summary += fmt.Sprintf(" RC=%d", msg.ResultCode)
	}

	metadata := map[string]any{
		"command":      msg.CommandName,
		"command_code": msg.Header.CommandCode,
		"app_id":       msg.Header.AppID,
		"app_name":     msg.AppName,
		"is_request":   msg.Header.IsRequest,
		"session_id":   msg.SessionID,
		"result_code":  msg.ResultCode,
		"origin_host":  msg.OriginHost,
		"origin_realm": msg.OriginRealm,
		"user_name":    msg.UserName,
	}
	if msg.IMSI != "" {
		metadata["imsi"] = msg.IMSI
	}
	if msg.MSISDN != "" {
		metadata["msisdn"] = msg.MSISDN
	}

	return &protocols.DecodedPacket{
		Packet:   pkt,
		Protocol: "Diameter",
		Summary:  summary,
		Metadata: metadata,
		Errors:   DetectErrors(msg),
	}
}

func (d *Decoder) Flush() []domain.Flow {
	var flows []domain.Flow

	for _, msg := range d.messages {
		direction := "Request"
		if !msg.Header.IsRequest {
			direction = "Answer"
		}

		metrics := map[string]any{
			"command":      msg.CommandName,
			"command_code": msg.Header.CommandCode,
			"app_id":       msg.Header.AppID,
			"app_name":     msg.AppName,
			"is_request":   msg.Header.IsRequest,
			"session_id":   msg.SessionID,
			"result_code":  msg.ResultCode,
			"origin_host":  msg.OriginHost,
			"is_error":     msg.IsError,
		}
		if msg.IMSI != "" {
			metrics["imsi"] = msg.IMSI
		}
		if msg.MSISDN != "" {
			metrics["msisdn"] = msg.MSISDN
		}

		flows = append(flows, domain.Flow{
			FlowID:  fmt.Sprintf("diameter-%s-%s-%d", msg.SessionID, direction, msg.Header.EndToEndID),
			Type:    domain.FlowDiameter,
			Metrics: metrics,
		})
	}

	return flows
}

func (d *Decoder) parseDiameter(pkt *domain.Packet) *DiameterMessage {
	payload := pkt.Payload

	// Verify Diameter version byte
	if payload[0] != 1 {
		return nil
	}

	// Parse 20-byte header
	msgLen := uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])
	if msgLen < 20 || int(msgLen) > len(payload) {
		return nil
	}

	flags := payload[4]
	cmdCode := uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])
	appID := binary.BigEndian.Uint32(payload[8:12])
	hopByHop := binary.BigEndian.Uint32(payload[12:16])
	endToEnd := binary.BigEndian.Uint32(payload[16:20])

	hdr := DiameterHeader{
		Version:     payload[0],
		Length:      msgLen,
		Flags:       flags,
		CommandCode: cmdCode,
		AppID:       appID,
		HopByHopID:  hopByHop,
		EndToEndID:  endToEnd,
		IsRequest:   (flags & 0x80) != 0,
	}

	cmdName := CommandCodes[cmdCode]
	if cmdName == "" {
		cmdName = fmt.Sprintf("Command_%d", cmdCode)
	}

	appName := ApplicationIDs[appID]
	if appName == "" {
		appName = fmt.Sprintf("App_%d", appID)
	}

	msg := &DiameterMessage{
		Header:      hdr,
		CommandName: cmdName,
		AppName:     appName,
	}

	// Parse AVPs
	avps := ParseAVPs(payload[20:msgLen])
	for _, avp := range avps {
		switch avp.Code {
		case AVPSessionID:
			msg.SessionID = avp.ExtractString()
		case AVPResultCode:
			msg.ResultCode = avp.ExtractUint32()
		case AVPOriginHost:
			msg.OriginHost = avp.ExtractString()
		case AVPOriginRealm:
			msg.OriginRealm = avp.ExtractString()
		case AVPDestinationHost:
			msg.DestinationHost = avp.ExtractString()
		case AVPCCRequestType:
			msg.CCRequestType = avp.ExtractUint32()
		case AVPUserName:
			msg.UserName = avp.ExtractString()
		case AVPSubscriptionID:
			// Grouped AVP containing Subscription-Id-Type (450) and Subscription-Id-Data (444)
			subAVPs := avp.ParseGroupedAVP()
			var subType uint32
			var subData string
			for _, sa := range subAVPs {
				switch sa.Code {
				case AVPSubscriptionIDType:
					subType = sa.ExtractUint32()
				case AVPSubscriptionIDData:
					subData = sa.ExtractString()
				}
			}
			if subData != "" {
				switch subType {
				case 1: // END_USER_IMSI
					msg.IMSI = subData
				case 0: // END_USER_E164 (MSISDN)
					msg.MSISDN = subData
				}
			}
		case AVP3GPPMSISDN:
			if avp.VendorID == 10415 && len(avp.Data) > 0 {
				msg.MSISDN = avp.ExtractString()
			}
		}
	}

	// S6a (AppID 16777251): derive IMSI from UserName if not found via Subscription-Id
	if msg.IMSI == "" && msg.UserName != "" && appID == 16777251 {
		msg.IMSI = msg.UserName
	}

	msg.IsError = !hdr.IsRequest && msg.ResultCode != 0 && msg.ResultCode != 2001 && msg.ResultCode != 2002

	direction := "Request"
	if !hdr.IsRequest {
		direction = "Answer"
	}

	pkt.AppProtocol = "Diameter"
	pkt.Summary = fmt.Sprintf("%s %s", cmdName, direction)
	if msg.ResultCode != 0 {
		pkt.Summary += fmt.Sprintf(" RC=%d", msg.ResultCode)
	}

	d.messages = append(d.messages, msg)

	return msg
}

func isDiameterPort(src, dst uint16) bool {
	return src == 3868 || dst == 3868
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

var _ protocols.StreamingDecoder = (*Decoder)(nil)
