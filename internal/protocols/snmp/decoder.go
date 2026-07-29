package snmp

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/protocols"
)

// Decoder decodes SNMP v1/v2c messages on UDP port 161 (agent queries/responses)
// and 162 (traps). Each decoded message becomes its own flow — SNMP is a
// request/response-per-datagram protocol, not a persistent session.
type Decoder struct {
	messages []*Message
}

// Message holds everything decoded from one SNMP datagram.
type Message struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	Timestamp        time.Time

	Version     int64
	VersionName string
	Community   string

	PDUType byte
	PDUName string

	RequestID       int64
	ErrorStatus     int64
	ErrorStatusName string
	ErrorIndex      int64
	IsError         bool

	// SNMPv1 Trap-PDU only (PDUTrap) — the trap has no request-id/error-status.
	IsTrap          bool
	EnterpriseOID   string
	AgentAddr       string
	GenericTrap     int64
	GenericTrapName string
	SpecificTrap    int64

	// SNMPv3 only. The USM security header (engine ID, username, auth/priv
	// flags) is always cleartext even when the PDU itself is encrypted, so
	// this is decoded whether or not the payload can be.
	IsV3            bool
	MsgID           int64
	SecurityModel   int64
	AuthFlag        bool
	PrivFlag        bool
	EngineID        string
	UserName        string
	PayloadEncrypted bool

	VarBinds []VarBind
}

func NewDecoder() *Decoder {
	return &Decoder{}
}

func (d *Decoder) Name() string { return "snmp" }

func isSNMPPort(src, dst uint16) bool {
	return src == 161 || dst == 161 || src == 162 || dst == 162
}

func (d *Decoder) HandlePacket(pkt *domain.Packet) {
	if pkt.Protocol != "UDP" {
		return
	}
	if !isSNMPPort(pkt.SrcPort, pkt.DstPort) {
		return
	}
	if len(pkt.Payload) < 10 {
		return
	}
	d.parseSNMP(pkt)
}

func (d *Decoder) HandlePacketLive(pkt *domain.Packet) *protocols.DecodedPacket {
	if pkt.Protocol != "UDP" {
		return nil
	}
	if !isSNMPPort(pkt.SrcPort, pkt.DstPort) {
		return nil
	}
	if len(pkt.Payload) < 10 {
		return nil
	}

	msg := d.parseSNMP(pkt)
	if msg == nil {
		return nil
	}

	var errs []domain.PacketError
	if msg.IsError {
		errs = append(errs, domain.PacketError{
			Code:        "SNMP_" + msg.ErrorStatusName,
			Title:       "SNMP " + msg.ErrorStatusName,
			Description: fmt.Sprintf("%s returned %s (index %d)", msg.PDUName, msg.ErrorStatusName, msg.ErrorIndex),
			Severity:    "warning",
		})
	}

	metadata := map[string]any{"version": msg.VersionName}
	if msg.IsV3 {
		metadata["user_name"] = msg.UserName
		metadata["payload_encrypted"] = msg.PayloadEncrypted
	} else {
		metadata["community"] = msg.Community
	}
	if msg.PDUName != "" {
		metadata["pdu_type"] = msg.PDUName
		metadata["request_id"] = msg.RequestID
		metadata["varbinds"] = len(msg.VarBinds)
	}

	return &protocols.DecodedPacket{
		Packet:   pkt,
		Protocol: "SNMP",
		Summary:  buildSummary(msg),
		Metadata: metadata,
		Errors:   errs,
	}
}

func (d *Decoder) Flush() []domain.Flow {
	var flows []domain.Flow
	for i, msg := range d.messages {
		metrics := map[string]any{
			"version": msg.VersionName,
		}
		if msg.IsV3 {
			metrics["msg_id"] = msg.MsgID
			metrics["security_model"] = msg.SecurityModel
			metrics["auth_enabled"] = msg.AuthFlag
			metrics["priv_enabled"] = msg.PrivFlag
			metrics["engine_id"] = msg.EngineID
			metrics["user_name"] = msg.UserName
			metrics["payload_encrypted"] = msg.PayloadEncrypted
		} else {
			metrics["community"] = msg.Community
		}
		// PDUName is only populated when the PDU itself was decodable —
		// never true for a privacy-encrypted SNMPv3 ScopedPDU.
		if msg.PDUName != "" {
			metrics["pdu_type"] = msg.PDUName
			metrics["is_error"] = msg.IsError
			metrics["varbind_count"] = len(msg.VarBinds)
			if !msg.IsTrap {
				metrics["request_id"] = msg.RequestID
				metrics["error_status"] = msg.ErrorStatusName
				metrics["error_index"] = msg.ErrorIndex
			} else {
				metrics["enterprise_oid"] = msg.EnterpriseOID
				metrics["agent_addr"] = msg.AgentAddr
				metrics["generic_trap"] = msg.GenericTrapName
				metrics["specific_trap"] = msg.SpecificTrap
			}
		}
		if len(msg.VarBinds) > 0 {
			oids := make([]string, len(msg.VarBinds))
			values := make(map[string]string, len(msg.VarBinds))
			for i, vb := range msg.VarBinds {
				oids[i] = vb.OID
				values[vb.OID] = vb.Value
			}
			metrics["oids"] = oids
			metrics["values"] = values
		}

		flows = append(flows, domain.Flow{
			FlowID:    fmt.Sprintf("snmp-%s:%d-%s:%d-%d", msg.SrcIP, msg.SrcPort, msg.DstIP, msg.DstPort, i),
			Type:      domain.FlowSNMP,
			SrcIP:     msg.SrcIP,
			DstIP:     msg.DstIP,
			SrcPort:   msg.SrcPort,
			DstPort:   msg.DstPort,
			StartTime: msg.Timestamp,
			EndTime:   msg.Timestamp,
			Metrics:   metrics,
		})
	}
	return flows
}

// parseSNMP parses one SNMP datagram: SEQUENCE { version, community, pdu }.
func (d *Decoder) parseSNMP(pkt *domain.Packet) *Message {
	payload := pkt.Payload

	tag, content, _, err := readTLV(payload, 0)
	if err != nil || tag != tagSequence {
		return nil
	}

	verTag, verContent, offset, err := readTLV(content, 0)
	if err != nil || verTag != tagInteger {
		return nil
	}
	version := decodeInt(verContent)
	if version < 0 || version > 3 {
		return nil // not a plausible SNMP version — reject rather than misdecode
	}
	if version == 3 {
		msg := parseV3(content, offset, pkt)
		if msg == nil {
			return nil
		}
		pkt.AppProtocol = "SNMP"
		pkt.Summary = buildSummary(msg)
		d.messages = append(d.messages, msg)
		return msg
	}

	commTag, commContent, offset, err := readTLV(content, offset)
	if err != nil || commTag != tagOctetString {
		return nil
	}
	community := string(commContent)

	pduTag, pduContent, _, err := readTLV(content, offset)
	if err != nil {
		return nil
	}
	pduName := PDUNames[pduTag]
	if pduName == "" {
		return nil // unrecognized PDU type — not SNMP, or a version we don't handle
	}

	msg := &Message{
		SrcIP:       pkt.SrcIP,
		DstIP:       pkt.DstIP,
		SrcPort:     pkt.SrcPort,
		DstPort:     pkt.DstPort,
		Timestamp:   pkt.Timestamp,
		Version:     version,
		VersionName: VersionNames[version],
		Community:   community,
		PDUType:     pduTag,
		PDUName:     pduName,
	}

	if pduTag == PDUTrap {
		parseTrapPDU(pduContent, msg)
	} else {
		parseRequestPDU(pduContent, msg)
	}

	pkt.AppProtocol = "SNMP"
	pkt.Summary = buildSummary(msg)

	d.messages = append(d.messages, msg)
	return msg
}

// parseV3 parses an SNMPv3 message: SEQUENCE { msgVersion, msgGlobalData,
// msgSecurityParameters, msgData }. msgGlobalData and the USM security
// parameters (engine ID, username, auth/priv flags) are always cleartext
// per RFC 3412/3414, even when msgData (the ScopedPDU) is encrypted — so
// this always recovers "who polled what" even when it can't recover "what
// they asked". If msgData turns out to be an unencrypted ScopedPDU (no
// privacy flag), the inner PDU is parsed too, same as v1/v2c.
func parseV3(content []byte, offset int, pkt *domain.Packet) *Message {
	hdrTag, hdrContent, offset, err := readTLV(content, offset)
	if err != nil || hdrTag != tagSequence {
		return nil
	}

	msg := &Message{
		SrcIP:       pkt.SrcIP,
		DstIP:       pkt.DstIP,
		SrcPort:     pkt.SrcPort,
		DstPort:     pkt.DstPort,
		Timestamp:   pkt.Timestamp,
		Version:     3,
		VersionName: VersionNames[3],
		IsV3:        true,
	}

	hOffset := 0
	if tag, c, next, err := readTLV(hdrContent, hOffset); err == nil && tag == tagInteger {
		msg.MsgID = decodeInt(c)
		hOffset = next
	}
	if _, _, next, err := readTLV(hdrContent, hOffset); err == nil {
		hOffset = next // msgMaxSize — not surfaced, only used for PDU size negotiation
	}
	if tag, c, next, err := readTLV(hdrContent, hOffset); err == nil && tag == tagOctetString {
		if len(c) > 0 {
			msg.AuthFlag = c[0]&0x01 != 0
			msg.PrivFlag = c[0]&0x02 != 0
		}
		hOffset = next
	}
	if tag, c, _, err := readTLV(hdrContent, hOffset); err == nil && tag == tagInteger {
		msg.SecurityModel = decodeInt(c)
	}

	// msgSecurityParameters: an OCTET STRING wrapping a nested SEQUENCE
	// (for the USM security model — the only one in common use).
	secTag, secContent, offset, err := readTLV(content, offset)
	if err == nil && secTag == tagOctetString && msg.SecurityModel == 3 {
		if usmTag, usmContent, _, err := readTLV(secContent, 0); err == nil && usmTag == tagSequence {
			uOffset := 0
			if tag, c, next, err := readTLV(usmContent, uOffset); err == nil && tag == tagOctetString {
				msg.EngineID = "0x" + hex.EncodeToString(c)
				uOffset = next
			}
			if _, _, next, err := readTLV(usmContent, uOffset); err == nil {
				uOffset = next // msgAuthoritativeEngineBoots
			}
			if _, _, next, err := readTLV(usmContent, uOffset); err == nil {
				uOffset = next // msgAuthoritativeEngineTime
			}
			if tag, c, _, err := readTLV(usmContent, uOffset); err == nil && tag == tagOctetString {
				msg.UserName = string(c)
			}
		}
	}

	// msgData: either a plaintext ScopedPDU (SEQUENCE) if privacy is off, or
	// an encrypted OCTET STRING if privacy is on — RFC 3412 §6.
	dataTag, dataContent, _, err := readTLV(content, offset)
	if err != nil {
		return msg
	}
	if dataTag == tagOctetString {
		msg.PayloadEncrypted = true
		return msg
	}
	if dataTag != tagSequence {
		return msg
	}
	// Plaintext ScopedPDU: SEQUENCE { contextEngineID, contextName, data }.
	sOffset := 0
	if _, _, next, err := readTLV(dataContent, sOffset); err == nil {
		sOffset = next // contextEngineID
	}
	if _, _, next, err := readTLV(dataContent, sOffset); err == nil {
		sOffset = next // contextName
	}
	pduTag, pduContent, _, err := readTLV(dataContent, sOffset)
	if err != nil {
		return msg
	}
	pduName := PDUNames[pduTag]
	if pduName == "" {
		return msg
	}
	msg.PDUType = pduTag
	msg.PDUName = pduName
	if pduTag == PDUTrap {
		parseTrapPDU(pduContent, msg)
	} else {
		parseRequestPDU(pduContent, msg)
	}
	return msg
}

// parseRequestPDU parses the common PDU format shared by GetRequest,
// GetNextRequest, GetResponse, SetRequest, GetBulkRequest, InformRequest,
// SNMPv2-Trap and Report: SEQUENCE { request-id, error-status, error-index, varbindlist }.
func parseRequestPDU(data []byte, msg *Message) {
	offset := 0

	if tag, c, next, err := readTLV(data, offset); err == nil && tag == tagInteger {
		msg.RequestID = decodeInt(c)
		offset = next
	}
	if tag, c, next, err := readTLV(data, offset); err == nil && tag == tagInteger {
		msg.ErrorStatus = decodeInt(c)
		msg.ErrorStatusName = ErrorStatusNames[msg.ErrorStatus]
		msg.IsError = msg.ErrorStatus != 0
		offset = next
	}
	if tag, c, next, err := readTLV(data, offset); err == nil && tag == tagInteger {
		msg.ErrorIndex = decodeInt(c)
		offset = next
	}
	msg.VarBinds = parseVarBindList(data[offset:])
}

// parseTrapPDU parses the SNMPv1 Trap-PDU's own format (RFC 1157 §4.1.6):
// SEQUENCE { enterprise OID, agent-addr IpAddress, generic-trap INTEGER,
// specific-trap INTEGER, time-stamp TimeTicks, variable-bindings VarBindList }.
func parseTrapPDU(data []byte, msg *Message) {
	msg.IsTrap = true
	offset := 0

	if tag, c, next, err := readTLV(data, offset); err == nil && tag == tagOID {
		msg.EnterpriseOID = decodeOID(c)
		offset = next
	}
	if tag, c, next, err := readTLV(data, offset); err == nil && tag == tagIPAddress && len(c) == 4 {
		msg.AgentAddr = fmt.Sprintf("%d.%d.%d.%d", c[0], c[1], c[2], c[3])
		offset = next
	}
	if tag, c, next, err := readTLV(data, offset); err == nil && tag == tagInteger {
		msg.GenericTrap = decodeInt(c)
		msg.GenericTrapName = GenericTrapNames[msg.GenericTrap]
		offset = next
	}
	if tag, c, next, err := readTLV(data, offset); err == nil && tag == tagInteger {
		msg.SpecificTrap = decodeInt(c)
		offset = next
	}
	if tag, _, next, err := readTLV(data, offset); err == nil && tag == tagTimeTicks {
		offset = next
	}
	msg.VarBinds = parseVarBindList(data[offset:])
}

func buildSummary(msg *Message) string {
	if msg.IsV3 && msg.PDUName == "" {
		// USM header decoded, but the ScopedPDU is encrypted (or unrecognized) —
		// this is all that can be reported without the privacy key.
		who := msg.UserName
		if who == "" {
			who = "unknown user"
		}
		return fmt.Sprintf("SNMP v3 (encrypted) user=%s", who)
	}
	if msg.IsTrap {
		name := msg.GenericTrapName
		if name == "" {
			name = fmt.Sprintf("specific(%d)", msg.SpecificTrap)
		}
		return fmt.Sprintf("SNMP %s Trap: %s from %s", msg.VersionName, name, msg.AgentAddr)
	}
	parts := []string{fmt.Sprintf("SNMP %s %s", msg.VersionName, msg.PDUName)}
	if msg.IsV3 && msg.UserName != "" {
		parts = append(parts, "user="+msg.UserName)
	}
	if msg.IsError {
		parts = append(parts, msg.ErrorStatusName)
	}
	if len(msg.VarBinds) > 0 {
		parts = append(parts, msg.VarBinds[0].OID)
		if len(msg.VarBinds) > 1 {
			parts = append(parts, fmt.Sprintf("(+%d more)", len(msg.VarBinds)-1))
		}
	}
	return strings.Join(parts, " ")
}

// Ensure Decoder implements StreamingDecoder.
var _ protocols.StreamingDecoder = (*Decoder)(nil)
