// Package nas5g decodes NAS-5GS (Non-Access Stratum for 5G) messages
// as defined in 3GPP TS 24.501.
package nas5g

import (
	"encoding/binary"
	"fmt"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/protocols"
)

// Extended protocol discriminators
const (
	EPD5GMM = 0x7E // 5GS Mobility Management
	EPD5GSM = 0x2E // 5GS Session Management
)

// Security header type values
const (
	SecHdrPlain                    = 0x00
	SecHdrIntegrityProtected       = 0x01
	SecHdrIntegrityAndCiphered     = 0x02
	SecHdrIntegrityNewContext      = 0x03
	SecHdrIntegrityCipheredNewCtx  = 0x04
)

// 5GMM message type codes
const (
	MsgRegistrationRequest           = 0x41
	MsgRegistrationAccept            = 0x42
	MsgRegistrationComplete          = 0x43
	MsgRegistrationReject            = 0x44
	MsgDeregistrationRequestUEOrig   = 0x45
	MsgDeregistrationAcceptUEOrig    = 0x46
	MsgDeregistrationRequestUETerm   = 0x47
	MsgDeregistrationAcceptUETerm    = 0x48
	MsgServiceRequest                = 0x50
	MsgServiceReject                 = 0x51
	MsgServiceAccept                 = 0x52
	MsgConfigUpdateCommand           = 0x55
	MsgConfigUpdateComplete          = 0x56
	MsgAuthRequest                   = 0x57
	MsgAuthResponse                  = 0x58
	MsgAuthReject                    = 0x59
	MsgAuthFailure                   = 0x5a
	MsgAuthResult                    = 0x5b
	MsgIdentityRequest               = 0x5c
	MsgIdentityResponse              = 0x5d
	MsgSecurityModeCommand           = 0x5e
	MsgSecurityModeComplete          = 0x5f
	MsgSecurityModeReject            = 0x60
	Msg5GMMStatus                    = 0x64
	MsgNotification                  = 0x65
	MsgNotificationResponse          = 0x66
	MsgULNASTransport                = 0x67
	MsgDLNASTransport                = 0x68
)

// 5GSM message type codes
const (
	MsgPDUSessionEstablishmentRequest  = 0xc1
	MsgPDUSessionEstablishmentAccept   = 0xc2
	MsgPDUSessionEstablishmentReject   = 0xc3
	MsgPDUSessionAuthCommand           = 0xc5
	MsgPDUSessionAuthComplete          = 0xc6
	MsgPDUSessionAuthResult            = 0xc7
	MsgPDUSessionModificationRequest   = 0xc9
	MsgPDUSessionModificationReject    = 0xca
	MsgPDUSessionModificationCommand   = 0xcb
	MsgPDUSessionModificationComplete  = 0xcc
	MsgPDUSessionModificationCmdReject = 0xcd
	MsgPDUSessionReleaseRequest        = 0xd1
	MsgPDUSessionReleaseReject         = 0xd2
	MsgPDUSessionReleaseCommand        = 0xd3
	MsgPDUSessionReleaseComplete       = 0xd4
	Msg5GSMStatus                      = 0xd6
)

// 5GMM message names
var mmMessageNames = map[uint8]string{
	MsgRegistrationRequest:          "Registration Request",
	MsgRegistrationAccept:           "Registration Accept",
	MsgRegistrationComplete:         "Registration Complete",
	MsgRegistrationReject:           "Registration Reject",
	MsgDeregistrationRequestUEOrig:  "Deregistration Request (UE orig)",
	MsgDeregistrationAcceptUEOrig:   "Deregistration Accept (UE orig)",
	MsgDeregistrationRequestUETerm:  "Deregistration Request (UE term)",
	MsgDeregistrationAcceptUETerm:   "Deregistration Accept (UE term)",
	MsgServiceRequest:               "Service Request",
	MsgServiceReject:                "Service Reject",
	MsgServiceAccept:                "Service Accept",
	MsgConfigUpdateCommand:          "Configuration Update Command",
	MsgConfigUpdateComplete:         "Configuration Update Complete",
	MsgAuthRequest:                  "Authentication Request",
	MsgAuthResponse:                 "Authentication Response",
	MsgAuthReject:                   "Authentication Reject",
	MsgAuthFailure:                  "Authentication Failure",
	MsgAuthResult:                   "Authentication Result",
	MsgIdentityRequest:              "Identity Request",
	MsgIdentityResponse:             "Identity Response",
	MsgSecurityModeCommand:          "Security Mode Command",
	MsgSecurityModeComplete:         "Security Mode Complete",
	MsgSecurityModeReject:           "Security Mode Reject",
	Msg5GMMStatus:                   "5GMM Status",
	MsgNotification:                 "Notification",
	MsgNotificationResponse:         "Notification Response",
	MsgULNASTransport:               "UL NAS Transport",
	MsgDLNASTransport:               "DL NAS Transport",
}

// 5GSM message names
var smMessageNames = map[uint8]string{
	MsgPDUSessionEstablishmentRequest:  "PDU Session Establishment Request",
	MsgPDUSessionEstablishmentAccept:   "PDU Session Establishment Accept",
	MsgPDUSessionEstablishmentReject:   "PDU Session Establishment Reject",
	MsgPDUSessionAuthCommand:           "PDU Session Auth Command",
	MsgPDUSessionAuthComplete:          "PDU Session Auth Complete",
	MsgPDUSessionAuthResult:            "PDU Session Auth Result",
	MsgPDUSessionModificationRequest:   "PDU Session Modification Request",
	MsgPDUSessionModificationReject:    "PDU Session Modification Reject",
	MsgPDUSessionModificationCommand:   "PDU Session Modification Command",
	MsgPDUSessionModificationComplete:  "PDU Session Modification Complete",
	MsgPDUSessionModificationCmdReject: "PDU Session Modification Command Reject",
	MsgPDUSessionReleaseRequest:        "PDU Session Release Request",
	MsgPDUSessionReleaseReject:         "PDU Session Release Reject",
	MsgPDUSessionReleaseCommand:        "PDU Session Release Command",
	MsgPDUSessionReleaseComplete:       "PDU Session Release Complete",
	Msg5GSMStatus:                      "5GSM Status",
}

// 5GS registration type values
var registrationTypes = map[uint8]string{
	0x01: "Initial",
	0x02: "Mobility",
	0x03: "Periodic",
	0x04: "Emergency",
}

// 5GMM cause values
var mmCauseNames = map[uint8]string{
	3:  "Illegal UE",
	5:  "PEI not accepted",
	6:  "Illegal ME",
	7:  "5GS services not allowed",
	9:  "UE identity cannot be derived",
	10: "Implicitly deregistered",
	11: "PLMN not allowed",
	12: "Tracking area not allowed",
	13: "Roaming not allowed in this TA",
	15: "No suitable cells in TA",
	20: "MAC failure",
	21: "Synch failure",
	22: "Congestion",
	23: "UE security capabilities mismatch",
	24: "Security mode rejected, unspecified",
	26: "Non-5G authentication unacceptable",
	27: "N1 mode not allowed",
	28: "Restricted service area",
	31: "Redirection to EPC required",
	43: "LADN not available",
	62: "No network slices available",
	65: "Maximum number of PDU sessions reached",
	67: "Insufficient resources for slice and DNN",
	69: "Message not compatible with protocol state",
	71: "Protocol error, unspecified",
	72: "APN restriction value incompatible with active PDU session",
}

// securityHeaderNames maps security header type to readable name.
var securityHeaderNames = map[uint8]string{
	SecHdrPlain:                   "Plain",
	SecHdrIntegrityProtected:      "IntegrityProtected",
	SecHdrIntegrityAndCiphered:    "Ciphered",
	SecHdrIntegrityNewContext:     "IntegrityProtected+NewCtx",
	SecHdrIntegrityCipheredNewCtx: "Ciphered+NewCtx",
}

// nasRecord holds information about a decoded NAS-5GS message.
type nasRecord struct {
	SrcIP            string
	DstIP            string
	SrcPort          uint16
	DstPort          uint16
	FrameNum         uint64
	Procedure        string
	MessageType      string
	RegistrationType string
	SecurityHeader   string
	CauseCode        uint8
	CauseName        string
	PDUSessionID     uint8
	IsError          bool
	IsMM             bool // 5GMM vs 5GSM
	AuthFailures     int
	MMMessages       int
	SMMessages       int
}

// Decoder decodes NAS-5GS messages, including those embedded in NGAP/SCTP.
type Decoder struct {
	records      []*nasRecord
	authFailures map[string]int // UE key → auth failure count
}

// NewDecoder creates a new NAS-5GS decoder.
func NewDecoder() *Decoder {
	return &Decoder{
		authFailures: make(map[string]int),
	}
}

func (d *Decoder) Name() string { return "nas5g" }

func (d *Decoder) HandlePacket(pkt *domain.Packet) {
	// Accept SCTP (from NGAP) or any packet with NAS signature
	if pkt.Protocol != "SCTP" && pkt.Protocol != "UDP" && pkt.Protocol != "TCP" {
		return
	}
	if len(pkt.Payload) < 3 {
		return
	}
	d.scanPayload(pkt)
}

func (d *Decoder) HandlePacketLive(pkt *domain.Packet) *protocols.DecodedPacket {
	if pkt.Protocol != "SCTP" && pkt.Protocol != "UDP" && pkt.Protocol != "TCP" {
		return nil
	}
	if len(pkt.Payload) < 3 {
		return nil
	}

	rec := d.scanPayload(pkt)
	if rec == nil {
		return nil
	}

	summary := buildNASSummary(rec)

	var errs []domain.PacketError
	if rec.IsError && rec.CauseCode != 0 {
		errs = append(errs, domain.PacketError{
			Code:        fmt.Sprintf("NAS5G_%d", rec.CauseCode),
			Title:       "NAS-5GS " + rec.MessageType + " Failed",
			Description: fmt.Sprintf("Cause: %s (%d)", rec.CauseName, rec.CauseCode),
			Severity:    "error",
		})
	}

	return &protocols.DecodedPacket{
		Packet:   pkt,
		Protocol: "NAS5G",
		Summary:  summary,
		Metadata: map[string]any{
			"procedure":         rec.Procedure,
			"message_type":      rec.MessageType,
			"registration_type": rec.RegistrationType,
			"security_header":   rec.SecurityHeader,
			"cause_code":        rec.CauseCode,
			"cause_name":        rec.CauseName,
			"pdu_session_id":    rec.PDUSessionID,
			"is_error":          rec.IsError,
		},
		Errors: errs,
	}
}

func (d *Decoder) Flush() []domain.Flow {
	var flows []domain.Flow

	for _, rec := range d.records {
		ueKey := fmt.Sprintf("%s-%d", rec.SrcIP, rec.SrcPort)
		authFails := d.authFailures[ueKey]

		flows = append(flows, domain.Flow{
			FlowID:  fmt.Sprintf("nas5g-%s-%d", rec.SrcIP, rec.FrameNum),
			Type:    domain.FlowNAS5G,
			SrcIP:   rec.SrcIP,
			DstIP:   rec.DstIP,
			SrcPort: rec.SrcPort,
			DstPort: rec.DstPort,
			Metrics: map[string]any{
				"procedure":         rec.Procedure,
				"message_type":      rec.MessageType,
				"registration_type": rec.RegistrationType,
				"security_header":   rec.SecurityHeader,
				"cause_code":        rec.CauseCode,
				"cause_name":        rec.CauseName,
				"pdu_session_id":    rec.PDUSessionID,
				"is_error":          rec.IsError,
				"auth_failures":     authFails,
				"mm_messages":       rec.MMMessages,
				"sm_messages":       rec.SMMessages,
			},
		})
	}

	return flows
}

// scanPayload scans the packet payload for NAS-5GS signatures.
// Looks for 0x7E (5GMM EPD) or 0x2E (5GSM EPD) followed by security header byte.
func (d *Decoder) scanPayload(pkt *domain.Packet) *nasRecord {
	payload := pkt.Payload

	// First try to extract from SCTP DATA chunk (same helper as NGAP)
	if pkt.Protocol == "SCTP" {
		inner := extractDataFromSCTP(payload)
		if len(inner) >= 3 {
			rec := d.tryParseNAS(inner, pkt)
			if rec != nil {
				return rec
			}
		}
	}

	// Also scan the raw payload for NAS signatures
	for i := 0; i+2 < len(payload); i++ {
		epd := payload[i]
		if epd == EPD5GMM || epd == EPD5GSM {
			rec := d.tryParseNAS(payload[i:], pkt)
			if rec != nil {
				return rec
			}
		}
	}

	return nil
}

// tryParseNAS attempts to parse a NAS-5GS message starting at data[0].
func (d *Decoder) tryParseNAS(data []byte, pkt *domain.Packet) *nasRecord {
	if len(data) < 3 {
		return nil
	}

	epd := data[0]
	if epd != EPD5GMM && epd != EPD5GSM {
		return nil
	}

	isMM := epd == EPD5GMM
	var secHdr uint8
	var pduSessionID uint8
	var msgType uint8
	var bodyOffset int

	if isMM {
		secHdr = data[1] & 0x0F
		secHdrName, ok := securityHeaderNames[secHdr]
		if !ok {
			secHdrName = fmt.Sprintf("SecHdr_%d", secHdr)
		}

		switch secHdr {
		case SecHdrPlain:
			if len(data) < 3 {
				return nil
			}
			msgType = data[2]
			bodyOffset = 3

		case SecHdrIntegrityProtected, SecHdrIntegrityNewContext:
			// MAC (4 bytes) + Sequence number (1 byte) + message type (1 byte)
			if len(data) < 8 {
				return nil
			}
			msgType = data[7]
			bodyOffset = 8

		case SecHdrIntegrityAndCiphered, SecHdrIntegrityCipheredNewCtx:
			if len(data) < 8 {
				return nil
			}
			msgType = data[7]
			bodyOffset = 8

		default:
			_ = secHdrName
			return nil
		}

		rec := d.buildMMRecord(pkt, secHdr, msgType, data, bodyOffset)
		return rec
	}

	// 5GSM: byte 1 = PDU session ID, byte 2 = PTI (procedure transaction identity), byte 3 = message type
	if len(data) < 4 {
		return nil
	}
	pduSessionID = data[1]
	// byte 2 = PTI (skip)
	msgType = data[3]
	bodyOffset = 4

	rec := d.buildSMRecord(pkt, pduSessionID, msgType, data, bodyOffset)
	return rec
}

func (d *Decoder) buildMMRecord(pkt *domain.Packet, secHdr, msgType uint8, data []byte, bodyOffset int) *nasRecord {
	msgName, ok := mmMessageNames[msgType]
	if !ok {
		return nil // Unknown 5GMM message type — probably not NAS
	}

	secHdrName := securityHeaderNames[secHdr]
	if secHdrName == "" {
		secHdrName = fmt.Sprintf("SecHdr_%d", secHdr)
	}

	procedure := classifyMMProcedure(msgType)

	rec := &nasRecord{
		SrcIP:          pkt.SrcIP,
		DstIP:          pkt.DstIP,
		SrcPort:        pkt.SrcPort,
		DstPort:        pkt.DstPort,
		FrameNum:       pkt.FrameNumber,
		Procedure:      procedure,
		MessageType:    msgName,
		SecurityHeader: secHdrName,
		IsMM:           true,
		MMMessages:     1,
	}

	// Parse body fields
	body := data
	if bodyOffset < len(data) {
		body = data[bodyOffset:]
	}

	switch msgType {
	case MsgRegistrationRequest:
		if len(body) >= 1 {
			regTypeByte := body[0] & 0x07
			if name, ok := registrationTypes[regTypeByte]; ok {
				rec.RegistrationType = name
			}
		}
	case MsgRegistrationReject, MsgServiceReject, MsgDeregistrationRequestUETerm:
		if len(body) >= 1 {
			rec.CauseCode = body[0]
			rec.CauseName = mmCauseNames[rec.CauseCode]
			if rec.CauseName == "" {
				rec.CauseName = fmt.Sprintf("Cause_%d", rec.CauseCode)
			}
			rec.IsError = true
		}
	case MsgAuthFailure:
		rec.IsError = true
		ueKey := fmt.Sprintf("%s-%d", pkt.SrcIP, pkt.SrcPort)
		d.authFailures[ueKey]++
		rec.AuthFailures = d.authFailures[ueKey]
		if len(body) >= 1 {
			rec.CauseCode = body[0]
			rec.CauseName = mmCauseNames[rec.CauseCode]
			if rec.CauseName == "" {
				rec.CauseName = fmt.Sprintf("Cause_%d", rec.CauseCode)
			}
		}
	case MsgAuthReject:
		rec.IsError = true
	case MsgSecurityModeReject:
		rec.IsError = true
		if len(body) >= 1 {
			rec.CauseCode = body[0]
			rec.CauseName = mmCauseNames[rec.CauseCode]
			if rec.CauseName == "" {
				rec.CauseName = fmt.Sprintf("Cause_%d", rec.CauseCode)
			}
		}
	}

	pkt.AppProtocol = "NAS5G"
	pkt.Summary = buildNASSummary(rec)

	d.records = append(d.records, rec)
	return rec
}

func (d *Decoder) buildSMRecord(pkt *domain.Packet, pduSessionID, msgType uint8, data []byte, bodyOffset int) *nasRecord {
	msgName, ok := smMessageNames[msgType]
	if !ok {
		return nil // Unknown 5GSM message type
	}

	procedure := classifySMProcedure(msgType)

	rec := &nasRecord{
		SrcIP:        pkt.SrcIP,
		DstIP:        pkt.DstIP,
		SrcPort:      pkt.SrcPort,
		DstPort:      pkt.DstPort,
		FrameNum:     pkt.FrameNumber,
		Procedure:    procedure,
		MessageType:  msgName,
		PDUSessionID: pduSessionID,
		IsMM:         false,
		SMMessages:   1,
	}

	// Parse body for cause codes in reject messages
	body := data
	if bodyOffset < len(data) {
		body = data[bodyOffset:]
	}

	switch msgType {
	case MsgPDUSessionEstablishmentReject, MsgPDUSessionModificationReject,
		MsgPDUSessionReleaseReject:
		rec.IsError = true
		if len(body) >= 1 {
			rec.CauseCode = body[0]
			// Use MM causes for SM as well (shared cause namespace per spec)
			rec.CauseName = mmCauseNames[rec.CauseCode]
			if rec.CauseName == "" {
				rec.CauseName = fmt.Sprintf("5GSM_Cause_%d", rec.CauseCode)
			}
		}
	}

	pkt.AppProtocol = "NAS5G"
	pkt.Summary = buildNASSummary(rec)

	d.records = append(d.records, rec)
	return rec
}

// classifyMMProcedure returns the high-level procedure name for a 5GMM message type.
func classifyMMProcedure(msgType uint8) string {
	switch msgType {
	case MsgRegistrationRequest, MsgRegistrationAccept, MsgRegistrationComplete, MsgRegistrationReject:
		return "Registration"
	case MsgDeregistrationRequestUEOrig, MsgDeregistrationAcceptUEOrig,
		MsgDeregistrationRequestUETerm, MsgDeregistrationAcceptUETerm:
		return "Deregistration"
	case MsgServiceRequest, MsgServiceReject, MsgServiceAccept:
		return "Service"
	case MsgAuthRequest, MsgAuthResponse, MsgAuthReject, MsgAuthFailure, MsgAuthResult:
		return "Authentication"
	case MsgSecurityModeCommand, MsgSecurityModeComplete, MsgSecurityModeReject:
		return "Security"
	case MsgIdentityRequest, MsgIdentityResponse:
		return "Identity"
	case MsgConfigUpdateCommand, MsgConfigUpdateComplete:
		return "ConfigurationUpdate"
	case MsgULNASTransport, MsgDLNASTransport:
		return "NASTransport"
	default:
		return "MM"
	}
}

// classifySMProcedure returns the high-level procedure name for a 5GSM message type.
func classifySMProcedure(msgType uint8) string {
	switch {
	case msgType >= MsgPDUSessionEstablishmentRequest && msgType <= MsgPDUSessionAuthResult:
		return "PDUSessionEstablishment"
	case msgType >= MsgPDUSessionModificationRequest && msgType <= MsgPDUSessionModificationCmdReject:
		return "PDUSessionModification"
	case msgType >= MsgPDUSessionReleaseRequest && msgType <= MsgPDUSessionReleaseComplete:
		return "PDUSessionRelease"
	default:
		return "SM"
	}
}

// buildNASSummary creates a human-readable summary for a NAS record.
func buildNASSummary(rec *nasRecord) string {
	s := "NAS5G " + rec.Procedure + " " + rec.MessageType
	if rec.RegistrationType != "" {
		s += " [" + rec.RegistrationType + "]"
	}
	if rec.PDUSessionID != 0 {
		s += fmt.Sprintf(" PDU-Session=%d", rec.PDUSessionID)
	}
	if rec.IsError && rec.CauseName != "" {
		s += " [" + rec.CauseName + "]"
	}
	return s
}

// extractDataFromSCTP extracts the user data payload from an SCTP DATA chunk.
// Mirrors the logic in the ngap package to avoid cross-package dependency.
func extractDataFromSCTP(data []byte) []byte {
	offset := 0
	for offset+4 <= len(data) {
		chunkType := data[offset]
		if offset+4 > len(data) {
			break
		}
		chunkLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if chunkLen < 4 {
			break
		}
		if chunkType == 0x00 { // DATA chunk
			dataStart := offset + 16
			dataEnd := offset + chunkLen
			if dataStart >= len(data) {
				break
			}
			if dataEnd > len(data) {
				dataEnd = len(data)
			}
			return data[dataStart:dataEnd]
		}
		padded := chunkLen
		if padded%4 != 0 {
			padded += 4 - (padded % 4)
		}
		offset += padded
	}
	return data
}

var _ protocols.StreamingDecoder = (*Decoder)(nil)
