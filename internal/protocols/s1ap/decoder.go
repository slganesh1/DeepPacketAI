package s1ap

import (
	"encoding/binary"
	"fmt"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/protocols"
)

// S1AP procedure codes
var ProcedureCodes = map[uint8]string{
	0:  "HandoverPreparation",
	1:  "HandoverResourceAllocation",
	2:  "HandoverNotification",
	3:  "PathSwitchRequest",
	4:  "HandoverCancel",
	5:  "E-RABSetup",
	6:  "E-RABModify",
	7:  "E-RABRelease",
	8:  "E-RABReleaseIndication",
	9:  "InitialContextSetup",
	10: "Paging",
	11: "downlinkNASTransport",
	12: "InitialUEMessage",
	13: "uplinkNASTransport",
	14: "Reset",
	15: "ErrorIndication",
	17: "UEContextRelease",
	18: "UEContextReleaseRequest",
	21: "UEContextModification",
	23: "HandoverRequired",
}

// PDU types
var PDUTypes = map[uint8]string{
	0: "InitiatingMessage",
	1: "SuccessfulOutcome",
	2: "UnsuccessfulOutcome",
}

// Decoder decodes S1AP protocol messages (outer wrapper only).
type Decoder struct {
	messages []s1apRecord
}

type s1apRecord struct {
	PDUType       string
	ProcedureCode uint8
	ProcedureName string
	SrcIP         string
	DstIP         string
	SrcPort       uint16
	DstPort       uint16
	FrameNum      uint64
}

func NewDecoder() *Decoder {
	return &Decoder{}
}

func (d *Decoder) Name() string { return "s1ap" }

func (d *Decoder) HandlePacket(pkt *domain.Packet) {
	if pkt.Protocol != "SCTP" {
		return
	}
	if pkt.SrcPort != 36412 && pkt.DstPort != 36412 {
		return
	}
	if len(pkt.Payload) < 4 {
		return
	}

	d.parseS1AP(pkt)
}

func (d *Decoder) HandlePacketLive(pkt *domain.Packet) *protocols.DecodedPacket {
	if pkt.Protocol != "SCTP" {
		return nil
	}
	if pkt.SrcPort != 36412 && pkt.DstPort != 36412 {
		return nil
	}
	if len(pkt.Payload) < 4 {
		return nil
	}

	rec := d.parseS1AP(pkt)
	if rec == nil {
		return nil
	}

	return &protocols.DecodedPacket{
		Packet:   pkt,
		Protocol: "S1AP",
		Summary:  fmt.Sprintf("%s %s", rec.PDUType, rec.ProcedureName),
		Metadata: map[string]any{
			"pdu_type":       rec.PDUType,
			"procedure_code": rec.ProcedureCode,
			"procedure_name": rec.ProcedureName,
		},
	}
}

func (d *Decoder) Flush() []domain.Flow {
	var flows []domain.Flow
	for _, rec := range d.messages {
		flows = append(flows, domain.Flow{
			FlowID:  fmt.Sprintf("s1ap-%s-%d-%d", rec.ProcedureName, rec.ProcedureCode, rec.FrameNum),
			Type:    domain.FlowS1AP,
			SrcIP:   rec.SrcIP,
			DstIP:   rec.DstIP,
			SrcPort: rec.SrcPort,
			DstPort: rec.DstPort,
			Metrics: map[string]any{
				"pdu_type":       rec.PDUType,
				"procedure_code": rec.ProcedureCode,
				"procedure_name": rec.ProcedureName,
			},
		})
	}
	return flows
}

func (d *Decoder) parseS1AP(pkt *domain.Packet) *s1apRecord {
	payload := pkt.Payload

	// S1AP uses ASN.1 PER encoding - we only decode the outer wrapper
	// First byte contains the PDU type (in top bits for APER)
	pduTypeIdx := payload[0] >> 5
	if pduTypeIdx > 2 {
		pduTypeIdx = payload[0] & 0x03
	}

	pduType := PDUTypes[pduTypeIdx]
	if pduType == "" {
		pduType = fmt.Sprintf("PDU_%d", pduTypeIdx)
	}

	// Procedure code is typically the second meaningful byte
	var procCode uint8
	if len(payload) >= 3 {
		procCode = payload[1]
		// Sometimes the procedure code is at offset 2
		if procCode > 50 && len(payload) > 3 {
			procCode = payload[2]
		}
	}

	procName := ProcedureCodes[procCode]
	if procName == "" {
		procName = fmt.Sprintf("Procedure_%d", procCode)
	}

	rec := &s1apRecord{
		PDUType:       pduType,
		ProcedureCode: procCode,
		ProcedureName: procName,
		SrcIP:         pkt.SrcIP,
		DstIP:         pkt.DstIP,
		SrcPort:       pkt.SrcPort,
		DstPort:       pkt.DstPort,
		FrameNum:      pkt.FrameNumber,
	}

	pkt.AppProtocol = "S1AP"
	pkt.Summary = fmt.Sprintf("%s %s", pduType, procName)

	d.messages = append(d.messages, *rec)
	return rec
}

// Suppress unused import warning
var _ = binary.BigEndian

var _ protocols.StreamingDecoder = (*Decoder)(nil)
