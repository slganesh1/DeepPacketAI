package ngap

import (
	"encoding/binary"
	"fmt"
	"time"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/protocols"
)

// NGAP procedure codes (5G NR - TS 38.413)
var ProcedureCodes = map[uint8]string{
	0:  "AMFConfigurationUpdate",
	1:  "HandoverCancel",
	2:  "HandoverNotification",
	3:  "HandoverPreparation",
	4:  "HandoverResourceAllocation",
	5:  "InitialContextSetup",
	6:  "NGReset",
	7:  "NGSetup",
	8:  "PathSwitchRequest",
	9:  "PDUSessionResourceModify",
	10: "PDUSessionResourceModifyIndication",
	11: "PDUSessionResourceRelease",
	12: "PDUSessionResourceSetup",
	14: "InitialUEMessage",
	15: "DownlinkNASTransport",
	16: "UplinkNASTransport",
	17: "NASNonDeliveryIndication",
	19: "Paging",
	20: "RANConfigurationUpdate",
	21: "UEContextModification",
	22: "UEContextRelease",
	23: "UEContextReleaseRequest",
	25: "ErrorIndication",
	26: "UERadioCapabilityCheck",
	27: "HandoverSuccess",
	29: "RerouteNASRequest",
	33: "AMFStatusIndication",
	40: "UplinkRANConfigurationTransfer",
	41: "DownlinkRANConfigurationTransfer",
	46: "UplinkRANStatusTransfer",
	47: "DownlinkRANStatusTransfer",
}

// PDU types (same as S1AP - ASN.1 APER)
var PDUTypes = map[uint8]string{
	0: "InitiatingMessage",
	1: "SuccessfulOutcome",
	2: "UnsuccessfulOutcome",
}

// Decoder decodes NGAP protocol messages (outer wrapper only).
type Decoder struct {
	messages []ngapRecord
}

type ngapRecord struct {
	PDUType       string
	ProcedureCode uint8
	ProcedureName string
	SrcIP         string
	DstIP         string
	SrcPort       uint16
	DstPort       uint16
	FrameNum      uint64
	IMSI          string
	Timestamp     time.Time
}

func NewDecoder() *Decoder {
	return &Decoder{}
}

func (d *Decoder) Name() string { return "ngap" }

func (d *Decoder) HandlePacket(pkt *domain.Packet) {
	if pkt.Protocol != "SCTP" {
		return
	}
	if pkt.SrcPort != 38412 && pkt.DstPort != 38412 {
		return
	}
	if len(pkt.Payload) < 4 {
		return
	}

	d.parseNGAP(pkt)
}

func (d *Decoder) HandlePacketLive(pkt *domain.Packet) *protocols.DecodedPacket {
	if pkt.Protocol != "SCTP" {
		return nil
	}
	if pkt.SrcPort != 38412 && pkt.DstPort != 38412 {
		return nil
	}
	if len(pkt.Payload) < 4 {
		return nil
	}

	rec := d.parseNGAP(pkt)
	if rec == nil {
		return nil
	}

	summary := fmt.Sprintf("%s %s", rec.PDUType, rec.ProcedureName)
	metadata := map[string]any{
		"pdu_type":       rec.PDUType,
		"procedure_code": rec.ProcedureCode,
		"procedure_name": rec.ProcedureName,
	}
	if rec.IMSI != "" {
		metadata["imsi"] = rec.IMSI
		summary += " IMSI=" + rec.IMSI
	}

	return &protocols.DecodedPacket{
		Packet:   pkt,
		Protocol: "NGAP",
		Summary:  summary,
		Metadata: metadata,
	}
}

func (d *Decoder) Flush() []domain.Flow {
	var flows []domain.Flow
	for _, rec := range d.messages {
		metrics := map[string]any{
			"pdu_type":       rec.PDUType,
			"procedure_code": rec.ProcedureCode,
			"procedure_name": rec.ProcedureName,
		}
		if rec.IMSI != "" {
			metrics["imsi"] = rec.IMSI
		}

		flows = append(flows, domain.Flow{
			FlowID:    fmt.Sprintf("ngap-%s-%d-%d", rec.ProcedureName, rec.ProcedureCode, rec.FrameNum),
			Type:      domain.FlowNGAP,
			SrcIP:     rec.SrcIP,
			DstIP:     rec.DstIP,
			SrcPort:   rec.SrcPort,
			DstPort:   rec.DstPort,
			StartTime: rec.Timestamp,
			EndTime:   rec.Timestamp,
			Metrics:   metrics,
		})
	}
	return flows
}

func (d *Decoder) parseNGAP(pkt *domain.Packet) *ngapRecord {
	// The SCTP LayerPayload contains raw SCTP chunk data.
	// We need to find the DATA chunk and extract the NGAP PDU from inside it.
	ngapPayload := extractNGAPFromSCTP(pkt.Payload)
	if len(ngapPayload) < 4 {
		return nil
	}

	// NGAP uses ASN.1 APER encoding
	// Byte 0: PDU type in top bits (0=Initiating, 1=Successful, 2=Unsuccessful)
	pduTypeIdx := ngapPayload[0] >> 5
	if pduTypeIdx > 2 {
		pduTypeIdx = ngapPayload[0] & 0x03
	}

	pduType := PDUTypes[pduTypeIdx]
	if pduType == "" {
		pduType = fmt.Sprintf("PDU_%d", pduTypeIdx)
	}

	// Procedure code is the second byte
	var procCode uint8
	if len(ngapPayload) >= 3 {
		procCode = ngapPayload[1]
		if procCode > 50 && len(ngapPayload) > 3 {
			procCode = ngapPayload[2]
		}
	}

	procName := ProcedureCodes[procCode]
	if procName == "" {
		procName = fmt.Sprintf("Procedure_%d", procCode)
	}

	// Extract NAS identity — scan the full NGAP payload for NAS Registration Requests.
	// NAS PDUs can appear in InitialUEMessage (14), UplinkNASTransport (16),
	// DownlinkNASTransport (15), and other procedures that carry NAS-PDU IEs.
	var imsi string
	imsi = extractNASIdentity(ngapPayload)

	rec := &ngapRecord{
		PDUType:       pduType,
		ProcedureCode: procCode,
		ProcedureName: procName,
		SrcIP:         pkt.SrcIP,
		DstIP:         pkt.DstIP,
		SrcPort:       pkt.SrcPort,
		DstPort:       pkt.DstPort,
		FrameNum:      pkt.FrameNumber,
		IMSI:          imsi,
		Timestamp:     pkt.Timestamp,
	}

	pkt.AppProtocol = "NGAP"
	pkt.Summary = fmt.Sprintf("%s %s", pduType, procName)
	if imsi != "" {
		pkt.Summary += " IMSI=" + imsi
	}

	d.messages = append(d.messages, *rec)
	return rec
}

// extractNGAPFromSCTP extracts the NGAP PDU from SCTP chunk data.
// SCTP DATA chunk format: Type(1B) + Flags(1B) + Length(2B) + TSN(4B)
//   + StreamID(2B) + StreamSeqNo(2B) + PPID(4B) + UserData(...)
// Some packets bundle SACK chunks (type=3) before the DATA chunk.
func extractNGAPFromSCTP(data []byte) []byte {
	offset := 0
	for offset+4 <= len(data) {
		chunkType := data[offset]
		chunkLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))

		if chunkLen < 4 {
			break
		}

		if chunkType == 0x00 { // DATA chunk
			// DATA chunk header is 16 bytes; user data starts at offset+16
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

		// Skip to next chunk (padded to 4-byte boundary)
		padded := chunkLen
		if padded%4 != 0 {
			padded += 4 - (padded % 4)
		}
		offset += padded
	}

	// Fallback: if no DATA chunk found, return original data
	// (may happen if gopacket already stripped chunk headers in some versions)
	return data
}

var _ protocols.StreamingDecoder = (*Decoder)(nil)
