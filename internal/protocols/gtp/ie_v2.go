package gtp

import (
	"encoding/binary"
	"fmt"
	"net"
)

// GTPv2-C IE Type constants (3GPP TS 29.274)
const (
	IETypeIMSI           = 1
	IETypeCause          = 2
	IETypeRecovery       = 3
	IETypeAPN            = 71
	IETypeAMBR           = 72
	IETypeEBI            = 73
	IETypeMEI            = 75
	IETypeMSISDN         = 76
	IETypeIndication     = 77
	IETypePAA            = 79
	IETypeBearerQoS      = 80
	IETypeRATType        = 82
	IETypeServingNetwork = 83
	IETypeULI            = 86
	IETypeFTEID          = 87
	IETypeBearerContext  = 93
	IETypeChargingID     = 94
	IETypePDNType        = 99
)

// QCI names per 3GPP TS 23.203
var QCINames = map[uint8]string{
	1:  "Conversational Voice",
	2:  "Conversational Video (Live Streaming)",
	3:  "Real Time Gaming",
	4:  "Non-Conversational Video (Buffered Streaming)",
	5:  "IMS Signalling",
	6:  "Video (Buffered Streaming) / TCP-based",
	7:  "Voice, Video, Interactive Gaming",
	8:  "Video (Buffered Streaming) / TCP-based",
	9:  "Video (Buffered Streaming) / TCP-based (Default Bearer)",
	65: "Mission Critical PTT (MCData)",
	66: "Non-Mission Critical PTT (MCData)",
	69: "Mission Critical Delay Sensitive Signalling",
	70: "Mission Critical Data",
}

// RAT type names per 3GPP TS 29.274
var RATTypeNames = map[uint8]string{
	1: "UTRAN",
	2: "GERAN",
	3: "WLAN",
	4: "GAN",
	5: "HSPA Evolution",
	6: "E-UTRAN",
	7: "Virtual",
	8: "E-UTRAN-NB-IoT",
	9: "LTE-M",
	10: "NR",
}

// F-TEID interface type names per 3GPP TS 29.274 Table 8.22-1
var FTEIDInterfaceNames = map[uint8]string{
	0:  "S1-U eNodeB",
	1:  "S1-U SGW",
	2:  "S12 RNC",
	3:  "S12 SGW",
	4:  "S5/S8 SGW",
	5:  "S5/S8 PGW",
	6:  "S5/S8 SGW (PGW C)",
	7:  "S5/S8 PGW (SGW C)",
	8:  "S5/S8 SGW (PMIPv6)",
	9:  "S5/S8 PGW (PMIPv6)",
	10: "S11 MME",
	11: "S11/S4 SGW",
	12: "S10 MME",
	13: "S10 old-MME",
	14: "S3 MME",
	15: "S3 SGSN",
	16: "S4 SGSN",
	17: "S4 SGW",
	18: "S16 SGSN",
	19: "eNodeB (N26)",
	20: "MME (N26)",
	21: "S11 MME (Emergency)",
	37: "N3 gNB",
	38: "N3 UPF",
	39: "N9 UPF (UL CL)",
	40: "N9 UPF (DL)",
}

// GTPv2IESet contains all parsed Information Elements from a GTPv2-C message.
type GTPv2IESet struct {
	// Subscriber identity
	IMSI   string
	MSISDN string
	MEI    string // IMEI/IMEISV

	// Session
	APN          string
	PDNType      string
	PDNAddress   string
	ServingMCCMNC string
	RATType      string

	// Bandwidth
	AMBRUplink   uint32 // kbps
	AMBRDownlink uint32 // kbps

	// Location
	TAI  string // MCC-MNC-TAC
	ECGI string // MCC-MNC-ECI

	// Bearers
	Bearers []BearerInfo

	// Tunnel endpoints (top-level, outside bearer contexts)
	FTEIDs []FTEIDInfo

	// Other
	Cause      uint8
	Recovery   uint8
	ChargingID uint32
}

// BearerInfo represents a parsed Bearer Context IE.
type BearerInfo struct {
	EBI         uint8
	QCI         uint8
	QCIName     string
	MBRUplink   uint64 // kbps
	MBRDownlink uint64 // kbps
	GBRUplink   uint64 // kbps
	GBRDownlink uint64 // kbps
	Cause       uint8
	ChargingID  uint32
	FTEIDs      []FTEIDInfo
}

// FTEIDInfo represents a parsed F-TEID IE.
type FTEIDInfo struct {
	InterfaceType uint8
	InterfaceName string
	TEID          uint32
	IPv4          string
	IPv6          string
}

// ParseGTPv2IEs scans all GTPv2-C IEs in data and returns a populated GTPv2IESet.
// GTPv2-C IE format: Type(1B) + Length(2B BE) + CR+Instance(1B) + Data(LengthB)
func ParseGTPv2IEs(data []byte) *GTPv2IESet {
	ies := &GTPv2IESet{}
	offset := 0

	for offset+4 <= len(data) {
		ieType := data[offset]
		ieLen := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
		// byte at offset+3 is CR(4bits) + Instance(4bits)
		dataStart := offset + 4
		if dataStart+ieLen > len(data) {
			break
		}
		ieData := data[dataStart : dataStart+ieLen]

		switch ieType {
		case IETypeIMSI:
			ies.IMSI = decodeBCD(ieData)
		case IETypeMSISDN:
			ies.MSISDN = decodeBCD(ieData)
		case IETypeMEI:
			ies.MEI = decodeBCD(ieData)
		case IETypeAPN:
			ies.APN = decodeAPN(ieData)
		case IETypeCause:
			if len(ieData) >= 1 {
				ies.Cause = ieData[0]
			}
		case IETypeRecovery:
			if len(ieData) >= 1 {
				ies.Recovery = ieData[0]
			}
		case IETypeAMBR:
			parseAMBR(ieData, ies)
		case IETypeEBI:
			if len(ieData) >= 1 {
				// The EBI is in the lower 4 bits, spare in upper 4
				ebi := ieData[0] & 0x0F
				// Store at top-level if no bearer context wrapping
				if len(ies.Bearers) == 0 {
					ies.Bearers = append(ies.Bearers, BearerInfo{EBI: ebi})
				}
			}
		case IETypePAA:
			parsePAA(ieData, ies)
		case IETypePDNType:
			if len(ieData) >= 1 {
				ies.PDNType = pdnTypeName(ieData[0] & 0x07)
			}
		case IETypeBearerQoS:
			// Top-level bearer QoS (rare, usually inside Bearer Context)
			qos := parseBearerQoS(ieData)
			if qos != nil && len(ies.Bearers) > 0 {
				ies.Bearers[len(ies.Bearers)-1].QCI = qos.QCI
				ies.Bearers[len(ies.Bearers)-1].QCIName = qos.QCIName
				ies.Bearers[len(ies.Bearers)-1].MBRUplink = qos.MBRUplink
				ies.Bearers[len(ies.Bearers)-1].MBRDownlink = qos.MBRDownlink
				ies.Bearers[len(ies.Bearers)-1].GBRUplink = qos.GBRUplink
				ies.Bearers[len(ies.Bearers)-1].GBRDownlink = qos.GBRDownlink
			}
		case IETypeRATType:
			if len(ieData) >= 1 {
				name := RATTypeNames[ieData[0]]
				if name == "" {
					name = fmt.Sprintf("RAT_%d", ieData[0])
				}
				ies.RATType = name
			}
		case IETypeServingNetwork:
			ies.ServingMCCMNC = parseServingNetwork(ieData)
		case IETypeULI:
			parseULI(ieData, ies)
		case IETypeFTEID:
			fteid := parseFTEID(ieData)
			if fteid != nil {
				ies.FTEIDs = append(ies.FTEIDs, *fteid)
			}
		case IETypeBearerContext:
			bc := parseBearerContext(ieData)
			if bc != nil {
				ies.Bearers = append(ies.Bearers, *bc)
			}
		case IETypeChargingID:
			if len(ieData) >= 4 {
				ies.ChargingID = binary.BigEndian.Uint32(ieData[0:4])
			}
		}

		offset = dataStart + ieLen
	}

	return ies
}

// parseAMBR parses the AMBR IE (IE 72): UL(4B) + DL(4B) in kbps.
func parseAMBR(data []byte, ies *GTPv2IESet) {
	if len(data) < 8 {
		return
	}
	ies.AMBRUplink = binary.BigEndian.Uint32(data[0:4])
	ies.AMBRDownlink = binary.BigEndian.Uint32(data[4:8])
}

// parsePAA parses the PDN Address Allocation IE (IE 79).
// Format: PDNType(1B) + Address bytes
func parsePAA(data []byte, ies *GTPv2IESet) {
	if len(data) < 1 {
		return
	}
	pdnType := data[0] & 0x07
	ies.PDNType = pdnTypeName(pdnType)

	switch pdnType {
	case 1: // IPv4
		if len(data) >= 5 {
			ies.PDNAddress = net.IP(data[1:5]).String()
		}
	case 2: // IPv6
		if len(data) >= 9 {
			// 8 bytes: prefix length (1B) + IPv6 interface identifier (8B)
			// Some implementations put 16 bytes for full IPv6
			if len(data) >= 17 {
				ies.PDNAddress = net.IP(data[1:17]).String()
			} else {
				// Just prefix length + partial
				ies.PDNAddress = fmt.Sprintf("::/%d", data[1])
			}
		}
	case 3: // IPv4v6
		if len(data) >= 13 {
			// IPv6 prefix (8B) then IPv4 (4B)
			ipv4 := net.IP(data[9:13]).String()
			ies.PDNAddress = ipv4 // show IPv4 part for simplicity
		}
	}
}

// parseFTEID parses a Fully Qualified TEID IE (IE 87).
// Format: Flags(1B) + TEID(4B) + [IPv4(4B)] + [IPv6(16B)]
func parseFTEID(data []byte) *FTEIDInfo {
	if len(data) < 5 {
		return nil
	}

	flags := data[0]
	v4Present := (flags & 0x80) != 0
	v6Present := (flags & 0x40) != 0
	interfaceType := flags & 0x3F

	fteid := &FTEIDInfo{
		InterfaceType: interfaceType,
		TEID:          binary.BigEndian.Uint32(data[1:5]),
	}

	name := FTEIDInterfaceNames[interfaceType]
	if name == "" {
		name = fmt.Sprintf("Interface_%d", interfaceType)
	}
	fteid.InterfaceName = name

	offset := 5
	if v4Present {
		if offset+4 > len(data) {
			return fteid
		}
		fteid.IPv4 = net.IP(data[offset : offset+4]).String()
		offset += 4
	}
	if v6Present {
		if offset+16 > len(data) {
			return fteid
		}
		fteid.IPv6 = net.IP(data[offset : offset+16]).String()
	}

	return fteid
}

// parseBearerQoS parses a Bearer Level QoS IE (IE 80).
// Format: Flags(1B) + QCI(1B) + MBR_UL(5B) + MBR_DL(5B) + GBR_UL(5B) + GBR_DL(5B) = 22 bytes
func parseBearerQoS(data []byte) *BearerInfo {
	if len(data) < 22 {
		return nil
	}

	// Byte 0: spare(1b) + PCI(1b) + PL(4b) + spare(1b) + PVI(1b)
	qci := data[1]

	info := &BearerInfo{
		QCI: qci,
	}

	name := QCINames[qci]
	if name == "" {
		name = fmt.Sprintf("QCI_%d", qci)
	}
	info.QCIName = name

	info.MBRUplink = decode5ByteRate(data[2:7])
	info.MBRDownlink = decode5ByteRate(data[7:12])
	info.GBRUplink = decode5ByteRate(data[12:17])
	info.GBRDownlink = decode5ByteRate(data[17:22])

	return info
}

// parseBearerContext parses a Bearer Context grouped IE (IE 93).
// It contains nested IEs: EBI, Bearer QoS, F-TEID, Cause, Charging ID, etc.
func parseBearerContext(data []byte) *BearerInfo {
	bc := &BearerInfo{}
	offset := 0

	for offset+4 <= len(data) {
		ieType := data[offset]
		ieLen := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
		dataStart := offset + 4
		if dataStart+ieLen > len(data) {
			break
		}
		ieData := data[dataStart : dataStart+ieLen]

		switch ieType {
		case IETypeEBI:
			if len(ieData) >= 1 {
				bc.EBI = ieData[0] & 0x0F
			}
		case IETypeBearerQoS:
			qos := parseBearerQoS(ieData)
			if qos != nil {
				bc.QCI = qos.QCI
				bc.QCIName = qos.QCIName
				bc.MBRUplink = qos.MBRUplink
				bc.MBRDownlink = qos.MBRDownlink
				bc.GBRUplink = qos.GBRUplink
				bc.GBRDownlink = qos.GBRDownlink
			}
		case IETypeFTEID:
			fteid := parseFTEID(ieData)
			if fteid != nil {
				bc.FTEIDs = append(bc.FTEIDs, *fteid)
			}
		case IETypeCause:
			if len(ieData) >= 1 {
				bc.Cause = ieData[0]
			}
		case IETypeChargingID:
			if len(ieData) >= 4 {
				bc.ChargingID = binary.BigEndian.Uint32(ieData[0:4])
			}
		}

		offset = dataStart + ieLen
	}

	return bc
}

// parseServingNetwork parses the Serving Network IE (IE 83).
// Format: 3 bytes BCD encoded MCC + MNC (same as in NAS/TAI)
// Byte 0: MCC digit 2 | MCC digit 1
// Byte 1: MNC digit 3 | MCC digit 3
// Byte 2: MNC digit 2 | MNC digit 1
func parseServingNetwork(data []byte) string {
	if len(data) < 3 {
		return ""
	}

	mcc1 := data[0] & 0x0F
	mcc2 := (data[0] >> 4) & 0x0F
	mcc3 := data[1] & 0x0F
	mnc3 := (data[1] >> 4) & 0x0F
	mnc1 := data[2] & 0x0F
	mnc2 := (data[2] >> 4) & 0x0F

	mcc := fmt.Sprintf("%d%d%d", mcc1, mcc2, mcc3)

	if mnc3 == 0x0F {
		// 2-digit MNC
		return fmt.Sprintf("%s-%d%d", mcc, mnc1, mnc2)
	}
	return fmt.Sprintf("%s-%d%d%d", mcc, mnc1, mnc2, mnc3)
}

// parseULI parses the User Location Information IE (IE 86).
// Format: Flags(1B) + [CGI] + [SAI] + [RAI] + [TAI] + [ECGI] + ...
// We focus on TAI and ECGI as the most commonly used in LTE/5G.
func parseULI(data []byte, ies *GTPv2IESet) {
	if len(data) < 1 {
		return
	}

	flags := data[0]
	offset := 1

	// CGI present (bit 0) — 7 bytes
	if flags&0x01 != 0 {
		offset += 7
	}
	// SAI present (bit 1) — 7 bytes
	if flags&0x02 != 0 {
		offset += 7
	}
	// RAI present (bit 2) — 7 bytes
	if flags&0x04 != 0 {
		offset += 7
	}
	// TAI present (bit 3) — 5 bytes: PLMN(3B) + TAC(2B)
	if flags&0x08 != 0 {
		if offset+5 <= len(data) {
			plmn := parseServingNetwork(data[offset : offset+3])
			tac := binary.BigEndian.Uint16(data[offset+3 : offset+5])
			ies.TAI = fmt.Sprintf("%s-TAC:%d", plmn, tac)
		}
		offset += 5
	}
	// ECGI present (bit 4) — 7 bytes: PLMN(3B) + spare(4bits) + ECI(28bits)
	if flags&0x10 != 0 {
		if offset+7 <= len(data) {
			plmn := parseServingNetwork(data[offset : offset+3])
			eci := binary.BigEndian.Uint32(data[offset+3:offset+7]) & 0x0FFFFFFF
			ies.ECGI = fmt.Sprintf("%s-ECI:%d", plmn, eci)
		}
	}
}

// decode5ByteRate decodes a 5-byte big-endian rate value (used in Bearer QoS).
// Rates are in kbps.
func decode5ByteRate(data []byte) uint64 {
	if len(data) < 5 {
		return 0
	}
	return uint64(data[0])<<32 |
		uint64(data[1])<<24 |
		uint64(data[2])<<16 |
		uint64(data[3])<<8 |
		uint64(data[4])
}

// pdnTypeName returns the name for a PDN type value.
func pdnTypeName(t uint8) string {
	switch t {
	case 1:
		return "IPv4"
	case 2:
		return "IPv6"
	case 3:
		return "IPv4v6"
	default:
		return fmt.Sprintf("PDN_%d", t)
	}
}

// ToMetrics converts a GTPv2IESet to a flat map suitable for flow metrics storage.
func (ies *GTPv2IESet) ToMetrics() map[string]any {
	m := make(map[string]any)

	if ies.IMSI != "" {
		m["imsi"] = ies.IMSI
	}
	if ies.MSISDN != "" {
		m["msisdn"] = ies.MSISDN
	}
	if ies.MEI != "" {
		m["mei"] = ies.MEI
	}
	if ies.APN != "" {
		m["apn"] = ies.APN
	}
	if ies.PDNType != "" {
		m["pdn_type"] = ies.PDNType
	}
	if ies.PDNAddress != "" {
		m["pdn_address"] = ies.PDNAddress
	}
	if ies.ServingMCCMNC != "" {
		m["serving_network"] = ies.ServingMCCMNC
	}
	if ies.RATType != "" {
		m["rat_type"] = ies.RATType
	}
	if ies.AMBRUplink > 0 {
		m["ambr_uplink_kbps"] = ies.AMBRUplink
	}
	if ies.AMBRDownlink > 0 {
		m["ambr_downlink_kbps"] = ies.AMBRDownlink
	}
	if ies.TAI != "" {
		m["tai"] = ies.TAI
	}
	if ies.ECGI != "" {
		m["ecgi"] = ies.ECGI
	}
	if ies.Recovery > 0 {
		m["recovery"] = ies.Recovery
	}
	if ies.ChargingID > 0 {
		m["charging_id"] = ies.ChargingID
	}

	// Bearer details
	if len(ies.Bearers) > 0 {
		m["bearer_count"] = len(ies.Bearers)
		var bearerList []map[string]any
		for _, b := range ies.Bearers {
			bm := map[string]any{
				"ebi": b.EBI,
			}
			if b.QCI > 0 {
				bm["qci"] = b.QCI
				bm["qci_name"] = b.QCIName
			}
			if b.MBRUplink > 0 {
				bm["mbr_uplink_kbps"] = b.MBRUplink
			}
			if b.MBRDownlink > 0 {
				bm["mbr_downlink_kbps"] = b.MBRDownlink
			}
			if b.GBRUplink > 0 {
				bm["gbr_uplink_kbps"] = b.GBRUplink
			}
			if b.GBRDownlink > 0 {
				bm["gbr_downlink_kbps"] = b.GBRDownlink
			}
			if b.Cause > 0 {
				bm["cause"] = b.Cause
			}
			if b.ChargingID > 0 {
				bm["charging_id"] = b.ChargingID
			}
			if len(b.FTEIDs) > 0 {
				var fteids []map[string]any
				for _, f := range b.FTEIDs {
					fm := map[string]any{
						"interface": f.InterfaceName,
						"teid":      fmt.Sprintf("0x%08x", f.TEID),
					}
					if f.IPv4 != "" {
						fm["ipv4"] = f.IPv4
					}
					if f.IPv6 != "" {
						fm["ipv6"] = f.IPv6
					}
					fteids = append(fteids, fm)
				}
				bm["fteids"] = fteids
			}
			bearerList = append(bearerList, bm)
		}
		m["bearers"] = bearerList
	}

	// Top-level F-TEIDs (sender/control FTEIDs)
	if len(ies.FTEIDs) > 0 {
		var fteids []map[string]any
		for _, f := range ies.FTEIDs {
			fm := map[string]any{
				"interface": f.InterfaceName,
				"teid":      fmt.Sprintf("0x%08x", f.TEID),
			}
			if f.IPv4 != "" {
				fm["ipv4"] = f.IPv4
			}
			if f.IPv6 != "" {
				fm["ipv6"] = f.IPv6
			}
			fteids = append(fteids, fm)
		}
		m["fteids"] = fteids
	}

	return m
}
