package gtp

import (
	"encoding/binary"
	"net"
	"testing"
)

// makeIE builds a GTPv2-C IE: type(1B) + length(2B BE) + spare/instance(1B) + data
func makeIE(ieType byte, data []byte) []byte {
	ie := make([]byte, 4+len(data))
	ie[0] = ieType
	binary.BigEndian.PutUint16(ie[1:3], uint16(len(data)))
	ie[3] = 0 // spare + instance
	copy(ie[4:], data)
	return ie
}

func TestParseGTPv2IEs_IMSI(t *testing.T) {
	// BCD: each byte = lo nibble first, hi nibble second. 0xF = padding.
	// 0x13 → 3,1  0x20 → 0,2  0x06 → 6,0  0x00 → 0,0  0x00 → 0,0  0x00 → 0,0  0x01 → 1,0  0x0F → 0,skip
	// Result: "310260000000100"
	imsiData := []byte{0x13, 0x20, 0x06, 0x00, 0x00, 0x00, 0x01, 0x0F}
	payload := makeIE(IETypeIMSI, imsiData)

	ies := ParseGTPv2IEs(payload)

	want := "310260000000100"
	if ies.IMSI != want {
		t.Errorf("IMSI = %q, want %q", ies.IMSI, want)
	}
}

func TestParseGTPv2IEs_MEI(t *testing.T) {
	// MEI (IMEI): 86740300461107 in BCD
	meiData := []byte{0x68, 0x47, 0x30, 0x40, 0x16, 0x11, 0x70}
	payload := makeIE(IETypeMEI, meiData)

	ies := ParseGTPv2IEs(payload)

	expected := decodeBCD(meiData)
	if ies.MEI != expected {
		t.Errorf("MEI = %q, want %q", ies.MEI, expected)
	}
}

func TestParseGTPv2IEs_APN(t *testing.T) {
	apnData := []byte{8, 'i', 'n', 't', 'e', 'r', 'n', 'e', 't'}
	payload := makeIE(IETypeAPN, apnData)

	ies := ParseGTPv2IEs(payload)
	if ies.APN != "internet" {
		t.Errorf("APN = %q, want %q", ies.APN, "internet")
	}
}

func TestParseGTPv2IEs_Cause(t *testing.T) {
	payload := makeIE(IETypeCause, []byte{16}) // Request Accepted
	ies := ParseGTPv2IEs(payload)
	if ies.Cause != 16 {
		t.Errorf("Cause = %d, want 16", ies.Cause)
	}
}

func TestParseGTPv2IEs_Recovery(t *testing.T) {
	payload := makeIE(IETypeRecovery, []byte{42})
	ies := ParseGTPv2IEs(payload)
	if ies.Recovery != 42 {
		t.Errorf("Recovery = %d, want 42", ies.Recovery)
	}
}

func TestParseGTPv2IEs_AMBR(t *testing.T) {
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], 50000) // UL 50000 kbps
	binary.BigEndian.PutUint32(data[4:8], 100000) // DL 100000 kbps
	payload := makeIE(IETypeAMBR, data)

	ies := ParseGTPv2IEs(payload)
	if ies.AMBRUplink != 50000 {
		t.Errorf("AMBRUplink = %d, want 50000", ies.AMBRUplink)
	}
	if ies.AMBRDownlink != 100000 {
		t.Errorf("AMBRDownlink = %d, want 100000", ies.AMBRDownlink)
	}
}

func TestParseGTPv2IEs_PDNType(t *testing.T) {
	tests := []struct {
		val  byte
		want string
	}{
		{1, "IPv4"},
		{2, "IPv6"},
		{3, "IPv4v6"},
	}
	for _, tt := range tests {
		payload := makeIE(IETypePDNType, []byte{tt.val})
		ies := ParseGTPv2IEs(payload)
		if ies.PDNType != tt.want {
			t.Errorf("PDNType(%d) = %q, want %q", tt.val, ies.PDNType, tt.want)
		}
	}
}

func TestParseGTPv2IEs_PAA_IPv4(t *testing.T) {
	data := []byte{1} // PDN type IPv4
	data = append(data, net.ParseIP("10.45.0.2").To4()...)
	payload := makeIE(IETypePAA, data)

	ies := ParseGTPv2IEs(payload)
	if ies.PDNType != "IPv4" {
		t.Errorf("PDNType = %q, want IPv4", ies.PDNType)
	}
	if ies.PDNAddress != "10.45.0.2" {
		t.Errorf("PDNAddress = %q, want 10.45.0.2", ies.PDNAddress)
	}
}

func TestParseGTPv2IEs_RATType(t *testing.T) {
	payload := makeIE(IETypeRATType, []byte{6}) // E-UTRAN
	ies := ParseGTPv2IEs(payload)
	if ies.RATType != "E-UTRAN" {
		t.Errorf("RATType = %q, want E-UTRAN", ies.RATType)
	}
}

func TestParseGTPv2IEs_ServingNetwork(t *testing.T) {
	// MCC=208, MNC=93
	// Byte 0: MCC2|MCC1 = 0x02 | (0x00 << 4) = 0x02... wait
	// Actually: Byte 0: MCC digit 2 << 4 | MCC digit 1
	// MCC = 208: digits 2, 0, 8
	// Byte 0: digit2=0, digit1=2 → 0x02
	// Byte 1: MNC3=3 << 4 | MCC3=8 → 0x38
	// Byte 2: MNC2=9, MNC1=3... wait, MNC=93: digits 9, 3
	// MNC = 93: digit1=9, digit2=3, digit3=F (2-digit MNC)
	// Byte 1: MNC3(F)<<4 | MCC3(8) → 0xF8
	// Byte 2: MNC2(3)<<4 | MNC1(9) → 0x39
	data := []byte{0x02, 0xF8, 0x39}
	payload := makeIE(IETypeServingNetwork, data)

	ies := ParseGTPv2IEs(payload)
	if ies.ServingMCCMNC != "208-93" {
		t.Errorf("ServingMCCMNC = %q, want 208-93", ies.ServingMCCMNC)
	}
}

func TestParseGTPv2IEs_ServingNetwork_3DigitMNC(t *testing.T) {
	// MCC=310, MNC=260
	// Byte 0: MCC2(1)<<4 | MCC1(3) → 0x13
	// Byte 1: MNC3(0)<<4 | MCC3(0) → 0x00
	// Byte 2: MNC2(6)<<4 | MNC1(2) → 0x62
	data := []byte{0x13, 0x00, 0x62}
	payload := makeIE(IETypeServingNetwork, data)

	ies := ParseGTPv2IEs(payload)
	if ies.ServingMCCMNC != "310-260" {
		t.Errorf("ServingMCCMNC = %q, want 310-260", ies.ServingMCCMNC)
	}
}

func TestParseGTPv2IEs_FTEID(t *testing.T) {
	// F-TEID with IPv4: flags=0x80|interfaceType(10=S11 MME), TEID, IPv4
	data := make([]byte, 9)
	data[0] = 0x80 | 10 // V4 flag + interface type 10 (S11 MME)
	binary.BigEndian.PutUint32(data[1:5], 0x12345678)
	copy(data[5:9], net.ParseIP("192.168.1.1").To4())

	payload := makeIE(IETypeFTEID, data)
	ies := ParseGTPv2IEs(payload)

	if len(ies.FTEIDs) != 1 {
		t.Fatalf("expected 1 FTEID, got %d", len(ies.FTEIDs))
	}
	f := ies.FTEIDs[0]
	if f.InterfaceType != 10 {
		t.Errorf("InterfaceType = %d, want 10", f.InterfaceType)
	}
	if f.InterfaceName != "S11 MME" {
		t.Errorf("InterfaceName = %q, want S11 MME", f.InterfaceName)
	}
	if f.TEID != 0x12345678 {
		t.Errorf("TEID = 0x%08x, want 0x12345678", f.TEID)
	}
	if f.IPv4 != "192.168.1.1" {
		t.Errorf("IPv4 = %q, want 192.168.1.1", f.IPv4)
	}
}

func TestParseGTPv2IEs_BearerQoS(t *testing.T) {
	// Bearer QoS: Flags(1B) + QCI(1B) + MBR_UL(5B) + MBR_DL(5B) + GBR_UL(5B) + GBR_DL(5B) = 22 bytes
	// Offsets: [0]=flags, [1]=QCI, [2-6]=MBR_UL, [7-11]=MBR_DL, [12-16]=GBR_UL, [17-21]=GBR_DL
	data := make([]byte, 22)
	data[0] = 0 // flags (PCI, PL, PVI)
	data[1] = 9 // QCI 9 (Default Bearer)

	// MBR UL = 1000 kbps: 5 bytes big endian at [2..6]
	// 1000 = 0x3E8 → [0x00, 0x00, 0x00, 0x03, 0xE8]
	data[5] = 0x03
	data[6] = 0xE8
	// MBR DL = 2000 kbps: 5 bytes big endian at [7..11]
	// 2000 = 0x7D0 → [0x00, 0x00, 0x00, 0x07, 0xD0]
	data[10] = 0x07
	data[11] = 0xD0

	info := parseBearerQoS(data)
	if info == nil {
		t.Fatal("parseBearerQoS returned nil")
	}
	if info.QCI != 9 {
		t.Errorf("QCI = %d, want 9", info.QCI)
	}
	if info.QCIName != "Video (Buffered Streaming) / TCP-based (Default Bearer)" {
		t.Errorf("QCIName = %q", info.QCIName)
	}
	if info.MBRUplink != 1000 {
		t.Errorf("MBRUplink = %d, want 1000", info.MBRUplink)
	}
	if info.MBRDownlink != 2000 {
		t.Errorf("MBRDownlink = %d, want 2000", info.MBRDownlink)
	}
}

func TestParseGTPv2IEs_BearerContext(t *testing.T) {
	// Build a Bearer Context grouped IE containing EBI + Bearer QoS + F-TEID

	// EBI IE: value = 5
	ebiIE := makeIE(IETypeEBI, []byte{5})

	// Bearer QoS IE
	qosData := make([]byte, 22)
	qosData[1] = 1 // QCI 1 (Conversational Voice)
	qosIE := makeIE(IETypeBearerQoS, qosData)

	// F-TEID IE
	fteidData := make([]byte, 9)
	fteidData[0] = 0x80 | 4 // V4 + S5/S8 SGW
	binary.BigEndian.PutUint32(fteidData[1:5], 0xABCD0001)
	copy(fteidData[5:9], net.ParseIP("10.0.0.1").To4())
	fteidIE := makeIE(IETypeFTEID, fteidData)

	// Combine into Bearer Context data
	bcData := append(append(ebiIE, qosIE...), fteidIE...)
	bcIE := makeIE(IETypeBearerContext, bcData)

	ies := ParseGTPv2IEs(bcIE)

	if len(ies.Bearers) != 1 {
		t.Fatalf("expected 1 bearer, got %d", len(ies.Bearers))
	}
	bc := ies.Bearers[0]
	if bc.EBI != 5 {
		t.Errorf("EBI = %d, want 5", bc.EBI)
	}
	if bc.QCI != 1 {
		t.Errorf("QCI = %d, want 1", bc.QCI)
	}
	if bc.QCIName != "Conversational Voice" {
		t.Errorf("QCIName = %q, want Conversational Voice", bc.QCIName)
	}
	if len(bc.FTEIDs) != 1 {
		t.Fatalf("expected 1 FTEID in bearer, got %d", len(bc.FTEIDs))
	}
	if bc.FTEIDs[0].TEID != 0xABCD0001 {
		t.Errorf("FTEID TEID = 0x%08x, want 0xABCD0001", bc.FTEIDs[0].TEID)
	}
	if bc.FTEIDs[0].IPv4 != "10.0.0.1" {
		t.Errorf("FTEID IPv4 = %q, want 10.0.0.1", bc.FTEIDs[0].IPv4)
	}
}

func TestParseGTPv2IEs_ULI_TAI_ECGI(t *testing.T) {
	// ULI with TAI + ECGI
	// Flags: TAI (bit 3) + ECGI (bit 4) = 0x18
	var data []byte
	data = append(data, 0x18) // flags

	// TAI: PLMN(3B) + TAC(2B)
	// MCC=208, MNC=93 → same as serving network test
	data = append(data, 0x02, 0xF8, 0x39)
	tac := make([]byte, 2)
	binary.BigEndian.PutUint16(tac, 1234)
	data = append(data, tac...)

	// ECGI: PLMN(3B) + spare(4bits)+ECI(28bits) = 4B
	data = append(data, 0x02, 0xF8, 0x39)
	eci := make([]byte, 4)
	binary.BigEndian.PutUint32(eci, 0x01234567&0x0FFFFFFF)
	data = append(data, eci...)

	payload := makeIE(IETypeULI, data)
	ies := ParseGTPv2IEs(payload)

	if ies.TAI != "208-93-TAC:1234" {
		t.Errorf("TAI = %q, want 208-93-TAC:1234", ies.TAI)
	}
	if ies.ECGI != "208-93-ECI:19088743" {
		t.Errorf("ECGI = %q, want 208-93-ECI:19088743", ies.ECGI)
	}
}

func TestParseGTPv2IEs_ChargingID(t *testing.T) {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, 12345678)
	payload := makeIE(IETypeChargingID, data)

	ies := ParseGTPv2IEs(payload)
	if ies.ChargingID != 12345678 {
		t.Errorf("ChargingID = %d, want 12345678", ies.ChargingID)
	}
}

func TestParseGTPv2IEs_FullCreateSession(t *testing.T) {
	// Simulate a Create Session Request with multiple IEs
	var payload []byte

	// IMSI
	payload = append(payload, makeIE(IETypeIMSI, []byte{0x13, 0x20, 0x06, 0x00, 0x00, 0x70, 0x84, 0x7F})...)

	// MSISDN
	payload = append(payload, makeIE(IETypeMSISDN, []byte{0x33, 0x55, 0x55, 0x12, 0x34, 0xF5})...)

	// MEI
	payload = append(payload, makeIE(IETypeMEI, []byte{0x68, 0x47, 0x30, 0x40, 0x16, 0x11, 0x70, 0xF0})...)

	// APN
	payload = append(payload, makeIE(IETypeAPN, []byte{8, 'i', 'n', 't', 'e', 'r', 'n', 'e', 't'})...)

	// RAT Type = E-UTRAN
	payload = append(payload, makeIE(IETypeRATType, []byte{6})...)

	// Serving Network: MCC=208, MNC=93
	payload = append(payload, makeIE(IETypeServingNetwork, []byte{0x02, 0xF8, 0x39})...)

	// AMBR: UL=50000, DL=100000
	ambrData := make([]byte, 8)
	binary.BigEndian.PutUint32(ambrData[0:4], 50000)
	binary.BigEndian.PutUint32(ambrData[4:8], 100000)
	payload = append(payload, makeIE(IETypeAMBR, ambrData)...)

	// PAA: IPv4 = 10.45.0.2
	paaData := []byte{1}
	paaData = append(paaData, net.ParseIP("10.45.0.2").To4()...)
	payload = append(payload, makeIE(IETypePAA, paaData)...)

	// F-TEID: S11 MME
	fteidData := make([]byte, 9)
	fteidData[0] = 0x80 | 10
	binary.BigEndian.PutUint32(fteidData[1:5], 0x00000001)
	copy(fteidData[5:9], net.ParseIP("192.168.2.10").To4())
	payload = append(payload, makeIE(IETypeFTEID, fteidData)...)

	// Bearer Context with EBI=5, QCI=9
	ebiIE := makeIE(IETypeEBI, []byte{5})
	qosData := make([]byte, 22)
	qosData[1] = 9
	qosIE := makeIE(IETypeBearerQoS, qosData)
	bcData := append(ebiIE, qosIE...)
	payload = append(payload, makeIE(IETypeBearerContext, bcData)...)

	ies := ParseGTPv2IEs(payload)

	if ies.IMSI == "" {
		t.Error("IMSI should not be empty")
	}
	if ies.MSISDN == "" {
		t.Error("MSISDN should not be empty")
	}
	if ies.MEI == "" {
		t.Error("MEI should not be empty")
	}
	if ies.APN != "internet" {
		t.Errorf("APN = %q, want internet", ies.APN)
	}
	if ies.RATType != "E-UTRAN" {
		t.Errorf("RATType = %q, want E-UTRAN", ies.RATType)
	}
	if ies.ServingMCCMNC != "208-93" {
		t.Errorf("ServingMCCMNC = %q, want 208-93", ies.ServingMCCMNC)
	}
	if ies.AMBRUplink != 50000 {
		t.Errorf("AMBRUplink = %d, want 50000", ies.AMBRUplink)
	}
	if ies.AMBRDownlink != 100000 {
		t.Errorf("AMBRDownlink = %d, want 100000", ies.AMBRDownlink)
	}
	if ies.PDNType != "IPv4" {
		t.Errorf("PDNType = %q, want IPv4", ies.PDNType)
	}
	if ies.PDNAddress != "10.45.0.2" {
		t.Errorf("PDNAddress = %q, want 10.45.0.2", ies.PDNAddress)
	}
	if len(ies.FTEIDs) != 1 {
		t.Errorf("expected 1 top-level FTEID, got %d", len(ies.FTEIDs))
	}
	if len(ies.Bearers) != 1 {
		t.Fatalf("expected 1 bearer, got %d", len(ies.Bearers))
	}
	if ies.Bearers[0].EBI != 5 {
		t.Errorf("Bearer EBI = %d, want 5", ies.Bearers[0].EBI)
	}
	if ies.Bearers[0].QCI != 9 {
		t.Errorf("Bearer QCI = %d, want 9", ies.Bearers[0].QCI)
	}

	// Verify ToMetrics produces expected keys
	m := ies.ToMetrics()
	if m["imsi"] == nil {
		t.Error("ToMetrics missing imsi")
	}
	if m["rat_type"] != "E-UTRAN" {
		t.Errorf("ToMetrics rat_type = %v", m["rat_type"])
	}
	if m["bearer_count"] != 1 {
		t.Errorf("ToMetrics bearer_count = %v", m["bearer_count"])
	}
	if m["pdn_address"] != "10.45.0.2" {
		t.Errorf("ToMetrics pdn_address = %v", m["pdn_address"])
	}
}

func TestParseGTPv2IEs_Empty(t *testing.T) {
	ies := ParseGTPv2IEs([]byte{})
	if ies.IMSI != "" || ies.APN != "" || len(ies.Bearers) != 0 {
		t.Error("expected empty IEs for empty input")
	}
	m := ies.ToMetrics()
	if len(m) != 0 {
		t.Errorf("expected empty metrics for empty IEs, got %d keys", len(m))
	}
}

func TestDecode5ByteRate(t *testing.T) {
	// Test 5-byte rate decoding: 0x00 0x00 0x00 0x03 0xE8 = 1000
	data := []byte{0, 0, 0, 0x03, 0xE8}
	got := decode5ByteRate(data)
	if got != 1000 {
		t.Errorf("decode5ByteRate = %d, want 1000", got)
	}

	// Large rate: 0x01 0x00 0x00 0x00 0x00 = 4294967296
	data2 := []byte{1, 0, 0, 0, 0}
	got2 := decode5ByteRate(data2)
	if got2 != 4294967296 {
		t.Errorf("decode5ByteRate = %d, want 4294967296", got2)
	}
}

func TestParseFTEID_V6(t *testing.T) {
	// F-TEID with IPv6 only
	data := make([]byte, 21) // 1(flags) + 4(TEID) + 16(IPv6)
	data[0] = 0x40 | 37     // V6 flag + interface type 37 (N3 gNB)
	binary.BigEndian.PutUint32(data[1:5], 0xDEADBEEF)
	ipv6 := net.ParseIP("2001:db8::1")
	copy(data[5:21], ipv6.To16())

	fteid := parseFTEID(data)
	if fteid == nil {
		t.Fatal("parseFTEID returned nil")
	}
	if fteid.InterfaceType != 37 {
		t.Errorf("InterfaceType = %d, want 37", fteid.InterfaceType)
	}
	if fteid.InterfaceName != "N3 gNB" {
		t.Errorf("InterfaceName = %q, want N3 gNB", fteid.InterfaceName)
	}
	if fteid.TEID != 0xDEADBEEF {
		t.Errorf("TEID = 0x%08x, want 0xDEADBEEF", fteid.TEID)
	}
	if fteid.IPv4 != "" {
		t.Errorf("IPv4 should be empty, got %q", fteid.IPv4)
	}
	if fteid.IPv6 != "2001:db8::1" {
		t.Errorf("IPv6 = %q, want 2001:db8::1", fteid.IPv6)
	}
}

func TestParseServingNetwork(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "MCC=208 MNC=93 (2-digit)",
			data: []byte{0x02, 0xF8, 0x39},
			want: "208-93",
		},
		{
			name: "MCC=310 MNC=260 (3-digit)",
			data: []byte{0x13, 0x00, 0x62},
			want: "310-260",
		},
		{
			name: "MCC=001 MNC=01 (test)",
			data: []byte{0x00, 0xF1, 0x10},
			want: "001-01",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseServingNetwork(tt.data)
			if got != tt.want {
				t.Errorf("parseServingNetwork = %q, want %q", got, tt.want)
			}
		})
	}
}
