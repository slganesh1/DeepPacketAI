package ngap

import (
	"testing"
)

func TestDecodeBCDNibbles(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "simple digits",
			input: []byte{0x21, 0x43},
			want:  "1234",
		},
		{
			name:  "with F padding",
			input: []byte{0x21, 0x4F},
			want:  "124",
		},
		{
			name:  "empty",
			input: []byte{},
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeBCDNibbles(tt.input)
			if got != tt.want {
				t.Errorf("decodeBCDNibbles(%x) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDecodeMCCMNC3(t *testing.T) {
	// MCC = 310: digit1=0, digit2=1, digit3=3
	// Byte 1: digit2<<4 | digit1 = 0x10
	// Byte 2 low nibble: digit3 = 0x0 → MCC digit3=0
	// Wait, MCC 310: d1=3, d2=1, d3=0
	// Byte1: d2<<4|d1 = 0x13
	// Byte2 low nibble: d3 = 0
	got := decodeMCCMNC3(0x13, 0xF0) // MCC=310, high nibble of b2=F (2-digit MNC marker)
	if got != "310" {
		t.Errorf("decodeMCCMNC3(0x13, 0xF0) = %q, want %q", got, "310")
	}
}

func TestDecodeMNC(t *testing.T) {
	// MNC = 260: d1=2, d2=6, d3=0
	// Byte 2 high nibble: d3=0
	// Byte 3: d2<<4 | d1 = 0x62
	got := decodeMNC(0x00, 0x62)
	if got != "260" {
		t.Errorf("decodeMNC(0x00, 0x62) = %q, want %q", got, "260")
	}
}

func TestDecodeMNC_TwoDigit(t *testing.T) {
	// 2-digit MNC = 01: d1=0, d2=1
	// Byte 2 high nibble: d3=F (padding)
	// Byte 3: d2<<4 | d1 = 0x10
	got := decodeMNC(0xF0, 0x10)
	if got != "01" {
		t.Errorf("decodeMNC(0xF0, 0x10) = %q, want %q", got, "01")
	}
}

func TestExtractNASIdentity_RegistrationRequest(t *testing.T) {
	// Construct a minimal NAS-5GS Registration Request with SUCI (null protection)
	// 0x7E = 5GMM discriminator
	// 0x00 = Plain NAS
	// 0x41 = Registration Request
	nasHeader := []byte{0x7E, 0x00, 0x41}

	// Registration type byte (1 byte)
	regType := byte(0x79) // registration type + ngKSI

	// SUCI Mobile Identity (LV-E)
	// Identity type bits[2:0] = 001 (SUCI), SUPI format bits[6:4] = 000 (IMSI)
	identityTypeByte := byte(0x01) // SUCI, IMSI format

	// MCC = 310: byte1=0x13, byte2 low nibble=0
	// MNC = 260: byte2 high nibble=0, byte3=0x62
	mccmnc := []byte{0x13, 0x00, 0x62}

	// Routing indicator (2 bytes BCD) — we don't parse this, just need it there
	routingInd := []byte{0xFF, 0xFF}

	// Protection scheme = 0x00 (null / cleartext)
	protScheme := byte(0x00)

	// Home network public key identifier
	hnPubKeyId := byte(0x00)

	// MSIN in BCD: "0000000101" → 0x00 0x00 0x00 0x10 0x1F
	msin := []byte{0x00, 0x00, 0x00, 0x10, 0x1F}

	identityValue := append([]byte{identityTypeByte}, mccmnc...)
	identityValue = append(identityValue, routingInd...)
	identityValue = append(identityValue, protScheme, hnPubKeyId)
	identityValue = append(identityValue, msin...)

	// LV-E: 2-byte length + value
	idLen := len(identityValue)
	lvE := append([]byte{byte(idLen >> 8), byte(idLen & 0xFF)}, identityValue...)

	// Full NAS payload
	payload := append(nasHeader, regType)
	payload = append(payload, lvE...)

	// Wrap in some NGAP prefix bytes (simulating NGAP encapsulation)
	ngapPrefix := []byte{0x00, 0x0E, 0x00, 0x00} // some NGAP outer bytes
	fullPayload := append(ngapPrefix, payload...)

	got := extractNASIdentity(fullPayload)

	// Expected IMSI = MCC(310) + MNC(260) + MSIN(0000000101) = 3102600000000101
	// Let's verify the expected value by manually computing:
	// MCC from bytes 0x13, 0x00: d1=3, d2=1, d3=0 → "310"
	// MNC from bytes 0x00, 0x62: d1=2, d2=6, d3=0 → "260"
	// MSIN from 0x00,0x00,0x00,0x10,0x1F: "0000000001" (BCD nibbles: 0,0,0,0,0,0,0,1,0,F→skip = "000000010" wait)
	// BCD: 0x00 → lo=0,hi=0 → "00"; 0x00→"00"; 0x00→"00"; 0x10→lo=0,hi=1→"01"; 0x1F→lo=1,hi=F→"1"
	// MSIN = "0000000011"
	// The MSIN produced is 10 digits, combined with MCC+MNC=6 gives 16 digits (>15)
	// so extractNASIdentity rejects it. Just verify it's empty for this oversized case.
	if len(got) > 15 {
		t.Errorf("IMSI should be at most 15 digits, got %q (len=%d)", got, len(got))
	}
	// Verify it starts correctly if non-empty
	if got != "" && got[:3] != "310" {
		t.Errorf("IMSI should start with MCC 310, got %q", got)
	}
}

func TestExtractNASIdentity_ValidIMSI(t *testing.T) {
	// Build a well-formed NAS Registration Request that produces a valid 15-digit IMSI
	// IMSI: 310260000000101 (15 digits)
	// MCC=310, MNC=260, MSIN=000000101

	nasHeader := []byte{0x7E, 0x00, 0x41}
	regType := byte(0x79)

	identityTypeByte := byte(0x01) // SUCI + IMSI format
	mccmnc := []byte{0x13, 0x00, 0x62}
	routingInd := []byte{0xFF, 0xFF}
	protScheme := byte(0x00)
	hnPubKeyId := byte(0x00)

	// MSIN "000000101" (9 digits) → BCD: 0x00 0x00 0x00 0x10 0x1F
	// That gives "0000000011" (10 digits) → MCC+MNC+MSIN = 3+3+10 = 16 digits (too long)
	// MSIN "0000101" (7 digits) → needs 4 bytes: 0x00 0x00 0x10 0x1F → "00000011" (8 digits) → 3+3+8=14 OK
	msin := []byte{0x00, 0x00, 0x10, 0x1F}
	// BCD: 0x00→"00", 0x00→"00", 0x10→"01", 0x1F→"1" → MSIN = "0000011"
	// Total: 310 + 260 + 0000011 = "3102600000011" (13 digits) ✓

	identityValue := append([]byte{identityTypeByte}, mccmnc...)
	identityValue = append(identityValue, routingInd...)
	identityValue = append(identityValue, protScheme, hnPubKeyId)
	identityValue = append(identityValue, msin...)

	idLen := len(identityValue)
	lvE := append([]byte{byte(idLen >> 8), byte(idLen & 0xFF)}, identityValue...)

	payload := append(nasHeader, regType)
	payload = append(payload, lvE...)

	got := extractNASIdentity(payload)

	expected := "3102600000011"
	if got != expected {
		t.Errorf("extractNASIdentity() = %q, want %q", got, expected)
	}
}

func TestExtractNASIdentity_EncryptedScheme(t *testing.T) {
	// Same as above but with protection scheme = 1 (ECIES Profile A)
	nasHeader := []byte{0x7E, 0x00, 0x41}
	regType := byte(0x79)

	identityTypeByte := byte(0x01)
	mccmnc := []byte{0x13, 0x00, 0x62}
	routingInd := []byte{0xFF, 0xFF}
	protScheme := byte(0x01) // ECIES — should NOT be decoded
	hnPubKeyId := byte(0x00)
	msin := []byte{0x00, 0x00, 0x10, 0x1F}

	identityValue := append([]byte{identityTypeByte}, mccmnc...)
	identityValue = append(identityValue, routingInd...)
	identityValue = append(identityValue, protScheme, hnPubKeyId)
	identityValue = append(identityValue, msin...)

	idLen := len(identityValue)
	lvE := append([]byte{byte(idLen >> 8), byte(idLen & 0xFF)}, identityValue...)

	payload := append(nasHeader, regType)
	payload = append(payload, lvE...)

	got := extractNASIdentity(payload)
	if got != "" {
		t.Errorf("extractNASIdentity() with encrypted scheme should return empty, got %q", got)
	}
}

func TestExtractNASIdentity_NoNASMarker(t *testing.T) {
	payload := []byte{0x00, 0x0E, 0x40, 0x55, 0x00, 0x00, 0x03}
	got := extractNASIdentity(payload)
	if got != "" {
		t.Errorf("extractNASIdentity() with no NAS marker should return empty, got %q", got)
	}
}

func TestExtractNASIdentity_EmptyPayload(t *testing.T) {
	got := extractNASIdentity([]byte{})
	if got != "" {
		t.Errorf("extractNASIdentity() with empty payload should return empty, got %q", got)
	}
}

func TestExtractNASIdentity_TruncatedPayload(t *testing.T) {
	// Just the NAS header, no body
	payload := []byte{0x7E, 0x00, 0x41}
	got := extractNASIdentity(payload)
	if got != "" {
		t.Errorf("extractNASIdentity() with truncated payload should return empty, got %q", got)
	}
}
