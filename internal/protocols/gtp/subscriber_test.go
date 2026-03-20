package gtp

import (
	"encoding/binary"
	"testing"
)

func TestDecodeBCD(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "simple IMSI",
			input: []byte{0x13, 0x20, 0x06, 0x00, 0x00, 0x00, 0x10},
			want:  "31026000000001",
		},
		{
			name:  "with F padding",
			input: []byte{0x13, 0x20, 0x06, 0x00, 0x00, 0x00, 0x1F},
			want:  "3102600000001",
		},
		{
			name:  "all zeros",
			input: []byte{0x00, 0x00, 0x00},
			want:  "000000",
		},
		{
			name:  "empty",
			input: []byte{},
			want:  "",
		},
		{
			name:  "single byte",
			input: []byte{0x21},
			want:  "12",
		},
		{
			name:  "F in low nibble skipped",
			input: []byte{0xFF},
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeBCD(tt.input)
			if got != tt.want {
				t.Errorf("decodeBCD(%x) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDecodeAPN(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "internet",
			input: []byte{8, 'i', 'n', 't', 'e', 'r', 'n', 'e', 't'},
			want:  "internet",
		},
		{
			name:  "two labels",
			input: []byte{3, 'i', 'm', 's', 10, 'm', 'n', 'c', '0', '0', '1', '.', 'm', 'c', 'c'},
			want:  "ims.mnc001.mcc",
		},
		{
			name:  "empty",
			input: []byte{},
			want:  "",
		},
		{
			name:  "zero length label",
			input: []byte{0},
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeAPN(tt.input)
			if got != tt.want {
				t.Errorf("decodeAPN(%x) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractSubscriberIEsV2(t *testing.T) {
	// Build a GTPv2-C IE payload with IMSI (type 1), MSISDN (type 76), APN (type 71)

	// IMSI IE: type=1, length=8, spare=0, data=BCD(310260000000101)
	imsiData := []byte{0x13, 0x20, 0x06, 0x00, 0x00, 0x00, 0x01, 0x0F}
	imsiIE := makeGTPv2IE(1, imsiData)

	// MSISDN IE: type=76, length=6, spare=0, data=BCD(15551234567)
	msisdnData := []byte{0x51, 0x55, 0x21, 0x43, 0x65, 0x7F}
	msisdnIE := makeGTPv2IE(76, msisdnData)

	// APN IE: type=71, length depends on content
	apnData := []byte{8, 'i', 'n', 't', 'e', 'r', 'n', 'e', 't'}
	apnIE := makeGTPv2IE(71, apnData)

	payload := append(append(imsiIE, msisdnIE...), apnIE...)

	imsi, msisdn, apn := extractSubscriberIEs(payload, 2)

	expectedIMSI := decodeBCD(imsiData)
	if imsi != expectedIMSI {
		t.Errorf("IMSI = %q, want %q", imsi, expectedIMSI)
	}

	expectedMSISDN := decodeBCD(msisdnData)
	if msisdn != expectedMSISDN {
		t.Errorf("MSISDN = %q, want %q", msisdn, expectedMSISDN)
	}

	if apn != "internet" {
		t.Errorf("APN = %q, want %q", apn, "internet")
	}
}

func TestExtractSubscriberIEsV2_Empty(t *testing.T) {
	imsi, msisdn, apn := extractSubscriberIEs([]byte{}, 2)
	if imsi != "" || msisdn != "" || apn != "" {
		t.Errorf("expected empty results for empty payload, got imsi=%q msisdn=%q apn=%q", imsi, msisdn, apn)
	}
}

func TestExtractSubscriberIEsV2_NoSubscriberIEs(t *testing.T) {
	// Build a cause IE (type 2) only
	causeIE := makeGTPv2IE(2, []byte{16}) // cause=16 (Request Accepted)
	imsi, msisdn, apn := extractSubscriberIEs(causeIE, 2)
	if imsi != "" || msisdn != "" || apn != "" {
		t.Errorf("expected empty for non-subscriber IEs, got imsi=%q msisdn=%q apn=%q", imsi, msisdn, apn)
	}
}

func TestExtractSubscriberIEsV1(t *testing.T) {
	// Build a GTPv1-C payload with IMSI (type 2, TV format, 8 bytes BCD)
	var payload []byte

	// IMSI TV: type=2, 8 bytes BCD
	payload = append(payload, 2) // IE type
	imsiData := []byte{0x13, 0x20, 0x06, 0x00, 0x00, 0x00, 0x01, 0x0F}
	payload = append(payload, imsiData...)

	imsi, _, _ := extractSubscriberIEs(payload, 1)
	expectedIMSI := decodeBCD(imsiData)
	if imsi != expectedIMSI {
		t.Errorf("IMSI = %q, want %q", imsi, expectedIMSI)
	}
}

func TestExtractSubscriberIEsUnsupportedVersion(t *testing.T) {
	imsi, msisdn, apn := extractSubscriberIEs([]byte{1, 0, 8, 0, 0x13}, 3)
	if imsi != "" || msisdn != "" || apn != "" {
		t.Errorf("expected empty for unsupported version 3")
	}
}

// makeGTPv2IE constructs a GTPv2-C IE: type(1B) + length(2B BE) + spare(1B) + data
func makeGTPv2IE(ieType byte, data []byte) []byte {
	ie := make([]byte, 4+len(data))
	ie[0] = ieType
	binary.BigEndian.PutUint16(ie[1:3], uint16(len(data)))
	ie[3] = 0 // spare
	copy(ie[4:], data)
	return ie
}
