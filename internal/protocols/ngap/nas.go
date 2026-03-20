package ngap

import "strings"

// extractNASIdentity performs a heuristic scan of the NGAP payload for a
// NAS-5GS Registration Request containing a SUCI with null protection scheme,
// and extracts the cleartext IMSI.
//
// Limitations:
//   - Only works on plain NAS (security header type 0x00) — encrypted NAS is opaque
//   - Only works with null protection scheme (0x00) — ECIES-encrypted SUCI cannot be decoded
//   - Heuristic byte scanning instead of full ASN.1 APER decoding
func extractNASIdentity(payload []byte) string {
	// Scan for NAS-5GS Registration Request marker:
	//   0x7E = 5GS Mobility Management (5GMM) protocol discriminator
	//   0x00 = Plain NAS (security header type = 0)
	//   0x41 = Registration Request message type
	for i := 0; i+3 < len(payload); i++ {
		if payload[i] == 0x7E && payload[i+1] == 0x00 && payload[i+2] == 0x41 {
			result := parseRegistrationRequest(payload[i+3:])
			if result != "" {
				return result
			}
		}
	}
	return ""
}

// parseRegistrationRequest parses the body of a Registration Request starting
// after the message type byte (0x41).
func parseRegistrationRequest(data []byte) string {
	// Registration Type is 1 byte (ngKSI + registration type)
	if len(data) < 3 {
		return ""
	}

	// Skip Registration Type (1 byte)
	offset := 1

	// 5GS Mobile Identity — LV-E format: 2-byte length + value
	if offset+2 > len(data) {
		return ""
	}
	idLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	if idLen < 4 || offset+idLen > len(data) {
		return ""
	}

	idValue := data[offset : offset+idLen]
	return parseSUCI(idValue)
}

// parseSUCI decodes a SUCI (Subscription Concealed Identifier) from the
// 5GS Mobile Identity value bytes.
func parseSUCI(data []byte) string {
	if len(data) < 8 {
		return ""
	}

	// Byte 0: spare(4 bits) | SUPI format(3 bits) | identity type(3 bits)
	// Actually: byte 0 lower 3 bits = identity type, bits 3-6 = SUPI format
	identityType := data[0] & 0x07
	supiFormat := (data[0] >> 4) & 0x07

	// Identity type must be 001 (SUCI)
	if identityType != 1 {
		return ""
	}

	// SUPI format must be 0 (IMSI)
	if supiFormat != 0 {
		return ""
	}

	// Bytes 1-2: MCC + MNC (BCD encoded, 3 bytes total starting at byte 1)
	if len(data) < 8 {
		return ""
	}

	mcc := decodeMCCMNC3(data[1], data[2])
	mnc := decodeMNC(data[2], data[3])

	// Byte 4-5: Routing Indicator (BCD, 2 bytes) — we skip it
	// Byte 6: Protection scheme ID
	// Byte 7: Home network public key identifier

	protectionScheme := data[6]

	// Only decode if protection scheme is null (0x00 = cleartext)
	if protectionScheme != 0x00 {
		return ""
	}

	// Bytes 8+: MSIN in BCD encoding
	if len(data) <= 8 {
		return ""
	}

	msin := decodeBCDNibbles(data[8:])

	imsi := mcc + mnc + msin

	// Validate: IMSI should be 10-15 digits
	if len(imsi) < 10 || len(imsi) > 15 {
		return ""
	}

	// Verify all digits
	for _, c := range imsi {
		if c < '0' || c > '9' {
			return ""
		}
	}

	return imsi
}

// decodeMCCMNC3 decodes MCC from two BCD bytes.
// Byte 1: digit2 | digit1 (MCC digit 1 = low nibble, MCC digit 2 = high nibble)
// Byte 2: MNC digit 3 | MCC digit 3
func decodeMCCMNC3(b1, b2 byte) string {
	d1 := b1 & 0x0F
	d2 := (b1 >> 4) & 0x0F
	d3 := b2 & 0x0F

	var sb strings.Builder
	if d1 <= 9 {
		sb.WriteByte('0' + d1)
	}
	if d2 <= 9 {
		sb.WriteByte('0' + d2)
	}
	if d3 <= 9 {
		sb.WriteByte('0' + d3)
	}
	return sb.String()
}

// decodeMNC decodes MNC from two bytes.
// Byte 2 (same b2 from MCC): high nibble = MNC digit 3 (0xF if 2-digit MNC)
// Byte 3: MNC digit 2 | MNC digit 1
func decodeMNC(b2, b3 byte) string {
	d1 := b3 & 0x0F
	d2 := (b3 >> 4) & 0x0F
	d3 := (b2 >> 4) & 0x0F

	var sb strings.Builder
	if d1 <= 9 {
		sb.WriteByte('0' + d1)
	}
	if d2 <= 9 {
		sb.WriteByte('0' + d2)
	}
	// d3 = 0xF means 2-digit MNC, skip it
	if d3 <= 9 {
		sb.WriteByte('0' + d3)
	}
	return sb.String()
}

// decodeBCDNibbles decodes BCD-encoded bytes to a digit string.
// Each byte: low nibble first, high nibble second. 0xF = padding (skip).
func decodeBCDNibbles(data []byte) string {
	var sb strings.Builder
	sb.Grow(len(data) * 2)
	for _, b := range data {
		lo := b & 0x0F
		hi := (b >> 4) & 0x0F
		if lo <= 9 {
			sb.WriteByte('0' + lo)
		}
		if hi <= 9 {
			sb.WriteByte('0' + hi)
		}
	}
	return sb.String()
}
