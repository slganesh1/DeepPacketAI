package gtp

import (
	"encoding/binary"
	"strings"
)

// decodeBCD decodes a BCD-encoded byte slice into a digit string.
// Each byte contains two BCD digits: low nibble first, high nibble second.
// Nibble value 0xF is treated as padding and skipped.
func decodeBCD(data []byte) string {
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

// decodeAPN decodes a label-encoded APN (Access Point Name).
// Each segment is prefixed by a length byte; segments are joined with dots.
func decodeAPN(data []byte) string {
	var parts []string
	offset := 0
	for offset < len(data) {
		labelLen := int(data[offset])
		offset++
		if labelLen == 0 || offset+labelLen > len(data) {
			break
		}
		parts = append(parts, string(data[offset:offset+labelLen]))
		offset += labelLen
	}
	return strings.Join(parts, ".")
}

// extractSubscriberIEs scans GTP Information Elements after the header
// to extract IMSI, MSISDN, and APN values.
func extractSubscriberIEs(data []byte, version uint8) (imsi, msisdn, apn string) {
	if version == 2 {
		return extractSubscriberIEsV2(data)
	}
	if version == 1 {
		return extractSubscriberIEsV1(data)
	}
	return
}

// extractSubscriberIEsV2 parses GTPv2-C IEs.
// Format: IEType(1B) + Length(2B BE) + Spare(1B) + Data(LengthB)
func extractSubscriberIEsV2(data []byte) (imsi, msisdn, apn string) {
	offset := 0
	for offset+4 <= len(data) {
		ieType := data[offset]
		if offset+3 > len(data) {
			break
		}
		ieLen := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
		// Spare byte at offset+3, data starts at offset+4
		dataStart := offset + 4
		if dataStart+ieLen > len(data) {
			break
		}
		ieData := data[dataStart : dataStart+ieLen]

		switch ieType {
		case 1: // IMSI
			imsi = decodeBCD(ieData)
		case 76: // MSISDN
			msisdn = decodeBCD(ieData)
		case 71: // APN
			apn = decodeAPN(ieData)
		}

		offset = dataStart + ieLen
	}
	return
}

// extractSubscriberIEsV1 parses GTPv1-C IEs.
// Uses a mix of TV (type-value, fixed length) and TLV (type-length-value) formats.
func extractSubscriberIEsV1(data []byte) (imsi, msisdn, apn string) {
	offset := 0
	for offset < len(data) {
		ieType := data[offset]

		if ieType < 128 {
			// TV-format IEs (type < 128) have fixed sizes
			switch ieType {
			case 2: // IMSI — fixed 8 bytes BCD
				if offset+9 > len(data) {
					return
				}
				imsi = decodeBCD(data[offset+1 : offset+9])
				offset += 9
			case 1: // Cause — 1 byte value
				offset += 2
			case 3: // Routing Area Identity — 6 bytes
				offset += 7
			case 4: // TLLI — 4 bytes
				offset += 5
			case 5: // P-TMSI — 4 bytes
				offset += 5
			case 8: // Reordering Required — 1 byte
				offset += 2
			case 9: // Authentication Triplet — 28 bytes
				offset += 29
			case 11: // MAP Cause — 1 byte
				offset += 2
			case 12: // P-TMSI Signature — 3 bytes
				offset += 4
			case 13: // MS Validated — 1 byte
				offset += 2
			case 14: // Recovery — 1 byte
				offset += 2
			case 15: // Selection Mode — 1 byte
				offset += 2
			case 16: // Flow Label Data I — 2 bytes
				offset += 3
			case 17: // Flow Label Signalling — 2 bytes
				offset += 3
			case 18: // Flow Label Data II — 4 bytes
				offset += 5
			case 19: // MS Not Reachable Reason — 1 byte
				offset += 2
			case 20: // Charging ID — 4 bytes
				offset += 5
			default:
				// Unknown TV IE — we can't determine its length, so stop
				return
			}
		} else {
			// TLV-format IEs (type >= 128)
			if offset+3 > len(data) {
				return
			}
			tlvLen := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
			dataStart := offset + 3
			if dataStart+tlvLen > len(data) {
				return
			}
			tlvData := data[dataStart : dataStart+tlvLen]

			switch ieType {
			case 132: // APN (0x84)
				apn = decodeAPN(tlvData)
			case 133: // MSISDN (0x85)
				// MSISDN TLV may have a leading flags byte; skip it
				if len(tlvData) > 1 {
					msisdn = decodeBCD(tlvData[1:])
				}
			}

			offset = dataStart + tlvLen
		}
	}
	return
}
