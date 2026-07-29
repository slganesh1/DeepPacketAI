package snmp

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var errTruncated = errors.New("snmp: truncated BER element")

// readTLV reads one BER Tag-Length-Value element starting at offset in data,
// returning the tag byte, the content slice, and the offset of the next element.
// Only single-byte tags and definite-form lengths (short or long) are supported —
// sufficient for SNMP v1/v2c, which never uses high-tag-number or indefinite form.
func readTLV(data []byte, offset int) (tag byte, content []byte, next int, err error) {
	if offset >= len(data) {
		return 0, nil, offset, errTruncated
	}
	tag = data[offset]
	offset++

	if offset >= len(data) {
		return 0, nil, offset, errTruncated
	}
	lenByte := data[offset]
	offset++

	var length int
	if lenByte&0x80 == 0 {
		length = int(lenByte)
	} else {
		numBytes := int(lenByte & 0x7F)
		if numBytes == 0 || numBytes > 4 || offset+numBytes > len(data) {
			return 0, nil, offset, errTruncated
		}
		for i := 0; i < numBytes; i++ {
			length = (length << 8) | int(data[offset])
			offset++
		}
	}
	if length < 0 || offset+length > len(data) {
		return 0, nil, offset, errTruncated
	}
	return tag, data[offset : offset+length], offset + length, nil
}

// decodeInt decodes a BER INTEGER (signed, big-endian, minimal-length two's complement).
func decodeInt(b []byte) int64 {
	if len(b) == 0 {
		return 0
	}
	v := int64(int8(b[0])) // sign-extend the leading byte
	for _, c := range b[1:] {
		v = (v << 8) | int64(c)
	}
	return v
}

// decodeUint decodes an unsigned application-specific value (Counter32/Gauge32/
// TimeTicks/Counter64) — same encoding as INTEGER but never sign-extended.
func decodeUint(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = (v << 8) | uint64(c)
	}
	return v
}

// decodeOID decodes a BER OBJECT IDENTIFIER into dotted-decimal notation.
func decodeOID(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	first := int(b[0])
	parts := []int{first / 40, first % 40}

	val := 0
	for _, c := range b[1:] {
		val = (val << 7) | int(c&0x7F)
		if c&0x80 == 0 {
			parts = append(parts, val)
			val = 0
		}
	}

	strs := make([]string, len(parts))
	for i, p := range parts {
		strs[i] = strconv.Itoa(p)
	}
	return strings.Join(strs, ".")
}

// isPrintableASCII reports whether every byte is a printable, non-control character.
func isPrintableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}

// formatValue renders a varbind value tag+content as a human-readable string.
func formatValue(tag byte, content []byte) string {
	switch tag {
	case tagInteger:
		return strconv.FormatInt(decodeInt(content), 10)
	case tagOctetString:
		if isPrintableASCII(content) {
			return string(content)
		}
		return "0x" + hex.EncodeToString(content)
	case tagNull:
		return ""
	case tagOID:
		return decodeOID(content)
	case tagIPAddress:
		if len(content) == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", content[0], content[1], content[2], content[3])
		}
		return "0x" + hex.EncodeToString(content)
	case tagCounter32, tagGauge32, tagTimeTicks, tagCounter64:
		return strconv.FormatUint(decodeUint(content), 10)
	case tagOpaque:
		return "0x" + hex.EncodeToString(content)
	case tagNoSuchObject:
		return "noSuchObject"
	case tagNoSuchInstance:
		return "noSuchInstance"
	case tagEndOfMibView:
		return "endOfMibView"
	default:
		return "0x" + hex.EncodeToString(content)
	}
}

// parseVarBindList parses a VarBindList SEQUENCE OF { name OID, value ANY }.
func parseVarBindList(data []byte) []VarBind {
	tag, content, _, err := readTLV(data, 0)
	if err != nil || tag != tagSequence {
		return nil
	}

	var vbs []VarBind
	offset := 0
	for offset < len(content) {
		vbTag, vbContent, next, err := readTLV(content, offset)
		if err != nil {
			break
		}
		offset = next
		if vbTag != tagSequence {
			continue
		}

		oidTag, oidContent, oidNext, err := readTLV(vbContent, 0)
		if err != nil || oidTag != tagOID {
			continue
		}
		oid := decodeOID(oidContent)

		valTag, valContent, _, err := readTLV(vbContent, oidNext)
		value := ""
		if err == nil {
			value = formatValue(valTag, valContent)
		}
		vbs = append(vbs, VarBind{OID: oid, Value: value})
	}
	return vbs
}
