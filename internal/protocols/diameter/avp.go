package diameter

import (
	"encoding/binary"
	"fmt"
)

// AVP codes for commonly parsed AVPs.
const (
	AVPSessionID          uint32 = 263
	AVPResultCode         uint32 = 268
	AVPOriginHost         uint32 = 264
	AVPOriginRealm        uint32 = 296
	AVPDestinationHost    uint32 = 293
	AVPDestinationRealm   uint32 = 283
	AVPAuthAppID          uint32 = 258
	AVPCCRequestType      uint32 = 416
	AVPCCRequestNumber    uint32 = 415
	AVPUserName           uint32 = 1
	AVPSubscriptionID     uint32 = 443
	AVPSubscriptionIDType uint32 = 450
	AVPSubscriptionIDData uint32 = 444
	AVP3GPPMSISDN         uint32 = 701
)

// AVP represents a parsed Diameter AVP.
type AVP struct {
	Code     uint32
	Flags    uint8
	Length   uint32
	VendorID uint32
	Data     []byte
}

// ParseAVPs parses AVPs from a Diameter message body.
func ParseAVPs(data []byte) []AVP {
	var avps []AVP
	offset := 0

	for offset+8 <= len(data) {
		code := binary.BigEndian.Uint32(data[offset : offset+4])
		flags := data[offset+4]
		length := uint32(data[offset+5])<<16 | uint32(data[offset+6])<<8 | uint32(data[offset+7])

		if length < 8 || int(length) > len(data)-offset {
			break
		}

		avp := AVP{
			Code:   code,
			Flags:  flags,
			Length: length,
		}

		headerLen := 8
		vendorBit := (flags & 0x80) != 0
		if vendorBit {
			if offset+12 > len(data) {
				break
			}
			avp.VendorID = binary.BigEndian.Uint32(data[offset+8 : offset+12])
			headerLen = 12
		}

		dataEnd := offset + int(length)
		if dataEnd > len(data) {
			dataEnd = len(data)
		}
		avp.Data = data[offset+headerLen : dataEnd]
		avps = append(avps, avp)

		// Pad to 4-byte boundary
		padded := int(length)
		if padded%4 != 0 {
			padded += 4 - (padded % 4)
		}
		offset += padded
	}

	return avps
}

// ExtractString returns the AVP data as a string.
func (a *AVP) ExtractString() string {
	return string(a.Data)
}

// ExtractUint32 returns the AVP data as a uint32.
func (a *AVP) ExtractUint32() uint32 {
	if len(a.Data) >= 4 {
		return binary.BigEndian.Uint32(a.Data[:4])
	}
	return 0
}

// ParseGroupedAVP parses the data of a grouped AVP as a list of sub-AVPs.
func (a *AVP) ParseGroupedAVP() []AVP {
	return ParseAVPs(a.Data)
}

// ResultCodeName returns a human-readable result code name.
func ResultCodeName(code uint32) string {
	names := map[uint32]string{
		1001: "MULTI_ROUND_AUTH",
		2001: "SUCCESS",
		2002: "LIMITED_SUCCESS",
		3001: "COMMAND_UNSUPPORTED",
		3002: "UNABLE_TO_DELIVER",
		3003: "REALM_NOT_SERVED",
		3004: "TOO_BUSY",
		3005: "LOOP_DETECTED",
		3006: "REDIRECT_INDICATION",
		3007: "APPLICATION_UNSUPPORTED",
		3008: "INVALID_HDR_BITS",
		3009: "INVALID_AVP_BITS",
		3010: "UNKNOWN_PEER",
		4001: "AUTHENTICATION_REJECTED",
		4181: "AUTHENTICATION_DATA_UNAVAILABLE",
		5001: "AVP_UNSUPPORTED",
		5002: "UNKNOWN_SESSION_ID",
		5003: "AUTHORIZATION_REJECTED",
		5004: "INVALID_AVP_VALUE",
		5005: "MISSING_AVP",
		5006: "RESOURCES_EXCEEDED",
		5007: "CONTRADICTING_AVPS",
		5008: "AVP_NOT_ALLOWED",
		5009: "AVP_OCCURS_TOO_MANY_TIMES",
		5010: "NO_COMMON_APPLICATION",
		5011: "UNSUPPORTED_VERSION",
		5012: "UNABLE_TO_COMPLY",
		5030: "USER_UNKNOWN",
		5031: "RAT_NOT_ALLOWED",
		5032: "ROAMING_NOT_ALLOWED",
	}
	if name, ok := names[code]; ok {
		return name
	}
	return fmt.Sprintf("RESULT_%d", code)
}
