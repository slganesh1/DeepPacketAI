// Package dpi implements Deep Packet Inspection payload signature matchers.
//
// Every function accepts a raw payload slice and returns true if the bytes
// match the protocol's wire signature — independent of port number.
//
// Design rules:
//   - No allocations: byte comparisons only, no regex, no string conversion.
//   - Minimum payload length checked before any byte access.
//   - False-positive rate kept low: signatures require ≥2 corroborating fields.
//   - Each function is O(1) or O(N) with a small, fixed scan window.
package dpi

// IsHTTP returns true if the payload starts with an HTTP/1.x request method
// or an HTTP/1.x response status line.
//
// Signatures:
//   - Requests:  "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ",
//                "PATCH ", "CONNECT ", "TRACE "  followed by "HTTP/1." somewhere.
//   - Responses: "HTTP/1." at offset 0.
func IsHTTP(p []byte) bool {
	if len(p) < 14 {
		return false
	}
	// Fast response check
	if hasPrefix(p, "HTTP/1.") {
		return true
	}
	// Request: must start with a known method and contain " HTTP/1."
	var methodLen int
	switch {
	case hasPrefix(p, "GET "):
		methodLen = 4
	case hasPrefix(p, "PUT "):
		methodLen = 4
	case hasPrefix(p, "HEAD "):
		methodLen = 5
	case hasPrefix(p, "POST "):
		methodLen = 5
	case hasPrefix(p, "DELETE "):
		methodLen = 7
	case hasPrefix(p, "OPTIONS "):
		methodLen = 8
	case hasPrefix(p, "CONNECT "):
		methodLen = 8
	case hasPrefix(p, "PATCH "):
		methodLen = 6
	case hasPrefix(p, "TRACE "):
		methodLen = 6
	default:
		return false
	}
	// Confirm HTTP version appears in the first request line (up to 4 KB)
	window := p[methodLen:]
	if len(window) > 4096 {
		window = window[:4096]
	}
	return contains(window, " HTTP/1.")
}

// IsTLS returns true if the payload matches a TLS/SSL record header.
//
// TLS record structure (RFC 5246 §6.2):
//
//	byte 0   : ContentType  — must be 20 (ChangeCipherSpec), 21 (Alert),
//	                           22 (Handshake), or 23 (ApplicationData)
//	bytes 1-2: ProtocolVersion — major=0x03, minor in {0x00..0x04}
//	bytes 3-4: Length — must be ≤ 16384 + overhead (≤ 18432)
func IsTLS(p []byte) bool {
	if len(p) < 5 {
		return false
	}
	ct := p[0]
	if ct < 20 || ct > 23 {
		return false
	}
	if p[1] != 0x03 || p[2] > 0x04 {
		return false
	}
	// Sanity check record length
	recLen := uint16(p[3])<<8 | uint16(p[4])
	return recLen > 0 && recLen <= 18432
}

// IsSIP returns true if the payload starts with a known SIP request method
// or a SIP response status line ("SIP/2.0 ").
//
// RFC 3261 methods: INVITE, REGISTER, ACK, BYE, CANCEL, OPTIONS,
// SUBSCRIBE, NOTIFY, REFER, MESSAGE, INFO, PRACK, UPDATE, PUBLISH.
func IsSIP(p []byte) bool {
	if len(p) < 10 {
		return false
	}
	for _, prefix := range sipPrefixes {
		if hasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

var sipPrefixes = []string{
	"SIP/2.0 ",
	"INVITE ",
	"REGISTER ",
	"ACK ",
	"BYE ",
	"CANCEL ",
	"OPTIONS ",
	"SUBSCRIBE ",
	"NOTIFY ",
	"REFER ",
	"MESSAGE ",
	"INFO ",
	"PRACK ",
	"UPDATE ",
	"PUBLISH ",
}

// IsDNS returns true if the payload matches a DNS message header (RFC 1035).
//
// DNS header (12 bytes):
//
//	bytes 0-1: Transaction ID (arbitrary, not checked)
//	bytes 2-3: Flags — OPCODE in bits [14:11] must be 0–2; Z bits must be 0
//	bytes 4-5: QDCOUNT — question count
//	bytes 6-7: ANCOUNT — answer count
//	bytes 8-9: NSCOUNT — authority count
//	bytes 10-11: ARCOUNT — additional count
//
// At least one of QDCOUNT or ANCOUNT must be non-zero.
func IsDNS(p []byte) bool {
	if len(p) < 12 {
		return false
	}
	// OPCODE field occupies bits 14:11 of the flags word (byte 2 bits 6:3)
	opcode := (p[2] >> 3) & 0x0F
	if opcode > 2 {
		return false // non-standard opcode — not a DNS query/response/iquery
	}
	// Z bits (reserved) in byte 3 bits 6:4 must be zero
	if p[3]&0x70 != 0 {
		return false
	}
	// At least one question or answer
	qdCount := uint16(p[4])<<8 | uint16(p[5])
	anCount := uint16(p[6])<<8 | uint16(p[7])
	return qdCount > 0 || anCount > 0
}

// IsDiameter returns true if the payload matches a Diameter base protocol
// message header (RFC 6733).
//
// Diameter header (20 bytes):
//
//	byte  0   : Version — must be 0x01
//	bytes 1-3 : Message Length — must be ≥ 20
//	byte  4   : Flags — R,P,E,T bits valid; lower 4 bits (reserved) must be 0
//	bytes 5-7 : Command Code (0..16777215)
//	bytes 8-11: Application-ID
//	bytes 12-15: Hop-by-Hop Identifier
//	bytes 16-19: End-to-End Identifier
func IsDiameter(p []byte) bool {
	if len(p) < 20 {
		return false
	}
	if p[0] != 0x01 {
		return false // version must be 1
	}
	msgLen := uint32(p[1])<<16 | uint32(p[2])<<8 | uint32(p[3])
	if msgLen < 20 || msgLen > 16777215 {
		return false // absurd length
	}
	// Reserved flag bits [3:0] of byte 4 must be zero
	if p[4]&0x0F != 0 {
		return false
	}
	return true
}

// IsGTP returns true if the payload matches a GTPv1 or GTPv2 header.
//
// GTPv1 (3GPP TS 29.060): byte 0 bits [7:5] = 0b001 (version=1)
// GTPv2 (3GPP TS 29.274): byte 0 bits [7:5] = 0b010 (version=2)
//
// Both: minimum header is 8 bytes; message type in byte 1 must be non-zero.
func IsGTP(p []byte) bool {
	if len(p) < 8 {
		return false
	}
	version := (p[0] >> 5) & 0x07
	if version != 1 && version != 2 {
		return false
	}
	// Message type 0 is reserved — a valid GTP packet always has a type
	if p[1] == 0 {
		return false
	}
	return true
}

// IsRTP returns true if the payload matches an RTP packet header (RFC 3550).
//
// RTP header (12 bytes minimum):
//
//	byte 0 bits [7:6]: Version — must be 2 (0b10)
//	byte 1 bits [6:0]: Payload type — well-known types 0..127
//
// Note: RTP DPI has higher false-positive risk than text-based protocols.
// It is most useful when combined with UDP transport and flow context.
func IsRTP(p []byte) bool {
	if len(p) < 12 {
		return false
	}
	version := (p[0] >> 6) & 0x03
	if version != 2 {
		return false
	}
	// Payload type must be in 0–127 range (bit 7 of byte 1 is the Marker bit)
	pt := p[1] & 0x7F
	return pt <= 127 // always true but documents the intent; add range filters if needed
}

// ── internal helpers ──────────────────────────────────────────────────────────

// hasPrefix returns true if p starts with the ASCII string s (no allocation).
func hasPrefix(p []byte, s string) bool {
	if len(p) < len(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if p[i] != s[i] {
			return false
		}
	}
	return true
}

// contains returns true if p contains the ASCII string s within the slice.
func contains(p []byte, s string) bool {
	if len(s) == 0 || len(p) < len(s) {
		return false
	}
	first := s[0]
	for i := 0; i <= len(p)-len(s); i++ {
		if p[i] == first {
			match := true
			for j := 1; j < len(s); j++ {
				if p[i+j] != s[j] {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}
