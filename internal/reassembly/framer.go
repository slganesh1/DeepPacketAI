package reassembly

import (
	"encoding/binary"
	"strings"
)

// MessageFramer accumulates reassembled TCP bytes and extracts complete
// protocol messages based on protocol-specific framing rules.
type MessageFramer interface {
	// Feed adds bytes to the buffer and returns any complete messages.
	Feed(data []byte) [][]byte
	// Flush returns remaining buffered data (partial message).
	Flush() []byte
}

// SelectFramer returns an appropriate MessageFramer for the given ports.
// Returns nil for ports we don't reassemble (packets go directly to decoders).
func SelectFramer(srcPort, dstPort uint16) MessageFramer {
	if srcPort == 5060 || dstPort == 5060 || srcPort == 5061 || dstPort == 5061 {
		return &SIPFramer{}
	}
	if isHTTPPort(srcPort) || isHTTPPort(dstPort) {
		return &HTTPFramer{}
	}
	if isTLSPort(srcPort) || isTLSPort(dstPort) {
		return &TLSFramer{}
	}
	if srcPort == 3868 || dstPort == 3868 {
		return &DiameterFramer{}
	}
	if srcPort == 8009 || dstPort == 8009 {
		return &AJPFramer{}
	}
	return nil
}

func isHTTPPort(port uint16) bool {
	switch port {
	case 80, 8080, 8000, 8888, 3000:
		return true
	}
	return false
}

func isTLSPort(port uint16) bool {
	switch port {
	case 443, 8443, 993, 995, 465, 636:
		return true
	}
	return false
}

// --- SIP Framer ---

// SIPFramer detects SIP message boundaries using \r\n\r\n header terminator
// and Content-Length for body bytes.
type SIPFramer struct {
	buf []byte
}

func (f *SIPFramer) Feed(data []byte) [][]byte {
	f.buf = append(f.buf, data...)
	var msgs [][]byte

	for {
		idx := strings.Index(string(f.buf), "\r\n\r\n")
		if idx == -1 {
			break
		}
		headerEnd := idx + 4

		// Check for Content-Length to include body
		bodyLen := extractContentLength(f.buf[:idx])
		totalLen := headerEnd + bodyLen

		if len(f.buf) < totalLen {
			break // Wait for more data
		}

		msg := make([]byte, totalLen)
		copy(msg, f.buf[:totalLen])
		msgs = append(msgs, msg)
		f.buf = f.buf[totalLen:]
	}

	return msgs
}

func (f *SIPFramer) Flush() []byte {
	remaining := f.buf
	f.buf = nil
	return remaining
}

// --- HTTP Framer ---

// HTTPFramer detects HTTP message boundaries using \r\n\r\n header terminator
// and Content-Length for body bytes.
type HTTPFramer struct {
	buf []byte
}

func (f *HTTPFramer) Feed(data []byte) [][]byte {
	f.buf = append(f.buf, data...)
	var msgs [][]byte

	for {
		idx := strings.Index(string(f.buf), "\r\n\r\n")
		if idx == -1 {
			break
		}
		headerEnd := idx + 4

		bodyLen := extractContentLength(f.buf[:idx])
		totalLen := headerEnd + bodyLen

		if len(f.buf) < totalLen {
			break
		}

		msg := make([]byte, totalLen)
		copy(msg, f.buf[:totalLen])
		msgs = append(msgs, msg)
		f.buf = f.buf[totalLen:]
	}

	return msgs
}

func (f *HTTPFramer) Flush() []byte {
	remaining := f.buf
	f.buf = nil
	return remaining
}

// --- TLS Framer ---

// TLSFramer detects TLS record boundaries using the 5-byte record header:
// ContentType(1B) + Version(2B) + Length(2B).
type TLSFramer struct {
	buf []byte
}

func (f *TLSFramer) Feed(data []byte) [][]byte {
	f.buf = append(f.buf, data...)
	var msgs [][]byte

	for {
		if len(f.buf) < 5 {
			break
		}

		contentType := f.buf[0]
		if contentType < 20 || contentType > 23 {
			// Not a valid TLS record; skip one byte to resync
			f.buf = f.buf[1:]
			continue
		}

		recordLen := int(binary.BigEndian.Uint16(f.buf[3:5]))
		totalLen := 5 + recordLen

		if len(f.buf) < totalLen {
			break
		}

		msg := make([]byte, totalLen)
		copy(msg, f.buf[:totalLen])
		msgs = append(msgs, msg)
		f.buf = f.buf[totalLen:]
	}

	return msgs
}

func (f *TLSFramer) Flush() []byte {
	remaining := f.buf
	f.buf = nil
	return remaining
}

// --- Diameter Framer ---

// DiameterFramer detects Diameter message boundaries using the 4-byte header:
// Version(1B) + Length(3B).
type DiameterFramer struct {
	buf []byte
}

func (f *DiameterFramer) Feed(data []byte) [][]byte {
	f.buf = append(f.buf, data...)
	var msgs [][]byte

	for {
		if len(f.buf) < 4 {
			break
		}

		if f.buf[0] != 1 {
			// Not a valid Diameter message; skip one byte to resync
			f.buf = f.buf[1:]
			continue
		}

		msgLen := int(f.buf[1])<<16 | int(f.buf[2])<<8 | int(f.buf[3])
		if msgLen < 20 {
			f.buf = f.buf[1:]
			continue
		}

		if len(f.buf) < msgLen {
			break
		}

		msg := make([]byte, msgLen)
		copy(msg, f.buf[:msgLen])
		msgs = append(msgs, msg)
		f.buf = f.buf[msgLen:]
	}

	return msgs
}

func (f *DiameterFramer) Flush() []byte {
	remaining := f.buf
	f.buf = nil
	return remaining
}

// --- AJP Framer ---

// AJPFramer detects AJP13 message boundaries using its 4-byte header:
// Magic(2B, 0x1234 or "AB") + DataLength(2B), followed by that many bytes.
type AJPFramer struct {
	buf []byte
}

func (f *AJPFramer) Feed(data []byte) [][]byte {
	f.buf = append(f.buf, data...)
	var msgs [][]byte

	for {
		if len(f.buf) < 4 {
			break
		}
		magic := binary.BigEndian.Uint16(f.buf[0:2])
		if magic != 0x1234 && magic != 0x4142 {
			// Not a valid AJP header; skip one byte to resync.
			f.buf = f.buf[1:]
			continue
		}

		dataLen := int(binary.BigEndian.Uint16(f.buf[2:4]))
		totalLen := 4 + dataLen

		if len(f.buf) < totalLen {
			break
		}

		msg := make([]byte, totalLen)
		copy(msg, f.buf[:totalLen])
		msgs = append(msgs, msg)
		f.buf = f.buf[totalLen:]
	}

	return msgs
}

func (f *AJPFramer) Flush() []byte {
	remaining := f.buf
	f.buf = nil
	return remaining
}

// --- WebSocket Framer ---

// WebSocketFramer detects WebSocket frame boundaries from the wire format:
// FIN/Opcode(1B) + MASK/PayloadLen(1B) + [Extended Len] + [MaskKey(4B)] + Payload.
type WebSocketFramer struct {
	buf []byte
}

func (f *WebSocketFramer) Feed(data []byte) [][]byte {
	f.buf = append(f.buf, data...)
	var msgs [][]byte

	for {
		if len(f.buf) < 2 {
			break
		}

		masked := (f.buf[1] & 0x80) != 0
		payloadLen := int(f.buf[1] & 0x7F)
		headerLen := 2

		if payloadLen == 126 {
			if len(f.buf) < 4 {
				break
			}
			payloadLen = int(binary.BigEndian.Uint16(f.buf[2:4]))
			headerLen = 4
		} else if payloadLen == 127 {
			if len(f.buf) < 10 {
				break
			}
			payloadLen = int(binary.BigEndian.Uint64(f.buf[2:10]))
			headerLen = 10
		}

		if masked {
			headerLen += 4
		}

		totalLen := headerLen + payloadLen
		if len(f.buf) < totalLen {
			break
		}

		msg := make([]byte, totalLen)
		copy(msg, f.buf[:totalLen])
		msgs = append(msgs, msg)
		f.buf = f.buf[totalLen:]
	}

	return msgs
}

func (f *WebSocketFramer) Flush() []byte {
	remaining := f.buf
	f.buf = nil
	return remaining
}

// --- Helpers ---

// extractContentLength parses the Content-Length header value from HTTP/SIP headers.
func extractContentLength(headers []byte) int {
	s := string(headers)
	lower := strings.ToLower(s)
	idx := strings.Index(lower, "content-length:")
	if idx == -1 {
		return 0
	}
	rest := s[idx+len("content-length:"):]
	end := strings.IndexByte(rest, '\r')
	if end == -1 {
		end = strings.IndexByte(rest, '\n')
	}
	if end == -1 {
		end = len(rest)
	}
	val := strings.TrimSpace(rest[:end])
	var n int
	for _, c := range val {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			break
		}
	}
	return n
}
