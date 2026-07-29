package http2

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/protocols"
)

// HTTP/2 connection preface (client magic)
const connectionPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// Frame type constants
const (
	frameDATA         = 0
	frameHEADERS      = 1
	framePRIORITY     = 2
	frameRST_STREAM   = 3
	frameSETTINGS     = 4
	framePUSH_PROMISE = 5
	framePING         = 6
	frameGOAWAY       = 7
	frameWINDOW_UPDATE = 8
	frameCONTINUATION = 9
)

// frameTypeNames maps frame type byte to human-readable name.
var frameTypeNames = map[uint8]string{
	frameDATA:          "DATA",
	frameHEADERS:       "HEADERS",
	framePRIORITY:      "PRIORITY",
	frameRST_STREAM:    "RST_STREAM",
	frameSETTINGS:      "SETTINGS",
	framePUSH_PROMISE:  "PUSH_PROMISE",
	framePING:          "PING",
	frameGOAWAY:        "GOAWAY",
	frameWINDOW_UPDATE: "WINDOW_UPDATE",
	frameCONTINUATION:  "CONTINUATION",
}

// sbiPathPrefixes maps 3GPP SBI API path prefix to NF type.
var sbiPathPrefixes = []struct {
	prefix  string
	nfType  string
	service string
}{
	{"/nudm-sdm/", "UDM", "nudm-sdm"},
	{"/nudm-uecm/", "UDM", "nudm-uecm"},
	{"/nudm-ueau/", "UDM", "nudm-ueau"},
	{"/nudm-pp/", "UDM", "nudm-pp"},
	{"/nsmf-pdusession/", "SMF", "nsmf-pdusession"},
	{"/namf-comm/", "AMF", "namf-comm"},
	{"/namf-evts/", "AMF", "namf-evts"},
	{"/npcf-smpolicycontrol/", "PCF", "npcf-smpolicycontrol"},
	{"/npcf-ue-policy-control/", "PCF", "npcf-ue-policy-control"},
	{"/nausf-auth/", "AUSF", "nausf-auth"},
	{"/nnrf-nfm/", "NRF", "nnrf-nfm"},
	{"/nnrf-disc/", "NRF", "nnrf-disc"},
	{"/nudr-dr/", "UDR", "nudr-dr"},
	{"/nbsf-management/", "BSF", "nbsf-management"},
	{"/nchf-spendinglimitcontrol/", "CHF", "nchf-spendinglimitcontrol"},
	{"/nnssf-nsselection/", "NSSF", "nnssf-nsselection"},
}

// http2Stream tracks the state of a single HTTP/2 stream.
type http2Stream struct {
	StreamID    uint32
	Method      string
	Path        string
	NFType      string
	APIVersion  string
	Service     string
	ServiceName string
	StatusCode  string
	IsSBI       bool
}

// http2Record captures info from a parsed HTTP/2 flow.
type http2Record struct {
	SrcIP        string
	DstIP        string
	SrcPort      uint16
	DstPort      uint16
	FrameNum     uint64
	Timestamp    time.Time
	Streams      map[uint32]*http2Stream
	StreamCount  int
	ErrorCount   int
	DataBytes    int
	IsSBI        bool
	Method       string
	Path         string
	NFType       string
	APIVersion   string
	ServiceName  string
	StatusCode   string
}

// Decoder decodes HTTP/2 frames and 3GPP SBI API calls.
type Decoder struct {
	records []*http2Record
}

// NewDecoder creates a new HTTP/2 decoder.
func NewDecoder() *Decoder {
	return &Decoder{}
}

func (d *Decoder) Name() string { return "http2" }

func (d *Decoder) HandlePacket(pkt *domain.Packet) {
	if !isHTTP2Port(pkt.SrcPort, pkt.DstPort) && !isHTTP2Preface(pkt.Payload) {
		return
	}
	if pkt.Protocol != "TCP" {
		return
	}
	if len(pkt.Payload) < 9 {
		return
	}

	d.parseHTTP2(pkt)
}

func (d *Decoder) HandlePacketLive(pkt *domain.Packet) *protocols.DecodedPacket {
	if !isHTTP2Port(pkt.SrcPort, pkt.DstPort) && !isHTTP2Preface(pkt.Payload) {
		return nil
	}
	if pkt.Protocol != "TCP" {
		return nil
	}
	if len(pkt.Payload) < 9 {
		return nil
	}

	rec := d.parseHTTP2(pkt)
	if rec == nil {
		return nil
	}

	summary := buildSummary(rec)

	var errs []domain.PacketError
	if rec.ErrorCount > 0 {
		errs = append(errs, domain.PacketError{
			Code:        "HTTP2_ERRORS",
			Title:       "HTTP/2 Error Responses",
			Description: fmt.Sprintf("%d error responses (4xx/5xx)", rec.ErrorCount),
			Severity:    "warning",
		})
	}

	metadata := map[string]any{
		"method":       rec.Method,
		"path":         rec.Path,
		"status_code":  rec.StatusCode,
		"nf_type":      rec.NFType,
		"api_version":  rec.APIVersion,
		"service_name": rec.ServiceName,
		"stream_count": rec.StreamCount,
		"error_count":  rec.ErrorCount,
		"data_bytes":   rec.DataBytes,
		"is_sbi":       rec.IsSBI,
	}

	return &protocols.DecodedPacket{
		Packet:   pkt,
		Protocol: "HTTP2",
		Summary:  summary,
		Metadata: metadata,
		Errors:   errs,
	}
}

func (d *Decoder) Flush() []domain.Flow {
	var flows []domain.Flow

	for _, rec := range d.records {
		flowType := domain.FlowHTTP2
		if rec.IsSBI {
			flowType = domain.FlowSBI
		}

		flows = append(flows, domain.Flow{
			FlowID:    fmt.Sprintf("http2-%s-%d-%d", rec.SrcIP, rec.SrcPort, rec.FrameNum),
			Type:      flowType,
			SrcIP:     rec.SrcIP,
			DstIP:     rec.DstIP,
			SrcPort:   rec.SrcPort,
			DstPort:   rec.DstPort,
			StartTime: rec.Timestamp,
			EndTime:   rec.Timestamp,
			Metrics: map[string]any{
				"method":       rec.Method,
				"path":         rec.Path,
				"status_code":  rec.StatusCode,
				"nf_type":      rec.NFType,
				"api_version":  rec.APIVersion,
				"service_name": rec.ServiceName,
				"stream_count": rec.StreamCount,
				"error_count":  rec.ErrorCount,
				"data_bytes":   rec.DataBytes,
				"is_sbi":       rec.IsSBI,
			},
		})
	}

	return flows
}

func (d *Decoder) parseHTTP2(pkt *domain.Packet) *http2Record {
	payload := pkt.Payload

	// Skip connection preface if present
	offset := 0
	if len(payload) >= 24 && string(payload[:24]) == connectionPreface {
		offset = 24
	}

	rec := &http2Record{
		SrcIP:     pkt.SrcIP,
		DstIP:     pkt.DstIP,
		SrcPort:   pkt.SrcPort,
		DstPort:   pkt.DstPort,
		FrameNum:  pkt.FrameNumber,
		Timestamp: pkt.Timestamp,
		Streams:   make(map[uint32]*http2Stream),
	}

	// Parse HTTP/2 frames
	for offset+9 <= len(payload) {
		// 3-byte payload length
		payloadLen := int(payload[offset])<<16 | int(payload[offset+1])<<8 | int(payload[offset+2])
		frameType := payload[offset+3]
		// flags := payload[offset+4]  // available but not used in basic parsing
		streamID := binary.BigEndian.Uint32(payload[offset+5:offset+9]) & 0x7FFFFFFF

		frameEnd := offset + 9 + payloadLen
		if frameEnd > len(payload) {
			frameEnd = len(payload)
		}

		framePayload := payload[offset+9 : frameEnd]

		switch frameType {
		case frameHEADERS:
			if streamID > 0 {
				rec.StreamCount++
				stream := rec.getOrCreateStream(streamID)
				parseHPACKLiterals(framePayload, stream)
				classifyStream(stream)
				if stream.IsSBI {
					rec.IsSBI = true
				}
				// Track the most recent meaningful stream info for the record
				if stream.Method != "" && rec.Method == "" {
					rec.Method = stream.Method
				}
				if stream.Path != "" && rec.Path == "" {
					rec.Path = stream.Path
				}
				if stream.NFType != "" && rec.NFType == "" {
					rec.NFType = stream.NFType
				}
				if stream.APIVersion != "" && rec.APIVersion == "" {
					rec.APIVersion = stream.APIVersion
				}
				if stream.ServiceName != "" && rec.ServiceName == "" {
					rec.ServiceName = stream.ServiceName
				}
				if stream.StatusCode != "" {
					rec.StatusCode = stream.StatusCode
					if isErrorStatus(stream.StatusCode) {
						rec.ErrorCount++
					}
				}
			}

		case frameDATA:
			rec.DataBytes += len(framePayload)
		}

		offset += 9 + payloadLen
		if offset >= len(payload) {
			break
		}
	}

	// Only record if we parsed something meaningful
	if rec.StreamCount == 0 && rec.DataBytes == 0 {
		// Check if it was just a preface packet
		if !isHTTP2Preface(pkt.Payload) {
			return nil
		}
	}

	pkt.AppProtocol = "HTTP2"
	pkt.Summary = buildSummary(rec)

	d.records = append(d.records, rec)
	return rec
}

func (rec *http2Record) getOrCreateStream(id uint32) *http2Stream {
	if s, ok := rec.Streams[id]; ok {
		return s
	}
	s := &http2Stream{StreamID: id}
	rec.Streams[id] = s
	return s
}

// parseHPACKLiterals does a simple scan for HPACK literal headers in a HEADERS frame payload.
// This is a simplified literal-only parser (no dynamic table). It scans for common header patterns.
func parseHPACKLiterals(data []byte, stream *http2Stream) {
	i := 0
	for i < len(data) {
		b := data[i]

		if b&0x80 != 0 {
			// Indexed header (0xxxxxxx with MSB=1): single byte index
			i++
			continue
		}

		if b&0x40 != 0 {
			// Literal with incremental indexing (01xxxxxx)
			nameIdx := b & 0x3F
			i++
			if nameIdx == 0 {
				// New name follows
				name, ni := readHPACKString(data, i)
				i = ni
				val, vi := readHPACKString(data, i)
				i = vi
				applyHeader(stream, name, val)
			} else {
				// Indexed name, literal value
				val, vi := readHPACKString(data, i)
				i = vi
				applyIndexedNameHeader(stream, nameIdx, val)
			}
		} else if b&0x20 != 0 {
			// Dynamic table size update (001xxxxx)
			// Just skip: read the integer
			_, ni := readHPACKInt(data, i, 5)
			i = ni
		} else {
			// Literal without indexing (0000xxxx) or never indexed (0001xxxx)
			nameIdx := b & 0x0F
			i++
			if nameIdx == 0 {
				name, ni := readHPACKString(data, i)
				i = ni
				val, vi := readHPACKString(data, i)
				i = vi
				applyHeader(stream, name, val)
			} else {
				// Indexed name, literal value
				val, vi := readHPACKString(data, i)
				i = vi
				applyIndexedNameHeader(stream, nameIdx, val)
			}
		}
	}
}

// readHPACKInt reads an HPACK integer starting at offset, using N prefix bits.
func readHPACKInt(data []byte, offset, prefixBits int) (int, int) {
	if offset >= len(data) {
		return 0, offset
	}
	mask := (1 << prefixBits) - 1
	val := int(data[offset]) & mask
	offset++
	if val < mask {
		return val, offset
	}
	// Multi-byte integer
	shift := 0
	for offset < len(data) {
		b := data[offset]
		offset++
		val += int(b&0x7F) << shift
		shift += 7
		if b&0x80 == 0 {
			break
		}
	}
	return val, offset
}

// readHPACKString reads an HPACK string (length-prefixed, optionally Huffman).
func readHPACKString(data []byte, offset int) (string, int) {
	if offset >= len(data) {
		return "", offset
	}
	// huffman := (data[offset] & 0x80) != 0  // Huffman flag — not decoded in this simple parser
	strLen, newOffset := readHPACKInt(data, offset, 7)
	if newOffset+strLen > len(data) {
		return "", len(data)
	}
	s := string(data[newOffset : newOffset+strLen])
	return s, newOffset + strLen
}

// applyIndexedNameHeader applies a header where the name is from the HPACK static table.
// Static table indices for common headers:
//
//	1=:authority, 2=:method GET, 3=:method POST, 4=:path /, 5=:path /index.html,
//	6=:scheme http, 7=:scheme https, 8=:status 200, ..., 14=:status 500
func applyIndexedNameHeader(stream *http2Stream, nameIdx uint8, val string) {
	switch nameIdx {
	case 2, 3: // :method
		stream.Method = val
	case 4, 5: // :path
		stream.Path = val
	case 8, 9, 10, 11, 12, 13, 14: // :status (200–500 range in static table)
		stream.StatusCode = val
	}
}

// applyHeader applies a name/value pair to the stream.
func applyHeader(stream *http2Stream, name, val string) {
	switch strings.ToLower(name) {
	case ":method":
		stream.Method = val
	case ":path":
		stream.Path = val
	case ":status":
		stream.StatusCode = val
	}
}

// classifyStream assigns NF type, API version, and SBI flag from the path.
func classifyStream(stream *http2Stream) {
	if stream.Path == "" {
		return
	}

	for _, entry := range sbiPathPrefixes {
		if strings.HasPrefix(stream.Path, entry.prefix) {
			stream.NFType = entry.nfType
			stream.Service = entry.service
			stream.ServiceName = entry.service
			stream.IsSBI = true
			// Extract API version: look for /v1/, /v2/, etc.
			stream.APIVersion = extractAPIVersion(stream.Path)
			return
		}
	}
}

// extractAPIVersion extracts the API version segment (v1, v2, etc.) from a path.
func extractAPIVersion(path string) string {
	parts := strings.Split(path, "/")
	for _, p := range parts {
		if len(p) >= 2 && p[0] == 'v' {
			allDigits := true
			for _, c := range p[1:] {
				if c < '0' || c > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				return p
			}
		}
	}
	return ""
}

// isErrorStatus returns true if the HTTP status code indicates an error (4xx or 5xx).
func isErrorStatus(status string) bool {
	if len(status) < 1 {
		return false
	}
	return status[0] == '4' || status[0] == '5'
}

// isHTTP2Port returns true for common HTTP/2 and SBI ports.
func isHTTP2Port(src, dst uint16) bool {
	switch src {
	case 80, 443, 8080, 8443, 7777:
		return true
	}
	switch dst {
	case 80, 443, 8080, 8443, 7777:
		return true
	}
	return false
}

// isHTTP2Preface checks if the payload starts with the HTTP/2 connection preface.
func isHTTP2Preface(payload []byte) bool {
	if len(payload) >= 24 {
		return string(payload[:24]) == connectionPreface
	}
	// Also accept packets that look like HTTP/2 frames (but not HTTP/1 text)
	if len(payload) >= 9 {
		// Check if this looks like a valid HTTP/2 frame:
		// the first 3 bytes are the payload length, byte 3 is frame type (0-9), byte 4 is flags
		frameType := payload[3]
		if frameType <= 9 {
			payloadLen := int(payload[0])<<16 | int(payload[1])<<8 | int(payload[2])
			// Sanity check: payload length should be within a reasonable range
			if payloadLen >= 0 && payloadLen <= 16384 {
				// Make sure it does NOT look like HTTP/1.x (which starts with text like GET, POST, HTTP)
				if !looksLikeHTTP1(payload) {
					return true
				}
			}
		}
	}
	return false
}

// looksLikeHTTP1 returns true if the payload looks like an HTTP/1.x request or response.
func looksLikeHTTP1(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	prefix := string(payload[:4])
	switch prefix {
	case "GET ", "POST", "HEAD", "PUT ", "DELE", "PATC", "OPTI", "HTTP":
		return true
	}
	return false
}

// buildSummary constructs a human-readable summary for a HTTP/2 record.
func buildSummary(rec *http2Record) string {
	if rec.IsSBI {
		s := fmt.Sprintf("HTTP2 SBI %s", rec.NFType)
		if rec.Method != "" {
			s += " " + rec.Method
		}
		if rec.Path != "" {
			s += " " + rec.Path
		}
		if rec.StatusCode != "" {
			s += " [" + rec.StatusCode + "]"
		}
		return s
	}

	s := "HTTP2"
	if rec.Method != "" {
		s += " " + rec.Method
	}
	if rec.Path != "" {
		s += " " + rec.Path
	}
	if rec.StatusCode != "" {
		s += " [" + rec.StatusCode + "]"
	}
	if rec.StreamCount > 0 {
		s += fmt.Sprintf(" streams=%d", rec.StreamCount)
	}
	return s
}

var _ protocols.StreamingDecoder = (*Decoder)(nil)
