package http1

import (
	"fmt"
	"strings"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/dpi"
	"DeepPacketAI/internal/protocols"
)

// Decoder decodes HTTP/1.x request/response messages.
type Decoder struct {
	transactions map[string]*httpTransaction
	completed    []*httpTransaction
}

type httpTransaction struct {
	ID            string
	Method        string
	URI           string
	Host          string
	StatusCode    int
	StatusText    string
	ContentType   string
	ContentLength string
	UserAgent     string
	Server        string
	HasAuth       bool
	HasCookie     bool
	BodyPreview   string
	SrcIP         string
	DstIP         string
	SrcPort       uint16
	DstPort       uint16
	StartTime     interface{}
	EndTime       interface{}
	IsError       bool
}

func NewDecoder() *Decoder {
	return &Decoder{
		transactions: make(map[string]*httpTransaction),
	}
}

func (d *Decoder) Name() string { return "http1" }

func (d *Decoder) HandlePacket(pkt *domain.Packet) {
	if pkt.Protocol != "TCP" {
		return
	}
	if len(pkt.Payload) < 10 {
		return
	}
	if !isHTTPPort(pkt.SrcPort, pkt.DstPort) && !dpi.IsHTTP(pkt.Payload) {
		return
	}

	d.parseHTTP(pkt)
}

func (d *Decoder) HandlePacketLive(pkt *domain.Packet) *protocols.DecodedPacket {
	if pkt.Protocol != "TCP" {
		return nil
	}
	if len(pkt.Payload) < 10 {
		return nil
	}
	if !isHTTPPort(pkt.SrcPort, pkt.DstPort) && !dpi.IsHTTP(pkt.Payload) {
		return nil
	}

	tx := d.parseHTTP(pkt)
	if tx == nil {
		return nil
	}

	var errs []domain.PacketError
	if tx.StatusCode >= 400 && tx.StatusCode < 500 {
		errs = append(errs, domain.PacketError{
			Code:        fmt.Sprintf("HTTP_%d", tx.StatusCode),
			Title:       fmt.Sprintf("HTTP Client Error %d", tx.StatusCode),
			Description: fmt.Sprintf("%s %s returned %d %s", tx.Method, tx.URI, tx.StatusCode, tx.StatusText),
			Severity:    "warning",
		})
	} else if tx.StatusCode >= 500 {
		errs = append(errs, domain.PacketError{
			Code:        fmt.Sprintf("HTTP_%d", tx.StatusCode),
			Title:       fmt.Sprintf("HTTP Server Error %d", tx.StatusCode),
			Description: fmt.Sprintf("%s %s returned %d %s", tx.Method, tx.URI, tx.StatusCode, tx.StatusText),
			Severity:    "error",
		})
	}

	metadata := map[string]any{
		"method":      tx.Method,
		"uri":         tx.URI,
		"host":        tx.Host,
		"status_code": tx.StatusCode,
		"status_text": tx.StatusText,
	}
	if tx.ContentType != "" {
		metadata["content_type"] = tx.ContentType
	}
	if tx.UserAgent != "" {
		metadata["user_agent"] = tx.UserAgent
	}
	if tx.Server != "" {
		metadata["server"] = tx.Server
	}

	return &protocols.DecodedPacket{
		Packet:   pkt,
		Protocol: "HTTP",
		Summary:  pkt.Summary,
		Metadata: metadata,
		Errors:   errs,
	}
}

func (d *Decoder) Flush() []domain.Flow {
	var flows []domain.Flow

	for _, tx := range d.completed {
		metrics := map[string]any{
			"method":      tx.Method,
			"uri":         tx.URI,
			"host":        tx.Host,
			"status_code": tx.StatusCode,
			"is_error":    tx.IsError,
		}
		if tx.ContentType != "" {
			metrics["content_type"] = tx.ContentType
		}
		if tx.ContentLength != "" {
			metrics["content_length"] = tx.ContentLength
		}
		if tx.UserAgent != "" {
			metrics["user_agent"] = tx.UserAgent
		}
		if tx.Server != "" {
			metrics["server"] = tx.Server
		}
		if tx.HasAuth {
			metrics["has_auth"] = true
		}
		if tx.HasCookie {
			metrics["has_cookie"] = true
		}
		if tx.BodyPreview != "" {
			metrics["body_preview"] = tx.BodyPreview
		}

		flows = append(flows, domain.Flow{
			FlowID:  tx.ID,
			Type:    domain.FlowHTTP,
			SrcIP:   tx.SrcIP,
			DstIP:   tx.DstIP,
			SrcPort: tx.SrcPort,
			DstPort: tx.DstPort,
			Metrics: metrics,
		})
	}

	return flows
}

func (d *Decoder) parseHTTP(pkt *domain.Packet) *httpTransaction {
	line := firstLine(pkt.Payload)
	if line == "" {
		return nil
	}

	if isHTTPRequest(line) {
		return d.handleRequest(pkt, line)
	}
	if isHTTPResponse(line) {
		return d.handleResponse(pkt, line)
	}

	return nil
}

func (d *Decoder) handleRequest(pkt *domain.Packet, line string) *httpTransaction {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return nil
	}

	key := fmt.Sprintf("%s:%d-%s:%d", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort)

	tx := &httpTransaction{
		ID:            fmt.Sprintf("http-%s-%d", key, pkt.FrameNumber),
		Method:        parts[0],
		URI:           parts[1],
		Host:          extractHeaderValue(pkt.Payload, "Host"),
		ContentType:   extractHeaderValue(pkt.Payload, "Content-Type"),
		ContentLength: extractHeaderValue(pkt.Payload, "Content-Length"),
		UserAgent:     extractHeaderValue(pkt.Payload, "User-Agent"),
		HasAuth:       extractHeaderValue(pkt.Payload, "Authorization") != "",
		HasCookie:     extractHeaderValue(pkt.Payload, "Cookie") != "",
		BodyPreview:   extractBodyPreview(pkt.Payload),
		SrcIP:         pkt.SrcIP,
		DstIP:         pkt.DstIP,
		SrcPort:       pkt.SrcPort,
		DstPort:       pkt.DstPort,
		StartTime:     pkt.Timestamp,
	}

	d.transactions[key] = tx
	pkt.AppProtocol = "HTTP"
	pkt.Summary = fmt.Sprintf("%s %s", tx.Method, tx.URI)
	if tx.Host != "" {
		pkt.Summary += " Host:" + tx.Host
	}

	return tx
}

func (d *Decoder) handleResponse(pkt *domain.Packet, line string) *httpTransaction {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return nil
	}

	var statusCode int
	fmt.Sscanf(parts[1], "%d", &statusCode)

	statusText := ""
	if len(parts) >= 3 {
		statusText = parts[2]
	}

	// Match to request
	key := fmt.Sprintf("%s:%d-%s:%d", pkt.DstIP, pkt.DstPort, pkt.SrcIP, pkt.SrcPort)
	tx, ok := d.transactions[key]
	if !ok {
		tx = &httpTransaction{
			ID:      fmt.Sprintf("http-resp-%d", pkt.FrameNumber),
			SrcIP:   pkt.DstIP,
			DstIP:   pkt.SrcIP,
			SrcPort: pkt.DstPort,
			DstPort: pkt.SrcPort,
		}
	}

	tx.StatusCode = statusCode
	tx.StatusText = statusText
	tx.EndTime = pkt.Timestamp
	tx.IsError = statusCode >= 400

	// Extract response headers
	respContentType := extractHeaderValue(pkt.Payload, "Content-Type")
	respContentLen := extractHeaderValue(pkt.Payload, "Content-Length")
	respServer := extractHeaderValue(pkt.Payload, "Server")
	if respContentType != "" {
		tx.ContentType = respContentType
	}
	if respContentLen != "" {
		tx.ContentLength = respContentLen
	}
	if respServer != "" {
		tx.Server = respServer
	}
	if extractHeaderValue(pkt.Payload, "Set-Cookie") != "" {
		tx.HasCookie = true
	}

	// Body preview from response
	bodyPreview := extractBodyPreview(pkt.Payload)
	if bodyPreview != "" {
		tx.BodyPreview = bodyPreview
	}

	delete(d.transactions, key)
	d.completed = append(d.completed, tx)

	pkt.AppProtocol = "HTTP"
	pkt.Summary = fmt.Sprintf("%d %s (%s %s)", statusCode, statusText, tx.Method, tx.URI)

	return tx
}

func isHTTPPort(src, dst uint16) bool {
	httpPorts := map[uint16]bool{80: true, 8080: true, 8000: true, 8888: true, 3000: true}
	return httpPorts[src] || httpPorts[dst]
}

var httpMethods = []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE "}

func isHTTPRequest(line string) bool {
	for _, m := range httpMethods {
		if strings.HasPrefix(line, m) {
			return true
		}
	}
	return false
}

func isHTTPResponse(line string) bool {
	return strings.HasPrefix(line, "HTTP/1.0 ") || strings.HasPrefix(line, "HTTP/1.1 ")
}

func firstLine(payload []byte) string {
	for i, b := range payload {
		if b == '\r' || b == '\n' {
			return string(payload[:i])
		}
		if i > 200 {
			break
		}
	}
	return ""
}

func extractHeaderValue(payload []byte, header string) string {
	lines := strings.Split(string(payload), "\r\n")
	prefix := strings.ToLower(header) + ":"
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), prefix) {
			return strings.TrimSpace(line[len(prefix):])
		}
	}
	return ""
}

// extractBodyPreview extracts the first 200 characters of the HTTP body.
// The body starts after the blank line (\r\n\r\n) separating headers from body.
func extractBodyPreview(payload []byte) string {
	// Find the header/body separator (\r\n\r\n)
	idx := -1
	for i := 0; i+3 < len(payload); i++ {
		if payload[i] == '\r' && payload[i+1] == '\n' && payload[i+2] == '\r' && payload[i+3] == '\n' {
			idx = i + 4
			break
		}
	}
	if idx < 0 || idx >= len(payload) {
		return ""
	}

	body := payload[idx:]
	if len(body) == 0 {
		return ""
	}

	// Limit to 200 bytes and ensure it's printable text
	maxLen := 200
	if len(body) < maxLen {
		maxLen = len(body)
	}
	preview := body[:maxLen]

	// Check if it looks like text (not binary)
	for _, b := range preview {
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			return "[binary data]"
		}
	}

	return string(preview)
}

// Ensure Decoder implements StreamingDecoder.
var _ protocols.StreamingDecoder = (*Decoder)(nil)
