package http1

import (
	"fmt"
	"strings"
	"time"

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
	StartTime     time.Time
	EndTime       time.Time
	IsError       bool

	// SOAP awareness. A SOAP fault is a valid, well-formed XML document
	// that very often arrives with HTTP 200 (many stacks don't bother with
	// the "correct" 500), so it must be detected from the body, not the
	// status code — is_error is upgraded to true whenever one is found.
	IsSOAP        bool
	SOAPAction    string
	SOAPOperation string // local name of the first child of <soap:Body> — the operation being called or answered
	FaultCode     string
	FaultString   string
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
	if tx.FaultCode != "" || tx.FaultString != "" {
		// A SOAP fault is a well-formed XML document, very often delivered
		// with HTTP 200 — surface it as its own error regardless of status code.
		errs = append(errs, domain.PacketError{
			Code:        "SOAP_FAULT",
			Title:       "SOAP Fault",
			Description: fmt.Sprintf("%s: %s", tx.FaultCode, tx.FaultString),
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
	if tx.IsSOAP {
		metadata["is_soap"] = true
	}
	if tx.SOAPAction != "" {
		metadata["soap_action"] = tx.SOAPAction
	}
	if tx.SOAPOperation != "" {
		metadata["soap_operation"] = tx.SOAPOperation
	}
	if tx.FaultCode != "" {
		metadata["soap_fault_code"] = tx.FaultCode
	}
	if tx.FaultString != "" {
		metadata["soap_fault_string"] = tx.FaultString
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
		if tx.IsSOAP {
			metrics["is_soap"] = true
		}
		if tx.SOAPAction != "" {
			metrics["soap_action"] = tx.SOAPAction
		}
		if tx.SOAPOperation != "" {
			metrics["soap_operation"] = tx.SOAPOperation
		}
		if tx.FaultCode != "" {
			metrics["soap_fault_code"] = tx.FaultCode
		}
		if tx.FaultString != "" {
			metrics["soap_fault_string"] = tx.FaultString
		}

		flows = append(flows, domain.Flow{
			FlowID:    tx.ID,
			Type:      domain.FlowHTTP,
			SrcIP:     tx.SrcIP,
			DstIP:     tx.DstIP,
			SrcPort:   tx.SrcPort,
			DstPort:   tx.DstPort,
			StartTime: tx.StartTime,
			EndTime:   tx.EndTime,
			Metrics:   metrics,
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
		SOAPAction:    extractHeaderValue(pkt.Payload, "SOAPAction"),
		SrcIP:         pkt.SrcIP,
		DstIP:         pkt.DstIP,
		SrcPort:       pkt.SrcPort,
		DstPort:       pkt.DstPort,
		StartTime:     pkt.Timestamp,
	}

	if body := extractBody(pkt.Payload, soapScanWindow); len(body) > 0 {
		if isSOAPContentType(tx.ContentType) || tx.SOAPAction != "" || looksLikeSOAPEnvelope(body) {
			tx.IsSOAP = true
			tx.SOAPOperation = extractSOAPOperation(body)
		}
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

	// SOAP fault detection: a fault is a well-formed XML document that many
	// stacks return under HTTP 200, so it must be found in the body itself
	// rather than inferred from the status line.
	if body := extractBody(pkt.Payload, soapScanWindow); len(body) > 0 {
		if isSOAPContentType(tx.ContentType) || looksLikeSOAPEnvelope(body) {
			tx.IsSOAP = true
			if op := extractSOAPOperation(body); op != "" && tx.SOAPOperation == "" {
				tx.SOAPOperation = op
			}
			if code, str, found := detectSOAPFault(body); found {
				tx.FaultCode = code
				tx.FaultString = str
				tx.IsError = true
			}
		}
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

// httpMethods covers the standard RFC 7231 methods plus Apache mod_cluster's
// management-protocol extension methods (STATUS, CONFIG, ENABLE-APP, ...),
// which appear in real captures as cluster heartbeat/balancer traffic on
// non-standard ports and are otherwise indistinguishable from plain TCP.
var httpMethods = []string{
	"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE ",
	"STATUS ", "CONFIG ", "ENABLE-APP ", "DISABLE-APP ", "STOP-APP ", "REMOVE-APP ", "INFO ", "DUMP ", "PING ",
}

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

// findBodyStart returns the offset of the first byte after the header/body
// separator ("\r\n\r\n"), or -1 if the payload contains no such separator.
func findBodyStart(payload []byte) int {
	for i := 0; i+3 < len(payload); i++ {
		if payload[i] == '\r' && payload[i+1] == '\n' && payload[i+2] == '\r' && payload[i+3] == '\n' {
			return i + 4
		}
	}
	return -1
}

// extractBody returns up to maxLen bytes of the HTTP body, or nil if there is
// no header/body separator within the captured payload or the body is empty.
func extractBody(payload []byte, maxLen int) []byte {
	idx := findBodyStart(payload)
	if idx < 0 || idx >= len(payload) {
		return nil
	}
	body := payload[idx:]
	if len(body) > maxLen {
		body = body[:maxLen]
	}
	return body
}

// extractBodyPreview extracts the first 200 characters of the HTTP body.
// The body starts after the blank line (\r\n\r\n) separating headers from body.
func extractBodyPreview(payload []byte) string {
	body := extractBody(payload, 200)
	if len(body) == 0 {
		return ""
	}

	// Check if it looks like text (not binary)
	for _, b := range body {
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			return "[binary data]"
		}
	}

	return string(body)
}

// soapScanWindow is how much of the body is scanned for SOAP envelope/fault
// detection — larger than the 200-byte human-facing preview because faults
// and the operation element can appear well past that point.
const soapScanWindow = 8192

// isSOAPContentType returns true for the standard SOAP 1.1 and 1.2 content
// types. Many real servers mislabel SOAP responses as plain "text/xml"
// (legitimately SOAP 1.1's registered type) or omit/garble the header
// entirely, which is why callers also fall back to looksLikeSOAPEnvelope.
func isSOAPContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "application/soap+xml") || strings.Contains(ct, "text/xml")
}

// looksLikeSOAPEnvelope reports whether the body opens with a SOAP Envelope
// element, independent of any Content-Type header.
func looksLikeSOAPEnvelope(body []byte) bool {
	window := body
	if len(window) > 512 {
		window = window[:512]
	}
	s := strings.ToLower(string(window))
	return strings.Contains(s, ":envelope") || strings.Contains(s, "<envelope")
}

// extractXMLElementText returns the text content of the first element whose
// local name (ignoring any namespace prefix, e.g. "soap:Fault" -> "Fault")
// case-insensitively matches localName. This is a lightweight scan sized for
// SOAP fault/body elements, not a general XML parser: it does not handle
// nested elements sharing the same name, CDATA sections, or entity decoding.
func extractXMLElementText(body []byte, localName string) string {
	s := string(body)
	lower := strings.ToLower(s)
	target := strings.ToLower(localName)

	idx := 0
	for idx < len(lower) {
		open := strings.IndexByte(lower[idx:], '<')
		if open < 0 {
			return ""
		}
		open += idx
		closeAngle := strings.IndexByte(lower[open:], '>')
		if closeAngle < 0 {
			return ""
		}
		closeAngle += open

		tag := lower[open+1 : closeAngle]
		isClosing := strings.HasPrefix(tag, "/")
		tag = strings.TrimPrefix(tag, "/")
		tag = strings.TrimSuffix(tag, "/")
		if sp := strings.IndexAny(tag, " \t\r\n"); sp >= 0 {
			tag = tag[:sp]
		}
		name := tag
		if colon := strings.IndexByte(name, ':'); colon >= 0 {
			name = name[colon+1:]
		}

		if !isClosing && name == target {
			contentStart := closeAngle + 1
			endTagIdx := strings.Index(lower[contentStart:], "</")
			if endTagIdx < 0 {
				return ""
			}
			return strings.TrimSpace(s[contentStart : contentStart+endTagIdx])
		}
		idx = closeAngle + 1
	}
	return ""
}

// detectSOAPFault looks for a SOAP 1.1 <Fault> or SOAP 1.2 <soap:Fault>
// element and extracts its code/reason text — SOAP 1.1 uses
// faultcode/faultstring, SOAP 1.2 uses Code/Reason (with Reason wrapping a
// Text child).
func detectSOAPFault(body []byte) (code, str string, found bool) {
	lower := strings.ToLower(string(body))
	if !strings.Contains(lower, ":fault") && !strings.Contains(lower, "<fault") {
		return "", "", false
	}
	found = true
	if c := extractXMLElementText(body, "faultcode"); c != "" {
		code = c
	} else if c := extractXMLElementText(body, "code"); c != "" {
		code = c
	}
	if s := extractXMLElementText(body, "faultstring"); s != "" {
		str = s
	} else if s := extractXMLElementText(body, "text"); s != "" {
		// SOAP 1.2's <Reason> wraps the message in a <Text> child — try the
		// leaf element first since the lightweight scan (no nesting support)
		// would otherwise return <Reason>'s content as far as the first
		// closing tag it meets, which is </Text>, still nested inside it.
		str = s
	} else if s := extractXMLElementText(body, "reason"); s != "" {
		str = s
	}
	return code, str, found
}

// extractSOAPOperation returns the local name of the first child element of
// <soap:Body> — the operation being invoked (in a request) or answered (in a
// response).
func extractSOAPOperation(body []byte) string {
	s := string(body)
	lower := strings.ToLower(s)

	bodyIdx := strings.Index(lower, ":body")
	if bodyIdx < 0 {
		bodyIdx = strings.Index(lower, "<body")
		if bodyIdx < 0 {
			return ""
		}
	}
	openEnd := strings.IndexByte(lower[bodyIdx:], '>')
	if openEnd < 0 {
		return ""
	}
	start := bodyIdx + openEnd + 1

	// Advance to the first '<' after the <Body> opening tag.
	i := start
	for i < len(lower) && lower[i] != '<' {
		i++
	}
	if i >= len(lower) {
		return ""
	}
	if i+1 < len(lower) && lower[i+1] == '/' {
		return "" // Body has no child element
	}
	closeAngle := strings.IndexByte(lower[i:], '>')
	if closeAngle < 0 {
		return ""
	}
	closeAngle += i

	tag := s[i+1 : closeAngle]
	tag = strings.TrimSuffix(tag, "/")
	if sp := strings.IndexAny(tag, " \t\r\n"); sp >= 0 {
		tag = tag[:sp]
	}
	if colon := strings.IndexByte(tag, ':'); colon >= 0 {
		tag = tag[colon+1:]
	}
	return tag
}

// Ensure Decoder implements StreamingDecoder.
var _ protocols.StreamingDecoder = (*Decoder)(nil)
