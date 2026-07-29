package ajp

import (
	"encoding/binary"
	"fmt"
	"strings"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/protocols"
)

// Decoder decodes AJP13 forward-request/response exchanges on port 8009.
type Decoder struct {
	transactions map[string]*Transaction // keyed by the request's 5-tuple
	completed    []*Transaction
}

func NewDecoder() *Decoder {
	return &Decoder{transactions: make(map[string]*Transaction)}
}

func (d *Decoder) Name() string { return "ajp" }

func isAJPPort(src, dst uint16) bool {
	return src == 8009 || dst == 8009
}

func (d *Decoder) HandlePacket(pkt *domain.Packet) {
	if pkt.Protocol != "TCP" || len(pkt.Payload) < 5 {
		return
	}
	if !isAJPPort(pkt.SrcPort, pkt.DstPort) {
		return
	}
	d.parseAJP(pkt)
}

func (d *Decoder) HandlePacketLive(pkt *domain.Packet) *protocols.DecodedPacket {
	if pkt.Protocol != "TCP" || len(pkt.Payload) < 5 {
		return nil
	}
	if !isAJPPort(pkt.SrcPort, pkt.DstPort) {
		return nil
	}
	tx := d.parseAJP(pkt)
	if tx == nil {
		return nil
	}
	return &protocols.DecodedPacket{
		Packet:   pkt,
		Protocol: "AJP",
		Summary:  pkt.Summary,
		Metadata: map[string]any{
			"method":      tx.Method,
			"req_uri":     tx.ReqURI,
			"server_name": tx.ServerName,
			"soap_action": tx.SOAPAction,
			"status_code": tx.StatusCode,
		},
	}
}

func (d *Decoder) Flush() []domain.Flow {
	var flows []domain.Flow
	for _, tx := range d.completed {
		flows = append(flows, tx.toFlow())
	}
	return flows
}

func (tx *Transaction) toFlow() domain.Flow {
	m := map[string]any{
		"method":      tx.Method,
		"protocol":    tx.Protocol,
		"req_uri":     tx.ReqURI,
		"server_name": tx.ServerName,
		"server_port": tx.ServerPort,
		"remote_addr": tx.RemoteAddr,
		"remote_host": tx.RemoteHost,
		"is_ssl":      tx.IsSSL,
	}
	if tx.ContentType != "" {
		m["content_type"] = tx.ContentType
	}
	if tx.ContentLength != "" {
		m["content_length"] = tx.ContentLength
	}
	if tx.SOAPAction != "" {
		m["soap_action"] = tx.SOAPAction
	}
	if tx.HasResponse {
		m["status_code"] = tx.StatusCode
		m["status_message"] = tx.StatusMessage
		m["reuse_connection"] = tx.ReuseConn
		m["is_error"] = tx.StatusCode >= 400
	} else {
		m["is_error"] = false
	}

	return domain.Flow{
		FlowID:    tx.ID,
		Type:      domain.FlowAJP,
		SrcIP:     tx.SrcIP,
		DstIP:     tx.DstIP,
		SrcPort:   tx.SrcPort,
		DstPort:   tx.DstPort,
		StartTime: tx.QueryTime,
		EndTime:   tx.ReplyTime,
		Metrics:   m,
	}
}

// parseAJP dispatches a single AJP packet — either a Forward Request
// (Apache -> Container, magic 0x1234) or a container response packet
// (Container -> Apache, magic "AB" / 0x4142).
func (d *Decoder) parseAJP(pkt *domain.Packet) *Transaction {
	p := pkt.Payload
	if len(p) < 4 {
		return nil
	}
	magic := binary.BigEndian.Uint16(p[0:2])
	length := int(binary.BigEndian.Uint16(p[2:4]))

	body := p[4:]
	if length > 0 && len(body) > length {
		body = body[:length]
	}
	if len(body) == 0 {
		return nil
	}

	switch magic {
	case MagicForward:
		return d.handleForwardRequest(pkt, body)
	case MagicResponse:
		return d.handleContainerPacket(pkt, body)
	default:
		return nil
	}
}

func (d *Decoder) handleForwardRequest(pkt *domain.Packet, body []byte) *Transaction {
	if len(body) < 1 || body[0] != PrefixForwardRequest {
		return nil
	}
	r := &reader{buf: body[1:]}

	methodCode, ok := r.byte()
	if !ok {
		return nil
	}
	protocolStr, _ := r.str()
	reqURI, ok := r.str()
	if !ok {
		return nil
	}
	remoteAddr, _ := r.str()
	remoteHost, _ := r.str()
	serverName, _ := r.str()
	serverPort, _ := r.uint16()
	isSSLByte, _ := r.byte()
	numHeaders, _ := r.uint16()

	headers := make(map[string]string, numHeaders)
	for i := 0; i < int(numHeaders); i++ {
		code, ok := r.uint16()
		if !ok {
			break
		}
		var name string
		if code >= 0xA001 && code <= 0xA00E {
			name = RequestHeaderNames[code]
			val, ok := r.str()
			if !ok {
				break
			}
			if name != "" {
				headers[strings.ToLower(name)] = val
			}
			continue
		}
		// Not a well-known code: it's the 2-byte length of a literal header name.
		name, ok = r.strWithLen(code)
		if !ok {
			break
		}
		val, ok := r.str()
		if !ok {
			break
		}
		if name != "" {
			headers[strings.ToLower(name)] = val
		}
	}

	key := fmt.Sprintf("%s:%d-%s:%d", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort)
	contentType := headers["content-type"]
	method := MethodNames[methodCode]
	if method == "" {
		method = fmt.Sprintf("METHOD_%d", methodCode)
	}

	tx := &Transaction{
		ID:            fmt.Sprintf("ajp-%s-%d", key, pkt.FrameNumber),
		Method:        method,
		Protocol:      protocolStr,
		ReqURI:        reqURI,
		RemoteAddr:    remoteAddr,
		RemoteHost:    remoteHost,
		ServerName:    serverName,
		ServerPort:    serverPort,
		IsSSL:         isSSLByte == 1,
		Headers:       headers,
		ContentType:   contentType,
		ContentLength: headers["content-length"],
		SOAPAction:    extractSOAPAction(contentType, headers),
		SrcIP:         pkt.SrcIP,
		DstIP:         pkt.DstIP,
		SrcPort:       pkt.SrcPort,
		DstPort:       pkt.DstPort,
		QueryTime:     pkt.Timestamp,
	}

	d.transactions[key] = tx
	pkt.AppProtocol = "AJP"
	pkt.Summary = fmt.Sprintf("AJP %s %s -> %s", tx.Method, tx.ReqURI, tx.ServerName)
	return tx
}

func (d *Decoder) handleContainerPacket(pkt *domain.Packet, body []byte) *Transaction {
	if len(body) < 1 {
		return nil
	}
	prefix := body[0]
	// Response packets travel container -> Apache, i.e. reversed relative to
	// the request's own SrcIP/SrcPort, so look up the request under the
	// swapped key.
	key := fmt.Sprintf("%s:%d-%s:%d", pkt.DstIP, pkt.DstPort, pkt.SrcIP, pkt.SrcPort)
	tx, ok := d.transactions[key]

	switch prefix {
	case PrefixSendHeaders:
		r := &reader{buf: body[1:]}
		status, sok := r.uint16()
		statusMsg, _ := r.str()
		if !sok {
			return nil
		}
		if !ok {
			tx = &Transaction{
				ID:      fmt.Sprintf("ajp-resp-%d", pkt.FrameNumber),
				SrcIP:   pkt.DstIP,
				DstIP:   pkt.SrcIP,
				SrcPort: pkt.DstPort,
				DstPort: pkt.SrcPort,
			}
		}
		tx.StatusCode = int(status)
		tx.StatusMessage = statusMsg
		tx.HasResponse = true
		tx.ReplyTime = pkt.Timestamp
		pkt.AppProtocol = "AJP"
		pkt.Summary = fmt.Sprintf("AJP %d %s", tx.StatusCode, tx.StatusMessage)
		return tx

	case PrefixEndResponse:
		if !ok {
			return nil
		}
		if len(body) >= 2 {
			tx.ReuseConn = body[1] == 1
		}
		delete(d.transactions, key)
		d.completed = append(d.completed, tx)
		pkt.AppProtocol = "AJP"
		pkt.Summary = "AJP End Response"
		return tx

	default:
		return nil
	}
}

// extractSOAPAction pulls the SOAP action out of either a dedicated
// SOAPAction header (SOAP 1.1) or the action= parameter of a
// multipart/related Content-Type (SOAP 1.2 / MTOM+XOP), which is how
// SOAP-with-attachments carries it.
func extractSOAPAction(contentType string, headers map[string]string) string {
	if sa := headers["soapaction"]; sa != "" {
		return strings.Trim(sa, `"`)
	}
	lower := strings.ToLower(contentType)
	idx := strings.Index(lower, `action="`)
	if idx == -1 {
		return ""
	}
	rest := contentType[idx+len(`action="`):]
	end := strings.IndexByte(rest, '"')
	if end == -1 {
		return ""
	}
	return rest[:end]
}

// reader is a small forward-only cursor over an AJP-encoded byte buffer.
type reader struct {
	buf []byte
	pos int
}

func (r *reader) byte() (uint8, bool) {
	if r.pos >= len(r.buf) {
		return 0, false
	}
	b := r.buf[r.pos]
	r.pos++
	return b, true
}

func (r *reader) uint16() (uint16, bool) {
	if r.pos+2 > len(r.buf) {
		return 0, false
	}
	v := binary.BigEndian.Uint16(r.buf[r.pos : r.pos+2])
	r.pos += 2
	return v, true
}

// str reads an AJP string: a 2-byte big-endian length prefix, that many
// bytes, and a trailing NUL the length does not include.
func (r *reader) str() (string, bool) {
	l, ok := r.uint16()
	if !ok {
		return "", false
	}
	return r.strWithLen(l)
}

func (r *reader) strWithLen(l uint16) (string, bool) {
	if l == 0xFFFF {
		return "", true // AJP's encoding of a null string
	}
	if r.pos+int(l)+1 > len(r.buf) {
		return "", false
	}
	s := string(r.buf[r.pos : r.pos+int(l)])
	r.pos += int(l) + 1 // skip trailing NUL
	return s, true
}

// Ensure Decoder implements StreamingDecoder.
var _ protocols.StreamingDecoder = (*Decoder)(nil)
