// Package ajp decodes the Apache JServ Protocol (AJP13) — the binary
// connector protocol Apache httpd (mod_jk / mod_proxy_ajp) uses to forward
// requests to a servlet container (Tomcat, etc.) on port 8009. It does not
// decrypt or terminate TLS; it decodes the AJP framing that carries requests
// already stripped of TLS by the httpd front end.
package ajp

import "time"

// Magic bytes at the start of every AJP13 packet.
const (
	MagicForward  uint16 = 0x1234 // Apache -> Container
	MagicResponse uint16 = 0x4142 // Container -> Apache ("AB")
)

// Container -> Apache packet prefix codes.
const (
	PrefixSendBodyChunk uint8 = 3
	PrefixSendHeaders   uint8 = 4
	PrefixEndResponse   uint8 = 5
	PrefixGetBodyChunk  uint8 = 6
)

// PrefixForwardRequest is the only Apache -> Container prefix code this
// decoder interprets (the request itself; ping/shutdown/etc. are ignored).
const PrefixForwardRequest uint8 = 2

// MethodNames maps AJP method codes to their HTTP method name.
var MethodNames = map[uint8]string{
	1: "OPTIONS", 2: "GET", 3: "HEAD", 4: "POST", 5: "PUT", 6: "DELETE",
	7: "TRACE", 8: "PROPFIND", 9: "PROPPATCH", 10: "MKCOL", 11: "COPY",
	12: "MOVE", 13: "LOCK", 14: "UNLOCK", 15: "ACL", 16: "REPORT",
	17: "VERSION-CONTROL", 18: "CHECKIN", 19: "CHECKOUT", 20: "UNCHECKOUT",
	21: "SEARCH",
}

// RequestHeaderNames maps well-known AJP request header codes (sc_req_headers).
var RequestHeaderNames = map[uint16]string{
	0xA001: "Accept", 0xA002: "Accept-Charset", 0xA003: "Accept-Encoding",
	0xA004: "Accept-Language", 0xA005: "Authorization", 0xA006: "Connection",
	0xA007: "Content-Type", 0xA008: "Content-Length", 0xA009: "Cookie",
	0xA00A: "Cookie2", 0xA00B: "Host", 0xA00C: "Pragma", 0xA00D: "Referer",
	0xA00E: "User-Agent",
}

// Transaction tracks one AJP forward-request and its (optional) response.
type Transaction struct {
	ID string

	Method     string
	Protocol   string
	ReqURI     string
	RemoteAddr string
	RemoteHost string
	ServerName string
	ServerPort uint16
	IsSSL      bool
	Headers    map[string]string

	ContentType   string
	ContentLength string
	SOAPAction    string

	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	QueryTime        time.Time
	ReplyTime        time.Time

	HasResponse   bool
	StatusCode    int
	StatusMessage string
	ReuseConn     bool
}
