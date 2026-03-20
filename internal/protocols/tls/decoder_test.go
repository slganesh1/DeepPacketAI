package tls

import (
	"encoding/binary"
	"testing"

	"DeepPacketAI/internal/domain"
)

func TestParseSNI(t *testing.T) {
	// Build SNI extension data: ListLen(2B) + NameType(1B) + NameLen(2B) + Name
	hostname := "www.example.com"
	data := make([]byte, 2+1+2+len(hostname))
	binary.BigEndian.PutUint16(data[0:2], uint16(1+2+len(hostname)))
	data[2] = 0 // host_name
	binary.BigEndian.PutUint16(data[3:5], uint16(len(hostname)))
	copy(data[5:], hostname)

	got := parseSNI(data)
	if got != hostname {
		t.Errorf("parseSNI = %q, want %q", got, hostname)
	}
}

func TestParseSNI_Empty(t *testing.T) {
	got := parseSNI([]byte{})
	if got != "" {
		t.Errorf("parseSNI(empty) = %q, want empty", got)
	}
}

func TestParseALPN(t *testing.T) {
	// ALPN: ListLen(2B) + [ProtoLen(1B) + Proto]+
	h2 := "h2"
	http11 := "http/1.1"
	listLen := 1 + len(h2) + 1 + len(http11)
	data := make([]byte, 2+listLen)
	binary.BigEndian.PutUint16(data[0:2], uint16(listLen))
	offset := 2
	data[offset] = byte(len(h2))
	offset++
	copy(data[offset:], h2)
	offset += len(h2)
	data[offset] = byte(len(http11))
	offset++
	copy(data[offset:], http11)

	protos := parseALPN(data)
	if len(protos) != 2 {
		t.Fatalf("expected 2 ALPN protos, got %d", len(protos))
	}
	if protos[0] != "h2" {
		t.Errorf("ALPN[0] = %q, want h2", protos[0])
	}
	if protos[1] != "http/1.1" {
		t.Errorf("ALPN[1] = %q, want http/1.1", protos[1])
	}
}

func TestIsTLSPort(t *testing.T) {
	tests := []struct {
		src, dst uint16
		want     bool
	}{
		{12345, 443, true},
		{443, 12345, true},
		{8443, 12345, true},
		{80, 12345, false},
		{12345, 8080, false},
	}
	for _, tt := range tests {
		got := isTLSPort(tt.src, tt.dst)
		if got != tt.want {
			t.Errorf("isTLSPort(%d, %d) = %v, want %v", tt.src, tt.dst, got, tt.want)
		}
	}
}

func TestIsPrintableString(t *testing.T) {
	if !isPrintableString("hello.example.com") {
		t.Error("expected printable")
	}
	if isPrintableString("") {
		t.Error("empty should not be printable")
	}
	if isPrintableString(string([]byte{0x00, 0x01})) {
		t.Error("binary should not be printable")
	}
}

func TestDecoderHandlePacket_NonTCP(t *testing.T) {
	d := NewDecoder()
	pkt := &domain.Packet{
		Protocol: "UDP",
		SrcPort:  12345,
		DstPort:  443,
		Payload:  make([]byte, 100),
	}
	d.HandlePacket(pkt)
	if pkt.AppProtocol != "" {
		t.Errorf("UDP packet should not be labeled, got %q", pkt.AppProtocol)
	}
}

func TestDecoderHandlePacket_NonTLSPort(t *testing.T) {
	d := NewDecoder()
	pkt := &domain.Packet{
		Protocol: "TCP",
		SrcPort:  12345,
		DstPort:  80,
		Payload:  make([]byte, 100),
	}
	d.HandlePacket(pkt)
	if pkt.AppProtocol != "" {
		t.Errorf("port 80 packet should not be labeled as TLS, got %q", pkt.AppProtocol)
	}
}

// buildClientHello constructs a minimal TLS ClientHello with SNI extension.
func buildClientHello(sni string) []byte {
	// Build extensions: SNI
	sniExtData := make([]byte, 2+1+2+len(sni))
	binary.BigEndian.PutUint16(sniExtData[0:2], uint16(1+2+len(sni)))
	sniExtData[2] = 0
	binary.BigEndian.PutUint16(sniExtData[3:5], uint16(len(sni)))
	copy(sniExtData[5:], sni)

	// Extension: type=0 (SNI), length, data
	var extensions []byte
	extensions = append(extensions, 0, 0) // ext type = SNI
	extLen := make([]byte, 2)
	binary.BigEndian.PutUint16(extLen, uint16(len(sniExtData)))
	extensions = append(extensions, extLen...)
	extensions = append(extensions, sniExtData...)

	// ClientHello body: version(2) + random(32) + sessionIDLen(1) + cipherSuitesLen(2) + cipher(2) + compLen(1) + comp(1) + extTotalLen(2) + extensions
	var body []byte
	body = append(body, 0x03, 0x03) // TLS 1.2
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0) // session ID length = 0
	body = append(body, 0, 2)    // cipher suites length = 2
	body = append(body, 0xC0, 0x2F) // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	body = append(body, 1, 0)   // compression methods: length=1, null

	totalExtLen := make([]byte, 2)
	binary.BigEndian.PutUint16(totalExtLen, uint16(len(extensions)))
	body = append(body, totalExtLen...)
	body = append(body, extensions...)

	// Handshake: type(1) + length(3) + body
	hsLen := len(body)
	var handshake []byte
	handshake = append(handshake, HandshakeClientHello)
	handshake = append(handshake, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	handshake = append(handshake, body...)

	// TLS Record: contentType(1) + version(2) + length(2) + handshake
	var record []byte
	record = append(record, ContentTypeHandshake)
	record = append(record, 0x03, 0x01) // TLS 1.0 in record layer (typical)
	recLen := make([]byte, 2)
	binary.BigEndian.PutUint16(recLen, uint16(len(handshake)))
	record = append(record, recLen...)
	record = append(record, handshake...)

	return record
}

func TestDecoderClientHello_SNI(t *testing.T) {
	d := NewDecoder()
	payload := buildClientHello("api.example.com")

	pkt := &domain.Packet{
		Protocol:    "TCP",
		SrcIP:       "192.168.1.10",
		DstIP:       "93.184.216.34",
		SrcPort:     54321,
		DstPort:     443,
		Payload:     payload,
		FrameNumber: 1,
	}

	d.HandlePacket(pkt)

	if pkt.AppProtocol != "HTTPS" {
		t.Errorf("AppProtocol = %q, want HTTPS", pkt.AppProtocol)
	}
	if pkt.Summary == "" {
		t.Error("Summary should not be empty")
	}

	// Check flows
	flows := d.Flush()
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	f := flows[0]
	if f.Type != "TLS" {
		t.Errorf("FlowType = %q, want TLS", f.Type)
	}
	if f.Metrics["sni"] != "api.example.com" {
		t.Errorf("SNI = %v, want api.example.com", f.Metrics["sni"])
	}
}

func TestDecoderApplicationData(t *testing.T) {
	d := NewDecoder()

	// TLS Application Data record
	var record []byte
	record = append(record, ContentTypeApplicationData)
	record = append(record, 0x03, 0x03) // TLS 1.2
	appData := make([]byte, 50) // encrypted data
	recLen := make([]byte, 2)
	binary.BigEndian.PutUint16(recLen, uint16(len(appData)))
	record = append(record, recLen...)
	record = append(record, appData...)

	pkt := &domain.Packet{
		Protocol:    "TCP",
		SrcIP:       "192.168.1.10",
		DstIP:       "93.184.216.34",
		SrcPort:     54321,
		DstPort:     443,
		Payload:     record,
		FrameNumber: 2,
	}

	d.HandlePacket(pkt)

	if pkt.AppProtocol != "HTTPS" {
		t.Errorf("AppProtocol = %q, want HTTPS", pkt.AppProtocol)
	}
}

func TestDecoderFlush_Empty(t *testing.T) {
	d := NewDecoder()
	flows := d.Flush()
	if len(flows) != 0 {
		t.Errorf("expected 0 flows, got %d", len(flows))
	}
}
