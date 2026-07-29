package tls

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
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

// realSelfSignedCertDER is a genuine self-signed X.509 certificate generated
// with `openssl req -x509 -newkey rsa:2048 -subj "/C=US/O=TestOrg/CN=selfsigned.example.com"`,
// base64-encoded. Subject and Issuer are identical:
// "C=US, O=TestOrg, CN=selfsigned.example.com".
const realSelfSignedCertB64 = `MIIDYTCCAkmgAwIBAgIUVEmenf+ZBFjcKPoViC2C910KRhUwDQYJKoZIhvcNAQELBQAwQDELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB1Rlc3RPcmcxHzAdBgNVBAMMFnNlbGZzaWduZWQuZXhhbXBsZS5jb20wHhcNMjYwNzI4MTMyNzMwWhcNMjYwNzI5MTMyNzMwWjBAMQswCQYDVQQGEwJVUzEQMA4GA1UECgwHVGVzdE9yZzEfMB0GA1UEAwwWc2VsZnNpZ25lZC5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK8gxgN7oZcfcSuUkX3s0KcG9J/DbTHYS1Nl5DpIKaEj1jHeMUyeT54YxcX19m7SVTXEyP+Uv2nayTeILl0t7AQYmXO32sWGpnxG03dwG+wOnWrjFhANZqZDBbcuaxWbLJaTsSJsRsY/YxyO3zwNx+boORGDrWIT1pbaF0XWmE2HuihoglUhNpi5pRdLLq4SCzvlfkzAEDAgJLWyNvvuG488lVlVbR0xzNdBiHNZ94rDWraXMZlgRDiOGrnJLBBYG4QaD4y9EsVoVzGIVsdD+F1Xgu4eAWlxnRoj/nUKWLQlgpuSAoilTQDPDfUG56jmku8QMEwQWM9feGlgcJkh5GsCAwEAAaNTMFEwHQYDVR0OBBYEFJ+tQejJ7cefcVjfnz1jv/WJaz0MMB8GA1UdIwQYMBaAFJ+tQejJ7cefcVjfnz1jv/WJaz0MMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADcRgxdsheBxWcwV7/GX2B5L7AmKoSSQpaPcGQ6JvsuwSNVkAXwS1rpOgqOIj7/PRR4z3pCAMZO0sJYQRvJKeLv27IHkokjk0IcOMZnPSAef3SPII+mixn2k9CwPqgpjVvKR676ctVw2xhXypB63ZgfjK1R/qkbc68/1+qCIRGBhi5cN6y0x2AusbEamYoXV45PBmcN4sLjAlSrkf1Pt2JiblVe/ObE0V9B7JFEHc1RQXHtTQ4P3AUe9S15yOCOUfPTPeh32mmt9VB2DIPDvt6r1yJ+Rym85o4+aP1JohPADbvP0TLiurgMF//Bs8dRH43cObdbMA4MbJAuf/8LPvIY=`

func mustDecodeCert(t *testing.T) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(realSelfSignedCertB64)
	if err != nil {
		t.Fatalf("failed to decode fixture cert: %v", err)
	}
	return data
}

func TestExtractCNRealSelfSignedCert(t *testing.T) {
	data := mustDecodeCert(t)
	subject := extractCN(data, true)
	issuer := extractCN(data, false)
	if subject != "selfsigned.example.com" {
		t.Fatalf("subject: got %q, want selfsigned.example.com", subject)
	}
	if issuer != "selfsigned.example.com" {
		t.Fatalf("issuer: got %q, want selfsigned.example.com", issuer)
	}
	if subject != issuer {
		t.Fatalf("expected self-signed cert to have subject == issuer")
	}
}

func TestReadASN1LengthShortForm(t *testing.T) {
	data := []byte{0x0C, 0x05, 'h', 'e', 'l', 'l', 'o'}
	length, valStart, ok := readASN1Length(data, 1)
	if !ok || length != 5 || valStart != 2 {
		t.Fatalf("got length=%d valStart=%d ok=%v, want 5,2,true", length, valStart, ok)
	}
}

func TestReadASN1LengthLongForm1Byte(t *testing.T) {
	// tag(1) + 0x81 (long form, 1 length byte follows) + length byte (200) + value
	value := make([]byte, 200)
	for i := range value {
		value[i] = 'x'
	}
	data := append([]byte{0x0C, 0x81, 200}, value...)
	length, valStart, ok := readASN1Length(data, 1)
	if !ok || length != 200 || valStart != 3 {
		t.Fatalf("got length=%d valStart=%d ok=%v, want 200,3,true", length, valStart, ok)
	}
}

func TestReadASN1LengthLongForm2Bytes(t *testing.T) {
	// length = 300 (0x012C), encoded as 0x82 0x01 0x2C
	data := []byte{0x0C, 0x82, 0x01, 0x2C}
	length, valStart, ok := readASN1Length(data, 1)
	if !ok || length != 300 || valStart != 4 {
		t.Fatalf("got length=%d valStart=%d ok=%v, want 300,4,true", length, valStart, ok)
	}
}

func TestReadASN1LengthTruncated(t *testing.T) {
	data := []byte{0x0C, 0x82, 0x01} // claims 2 length bytes follow but only 1 present
	_, _, ok := readASN1Length(data, 1)
	if ok {
		t.Fatal("expected truncated long-form length to be rejected")
	}
}

func TestReadASN1LengthIndefiniteFormRejected(t *testing.T) {
	data := []byte{0x0C, 0x80} // 0x80 = indefinite form, not valid in DER
	_, _, ok := readASN1Length(data, 1)
	if ok {
		t.Fatal("expected indefinite-form length (0x80) to be rejected")
	}
}

// TestExtractCNLongFormCN proves the actual bug: a CN value of 147 bytes
// (well past the DER short-form 127-byte ceiling) previously came back blank
// because the length byte's high bit (0x81) was read as a literal length
// instead of a long-form marker.
func TestExtractCNLongFormCN(t *testing.T) {
	filler := make([]byte, 140)
	for i := range filler {
		filler[i] = 'a'
	}
	longCN := "device-" + string(filler)

	var certData []byte
	// Issuer CN (short form, ordinary length)
	certData = append(certData, 0x55, 0x04, 0x03) // OID commonName
	certData = append(certData, 0x0C, 0x05)       // UTF8String, length 5
	certData = append(certData, []byte("short")...)

	// Subject CN (long form: 0x81 + 1 length byte, since len(longCN) > 127)
	certData = append(certData, 0x55, 0x04, 0x03) // OID commonName
	certData = append(certData, 0x0C, 0x81, byte(len(longCN)))
	certData = append(certData, []byte(longCN)...)

	subject := extractCN(certData, true)
	if subject != longCN {
		t.Fatalf("subject: got %q (len %d), want long CN (len %d)", subject, len(subject), len(longCN))
	}
}

// TestPostCCSHandshakeRecordNotMisparsed reproduces the real bug behind a
// TLS cipher_suite value with no IANA assignment (observed in a real capture
// as 0x87e8): once a side sends ChangeCipherSpec, its next record — the
// encrypted Finished message — still carries record-layer ContentType
// Handshake (0x16), but the bytes are ciphertext. Before this fix, that
// ciphertext's first byte was blindly read as a handshake type (here it
// happens to be 0x02, i.e. ServerHello) and subsequent ciphertext bytes were
// parsed as if they were version/random/cipher-suite fields.
func TestPostCCSHandshakeRecordNotMisparsed(t *testing.T) {
	d := NewDecoder()

	client := &domain.Packet{
		Protocol: "TCP", SrcIP: "192.168.10.90", DstIP: "10.116.3.177",
		SrcPort: 33903, DstPort: 443, FrameNumber: 1,
	}

	// Client's ChangeCipherSpec record.
	client.Payload = []byte{ContentTypeChangeCipherSpec, 0x03, 0x03, 0x00, 0x01, 0x01}
	d.HandlePacket(client)

	// Client's encrypted Finished — record-layer ContentType is Handshake,
	// but the payload is ciphertext whose first byte happens to be 0x02.
	// (Real capture bytes truncated to record header + a handful of
	// ciphertext bytes; exact content beyond the type byte is irrelevant.)
	encryptedFinished := append([]byte{ContentTypeHandshake, 0x03, 0x03, 0x00, 0x40},
		[]byte{0x02, 0xcd, 0x6e, 0x61, 0x10, 0x88, 0x3e, 0x13, 0x78, 0x46}...)
	encryptedFinished = append(encryptedFinished, make([]byte, 0x40-10)...)
	client.Payload = encryptedFinished
	client.FrameNumber = 3
	d.HandlePacket(client)

	flows := d.Flush()
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	m := flows[0].Metrics
	if cs, ok := m["cipher_suite"]; ok {
		t.Fatalf("expected no cipher_suite to be derived from an encrypted post-CCS record, got %v", cs)
	}
	if !strings.Contains(m["handshake_messages"].(string), "Finished (encrypted)") {
		t.Fatalf("expected post-CCS record labeled as encrypted Finished, got %v", m["handshake_messages"])
	}
}

func TestFlushPairsSubjectIssuerFromSameRecord(t *testing.T) {
	d := NewDecoder()
	// Simulate a mutual-TLS connection: the server's Certificate message
	// (CA-signed, subject != issuer) followed by the client's Certificate
	// message (self-signed, subject == issuer). Subject/issuer must never be
	// mixed across the two records.
	d.records = append(d.records,
		tlsRecord{
			SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 443, DstPort: 51000,
			HandshakeType: "Certificate",
			CertSubject:   "server.example.com",
			CertIssuer:    "Example CA",
		},
		tlsRecord{
			SrcIP: "10.0.0.2", DstIP: "10.0.0.1", SrcPort: 51000, DstPort: 443,
			HandshakeType: "Certificate",
			CertSubject:   "client-device-42",
			CertIssuer:    "client-device-42",
		},
	)

	flows := d.Flush()
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	m := flows[0].Metrics
	subject, _ := m["cert_subject"].(string)
	issuer, _ := m["cert_issuer"].(string)
	// The last record processed wins (client's self-signed pair) — the
	// important assertion is that they come from the SAME record, not a
	// cross of server-subject with client-issuer or vice versa.
	if subject != issuer {
		t.Fatalf("expected paired subject/issuer from the same record, got subject=%q issuer=%q", subject, issuer)
	}
}
