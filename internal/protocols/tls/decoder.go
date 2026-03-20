package tls

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"strings"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/dpi"
	"DeepPacketAI/internal/protocols"
)

func md5sum(s string) string {
	h := md5.Sum([]byte(s))
	return fmt.Sprintf("%x", h)
}

// TLS content types
const (
	ContentTypeChangeCipherSpec = 20
	ContentTypeAlert            = 21
	ContentTypeHandshake        = 22
	ContentTypeApplicationData  = 23
)

// TLS handshake types
const (
	HandshakeClientHello   = 1
	HandshakeServerHello   = 2
	HandshakeCertificate   = 11
	HandshakeServerHelloDone = 14
)

// TLS version names
var TLSVersionNames = map[uint16]string{
	0x0300: "SSL 3.0",
	0x0301: "TLS 1.0",
	0x0302: "TLS 1.1",
	0x0303: "TLS 1.2",
	0x0304: "TLS 1.3",
}

// Cipher suite names (common ones)
var CipherSuiteNames = map[uint16]string{
	// TLS 1.3
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",

	// TLS 1.2 ECDHE
	0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",

	// TLS 1.2 DHE
	0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",

	// TLS 1.2 RSA
	0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
}

// Decoder extracts TLS handshake metadata without decryption.
type Decoder struct {
	records []tlsRecord
}

type tlsRecord struct {
	SrcIP         string
	DstIP         string
	SrcPort       uint16
	DstPort       uint16
	FrameNum      uint64
	HandshakeType string   // "ClientHello", "ServerHello", "Certificate", "AppData"
	TLSVersion    string
	SNI           string   // Server Name Indication (from ClientHello)
	CipherSuite   string   // Negotiated cipher (from ServerHello)
	CipherSuites  []string // Offered cipher names (from ClientHello, named only)
	CipherSuiteIDs []uint16 // All offered cipher IDs from ClientHello (for JA3)
	ExtensionTypes []uint16 // Extension type codes from ClientHello (for JA3)
	ALPN          []string // Application-Layer Protocol Negotiation
	CertSubject   string   // Certificate subject CN (from Certificate)
	CertIssuer    string   // Certificate issuer CN (from Certificate)
}

func NewDecoder() *Decoder {
	return &Decoder{}
}

func (d *Decoder) Name() string { return "tls" }

func (d *Decoder) HandlePacket(pkt *domain.Packet) {
	if pkt.Protocol != "TCP" {
		return
	}
	if len(pkt.Payload) < 5 {
		return
	}
	if !isTLSPort(pkt.SrcPort, pkt.DstPort) && !dpi.IsTLS(pkt.Payload) {
		return
	}

	d.parseTLS(pkt)
}

func (d *Decoder) HandlePacketLive(pkt *domain.Packet) *protocols.DecodedPacket {
	if pkt.Protocol != "TCP" {
		return nil
	}
	if len(pkt.Payload) < 5 {
		return nil
	}
	if !isTLSPort(pkt.SrcPort, pkt.DstPort) && !dpi.IsTLS(pkt.Payload) {
		return nil
	}

	rec := d.parseTLS(pkt)
	if rec == nil {
		return nil
	}

	metadata := map[string]any{
		"handshake_type": rec.HandshakeType,
		"tls_version":    rec.TLSVersion,
	}
	if rec.SNI != "" {
		metadata["sni"] = rec.SNI
	}
	if rec.CipherSuite != "" {
		metadata["cipher_suite"] = rec.CipherSuite
	}
	if len(rec.ALPN) > 0 {
		metadata["alpn"] = strings.Join(rec.ALPN, ", ")
	}
	if rec.CertSubject != "" {
		metadata["cert_subject"] = rec.CertSubject
	}
	if rec.CertIssuer != "" {
		metadata["cert_issuer"] = rec.CertIssuer
	}

	return &protocols.DecodedPacket{
		Packet:   pkt,
		Protocol: "TLS",
		Summary:  pkt.Summary,
		Metadata: metadata,
	}
}

func (d *Decoder) Flush() []domain.Flow {
	// Group records by connection (src:port -> dst:port)
	type connKey struct {
		srcIP, dstIP     string
		srcPort, dstPort uint16
	}

	connections := make(map[connKey][]*tlsRecord)
	for i := range d.records {
		rec := &d.records[i]
		k := connKey{rec.SrcIP, rec.DstIP, rec.SrcPort, rec.DstPort}
		rk := connKey{rec.DstIP, rec.SrcIP, rec.DstPort, rec.SrcPort}
		if _, ok := connections[rk]; ok {
			connections[rk] = append(connections[rk], rec)
		} else {
			connections[k] = append(connections[k], rec)
		}
	}

	var flows []domain.Flow
	for k, recs := range connections {
		metrics := map[string]any{}

		var sni, tlsVersion, cipher, certSubject, certIssuer string
		var alpn []string
		var cipherSuiteIDs []uint16
		var extTypes []uint16
		handshakeTypes := []string{}

		for _, r := range recs {
			if r.SNI != "" {
				sni = r.SNI
			}
			if r.TLSVersion != "" {
				tlsVersion = r.TLSVersion
			}
			if r.CipherSuite != "" {
				cipher = r.CipherSuite
			}
			if r.CertSubject != "" {
				certSubject = r.CertSubject
			}
			if r.CertIssuer != "" {
				certIssuer = r.CertIssuer
			}
			if len(r.ALPN) > 0 {
				alpn = r.ALPN
			}
			if len(r.CipherSuiteIDs) > 0 && len(cipherSuiteIDs) == 0 {
				cipherSuiteIDs = r.CipherSuiteIDs
			}
			if len(r.ExtensionTypes) > 0 && len(extTypes) == 0 {
				extTypes = r.ExtensionTypes
			}
			handshakeTypes = append(handshakeTypes, r.HandshakeType)
		}

		if sni != "" {
			metrics["sni"] = sni
		}
		if tlsVersion != "" {
			metrics["tls_version"] = tlsVersion
		}
		if cipher != "" {
			metrics["cipher_suite"] = cipher
		}
		if certSubject != "" {
			metrics["cert_subject"] = certSubject
		}
		if certIssuer != "" {
			metrics["cert_issuer"] = certIssuer
		}
		if len(alpn) > 0 {
			metrics["alpn"] = strings.Join(alpn, ", ")
		}
		metrics["handshake_messages"] = strings.Join(handshakeTypes, ", ")
		metrics["message_count"] = len(recs)

		// JA3 fingerprint (partial: version + ciphers + extensions)
		if len(cipherSuiteIDs) > 0 {
			ja3Str, ja3Hash := computeJA3(tlsVersionNum(tlsVersion), cipherSuiteIDs, extTypes)
			metrics["ja3_string"] = ja3Str
			metrics["ja3_hash"] = ja3Hash
			// Store raw IDs for detection rules
			ids := make([]int, len(cipherSuiteIDs))
			for i, v := range cipherSuiteIDs {
				ids[i] = int(v)
			}
			metrics["cipher_suite_ids"] = ids
		}

		// Security flags
		if cipher != "" {
			metrics["has_forward_secrecy"] = hasForwardSecrecy(cipher)
			metrics["cipher_strength"] = cipherStrength(cipher)
		}
		if certSubject != "" && certIssuer != "" {
			metrics["cert_self_signed"] = certSubject == certIssuer
		}

		flowID := fmt.Sprintf("tls-%s:%d-%s:%d", k.srcIP, k.srcPort, k.dstIP, k.dstPort)

		flows = append(flows, domain.Flow{
			FlowID:  flowID,
			Type:    domain.FlowTLS,
			SrcIP:   k.srcIP,
			DstIP:   k.dstIP,
			SrcPort: k.srcPort,
			DstPort: k.dstPort,
			Metrics: metrics,
		})
	}

	return flows
}

// computeJA3 produces a partial JA3 fingerprint from TLS ClientHello fields.
// Full JA3 = MD5(Version,Ciphers,Extensions,EllipticCurves,PointFormats).
// We compute: MD5(Version,Ciphers,Extensions,,) — omitting curves/point-formats.
func computeJA3(version uint16, cipherIDs, extTypes []uint16) (string, string) {
	cs := joinUint16s(filterGrease(cipherIDs))
	ex := joinUint16s(filterGrease(extTypes))
	input := fmt.Sprintf("%d,%s,%s,,", version, cs, ex)
	h := md5sum(input)
	return input, h
}

func joinUint16s(vals []uint16) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, "-")
}

func filterGrease(vals []uint16) []uint16 {
	out := vals[:0:len(vals)]
	for _, v := range vals {
		if v&0x0f0f != 0x0a0a {
			out = append(out, v)
		}
	}
	return out
}

func tlsVersionNum(name string) uint16 {
	for k, v := range TLSVersionNames {
		if v == name {
			return k
		}
	}
	return 0x0303 // default TLS 1.2
}

// hasForwardSecrecy returns true if the cipher suite provides forward secrecy.
func hasForwardSecrecy(cipher string) bool {
	return strings.Contains(cipher, "ECDHE") || strings.Contains(cipher, "DHE")
}

// cipherStrength returns a letter grade for the negotiated cipher.
func cipherStrength(cipher string) string {
	upper := strings.ToUpper(cipher)
	// F: fundamentally broken
	if strings.Contains(upper, "NULL") || strings.Contains(upper, "EXPORT") ||
		strings.Contains(upper, "ANON") || strings.Contains(upper, "_RC4_") ||
		strings.Contains(upper, "RC4") {
		return "F"
	}
	// D: DES / 3DES
	if strings.Contains(upper, "_DES_") || strings.Contains(upper, "3DES") {
		return "D"
	}
	// C: no forward secrecy (RSA key exchange)
	if !strings.Contains(upper, "ECDHE") && !strings.Contains(upper, "DHE") {
		return "C"
	}
	// B: forward secrecy but CBC mode
	if strings.Contains(upper, "_CBC_") {
		return "B"
	}
	// A: ECDHE/DHE + AEAD (GCM / CHACHA20 / CCM)
	return "A"
}

func (d *Decoder) parseTLS(pkt *domain.Packet) *tlsRecord {
	payload := pkt.Payload

	// TLS Record: ContentType(1B) + Version(2B) + Length(2B) + data
	contentType := payload[0]
	if contentType < 20 || contentType > 23 {
		return nil // Not a TLS record
	}

	recordVersion := binary.BigEndian.Uint16(payload[1:3])
	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))

	// Sanity check
	if recordVersion < 0x0300 || recordVersion > 0x0304 {
		// Could be 0x0301 in record layer even for TLS 1.3
		// Allow some flexibility
		if recordVersion != 0x0303 && recordVersion < 0x0300 {
			return nil
		}
	}

	versionName := TLSVersionNames[recordVersion]
	if versionName == "" {
		versionName = fmt.Sprintf("0x%04x", recordVersion)
	}

	rec := &tlsRecord{
		SrcIP:    pkt.SrcIP,
		DstIP:    pkt.DstIP,
		SrcPort:  pkt.SrcPort,
		DstPort:  pkt.DstPort,
		FrameNum: pkt.FrameNumber,
	}

	switch contentType {
	case ContentTypeHandshake:
		if 5+recordLen > len(payload) {
			recordLen = len(payload) - 5
		}
		if recordLen < 4 {
			return nil
		}
		d.parseHandshake(payload[5:5+recordLen], rec)

	case ContentTypeApplicationData:
		rec.HandshakeType = "ApplicationData"
		rec.TLSVersion = versionName

	case ContentTypeChangeCipherSpec:
		rec.HandshakeType = "ChangeCipherSpec"
		rec.TLSVersion = versionName

	case ContentTypeAlert:
		rec.HandshakeType = "Alert"
		rec.TLSVersion = versionName

	default:
		return nil
	}

	// Set packet labels
	proto := "TLS"
	if pkt.DstPort == 443 || pkt.SrcPort == 443 {
		proto = "HTTPS"
	}
	pkt.AppProtocol = proto

	summary := rec.HandshakeType
	if rec.SNI != "" {
		summary += " " + rec.SNI
	}
	if rec.TLSVersion != "" {
		summary += " [" + rec.TLSVersion + "]"
	}
	if rec.CipherSuite != "" {
		summary += " " + rec.CipherSuite
	}
	pkt.Summary = summary

	d.records = append(d.records, *rec)
	return rec
}

func (d *Decoder) parseHandshake(data []byte, rec *tlsRecord) {
	if len(data) < 4 {
		return
	}

	hsType := data[0]
	hsLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	hsData := data[4:]
	if hsLen > len(hsData) {
		hsData = data[4:]
	}

	switch hsType {
	case HandshakeClientHello:
		rec.HandshakeType = "ClientHello"
		d.parseClientHello(hsData, rec)
	case HandshakeServerHello:
		rec.HandshakeType = "ServerHello"
		d.parseServerHello(hsData, rec)
	case HandshakeCertificate:
		rec.HandshakeType = "Certificate"
		d.parseCertificate(hsData, rec)
	case HandshakeServerHelloDone:
		rec.HandshakeType = "ServerHelloDone"
	default:
		rec.HandshakeType = fmt.Sprintf("Handshake_%d", hsType)
	}
}

// parseClientHello extracts SNI, offered cipher suites, and ALPN from ClientHello.
// ClientHello format:
//   Version(2B) + Random(32B) + SessionIDLen(1B) + SessionID(var)
//   + CipherSuitesLen(2B) + CipherSuites(var)
//   + CompressionMethodsLen(1B) + CompressionMethods(var)
//   + ExtensionsLen(2B) + Extensions(var)
func (d *Decoder) parseClientHello(data []byte, rec *tlsRecord) {
	if len(data) < 38 {
		return
	}

	// Client version
	clientVersion := binary.BigEndian.Uint16(data[0:2])
	rec.TLSVersion = TLSVersionNames[clientVersion]
	if rec.TLSVersion == "" {
		rec.TLSVersion = fmt.Sprintf("0x%04x", clientVersion)
	}

	offset := 2 + 32 // version + random

	// Session ID
	if offset >= len(data) {
		return
	}
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	// Cipher suites
	if offset+2 > len(data) {
		return
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+cipherSuitesLen > len(data) {
		cipherSuitesLen = len(data) - offset
	}

	// Parse offered cipher suites — collect all IDs for JA3, names where known
	for i := 0; i < cipherSuitesLen; i += 2 {
		if offset+i+2 > len(data) {
			break
		}
		cs := binary.BigEndian.Uint16(data[offset+i : offset+i+2])
		// Skip GREASE values (0xXAXA pattern)
		if cs&0x0f0f == 0x0a0a {
			continue
		}
		rec.CipherSuiteIDs = append(rec.CipherSuiteIDs, cs)
		if name := CipherSuiteNames[cs]; name != "" {
			rec.CipherSuites = append(rec.CipherSuites, name)
		}
	}
	offset += cipherSuitesLen

	// Compression methods
	if offset >= len(data) {
		return
	}
	compLen := int(data[offset])
	offset += 1 + compLen

	// Extensions
	if offset+2 > len(data) {
		return
	}
	extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	extEnd := offset + extLen
	if extEnd > len(data) {
		extEnd = len(data)
	}

	d.parseExtensions(data[offset:extEnd], rec)
}

// parseServerHello extracts the negotiated cipher suite and version.
// ServerHello format:
//   Version(2B) + Random(32B) + SessionIDLen(1B) + SessionID(var)
//   + CipherSuite(2B) + CompressionMethod(1B) + [Extensions]
func (d *Decoder) parseServerHello(data []byte, rec *tlsRecord) {
	if len(data) < 38 {
		return
	}

	serverVersion := binary.BigEndian.Uint16(data[0:2])
	rec.TLSVersion = TLSVersionNames[serverVersion]
	if rec.TLSVersion == "" {
		rec.TLSVersion = fmt.Sprintf("0x%04x", serverVersion)
	}

	offset := 2 + 32 // version + random

	// Session ID
	if offset >= len(data) {
		return
	}
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	// Selected cipher suite
	if offset+2 > len(data) {
		return
	}
	cs := binary.BigEndian.Uint16(data[offset : offset+2])
	rec.CipherSuite = CipherSuiteNames[cs]
	if rec.CipherSuite == "" {
		rec.CipherSuite = fmt.Sprintf("0x%04x", cs)
	}
	offset += 2

	// Compression method
	offset += 1

	// Extensions (ServerHello may have supported_versions ext for TLS 1.3)
	if offset+2 <= len(data) {
		extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		extEnd := offset + extLen
		if extEnd > len(data) {
			extEnd = len(data)
		}
		d.parseServerExtensions(data[offset:extEnd], rec)
	}
}

// parseCertificate extracts the subject and issuer CN from the first certificate.
// Certificate format: CertsLength(3B) + [CertLength(3B) + CertData(var)]+
func (d *Decoder) parseCertificate(data []byte, rec *tlsRecord) {
	if len(data) < 3 {
		return
	}

	// Total certificates length
	offset := 3 // skip total length

	// First certificate
	if offset+3 > len(data) {
		return
	}
	certLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
	offset += 3
	if offset+certLen > len(data) {
		certLen = len(data) - offset
	}

	// Extract CN from the DER-encoded certificate
	// We do a simple heuristic scan for common OID patterns rather than full ASN.1 parsing
	certData := data[offset : offset+certLen]
	rec.CertSubject = extractCN(certData, true)
	rec.CertIssuer = extractCN(certData, false)
}

// parseExtensions processes TLS extensions from ClientHello.
func (d *Decoder) parseExtensions(data []byte, rec *tlsRecord) {
	offset := 0
	for offset+4 <= len(data) {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4
		if offset+extLen > len(data) {
			break
		}
		extData := data[offset : offset+extLen]

		// Collect all extension types for JA3 (skip GREASE values: 0xXAXA)
		if extType&0x0f0f != 0x0a0a {
			rec.ExtensionTypes = append(rec.ExtensionTypes, extType)
		}

		switch extType {
		case 0: // server_name (SNI)
			rec.SNI = parseSNI(extData)
		case 16: // application_layer_protocol_negotiation (ALPN)
			rec.ALPN = parseALPN(extData)
		case 43: // supported_versions
			// In ClientHello, this lists versions the client supports
			// The actual negotiated version comes from ServerHello's supported_versions
			if len(extData) >= 3 {
				listLen := int(extData[0])
				for i := 1; i+1 < 1+listLen && i+1 < len(extData); i += 2 {
					v := binary.BigEndian.Uint16(extData[i : i+2])
					if name, ok := TLSVersionNames[v]; ok {
						// Update to highest version offered
						rec.TLSVersion = name
					}
				}
			}
		}

		offset += extLen
	}
}

// parseServerExtensions processes TLS extensions from ServerHello.
func (d *Decoder) parseServerExtensions(data []byte, rec *tlsRecord) {
	offset := 0
	for offset+4 <= len(data) {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4
		if offset+extLen > len(data) {
			break
		}
		extData := data[offset : offset+extLen]

		switch extType {
		case 16: // ALPN
			rec.ALPN = parseALPN(extData)
		case 43: // supported_versions (TLS 1.3 uses this to indicate actual version)
			if len(extData) >= 2 {
				v := binary.BigEndian.Uint16(extData[0:2])
				if name, ok := TLSVersionNames[v]; ok {
					rec.TLSVersion = name
				}
			}
		}

		offset += extLen
	}
}

// parseSNI extracts the server name from the SNI extension.
// Format: ServerNameListLen(2B) + [NameType(1B) + NameLen(2B) + Name(var)]+
func parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// Skip list length (2 bytes)
	offset := 2
	if offset >= len(data) {
		return ""
	}
	nameType := data[offset]
	offset++
	if nameType != 0 { // 0 = host_name
		return ""
	}
	if offset+2 > len(data) {
		return ""
	}
	nameLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+nameLen > len(data) {
		nameLen = len(data) - offset
	}
	return string(data[offset : offset+nameLen])
}

// parseALPN extracts the ALPN protocol list.
// Format: ALPNListLen(2B) + [ProtoLen(1B) + Proto(var)]+
func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	offset := 2
	end := offset + listLen
	if end > len(data) {
		end = len(data)
	}

	var protos []string
	for offset < end {
		pLen := int(data[offset])
		offset++
		if offset+pLen > end {
			break
		}
		protos = append(protos, string(data[offset:offset+pLen]))
		offset += pLen
	}
	return protos
}

// extractCN does a heuristic scan for commonName (OID 2.5.4.3 = 55 04 03)
// in a DER-encoded X.509 certificate.
// If isSubject is true, returns the second occurrence (subject CN);
// if false, returns the first occurrence (issuer CN).
func extractCN(certData []byte, isSubject bool) string {
	// OID for commonName: 2.5.4.3 → DER bytes: 55 04 03
	cnOID := []byte{0x55, 0x04, 0x03}
	occurrence := 0
	target := 0
	if isSubject {
		target = 1 // subject is second CN in the cert structure (after issuer)
	}

	for i := 0; i+len(cnOID)+2 < len(certData); i++ {
		if certData[i] == cnOID[0] && certData[i+1] == cnOID[1] && certData[i+2] == cnOID[2] {
			if occurrence == target {
				// After the OID, there's a tag+length for the string value
				valOffset := i + 3
				if valOffset+2 > len(certData) {
					return ""
				}
				// ASN.1 string: tag(1B) + length(1B) + value
				strLen := int(certData[valOffset+1])
				valStart := valOffset + 2
				if valStart+strLen > len(certData) {
					strLen = len(certData) - valStart
				}
				if strLen <= 0 || strLen > 256 {
					return ""
				}
				cn := string(certData[valStart : valStart+strLen])
				// Validate it looks like a domain/name
				if isPrintableString(cn) {
					return cn
				}
			}
			occurrence++
		}
	}
	return ""
}

func isPrintableString(s string) bool {
	for _, c := range s {
		if c < 32 || c > 126 {
			return false
		}
	}
	return len(s) > 0
}

func isTLSPort(src, dst uint16) bool {
	tlsPorts := map[uint16]bool{
		443:  true, // HTTPS
		8443: true, // HTTPS alternate
		993:  true, // IMAPS
		995:  true, // POP3S
		465:  true, // SMTPS
		636:  true, // LDAPS
		5061: true, // SIP TLS
	}
	return tlsPorts[src] || tlsPorts[dst]
}

var _ protocols.StreamingDecoder = (*Decoder)(nil)
