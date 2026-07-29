package dns

import (
	"encoding/binary"
	"strings"
	"testing"
)

// encodeName encodes a dotted domain name into DNS wire format (no compression).
func encodeName(name string) []byte {
	if name == "" {
		return []byte{0}
	}
	var out []byte
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	return append(out, 0)
}

// buildResponse builds a minimal DNS response message: header + one question
// (for "example.com" A) + one answer record with the given owner name, type,
// class IN, a fixed TTL, and the given already-encoded RDATA.
func buildResponse(t *testing.T, owner string, rtype uint16, rdata []byte) []byte {
	t.Helper()
	var buf []byte

	// Header: ID, flags(QR=1), QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
	buf = append(buf, 0x12, 0x34)
	buf = append(buf, 0x81, 0x80)
	buf = append(buf, 0x00, 0x01)
	buf = append(buf, 0x00, 0x01)
	buf = append(buf, 0x00, 0x00)
	buf = append(buf, 0x00, 0x00)

	// Question: example.com A IN
	buf = append(buf, encodeName("example.com")...)
	buf = append(buf, 0x00, 0x01) // QTYPE A
	buf = append(buf, 0x00, 0x01) // QCLASS IN

	// Answer: owner name, type, class IN, TTL, RDLENGTH, RDATA
	buf = append(buf, encodeName(owner)...)
	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, rtype)
	buf = append(buf, typeBytes...)
	buf = append(buf, 0x00, 0x01) // CLASS IN
	buf = append(buf, 0x00, 0x00, 0x0e, 0x10) // TTL 3600
	rdlen := make([]byte, 2)
	binary.BigEndian.PutUint16(rdlen, uint16(len(rdata)))
	buf = append(buf, rdlen...)
	buf = append(buf, rdata...)

	return buf
}

func TestParseAnswersNS(t *testing.T) {
	rdata := encodeName("ns1.example.com")
	msg := buildResponse(t, "example.com", 2, rdata)
	got := parseAnswers(msg)
	if len(got) != 1 || got[0] != "ns1.example.com" {
		t.Fatalf("NS: got %v, want [ns1.example.com]", got)
	}
}

func TestParseAnswersSOA(t *testing.T) {
	var rdata []byte
	rdata = append(rdata, encodeName("ns1.example.com")...)
	rdata = append(rdata, encodeName("hostmaster.example.com")...)
	nums := []uint32{2024010101, 7200, 3600, 1209600, 300}
	for _, n := range nums {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, n)
		rdata = append(rdata, b...)
	}
	msg := buildResponse(t, "example.com", 6, rdata)
	got := parseAnswers(msg)
	want := "ns1.example.com hostmaster.example.com 2024010101 7200 3600 1209600 300"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("SOA: got %v, want [%s]", got, want)
	}
}

func TestParseAnswersMX(t *testing.T) {
	var rdata []byte
	rdata = append(rdata, 0x00, 0x0a) // preference 10
	rdata = append(rdata, encodeName("mail.example.com")...)
	msg := buildResponse(t, "example.com", 15, rdata)
	got := parseAnswers(msg)
	if len(got) != 1 || got[0] != "10 mail.example.com" {
		t.Fatalf("MX: got %v, want [10 mail.example.com]", got)
	}
}

func TestParseAnswersTXT(t *testing.T) {
	var rdata []byte
	for _, s := range []string{"v=spf1 include:_spf.example.com", "~all"} {
		rdata = append(rdata, byte(len(s)))
		rdata = append(rdata, []byte(s)...)
	}
	msg := buildResponse(t, "example.com", 16, rdata)
	got := parseAnswers(msg)
	want := "v=spf1 include:_spf.example.com ~all"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("TXT: got %v, want [%s]", got, want)
	}
}

func TestParseAnswersSRV(t *testing.T) {
	var rdata []byte
	rdata = append(rdata, 0x00, 0x00) // priority 0
	rdata = append(rdata, 0x00, 0x05) // weight 5
	rdata = append(rdata, 0x13, 0xc4) // port 5060
	rdata = append(rdata, encodeName("sipserver.example.com")...)
	msg := buildResponse(t, "_sip._udp.example.com", 33, rdata)
	got := parseAnswers(msg)
	if len(got) != 1 || got[0] != "0 5 5060 sipserver.example.com" {
		t.Fatalf("SRV: got %v, want [0 5 5060 sipserver.example.com]", got)
	}
}

func TestParseAnswersNAPTR(t *testing.T) {
	var rdata []byte
	rdata = append(rdata, 0x00, 0x64) // order 100
	rdata = append(rdata, 0x00, 0x0a) // preference 10
	for _, s := range []string{"u", "E2U+sip", "!^.*$!sip:info@example.com!"} {
		rdata = append(rdata, byte(len(s)))
		rdata = append(rdata, []byte(s)...)
	}
	rdata = append(rdata, 0x00) // replacement: root (empty name)
	msg := buildResponse(t, "example.com", 35, rdata)
	got := parseAnswers(msg)
	want := `100 10 "u" "E2U+sip" "!^.*$!sip:info@example.com!" `
	if len(got) != 1 || got[0] != want {
		t.Fatalf("NAPTR: got %q, want %q", got, want)
	}
}

func TestParseAnswersAStillWorks(t *testing.T) {
	msg := buildResponse(t, "example.com", 1, []byte{192, 0, 2, 1})
	got := parseAnswers(msg)
	if len(got) != 1 || got[0] != "192.0.2.1" {
		t.Fatalf("A: got %v, want [192.0.2.1]", got)
	}
}
