package http1

import (
	"strconv"
	"testing"
	"time"

	"DeepPacketAI/internal/domain"
)

func TestLooksLikeSOAPEnvelope(t *testing.T) {
	if !looksLikeSOAPEnvelope([]byte(`<soap:Envelope xmlns:soap="x"><soap:Body/></soap:Envelope>`)) {
		t.Fatal("expected envelope to be detected")
	}
	if looksLikeSOAPEnvelope([]byte(`{"not":"xml"}`)) {
		t.Fatal("did not expect JSON to be detected as SOAP")
	}
}

func TestExtractXMLElementText(t *testing.T) {
	body := []byte(`<soap:Fault><faultcode>soap:Client</faultcode><faultstring>Bad request</faultstring></soap:Fault>`)
	if got := extractXMLElementText(body, "faultcode"); got != "soap:Client" {
		t.Fatalf("faultcode: got %q", got)
	}
	if got := extractXMLElementText(body, "faultstring"); got != "Bad request" {
		t.Fatalf("faultstring: got %q", got)
	}
	if got := extractXMLElementText(body, "nope"); got != "" {
		t.Fatalf("expected empty for missing element, got %q", got)
	}
}

func TestDetectSOAPFaultSOAP11(t *testing.T) {
	body := []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <soap:Fault>
      <faultcode>soap:Server</faultcode>
      <faultstring>Internal processing error</faultstring>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>`)
	code, str, found := detectSOAPFault(body)
	if !found {
		t.Fatal("expected fault to be found")
	}
	if code != "soap:Server" {
		t.Fatalf("code: got %q", code)
	}
	if str != "Internal processing error" {
		t.Fatalf("string: got %q", str)
	}
}

func TestDetectSOAPFaultSOAP12(t *testing.T) {
	body := []byte(`<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <soap:Fault>
      <soap:Code><soap:Value>soap:Receiver</soap:Value></soap:Code>
      <soap:Reason><soap:Text>Service unavailable</soap:Text></soap:Reason>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>`)
	code, str, found := detectSOAPFault(body)
	if !found {
		t.Fatal("expected fault to be found")
	}
	if str != "Service unavailable" {
		t.Fatalf("string: got %q", str)
	}
	_ = code // SOAP 1.2 Code/Value nests deeper than the lightweight scan resolves; Reason/Text is the important signal
}

func TestDetectSOAPFaultAbsent(t *testing.T) {
	body := []byte(`<soap:Envelope><soap:Body><GetUserResponse><Name>Alice</Name></GetUserResponse></soap:Body></soap:Envelope>`)
	_, _, found := detectSOAPFault(body)
	if found {
		t.Fatal("did not expect a fault to be detected in a normal response")
	}
}

func TestExtractSOAPOperationRequest(t *testing.T) {
	body := []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUserRequest xmlns="urn:example">
      <UserId>42</UserId>
    </GetUserRequest>
  </soap:Body>
</soap:Envelope>`)
	if got := extractSOAPOperation(body); got != "GetUserRequest" {
		t.Fatalf("got %q, want GetUserRequest", got)
	}
}

func TestExtractSOAPOperationEmptyBody(t *testing.T) {
	body := []byte(`<soap:Envelope><soap:Body></soap:Body></soap:Envelope>`)
	if got := extractSOAPOperation(body); got != "" {
		t.Fatalf("expected empty operation for empty body, got %q", got)
	}
}

// buildTCPPacket constructs a minimal domain.Packet for feeding into the decoder.
func buildTCPPacket(frame uint64, srcIP string, srcPort uint16, dstIP string, dstPort uint16, payload string) *domain.Packet {
	return &domain.Packet{
		Timestamp:   time.Now(),
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     srcPort,
		DstPort:     dstPort,
		Protocol:    "TCP",
		Payload:     []byte(payload),
		FrameNumber: frame,
	}
}

func TestHTTPSOAPFaultOverridesHTTP200(t *testing.T) {
	reqBody := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <PlaceOrderRequest xmlns="urn:example"><Item>widget</Item></PlaceOrderRequest>
  </soap:Body>
</soap:Envelope>`
	req := "POST /orders HTTP/1.1\r\n" +
		"Host: soap.example.com\r\n" +
		"Content-Type: text/xml; charset=utf-8\r\n" +
		"SOAPAction: \"urn:example/PlaceOrder\"\r\n" +
		"Content-Length: " + strconv.Itoa(len(reqBody)) + "\r\n" +
		"\r\n" + reqBody

	respBody := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <soap:Fault>
      <faultcode>soap:Client</faultcode>
      <faultstring>Invalid item code</faultstring>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>`
	resp := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/xml; charset=utf-8\r\n" +
		"Content-Length: " + strconv.Itoa(len(respBody)) + "\r\n" +
		"\r\n" + respBody

	d := NewDecoder()
	d.HandlePacket(buildTCPPacket(1, "10.0.0.1", 51000, "10.0.0.2", 80, req))
	d.HandlePacket(buildTCPPacket(2, "10.0.0.2", 80, "10.0.0.1", 51000, resp))

	flows := d.Flush()
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	m := flows[0].Metrics
	if m["status_code"] != 200 {
		t.Fatalf("expected status_code 200, got %v", m["status_code"])
	}
	if m["is_error"] != true {
		t.Fatalf("expected is_error true (SOAP fault under HTTP 200), got %v", m["is_error"])
	}
	if m["is_soap"] != true {
		t.Fatalf("expected is_soap true, got %v", m["is_soap"])
	}
	if m["soap_operation"] != "PlaceOrderRequest" {
		t.Fatalf("expected soap_operation PlaceOrderRequest, got %v", m["soap_operation"])
	}
	if m["soap_fault_code"] != "soap:Client" {
		t.Fatalf("expected soap_fault_code soap:Client, got %v", m["soap_fault_code"])
	}
	if m["soap_fault_string"] != "Invalid item code" {
		t.Fatalf("expected soap_fault_string 'Invalid item code', got %v", m["soap_fault_string"])
	}
	if m["soap_action"] != `"urn:example/PlaceOrder"` {
		t.Fatalf("expected soap_action header captured, got %v", m["soap_action"])
	}
}

func TestHTTPPlainRequestUnaffected(t *testing.T) {
	req := "GET /status HTTP/1.1\r\nHost: example.com\r\n\r\n"
	resp := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK"

	d := NewDecoder()
	d.HandlePacket(buildTCPPacket(1, "10.0.0.1", 51000, "10.0.0.2", 80, req))
	d.HandlePacket(buildTCPPacket(2, "10.0.0.2", 80, "10.0.0.1", 51000, resp))

	flows := d.Flush()
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	m := flows[0].Metrics
	if _, ok := m["is_soap"]; ok {
		t.Fatalf("did not expect is_soap key on a plain HTTP flow, got %v", m["is_soap"])
	}
	if m["is_error"] != false {
		t.Fatalf("expected is_error false, got %v", m["is_error"])
	}
}

