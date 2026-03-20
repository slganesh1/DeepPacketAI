package regression_test

import (
	"testing"
	"time"
)

// TestHTTPLogin runs the pipeline against a synthetic HTTP capture containing
// a POST /login request followed by a 200 OK response.
//
// Expected: one HTTP flow, no security alerts.
func TestHTTPLogin(t *testing.T) {
	t0 := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)

	const (
		client  = "10.0.0.10"
		server  = "10.0.0.20"
		cliPort = uint16(54321)
		srvPort = uint16(80)
	)

	httpReq := []byte("POST /login HTTP/1.1\r\nHost: 10.0.0.20\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 27\r\n\r\nusername=admin&password=test")
	httpResp := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK")

	frames := []pcapFrame{
		// TCP 3-way handshake
		tcpFrame(client, server, cliPort, srvPort, true, false, false, false, 1000, 0, nil, t0),
		tcpFrame(server, client, srvPort, cliPort, true, true, false, false, 5000, 1001, nil, t0.Add(time.Millisecond)),
		tcpFrame(client, server, cliPort, srvPort, false, true, false, false, 1001, 5001, nil, t0.Add(2*time.Millisecond)),
		// HTTP request
		tcpFrame(client, server, cliPort, srvPort, false, true, true, false, 1001, 5001, httpReq, t0.Add(3*time.Millisecond)),
		// HTTP response
		tcpFrame(server, client, srvPort, cliPort, false, true, true, false, 5001, 1001+uint32(len(httpReq)), httpResp, t0.Add(10*time.Millisecond)),
		// FIN
		tcpFrame(client, server, cliPort, srvPort, false, true, false, true, 1001+uint32(len(httpReq)), 5001+uint32(len(httpResp)), nil, t0.Add(15*time.Millisecond)),
		tcpFrame(server, client, srvPort, cliPort, false, true, false, true, 5001+uint32(len(httpResp)), 1002+uint32(len(httpReq)), nil, t0.Add(16*time.Millisecond)),
	}

	pcap := writeTempPCAP(t, frames)
	snap := runPipeline(t, pcap)
	assertGolden(t, "http_login", snap)
}
