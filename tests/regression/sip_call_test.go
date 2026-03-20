package regression_test

import (
	"fmt"
	"testing"
	"time"
)

// TestSIPCall_NormalCall exercises the full pipeline with a clean SIP call:
//   INVITE → 180 Ringing → 200 OK → ACK → [bidirectional RTP] → BYE → 200 OK
//
// Expected: one SIP flow, one RTP flow, one correlated call, zero alerts.
func TestSIPCall_NormalCall(t *testing.T) {
	t0 := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	tick := func(secs int) time.Time { return t0.Add(time.Duration(secs) * time.Second) }

	const (
		caller = "10.0.0.1"
		callee = "10.0.0.2"
		sipPort = uint16(5060)
		rtpPortA = uint16(49152) // caller's RTP port
		rtpPortB = uint16(49154) // callee's RTP port
		callID   = "abc123-reg-test@10.0.0.1"
	)

	invite := fmt.Sprintf(
		"INVITE sip:bob@%s SIP/2.0\r\nCall-ID: %s\r\nFrom: <sip:alice@%s>\r\nTo: <sip:bob@%s>\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
		callee, callID, caller, callee,
	)
	ringing := fmt.Sprintf(
		"SIP/2.0 180 Ringing\r\nCall-ID: %s\r\nFrom: <sip:alice@%s>\r\nTo: <sip:bob@%s>\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
		callID, caller, callee,
	)
	ok200 := fmt.Sprintf(
		"SIP/2.0 200 OK\r\nCall-ID: %s\r\nFrom: <sip:alice@%s>\r\nTo: <sip:bob@%s>\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
		callID, caller, callee,
	)
	ack := fmt.Sprintf(
		"ACK sip:bob@%s SIP/2.0\r\nCall-ID: %s\r\nFrom: <sip:alice@%s>\r\nTo: <sip:bob@%s>\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n",
		callee, callID, caller, callee,
	)
	bye := fmt.Sprintf(
		"BYE sip:bob@%s SIP/2.0\r\nCall-ID: %s\r\nFrom: <sip:alice@%s>\r\nTo: <sip:bob@%s>\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n",
		callee, callID, caller, callee,
	)
	byeOK := fmt.Sprintf(
		"SIP/2.0 200 OK\r\nCall-ID: %s\r\nFrom: <sip:alice@%s>\r\nTo: <sip:bob@%s>\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n",
		callID, caller, callee,
	)

	var frames []pcapFrame

	// SIP signalling (t+0 to t+3s)
	frames = append(frames, udpFrame(caller, callee, sipPort, sipPort, []byte(invite), tick(0)))
	frames = append(frames, udpFrame(callee, caller, sipPort, sipPort, []byte(ringing), tick(1)))
	frames = append(frames, udpFrame(callee, caller, sipPort, sipPort, []byte(ok200), tick(2)))
	frames = append(frames, udpFrame(caller, callee, sipPort, sipPort, []byte(ack), tick(3)))

	// Bidirectional RTP (20 packets each direction, t+3s to t+33s = 30-second call)
	// Consecutive sequence numbers → max_seq_gap = 0 → no packet-loss alert
	var ssrcA uint32 = 0xAABBCC01
	var ssrcB uint32 = 0xAABBCC02
	for i := 0; i < 20; i++ {
		rtpTS := uint32(i * 160) // 8kHz, 20ms frames
		ts := tick(3 + i*1)
		frames = append(frames,
			udpFrame(caller, callee, rtpPortA, rtpPortB, rtpPayload(uint16(i+1), rtpTS, ssrcA), ts),
			udpFrame(callee, caller, rtpPortB, rtpPortA, rtpPayload(uint16(i+1), rtpTS, ssrcB), ts),
		)
	}

	// BYE at t+35s → 35-second call duration, above the 30s voipCallDrop threshold
	frames = append(frames, udpFrame(caller, callee, sipPort, sipPort, []byte(bye), tick(35)))
	frames = append(frames, udpFrame(callee, caller, sipPort, sipPort, []byte(byeOK), tick(36)))

	pcap := writeTempPCAP(t, frames)
	snap := runPipeline(t, pcap)
	assertGolden(t, "sip_call", snap)
}

// TestSIPCall_InviteFlood verifies that ≥20 INVITEs from a single source
// triggers the "SIP INVITE Flood / Toll Fraud" alert.
func TestSIPCall_InviteFlood(t *testing.T) {
	t0 := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)

	const (
		attacker = "10.1.1.1"
		target   = "10.0.0.2"
		sipPort  = uint16(5060)
	)

	var frames []pcapFrame
	for i := 0; i < 25; i++ {
		callID := fmt.Sprintf("flood-%d@attacker", i)
		msg := fmt.Sprintf(
			"INVITE sip:target@%s SIP/2.0\r\nCall-ID: %s\r\nFrom: <sip:alice@%s>\r\nTo: <sip:target@%s>\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
			target, callID, attacker, target,
		)
		frames = append(frames, udpFrame(attacker, target, sipPort, sipPort, []byte(msg),
			t0.Add(time.Duration(i)*time.Millisecond*100)))
	}

	pcap := writeTempPCAP(t, frames)
	snap := runPipeline(t, pcap)
	assertGolden(t, "sip_invite_flood", snap)
}
