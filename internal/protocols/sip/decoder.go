package sip

import (
	"fmt"
	"strings"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/dpi"
)

type SIPDecoder struct {
	sessions map[string]*SIPSession
}

func NewDecoder() *SIPDecoder {
	return &SIPDecoder{
		sessions: make(map[string]*SIPSession),
	}
}

func (d *SIPDecoder) Name() string {
	return "sip"
}

// Called for EVERY packet by the pipeline
func (d *SIPDecoder) HandlePacket(pkt *domain.Packet) {
	// SIP on well-known ports (5060/5061) or detected by payload signature
	isSIPPort := pkt.SrcPort == 5060 || pkt.DstPort == 5060 ||
		pkt.SrcPort == 5061 || pkt.DstPort == 5061
	if !isSIPPort && !dpi.IsSIP(pkt.Payload) {
		return
	}

	payload := strings.TrimSpace(string(pkt.Payload))
	if payload == "" {
		return
	}

	d.handlePayload(payload, pkt)
}

func (d *SIPDecoder) handlePayload(payload string, pkt *domain.Packet) {
	callID := extractHeader(payload, "Call-ID")
	if callID == "" {
		return
	}

	sess := d.getSession(callID, pkt)

	// Annotate the packet as SIP
	pkt.AppProtocol = "SIP"

	// Detect SIP method from request line (e.g. "INVITE sip:... SIP/2.0")
	if !strings.HasPrefix(payload, "SIP/") {
		// It's a SIP request — extract method from first token
		if spaceIdx := strings.IndexByte(payload, ' '); spaceIdx > 0 {
			method := payload[:spaceIdx]
			pkt.Summary = method + " " + callID

			// Store the initial method that created this session
			if sess.Method == "" {
				sess.Method = method
			}
		}
	}

	// INVITE
	if strings.HasPrefix(payload, "INVITE ") {
		sess.InviteTime = pkt.Timestamp
		sess.From = extractHeader(payload, "From")
		sess.To = extractHeader(payload, "To")
	}

	// BYE
	if strings.HasPrefix(payload, "BYE ") {
		sess.ByeTime = pkt.Timestamp
	}

	// SIP response
	if strings.HasPrefix(payload, "SIP/2.0") {
		sess.LastResponse = firstLine(payload)
		pkt.Summary = firstLine(payload) + " " + callID

		// Track first 200 OK for setup latency calculation
		statusCode := extractStatusCode(payload)
		if statusCode == 200 && sess.FirstResponseTime.IsZero() {
			sess.FirstResponseTime = pkt.Timestamp
		}

		// Detect SIP error responses (4xx/5xx/6xx)
		if statusCode >= 400 && statusCode < 500 {
			pkt.Errors = append(pkt.Errors, domain.PacketError{
				Code:        fmt.Sprintf("SIP_%d", statusCode),
				Title:       "SIP Client Error",
				Description: fmt.Sprintf("%s (Call-ID: %s)", firstLine(payload), callID),
				Severity:    "warning",
			})
		} else if statusCode >= 500 && statusCode < 600 {
			pkt.Errors = append(pkt.Errors, domain.PacketError{
				Code:        fmt.Sprintf("SIP_%d", statusCode),
				Title:       "SIP Server Error",
				Description: fmt.Sprintf("%s (Call-ID: %s)", firstLine(payload), callID),
				Severity:    "error",
			})
		} else if statusCode >= 600 {
			pkt.Errors = append(pkt.Errors, domain.PacketError{
				Code:        fmt.Sprintf("SIP_%d", statusCode),
				Title:       "SIP Global Failure",
				Description: fmt.Sprintf("%s (Call-ID: %s)", firstLine(payload), callID),
				Severity:    "critical",
			})
		}
	}

	// SDP — parse media parameters and track hold/unhold direction changes
	if strings.Contains(payload, "v=0") && strings.Contains(payload, "m=audio") {
		sdp := parseSDP(payload)
		if sdp != nil {
			sess.MediaIP = sdp["media_ip"]
			sess.MediaPort = sdp["media_port"]
			sess.trackDirectionChange(sdp["direction"], pkt.Timestamp)

			// Annotate packet with SDP direction info
			if pkt.Summary != "" {
				pkt.Summary += " [SDP direction=" + sdp["direction"] + "]"
			}
		}
	}
}


// Called ONCE at end of PCAP
func (d *SIPDecoder) Flush() []domain.Flow {
	var flows []domain.Flow

	for _, s := range d.sessions {
		end := s.ByeTime
		if end.IsZero() {
			end = s.StartTime
		}

		metrics := map[string]any{
			"method":     s.Method,
			"from":       s.From,
			"to":         s.To,
			"response":   s.LastResponse,
			"media_ip":   s.MediaIP,
			"media_port": s.MediaPort,
			"direction":  s.Direction,
		}

		// Include setup latency if INVITE and 200 OK were both captured
		if !s.InviteTime.IsZero() && !s.FirstResponseTime.IsZero() {
			metrics["setup_latency_ms"] = float64(s.FirstResponseTime.Sub(s.InviteTime).Microseconds()) / 1000.0
		}

		// Include hold tracking data
		if s.HoldCount > 0 {
			metrics["hold_count"] = s.HoldCount
			metrics["hold_events"] = s.holdEventStrings()
		}

		flows = append(flows, domain.Flow{
			FlowID:    s.CallID,
			Type:      domain.FlowSIP,
			SrcIP:     s.SrcIP,
			DstIP:     s.DstIP,
			StartTime: s.StartTime,
			EndTime:   end,
			Metrics:   metrics,
		})
	}

	return flows
}
