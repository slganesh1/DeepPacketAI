package correlation

import (
	"fmt"
	"time"

	"DeepPacketAI/internal/domain"
)

// CorrelatedSession links flows across multiple protocols into a single end-to-end session.
type CorrelatedSession struct {
	SessionID   string         `json:"session_id"`
	StartTime   time.Time      `json:"start_time"`
	EndTime     time.Time      `json:"end_time"`
	Protocols   []string       `json:"protocols"`
	SIPCallID   string         `json:"sip_call_id,omitempty"`
	DiameterSID string         `json:"diameter_session_id,omitempty"`
	GTPTEID     string         `json:"gtp_teid,omitempty"`
	PFCPSEID    string         `json:"pfcp_seid,omitempty"`
	IMSI        string         `json:"imsi,omitempty"`
	MSISDN      string         `json:"msisdn,omitempty"`
	Flows       []domain.Flow  `json:"flows"`
	Events      []SessionEvent `json:"events"`
}

// SessionEvent is a timestamped event within a correlated session.
type SessionEvent struct {
	Timestamp time.Time      `json:"timestamp"`
	Protocol  string         `json:"protocol"`
	Type      string         `json:"type"`
	Summary   string         `json:"summary"`
	SrcIP     string         `json:"src_ip"`
	DstIP     string         `json:"dst_ip"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// CrossProtocolCorrelator correlates flows across SIP, Diameter, GTP, and PFCP.
type CrossProtocolCorrelator struct{}

func NewCrossProtocolCorrelator() *CrossProtocolCorrelator {
	return &CrossProtocolCorrelator{}
}

// Correlate takes all flows and produces correlated sessions.
func (c *CrossProtocolCorrelator) Correlate(flows []domain.Flow) []CorrelatedSession {
	// Group flows by protocol type
	flowsByType := make(map[domain.FlowType][]domain.Flow)
	for _, f := range flows {
		flowsByType[f.Type] = append(flowsByType[f.Type], f)
	}

	var sessions []CorrelatedSession

	// Start from SIP flows as anchors (calls are the primary entity)
	sipFlows := flowsByType[domain.FlowSIP]
	for _, sip := range sipFlows {
		session := CorrelatedSession{
			SessionID: fmt.Sprintf("session-%s", sip.FlowID),
			StartTime: sip.StartTime,
			EndTime:   sip.EndTime,
			Flows:     []domain.Flow{sip},
			Protocols: []string{"SIP"},
			SIPCallID: sip.FlowID,
		}

		// Add SIP event
		session.Events = append(session.Events, SessionEvent{
			Timestamp: sip.StartTime,
			Protocol:  "SIP",
			Type:      "call_setup",
			Summary:   fmt.Sprintf("SIP Call %s", metricStr(sip.Metrics, "method")),
			SrcIP:     sip.SrcIP,
			DstIP:     sip.DstIP,
			Metadata:  sip.Metrics,
		})

		// Correlate with Diameter by time proximity and IP
		for _, dia := range flowsByType[domain.FlowDiameter] {
			if c.isTimeProximate(sip, dia) && c.hasIPOverlap(sip, dia) {
				session.Flows = append(session.Flows, dia)
				session.DiameterSID = metricStr(dia.Metrics, "session_id")
				addProtocol(&session, "Diameter")
				session.Events = append(session.Events, SessionEvent{
					Timestamp: dia.StartTime,
					Protocol:  "Diameter",
					Type:      metricStr(dia.Metrics, "command_name"),
					Summary:   fmt.Sprintf("Diameter %s", metricStr(dia.Metrics, "command_name")),
					SrcIP:     dia.SrcIP,
					DstIP:     dia.DstIP,
					Metadata:  dia.Metrics,
				})
			}
		}

		// Correlate with GTP by time proximity
		for _, gtp := range flowsByType[domain.FlowGTP] {
			if c.isTimeProximate(sip, gtp) {
				session.Flows = append(session.Flows, gtp)
				session.GTPTEID = metricStr(gtp.Metrics, "teid")
				addProtocol(&session, "GTP")
				session.Events = append(session.Events, SessionEvent{
					Timestamp: gtp.StartTime,
					Protocol:  "GTP",
					Type:      metricStr(gtp.Metrics, "message_type_name"),
					Summary:   fmt.Sprintf("GTP %s", metricStr(gtp.Metrics, "message_type_name")),
					SrcIP:     gtp.SrcIP,
					DstIP:     gtp.DstIP,
					Metadata:  gtp.Metrics,
				})
			}
		}

		// Correlate with PFCP by time proximity
		for _, pfcp := range flowsByType[domain.FlowPFCP] {
			if c.isTimeProximate(sip, pfcp) {
				session.Flows = append(session.Flows, pfcp)
				session.PFCPSEID = metricStr(pfcp.Metrics, "seid")
				addProtocol(&session, "PFCP")
				session.Events = append(session.Events, SessionEvent{
					Timestamp: pfcp.StartTime,
					Protocol:  "PFCP",
					Type:      metricStr(pfcp.Metrics, "message_type_name"),
					Summary:   fmt.Sprintf("PFCP %s", metricStr(pfcp.Metrics, "message_type_name")),
					SrcIP:     pfcp.SrcIP,
					DstIP:     pfcp.DstIP,
					Metadata:  pfcp.Metrics,
				})
			}
		}

		// Correlate RTP legs
		for _, rtp := range flowsByType[domain.FlowRTP] {
			if c.isTimeProximate(sip, rtp) && c.hasIPOverlap(sip, rtp) {
				session.Flows = append(session.Flows, rtp)
				addProtocol(&session, "RTP")
			}
		}

		// Correlate S1AP by time
		for _, s1ap := range flowsByType[domain.FlowS1AP] {
			if c.isTimeProximate(sip, s1ap) {
				session.Flows = append(session.Flows, s1ap)
				addProtocol(&session, "S1AP")
				session.Events = append(session.Events, SessionEvent{
					Timestamp: s1ap.StartTime,
					Protocol:  "S1AP",
					Type:      metricStr(s1ap.Metrics, "procedure_name"),
					Summary:   fmt.Sprintf("S1AP %s %s", metricStr(s1ap.Metrics, "pdu_type"), metricStr(s1ap.Metrics, "procedure_name")),
					SrcIP:     s1ap.SrcIP,
					DstIP:     s1ap.DstIP,
					Metadata:  s1ap.Metrics,
				})
			}
		}

		// Correlate NGAP by time
		for _, ngap := range flowsByType[domain.FlowNGAP] {
			if c.isTimeProximate(sip, ngap) {
				session.Flows = append(session.Flows, ngap)
				addProtocol(&session, "NGAP")
				session.Events = append(session.Events, SessionEvent{
					Timestamp: ngap.StartTime,
					Protocol:  "NGAP",
					Type:      metricStr(ngap.Metrics, "procedure_name"),
					Summary:   fmt.Sprintf("NGAP %s %s", metricStr(ngap.Metrics, "pdu_type"), metricStr(ngap.Metrics, "procedure_name")),
					SrcIP:     ngap.SrcIP,
					DstIP:     ngap.DstIP,
					Metadata:  ngap.Metrics,
				})
			}
		}

		// Update session end time to the latest flow
		for _, f := range session.Flows {
			if f.EndTime.After(session.EndTime) {
				session.EndTime = f.EndTime
			}
		}

		extractSubscriberInfo(&session)
		sessions = append(sessions, session)
	}

	// Also create sessions for standalone protocol groups (no SIP anchor)
	sessions = append(sessions, c.standaloneGTPSessions(flowsByType)...)

	return sessions
}

// standaloneGTPSessions creates sessions from GTP flows not already correlated to SIP.
func (c *CrossProtocolCorrelator) standaloneGTPSessions(flowsByType map[domain.FlowType][]domain.Flow) []CorrelatedSession {
	var sessions []CorrelatedSession

	for _, gtp := range flowsByType[domain.FlowGTP] {
		session := CorrelatedSession{
			SessionID: fmt.Sprintf("session-gtp-%s", gtp.FlowID),
			StartTime: gtp.StartTime,
			EndTime:   gtp.EndTime,
			Flows:     []domain.Flow{gtp},
			Protocols: []string{"GTP"},
			GTPTEID:   metricStr(gtp.Metrics, "teid"),
		}

		// Link PFCP to GTP by time
		for _, pfcp := range flowsByType[domain.FlowPFCP] {
			if c.isTimeProximate(gtp, pfcp) {
				session.Flows = append(session.Flows, pfcp)
				session.PFCPSEID = metricStr(pfcp.Metrics, "seid")
				addProtocol(&session, "PFCP")
			}
		}

		extractSubscriberInfo(&session)
		if len(session.Protocols) > 1 {
			sessions = append(sessions, session)
		}
	}

	return sessions
}

// isTimeProximate returns true if two flows overlap or are within 5 seconds of each other.
func (c *CrossProtocolCorrelator) isTimeProximate(a, b domain.Flow) bool {
	const tolerance = 5 * time.Second

	// If either has zero time, consider them proximate
	if a.StartTime.IsZero() || b.StartTime.IsZero() {
		return true
	}

	// Check overlap
	if a.StartTime.Before(b.EndTime.Add(tolerance)) && b.StartTime.Before(a.EndTime.Add(tolerance)) {
		return true
	}

	return false
}

// hasIPOverlap returns true if the flows share at least one IP address.
func (c *CrossProtocolCorrelator) hasIPOverlap(a, b domain.Flow) bool {
	ips := map[string]bool{a.SrcIP: true, a.DstIP: true}
	return ips[b.SrcIP] || ips[b.DstIP]
}

func metricStr(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key].(string)
	if !ok {
		return fmt.Sprintf("%v", m[key])
	}
	return v
}

// extractSubscriberInfo scans the session's flows for IMSI/MSISDN in their metrics.
func extractSubscriberInfo(s *CorrelatedSession) {
	for _, f := range s.Flows {
		if s.IMSI == "" {
			if v, ok := f.Metrics["imsi"].(string); ok && v != "" {
				s.IMSI = v
			}
		}
		if s.MSISDN == "" {
			if v, ok := f.Metrics["msisdn"].(string); ok && v != "" {
				s.MSISDN = v
			}
		}
		if s.IMSI != "" && s.MSISDN != "" {
			break
		}
	}
}

func addProtocol(s *CorrelatedSession, proto string) {
	for _, p := range s.Protocols {
		if p == proto {
			return
		}
	}
	s.Protocols = append(s.Protocols, proto)
}
