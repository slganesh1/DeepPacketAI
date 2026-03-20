// Package correlation — telecom session tracer.
//
// TelecomTracer builds end-to-end UE call traces by correlating flows from
// every layer of the 5G/4G stack:
//
//	UE → NGAP/NAS → GTP-C → PFCP → GTP-U → SIP → RTP
//
// Primary correlation key:  IMSI  (from NGAP, GTP-C, Diameter)
// Secondary keys (fallback): SIP Call-ID, GTP TEID, UE IP, time proximity
package correlation

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"DeepPacketAI/internal/domain"
)

// TelecomTracer correlates multi-protocol flows into TelecomSession records.
type TelecomTracer struct{}

func NewTelecomTracer() *TelecomTracer { return &TelecomTracer{} }

// Trace is the main entry point: takes all flows produced by protocol decoders
// and returns one TelecomSession per unique UE/subscriber or IMS call.
func (t *TelecomTracer) Trace(flows []domain.Flow) []domain.TelecomSession {
	// ── 1. Partition flows by type ─────────────────────────────────────────────
	idx := partitionByType(flows)

	// ── 2. Build IMSI index: imsi → (GTP-C | Diameter | NGAP) anchor flows ────
	//    An IMSI uniquely identifies a subscriber across all layers.
	imsiSessions := t.buildIMSISessions(idx)

	// ── 3. Attach remaining layers to IMSI sessions ───────────────────────────
	for id, sess := range imsiSessions {
		t.attachNGAP(sess, idx[domain.FlowNGAP])
		t.attachGTPC(sess, idx[domain.FlowGTP])
		t.attachDiameter(sess, idx[domain.FlowDiameter])
		t.attachPFCP(sess, idx[domain.FlowPFCP])
		t.attachGTPU(sess, idx[domain.FlowGTP])
		t.attachSIP(sess, idx[domain.FlowSIP])
		t.attachRTP(sess, idx[domain.FlowRTP])
		t.finalise(sess)
		imsiSessions[id] = sess
	}

	// ── 4. IMS-only sessions (SIP without any mobile-core flows) ──────────────
	imsOnly := t.buildIMSSessions(idx, imsiSessions)

	// ── 5. Collect and return ─────────────────────────────────────────────────
	var result []domain.TelecomSession
	for _, s := range imsiSessions {
		result = append(result, *s)
	}
	result = append(result, imsOnly...)
	return result
}

// ── Session builders ──────────────────────────────────────────────────────────

// buildIMSISessions creates one TelecomSession per unique IMSI found in GTP-C,
// Diameter, or NGAP flows. Returns a map keyed by IMSI.
func (t *TelecomTracer) buildIMSISessions(
	idx map[domain.FlowType][]domain.Flow,
) map[string]*domain.TelecomSession {

	sessions := make(map[string]*domain.TelecomSession)

	// Sources that carry IMSI: NGAP, GTP, Diameter
	imsiSources := []domain.FlowType{domain.FlowNGAP, domain.FlowGTP, domain.FlowDiameter}
	for _, ft := range imsiSources {
		for _, f := range idx[ft] {
			imsi := metricS(f.Metrics, "imsi")
			if imsi == "" {
				continue
			}
			if _, exists := sessions[imsi]; !exists {
				sess := &domain.TelecomSession{
					SessionID: "ue-" + imsi,
					IMSI:      imsi,
					MSISDN:    metricS(f.Metrics, "msisdn"),
					APN:       metricS(f.Metrics, "apn"),
				}
				// UE IP (PDN address) from GTP-C Create Session Response
				if ueIP := metricS(f.Metrics, "pdn_address"); ueIP != "" {
					sess.UEIP = ueIP
				}
				sessions[imsi] = sess
			} else {
				// Enrich existing session with newly seen fields
				s := sessions[imsi]
				if s.MSISDN == "" {
					s.MSISDN = metricS(f.Metrics, "msisdn")
				}
				if s.APN == "" {
					s.APN = metricS(f.Metrics, "apn")
				}
				if s.UEIP == "" {
					s.UEIP = metricS(f.Metrics, "pdn_address")
				}
			}
		}
	}
	return sessions
}

// buildIMSSessions produces sessions for SIP calls that have no IMSI anchor
// (standalone IMS / Wi-Fi calling / pure VoIP scenarios).
func (t *TelecomTracer) buildIMSSessions(
	idx map[domain.FlowType][]domain.Flow,
	claimed map[string]*domain.TelecomSession,
) []domain.TelecomSession {

	// Collect SIP flows not already claimed by an IMSI session
	claimedFlowIDs := make(map[string]bool)
	for _, s := range claimed {
		for _, h := range s.SIP {
			claimedFlowIDs[h.FlowID] = true
		}
	}

	var sessions []domain.TelecomSession
	for _, sipFlow := range idx[domain.FlowSIP] {
		if claimedFlowIDs[sipFlow.FlowID] {
			continue
		}
		callID := sipFlow.FlowID
		sess := domain.TelecomSession{
			SessionID: "ims-" + callID,
			SIPCallID: callID,
			SIPFrom:   metricS(sipFlow.Metrics, "from"),
			SIPTo:     metricS(sipFlow.Metrics, "to"),
			HasSIP:    true,
		}
		sess.SIP = []domain.TraceHop{flowToHop("SIP", sipFlow)}
		t.addEvent(&sess, sipFlow.StartTime, "SIP", "IMS_Call_Setup",
			fmt.Sprintf("SIP %s %s→%s", metricS(sipFlow.Metrics, "method"), sess.SIPFrom, sess.SIPTo),
			sipFlow.SrcIP, sipFlow.DstIP, sipFlow.Metrics)

		// Attach RTP matching SIP media endpoint
		mediaIP := metricS(sipFlow.Metrics, "media_ip")
		mediaPort := metricS(sipFlow.Metrics, "media_port")
		for _, rtpFlow := range idx[domain.FlowRTP] {
			if matchesMediaEndpoint(rtpFlow, mediaIP, mediaPort) {
				sess.RTP = append(sess.RTP, flowToHop("RTP", rtpFlow))
				sess.HasRTP = true
				t.addEvent(&sess, rtpFlow.StartTime, "RTP", "RTP_Stream",
					fmt.Sprintf("RTP SSRC=%s", metricS(rtpFlow.Metrics, "ssrc")),
					rtpFlow.SrcIP, rtpFlow.DstIP, nil)
			}
		}
		t.finalise(&sess)
		sessions = append(sessions, sess)
	}
	return sessions
}

// ── Per-layer attachment ──────────────────────────────────────────────────────

func (t *TelecomTracer) attachNGAP(sess *domain.TelecomSession, flows []domain.Flow) {
	for _, f := range flows {
		if metricS(f.Metrics, "imsi") != sess.IMSI && !timeOverlaps(sess, f) {
			continue
		}
		hop := flowToHop("NGAP", f)
		sess.NGAP = append(sess.NGAP, hop)
		sess.HasNGAP = true
		procName := metricS(f.Metrics, "procedure_name")
		t.addEvent(sess, f.StartTime, "NGAP", ngapStep(procName),
			fmt.Sprintf("NGAP %s %s", metricS(f.Metrics, "pdu_type"), procName),
			f.SrcIP, f.DstIP, f.Metrics)
	}
}

func (t *TelecomTracer) attachGTPC(sess *domain.TelecomSession, flows []domain.Flow) {
	for _, f := range flows {
		// GTP-U flows also come through FlowGTP — skip data-plane entries
		if metricS(f.Metrics, "is_gtpu") == "true" {
			continue
		}
		imsi := metricS(f.Metrics, "imsi")
		if imsi != "" && imsi != sess.IMSI {
			continue
		}
		if imsi == "" && !timeOverlaps(sess, f) {
			continue
		}
		hop := flowToHop("GTP-C", f)
		sess.GTPControl = append(sess.GTPControl, hop)
		sess.HasGTPC = true

		// Harvest header TEID (control-plane TEID)
		if teid, ok := f.Metrics["teid"]; ok && teid != nil {
			norm := normalizeHexTEID(teid)
			sess.TEIDs = appendUniq(sess.TEIDs, norm)
		}

		// Harvest all bearer F-TEIDs — these are the GTP-U data-plane TEIDs
		for _, bteid := range extractBearerFTEIDs(f.Metrics) {
			sess.TEIDs = appendUniq(sess.TEIDs, bteid)
			sess.BearerTEIDs = appendUniq(sess.BearerTEIDs, bteid)
		}

		// Harvest UE IP from PDN address
		if sess.UEIP == "" {
			sess.UEIP = metricS(f.Metrics, "pdn_address")
		}
		// Harvest APN
		if sess.APN == "" {
			sess.APN = metricS(f.Metrics, "apn")
		}
		// Harvest network context
		if sess.RATType == "" {
			sess.RATType = metricS(f.Metrics, "rat_type")
		}
		if sess.ServingNetwork == "" {
			sess.ServingNetwork = metricS(f.Metrics, "serving_network")
		}
		if sess.Location == "" {
			// prefer ECGI (more specific) then TAI
			if ecgi := metricS(f.Metrics, "ecgi"); ecgi != "" {
				sess.Location = ecgi
			} else if tai := metricS(f.Metrics, "tai"); tai != "" {
				sess.Location = tai
			}
		}
		if sess.PDNType == "" {
			sess.PDNType = metricS(f.Metrics, "pdn_type")
		}

		msgType := metricS(f.Metrics, "message_type_name")
		if msgType == "" {
			msgType = metricS(f.Metrics, "message_type")
		}
		teidHex := ""
		if teid, ok := f.Metrics["teid"]; ok {
			teidHex = normalizeHexTEID(teid)
		}
		t.addEvent(sess, f.StartTime, "GTP-C", gtpcStep(msgType),
			fmt.Sprintf("GTP-C %s TEID=%s", msgType, teidHex),
			f.SrcIP, f.DstIP, f.Metrics)
	}
}

func (t *TelecomTracer) attachPFCP(sess *domain.TelecomSession, flows []domain.Flow) {
	for _, f := range flows {
		if !timeOverlaps(sess, f) {
			continue
		}
		hop := flowToHop("PFCP", f)
		sess.PFCP = append(sess.PFCP, hop)
		sess.HasPFCP = true
		if seid := metricS(f.Metrics, "seid"); seid != "" {
			sess.SEIDs = appendUniq(sess.SEIDs, seid)
		}
		msgType := metricS(f.Metrics, "message_type_name")
		t.addEvent(sess, f.StartTime, "PFCP", pfcpStep(msgType),
			fmt.Sprintf("PFCP %s SEID=%s", msgType, metricS(f.Metrics, "seid")),
			f.SrcIP, f.DstIP, f.Metrics)
	}
}

func (t *TelecomTracer) attachGTPU(sess *domain.TelecomSession, flows []domain.Flow) {
	// Build a normalized hex TEID set from all TEIDs collected in GTP-C phase
	teidSet := make(map[string]bool)
	for _, id := range sess.TEIDs {
		teidSet[id] = true
	}

	for _, f := range flows {
		// Only GTP-U data-plane flows
		if metricS(f.Metrics, "is_gtpu") != "true" {
			continue
		}
		// Normalize this flow's TEID to hex for comparison
		teidHex := ""
		if teid, ok := f.Metrics["teid"]; ok {
			teidHex = normalizeHexTEID(teid)
		}
		// Match by bearer TEID (exact) or fall back to time proximity
		if !teidSet[teidHex] && !timeOverlaps(sess, f) {
			continue
		}
		hop := flowToHop("GTP-U", f)
		sess.GTPUser = append(sess.GTPUser, hop)
		sess.HasGTPU = true
		if teidHex != "" {
			sess.TEIDs = appendUniq(sess.TEIDs, teidHex)
		}
		t.addEvent(sess, f.StartTime, "GTP-U", "Data_Tunnel",
			fmt.Sprintf("GTP-U data TEID=%s", teidHex),
			f.SrcIP, f.DstIP, nil)
	}
}

func (t *TelecomTracer) attachDiameter(sess *domain.TelecomSession, flows []domain.Flow) {
	for _, f := range flows {
		imsi := metricS(f.Metrics, "imsi")
		if imsi != "" && imsi != sess.IMSI {
			continue
		}
		if imsi == "" && !timeOverlaps(sess, f) {
			continue
		}
		sess.Diameter = append(sess.Diameter, flowToHop("Diameter", f))
		sess.HasDiameter = true
		cmd := metricS(f.Metrics, "command_name")
		t.addEvent(sess, f.StartTime, "Diameter", diameterStep(cmd),
			fmt.Sprintf("Diameter %s", cmd),
			f.SrcIP, f.DstIP, f.Metrics)
	}
}

func (t *TelecomTracer) attachSIP(sess *domain.TelecomSession, flows []domain.Flow) {
	for _, f := range flows {
		// Match by UE IP appearing in the SIP flow, or time proximity
		if sess.UEIP != "" && (f.SrcIP == sess.UEIP || f.DstIP == sess.UEIP) {
			// strong match
		} else if !timeOverlaps(sess, f) {
			continue
		}
		sess.SIP = append(sess.SIP, flowToHop("SIP", f))
		sess.HasSIP = true
		if sess.SIPCallID == "" {
			sess.SIPCallID = f.FlowID
		}
		if sess.SIPFrom == "" {
			sess.SIPFrom = metricS(f.Metrics, "from")
		}
		if sess.SIPTo == "" {
			sess.SIPTo = metricS(f.Metrics, "to")
		}
		method := metricS(f.Metrics, "method")
		t.addEvent(sess, f.StartTime, "SIP", sipStep(method),
			fmt.Sprintf("SIP %s %s→%s", method, sess.SIPFrom, sess.SIPTo),
			f.SrcIP, f.DstIP, f.Metrics)
	}
}

func (t *TelecomTracer) attachRTP(sess *domain.TelecomSession, flows []domain.Flow) {
	// Collect media endpoints from SIP legs
	mediaEndpoints := make(map[string]string) // "ip:port" → ""
	for _, sipHop := range sess.SIP {
		ip := metricS(sipHop.Metrics, "media_ip")
		port := metricS(sipHop.Metrics, "media_port")
		if ip != "" && port != "" {
			mediaEndpoints[ip+":"+port] = ""
		}
	}

	for _, f := range flows {
		srcEP := fmt.Sprintf("%s:%d", f.SrcIP, f.SrcPort)
		dstEP := fmt.Sprintf("%s:%d", f.DstIP, f.DstPort)
		_, srcMatch := mediaEndpoints[srcEP]
		_, dstMatch := mediaEndpoints[dstEP]

		// If no SIP media endpoint known, fall back to time proximity
		matched := srcMatch || dstMatch
		if !matched {
			if len(mediaEndpoints) == 0 && timeOverlaps(sess, f) {
				matched = true
			}
		}
		if !matched {
			continue
		}
		sess.RTP = append(sess.RTP, flowToHop("RTP", f))
		sess.HasRTP = true
		ssrc := metricS(f.Metrics, "ssrc")
		t.addEvent(sess, f.StartTime, "RTP", "RTP_Media",
			fmt.Sprintf("RTP SSRC=%s pkt=%v jitter=%.1fms",
				ssrc, f.Metrics["packet_count"], metricF(f.Metrics, "jitter_ms")),
			f.SrcIP, f.DstIP, f.Metrics)
	}
}

// ── Finaliser ─────────────────────────────────────────────────────────────────

func (t *TelecomTracer) finalise(sess *domain.TelecomSession) {
	// Sort events chronologically
	sort.Slice(sess.Events, func(i, j int) bool {
		return sess.Events[i].Timestamp.Before(sess.Events[j].Timestamp)
	})

	// Compute session time bounds from events
	for _, e := range sess.Events {
		if sess.StartTime.IsZero() || e.Timestamp.Before(sess.StartTime) {
			sess.StartTime = e.Timestamp
		}
		if e.Timestamp.After(sess.EndTime) {
			sess.EndTime = e.Timestamp
		}
	}

	// Also consider RTP hop end times for EndTime
	for _, h := range sess.RTP {
		if h.EndTime.After(sess.EndTime) {
			sess.EndTime = h.EndTime
		}
	}

	// MOS from RTP if available
	for _, h := range sess.RTP {
		jitter := metricF(h.Metrics, "jitter_ms")
		gap := metricI(h.Metrics, "max_seq_gap")
		pkts := metricI(h.Metrics, "packet_count")
		if pkts > 0 {
			lossPct := float64(gap) / float64(pkts) * 100
			mos := computeSimpleMOS(lossPct, jitter)
			if sess.MOS == 0 || mos < sess.MOS {
				sess.MOS = mos
			}
		}
	}
	if sess.MOS > 0 {
		sess.Quality = mosQuality(sess.MOS)
	}

	// Completeness: a "full" 5G call trace has NGAP + GTP-C + SIP + RTP
	sess.IsComplete = sess.HasNGAP && sess.HasGTPC && sess.HasSIP && sess.HasRTP

	// Build lifecycle milestones and infer UE state
	buildLifecycle(sess)
}

// buildLifecycle derives UELifecycleStep milestones from sorted events and sets UEState.
func buildLifecycle(sess *domain.TelecomSession) {
	if len(sess.Events) == 0 {
		return
	}

	// Milestone step names we care about, in lifecycle order
	milestoneSteps := []string{
		"UE_Registration", "NAS_Uplink", "Context_Setup",
		"HSS_Authenticate", "HSS_Location_Update",
		"PDU_Session_Setup", "PDU_Session_Establish_Req", "PDU_Session_Establish_Resp",
		"PFCP_Establish_Req", "PFCP_Establish_Resp",
		"Data_Tunnel",
		"IMS_Register", "IMS_Call_Setup", "IMS_Call_Connected",
		"RTP_Media",
		"IMS_Call_Teardown", "PDU_Session_Release_Req", "UE_Context_Release",
	}
	milestoneSet := make(map[string]bool)
	for _, s := range milestoneSteps {
		milestoneSet[s] = true
	}

	seen := make(map[string]bool)
	for _, e := range sess.Events {
		if !milestoneSet[e.Step] || seen[e.Step] {
			continue
		}
		seen[e.Step] = true
		deltaMs := int64(0)
		if !sess.StartTime.IsZero() && !e.Timestamp.IsZero() {
			deltaMs = e.Timestamp.Sub(sess.StartTime).Milliseconds()
		}
		sess.Lifecycle = append(sess.Lifecycle, domain.UELifecycleStep{
			Step:      e.Step,
			Protocol:  e.Protocol,
			Timestamp: e.Timestamp,
			DeltaMs:   deltaMs,
			Details:   e.Summary,
		})
	}

	// Infer current UE state from the highest milestone reached
	sess.UEState = domain.UEStateIdle
	for _, lc := range sess.Lifecycle {
		switch lc.Step {
		case "UE_Registration", "NAS_Uplink":
			sess.UEState = domain.UEStateAttaching
		case "Context_Setup", "HSS_Authenticate", "HSS_Location_Update":
			sess.UEState = domain.UEStateRegistered
		case "PDU_Session_Setup", "PDU_Session_Establish_Req", "PFCP_Establish_Req":
			sess.UEState = domain.UEStatePDUEstablishing
		case "PDU_Session_Establish_Resp", "PFCP_Establish_Resp", "Data_Tunnel":
			sess.UEState = domain.UEStateActive
		case "IMS_Register", "IMS_Call_Setup", "IMS_Call_Connected", "RTP_Media":
			sess.UEState = domain.UEStateActive
		case "IMS_Call_Teardown", "PDU_Session_Release_Req", "UE_Context_Release":
			sess.UEState = domain.UEStateReleasing
		}
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func partitionByType(flows []domain.Flow) map[domain.FlowType][]domain.Flow {
	m := make(map[domain.FlowType][]domain.Flow)
	for _, f := range flows {
		m[f.Type] = append(m[f.Type], f)
	}
	return m
}

func flowToHop(proto string, f domain.Flow) domain.TraceHop {
	return domain.TraceHop{
		Protocol:  proto,
		FlowID:    f.FlowID,
		SrcIP:     f.SrcIP,
		DstIP:     f.DstIP,
		SrcPort:   f.SrcPort,
		DstPort:   f.DstPort,
		StartTime: f.StartTime,
		EndTime:   f.EndTime,
		Metrics:   f.Metrics,
	}
}

func (t *TelecomTracer) addEvent(
	sess *domain.TelecomSession,
	ts time.Time, proto, step, summary, srcIP, dstIP string,
	meta map[string]any,
) {
	if ts.IsZero() {
		ts = sess.StartTime
	}
	sess.Events = append(sess.Events, domain.TraceEvent{
		Timestamp: ts,
		Protocol:  proto,
		Step:      step,
		Summary:   summary,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		Metadata:  meta,
	})
}

// timeOverlaps returns true if flow f overlaps or is within 30 s of the
// session's current time bounds (used as fallback when no explicit key matches).
const timeWindow = 30 * time.Second

func timeOverlaps(sess *domain.TelecomSession, f domain.Flow) bool {
	if sess.StartTime.IsZero() || f.StartTime.IsZero() {
		return true
	}
	sessionEnd := sess.EndTime
	if sessionEnd.IsZero() {
		sessionEnd = sess.StartTime
	}
	fEnd := f.EndTime
	if fEnd.IsZero() {
		fEnd = f.StartTime
	}
	return f.StartTime.Before(sessionEnd.Add(timeWindow)) &&
		sess.StartTime.Before(fEnd.Add(timeWindow))
}

func matchesMediaEndpoint(f domain.Flow, mediaIP, mediaPort string) bool {
	if mediaIP == "" {
		return false
	}
	portN := atoi(mediaPort)
	return (f.SrcIP == mediaIP && int(f.SrcPort) == portN) ||
		(f.DstIP == mediaIP && int(f.DstPort) == portN)
}

func appendUniq(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

// ── Step name mappings ────────────────────────────────────────────────────────

func ngapStep(procName string) string {
	m := map[string]string{
		"InitialUEMessage":         "UE_Registration",
		"InitialContextSetup":      "Context_Setup",
		"PDUSessionResourceSetup":  "PDU_Session_Setup",
		"PDUSessionResourceRelease":"PDU_Session_Release",
		"UEContextRelease":         "UE_Context_Release",
		"DownlinkNASTransport":     "NAS_Downlink",
		"UplinkNASTransport":       "NAS_Uplink",
		"NGSetup":                  "NG_Setup",
		"HandoverPreparation":      "Handover_Prep",
		"HandoverNotification":     "Handover_Complete",
	}
	if s, ok := m[procName]; ok {
		return s
	}
	return "NGAP_" + procName
}

func gtpcStep(msgType string) string {
	m := map[string]string{
		"Create Session Request":  "PDU_Session_Establish_Req",
		"Create Session Response": "PDU_Session_Establish_Resp",
		"Delete Session Request":  "PDU_Session_Release_Req",
		"Delete Session Response": "PDU_Session_Release_Resp",
		"Modify Bearer Request":   "Bearer_Modify_Req",
		"Modify Bearer Response":  "Bearer_Modify_Resp",
	}
	if s, ok := m[msgType]; ok {
		return s
	}
	return "GTP-C_" + msgType
}

func pfcpStep(msgType string) string {
	m := map[string]string{
		"Session Establishment Request":  "PFCP_Establish_Req",
		"Session Establishment Response": "PFCP_Establish_Resp",
		"Session Modification Request":   "PFCP_Modify_Req",
		"Session Modification Response":  "PFCP_Modify_Resp",
		"Session Deletion Request":       "PFCP_Delete_Req",
		"Session Deletion Response":      "PFCP_Delete_Resp",
	}
	if s, ok := m[msgType]; ok {
		return s
	}
	return "PFCP_" + msgType
}

func sipStep(method string) string {
	m := map[string]string{
		"REGISTER": "IMS_Register",
		"INVITE":   "IMS_Call_Setup",
		"200":      "IMS_Call_Connected",
		"BYE":      "IMS_Call_Teardown",
		"CANCEL":   "IMS_Call_Cancel",
		"":         "IMS_Signal",
	}
	if s, ok := m[method]; ok {
		return s
	}
	return "IMS_" + method
}

func diameterStep(cmd string) string {
	m := map[string]string{
		"Update-Location":    "HSS_Location_Update",
		"Authentication":     "HSS_Authenticate",
		"Cancel-Location":    "HSS_Cancel_Location",
		"Insert-Subscriber":  "HSS_Subscribe",
		"Credit-Control":     "PCRF_Credit_Control",
	}
	if s, ok := m[cmd]; ok {
		return s
	}
	return "Diameter_" + cmd
}

// ── Metric extraction helpers ─────────────────────────────────────────────────

func metricS(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	switch v := m[key].(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}

func metricF(m map[string]any, key string) float64 {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	}
	return 0
}

func metricI(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return 0
}

// computeSimpleMOS computes a simplified MOS score from loss% and jitter.
// Uses the E-model approximation: MOS ≈ 4.5 − lossPenalty − jitterPenalty.
func computeSimpleMOS(lossPct, jitterMs float64) float64 {
	if lossPct > 100 {
		lossPct = 100
	}
	mos := 4.5 - (lossPct * 0.05) - (jitterMs * 0.01)
	if mos < 1.0 {
		mos = 1.0
	}
	return mos
}

func mosQuality(mos float64) string {
	switch {
	case mos >= 4.0:
		return "good"
	case mos >= 3.0:
		return "fair"
	default:
		return "poor"
	}
}

// ── TEID normalization helpers ────────────────────────────────────────────────

// normalizeHexTEID converts any TEID representation to lowercase hex "0x%08x".
// GTP-C header TEIDs are stored as uint32; bearer F-TEIDs in ToMetrics() are "0x%08x" strings.
func normalizeHexTEID(v any) string {
	switch t := v.(type) {
	case uint32:
		return fmt.Sprintf("0x%08x", t)
	case int:
		return fmt.Sprintf("0x%08x", uint32(t))
	case int64:
		return fmt.Sprintf("0x%08x", uint32(t))
	case float64:
		return fmt.Sprintf("0x%08x", uint32(t))
	case string:
		s := strings.TrimSpace(t)
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			// already hex — normalise to lowercase and zero-pad to 10 chars
			n, err := strconv.ParseUint(s[2:], 16, 32)
			if err == nil {
				return fmt.Sprintf("0x%08x", n)
			}
			return strings.ToLower(s)
		}
		// decimal string
		if n, err := strconv.ParseUint(s, 10, 32); err == nil {
			return fmt.Sprintf("0x%08x", n)
		}
		return s
	default:
		return fmt.Sprintf("%v", v)
	}
}

// extractBearerFTEIDs extracts all bearer-context F-TEID values from a GTP-C flow's metrics.
// The GTP decoder stores them as: metrics["bearers"] = []map[string]any{{"fteids": [{"teid":"0x..."}]}}
// Top-level F-TEIDs are at: metrics["fteids"] = [{"teid":"0x..."}]
func extractBearerFTEIDs(metrics map[string]any) []string {
	var teids []string

	// Helper to pull teid strings from a []map[string]any fteid list
	extractFromList := func(raw any) {
		list, ok := raw.([]any)
		if !ok {
			return
		}
		for _, item := range list {
			fm, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if tv, ok := fm["teid"]; ok {
				teids = append(teids, normalizeHexTEID(tv))
			}
		}
	}

	// Top-level F-TEIDs (sender/receiver control endpoints)
	if fteids, ok := metrics["fteids"]; ok {
		extractFromList(fteids)
	}

	// Bearer-level F-TEIDs (the actual GTP-U data-plane TEIDs)
	if bearers, ok := metrics["bearers"]; ok {
		bl, ok := bearers.([]any)
		if !ok {
			return teids
		}
		for _, b := range bl {
			bm, ok := b.(map[string]any)
			if !ok {
				continue
			}
			if fteids, ok := bm["fteids"]; ok {
				extractFromList(fteids)
			}
		}
	}

	return teids
}
