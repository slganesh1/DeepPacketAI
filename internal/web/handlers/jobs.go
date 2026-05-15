package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"DeepPacketAI/internal/analytics"
	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/storage"

	"github.com/go-chi/chi/v5"
)

type JobHandler struct {
	store storage.Store
}

func NewJobHandler(store storage.Store) *JobHandler {
	return &JobHandler{store: store}
}

func (h *JobHandler) GetJob(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid job id"})
		return
	}

	job, err := h.store.GetJob(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
		return
	}

	writeJSON(w, http.StatusOK, job)
}

func (h *JobHandler) ListJobs(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	status := r.URL.Query().Get("status")

	limit := 0
	if limitStr != "" {
		l, err := strconv.Atoi(limitStr)
		if err == nil {
			limit = l
		}
	}

	jobs, err := h.store.ListJobs(limit, status)
	if err != nil {
		http.Error(w, "failed to load jobs", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, jobs)
}

// GetJobSummary returns per-job aggregate stats and KPIs.
// GET /api/v1/jobs/{id}/summary
func (h *JobHandler) GetJobSummary(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid job id"})
		return
	}

	flows, err := h.store.GetFlowsByJob(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load flows"})
		return
	}

	calls, err := h.store.GetCallsByJob(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load calls"})
		return
	}

	events, err := h.store.QueryEvents(map[string]string{"job_id": strconv.FormatInt(id, 10)}, 0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load events"})
		return
	}

	packetCount, err := h.store.GetPacketCount(map[string]string{"job_id": strconv.FormatInt(id, 10)})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to count packets"})
		return
	}

	// Protocol breakdown
	protocolBreakdown := make(map[string]int)
	for _, f := range flows {
		protocolBreakdown[string(f.Type)]++
	}

	// Quality breakdown
	qualityBreakdown := make(map[string]int)
	totalMOS := 0.0
	mosCount := 0
	for _, c := range calls {
		if c.Quality != "" {
			qualityBreakdown[c.Quality]++
		}
		if c.MOS > 0 {
			totalMOS += c.MOS
			mosCount++
		}
	}
	avgMOS := 0.0
	if mosCount > 0 {
		avgMOS = totalMOS / float64(mosCount)
	}

	// Compute KPIs
	kpiReport := analytics.ComputeKPIs(flows, calls)

	writeJSON(w, http.StatusOK, map[string]any{
		"job_id":             id,
		"total_flows":        len(flows),
		"total_calls":        len(calls),
		"total_packets":      packetCount,
		"total_events":       len(events),
		"protocol_breakdown": protocolBreakdown,
		"quality_breakdown":  qualityBreakdown,
		"avg_mos":            avgMOS,
		"kpis":               kpiReport.KPIs,
	})
}

// ListJobFlows returns all flows for a specific job as structured JSON.
// GET /api/v1/jobs/{id}/flows
func (h *JobHandler) ListJobFlows(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid job id"})
		return
	}

	flows, err := h.store.GetFlowsByJob(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load flows"})
		return
	}

	// Optional type filter
	flowType := r.URL.Query().Get("type")
	if flowType != "" {
		var filtered []domain.Flow
		for _, f := range flows {
			if string(f.Type) == flowType {
				filtered = append(filtered, f)
			}
		}
		flows = filtered
	}

	// Convert to JSON-friendly structs
	type flowJSON struct {
		FlowID    string         `json:"flow_id"`
		Type      string         `json:"type"`
		SrcIP     string         `json:"src_ip"`
		DstIP     string         `json:"dst_ip"`
		SrcPort   uint16         `json:"src_port"`
		DstPort   uint16         `json:"dst_port"`
		StartTime string         `json:"start_time"`
		EndTime   string         `json:"end_time"`
		Metrics   map[string]any `json:"metrics,omitempty"`
	}

	result := make([]flowJSON, 0, len(flows))
	for _, f := range flows {
		result = append(result, flowJSON{
			FlowID:    f.FlowID,
			Type:      string(f.Type),
			SrcIP:     f.SrcIP,
			DstIP:     f.DstIP,
			SrcPort:   f.SrcPort,
			DstPort:   f.DstPort,
			StartTime: f.StartTime.Format("2006-01-02T15:04:05Z07:00"),
			EndTime:   f.EndTime.Format("2006-01-02T15:04:05Z07:00"),
			Metrics:   f.Metrics,
		})
	}

	writeJSON(w, http.StatusOK, result)
}

// ListJobEvents returns all events/alerts for a specific job.
// GET /api/v1/jobs/{id}/events
func (h *JobHandler) ListJobEvents(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid job id"})
		return
	}

	events, err := h.store.QueryEvents(map[string]string{"job_id": strconv.FormatInt(id, 10)}, 500)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load events"})
		return
	}

	if events == nil {
		events = []storage.EventRecord{}
	}

	writeJSON(w, http.StatusOK, events)
}

// DeleteJob removes a job and all its associated data.
// DELETE /api/v1/jobs/{id}
func (h *JobHandler) DeleteJob(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid job id"})
		return
	}
	if err := h.store.DeleteJob(id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// PurgePackets deletes all raw packet rows across all jobs (keeps flows/events/metadata).
// DELETE /api/v1/jobs/packets
func (h *JobHandler) PurgePackets(w http.ResponseWriter, r *http.Request) {
	if err := h.store.PurgeAllPackets(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "purged"})
}

// GetJobContext returns a structured text context for a specific job,
// including per-flow details, per-call details, and events/alerts.
// This is used by the AI chat to have actual data about the PCAP analysis.
func (h *JobHandler) GetJobContext(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid job id"})
		return
	}

	// Fetch flows, calls, and events for this job
	flows, err := h.store.GetFlowsByJob(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load flows"})
		return
	}

	calls, err := h.store.GetCallsByJob(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load calls"})
		return
	}

	events, err := h.store.QueryEvents(map[string]string{"job_id": strconv.FormatInt(id, 10)}, 200)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load events"})
		return
	}

	// Fetch packets for this job (limit to 500 to keep context manageable)
	packets, err := h.store.QueryPackets(map[string]string{"job_id": strconv.FormatInt(id, 10)}, 500, 0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load packets"})
		return
	}

	context := buildJobContextString(flows, calls, events, packets)
	writeJSON(w, http.StatusOK, map[string]string{"context": context})
}

// buildJobContextString creates a detailed text representation of job data for AI context.
// Field names match what each protocol decoder actually stores in Flow.Metrics.
func buildJobContextString(flows []domain.Flow, calls []domain.Call, events []storage.EventRecord, packets []storage.PacketRecord) string {
	var sb strings.Builder

	// Group flows by protocol type
	flowsByType := make(map[domain.FlowType][]domain.Flow)
	for _, f := range flows {
		flowsByType[f.Type] = append(flowsByType[f.Type], f)
	}

	// SIP Flows — decoder stores: method, from, to, response, media_ip, media_port, direction, hold_count, hold_events
	if sipFlows, ok := flowsByType[domain.FlowSIP]; ok && len(sipFlows) > 0 {
		sb.WriteString("## SIP Flows\n")
		for _, f := range sipFlows {
			sb.WriteString(fmt.Sprintf("- Flow %s | %s -> %s", f.FlowID, f.SrcIP, f.DstIP))
			if method, ok := f.Metrics["method"].(string); ok && method != "" {
				sb.WriteString(fmt.Sprintf(" | Method: %s", method))
			}
			if resp, ok := f.Metrics["response"].(string); ok && resp != "" {
				sb.WriteString(fmt.Sprintf(" | Response: %s", resp))
			}
			if from, ok := f.Metrics["from"].(string); ok && from != "" {
				sb.WriteString(fmt.Sprintf(" | From: %s", from))
			}
			if to, ok := f.Metrics["to"].(string); ok && to != "" {
				sb.WriteString(fmt.Sprintf(" | To: %s", to))
			}
			if mediaIP, ok := f.Metrics["media_ip"].(string); ok && mediaIP != "" {
				sb.WriteString(fmt.Sprintf(" | MediaIP: %s", mediaIP))
			}
			if mediaPort, ok := f.Metrics["media_port"].(string); ok && mediaPort != "" {
				sb.WriteString(fmt.Sprintf(" | MediaPort: %s", mediaPort))
			}
			if dir, ok := f.Metrics["direction"].(string); ok && dir != "" {
				sb.WriteString(fmt.Sprintf(" | Direction: %s", dir))
			}
			// Hold events
			if holdCount, ok := f.Metrics["hold_count"]; ok {
				sb.WriteString(fmt.Sprintf(" | HoldCount: %v", holdCount))
			}
			if holdEvents, ok := f.Metrics["hold_events"]; ok {
				sb.WriteString(fmt.Sprintf(" | HoldEvents: %v", holdEvents))
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	// RTP Flows — decoder stores: src_ip, src_port, dst_ip, dst_port, ssrc, packet_count, jitter_ms, max_seq_gap
	if rtpFlows, ok := flowsByType[domain.FlowRTP]; ok && len(rtpFlows) > 0 {
		sb.WriteString("## RTP Flows\n")
		for _, f := range rtpFlows {
			sb.WriteString(fmt.Sprintf("- Flow %s | %s -> %s", f.FlowID, f.SrcIP, f.DstIP))
			if ssrc, ok := f.Metrics["ssrc"]; ok {
				sb.WriteString(fmt.Sprintf(" | SSRC: %v", ssrc))
			}
			if pktCount, ok := f.Metrics["packet_count"]; ok {
				sb.WriteString(fmt.Sprintf(" | PacketCount: %v", pktCount))
			}
			if jitter, ok := f.Metrics["jitter_ms"]; ok {
				sb.WriteString(fmt.Sprintf(" | Jitter: %vms", jitter))
			}
			if seqGap, ok := f.Metrics["max_seq_gap"]; ok {
				sb.WriteString(fmt.Sprintf(" | MaxSeqGap: %v", seqGap))
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	// DNS Flows — decoder stores: query_name, query_type, reply_code, answers, latency_ms, is_error, error_type
	if dnsFlows, ok := flowsByType[domain.FlowDNS]; ok && len(dnsFlows) > 0 {
		sb.WriteString("## DNS Flows\n")
		for _, f := range dnsFlows {
			sb.WriteString(fmt.Sprintf("- Flow %s | %s -> %s", f.FlowID, f.SrcIP, f.DstIP))
			if name, ok := f.Metrics["query_name"].(string); ok && name != "" {
				sb.WriteString(fmt.Sprintf(" | Query: %s", name))
			}
			if qtype, ok := f.Metrics["query_type"].(string); ok && qtype != "" {
				sb.WriteString(fmt.Sprintf(" | Type: %s", qtype))
			}
			if rcode, ok := f.Metrics["reply_code"].(string); ok && rcode != "" {
				sb.WriteString(fmt.Sprintf(" | ReplyCode: %s", rcode))
			}
			if answers, ok := f.Metrics["answers"]; ok {
				sb.WriteString(fmt.Sprintf(" | Answers: %v", answers))
			}
			if latency, ok := f.Metrics["latency_ms"]; ok {
				sb.WriteString(fmt.Sprintf(" | Latency: %vms", latency))
			}
			if isErr, ok := f.Metrics["is_error"].(bool); ok && isErr {
				errType, _ := f.Metrics["error_type"].(string)
				sb.WriteString(fmt.Sprintf(" | ERROR: %s", errType))
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	// HTTP Flows — decoder stores: method, uri, host, status_code, is_error, content_type, content_length, user_agent, server, has_auth, has_cookie, body_preview
	if httpFlows, ok := flowsByType[domain.FlowHTTP]; ok && len(httpFlows) > 0 {
		sb.WriteString("## HTTP Flows\n")
		for _, f := range httpFlows {
			sb.WriteString(fmt.Sprintf("- Flow %s | %s -> %s", f.FlowID, f.SrcIP, f.DstIP))
			if method, ok := f.Metrics["method"].(string); ok && method != "" {
				sb.WriteString(fmt.Sprintf(" | Method: %s", method))
			}
			if uri, ok := f.Metrics["uri"].(string); ok && uri != "" {
				sb.WriteString(fmt.Sprintf(" | URI: %s", uri))
			}
			if host, ok := f.Metrics["host"].(string); ok && host != "" {
				sb.WriteString(fmt.Sprintf(" | Host: %s", host))
			}
			if status, ok := f.Metrics["status_code"]; ok {
				sb.WriteString(fmt.Sprintf(" | Status: %v", status))
			}
			if ct, ok := f.Metrics["content_type"].(string); ok && ct != "" {
				sb.WriteString(fmt.Sprintf(" | ContentType: %s", ct))
			}
			if cl, ok := f.Metrics["content_length"].(string); ok && cl != "" {
				sb.WriteString(fmt.Sprintf(" | ContentLength: %s", cl))
			}
			if ua, ok := f.Metrics["user_agent"].(string); ok && ua != "" {
				sb.WriteString(fmt.Sprintf(" | UserAgent: %s", ua))
			}
			if srv, ok := f.Metrics["server"].(string); ok && srv != "" {
				sb.WriteString(fmt.Sprintf(" | Server: %s", srv))
			}
			if hasAuth, ok := f.Metrics["has_auth"].(bool); ok && hasAuth {
				sb.WriteString(" | HasAuth")
			}
			if body, ok := f.Metrics["body_preview"].(string); ok && body != "" {
				sb.WriteString(fmt.Sprintf(" | Body: %s", body))
			}
			if isErr, ok := f.Metrics["is_error"].(bool); ok && isErr {
				sb.WriteString(" | ERROR")
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	// TLS/HTTPS Flows — decoder stores: sni, tls_version, cipher_suite, cert_subject, cert_issuer, alpn, handshake_messages, message_count
	if tlsFlows, ok := flowsByType[domain.FlowTLS]; ok && len(tlsFlows) > 0 {
		sb.WriteString("## TLS/HTTPS Flows\n")
		for _, f := range tlsFlows {
			sb.WriteString(fmt.Sprintf("- Flow %s | %s -> %s", f.FlowID, f.SrcIP, f.DstIP))
			if sni, ok := f.Metrics["sni"].(string); ok && sni != "" {
				sb.WriteString(fmt.Sprintf(" | SNI: %s", sni))
			}
			if ver, ok := f.Metrics["tls_version"].(string); ok && ver != "" {
				sb.WriteString(fmt.Sprintf(" | Version: %s", ver))
			}
			if cipher, ok := f.Metrics["cipher_suite"].(string); ok && cipher != "" {
				sb.WriteString(fmt.Sprintf(" | Cipher: %s", cipher))
			}
			if subj, ok := f.Metrics["cert_subject"].(string); ok && subj != "" {
				sb.WriteString(fmt.Sprintf(" | CertSubject: %s", subj))
			}
			if issuer, ok := f.Metrics["cert_issuer"].(string); ok && issuer != "" {
				sb.WriteString(fmt.Sprintf(" | CertIssuer: %s", issuer))
			}
			if alpn, ok := f.Metrics["alpn"].(string); ok && alpn != "" {
				sb.WriteString(fmt.Sprintf(" | ALPN: %s", alpn))
			}
			if count, ok := f.Metrics["message_count"]; ok {
				sb.WriteString(fmt.Sprintf(" | Messages: %v", count))
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	// Diameter Flows — decoder stores: command, command_code, app_id, app_name, is_request, session_id, result_code, origin_host, is_error, imsi, msisdn
	if diaFlows, ok := flowsByType[domain.FlowDiameter]; ok && len(diaFlows) > 0 {
		sb.WriteString("## Diameter Flows\n")
		for _, f := range diaFlows {
			sb.WriteString(fmt.Sprintf("- Flow %s | %s -> %s", f.FlowID, f.SrcIP, f.DstIP))
			if cmd, ok := f.Metrics["command"].(string); ok && cmd != "" {
				sb.WriteString(fmt.Sprintf(" | Command: %s", cmd))
			}
			if appName, ok := f.Metrics["app_name"].(string); ok && appName != "" {
				sb.WriteString(fmt.Sprintf(" | App: %s", appName))
			}
			if isReq, ok := f.Metrics["is_request"].(bool); ok {
				if isReq {
					sb.WriteString(" | Request")
				} else {
					sb.WriteString(" | Answer")
				}
			}
			if sessID, ok := f.Metrics["session_id"].(string); ok && sessID != "" {
				sb.WriteString(fmt.Sprintf(" | SessionID: %s", sessID))
			}
			if rc, ok := f.Metrics["result_code"]; ok {
				sb.WriteString(fmt.Sprintf(" | ResultCode: %v", rc))
			}
			if origin, ok := f.Metrics["origin_host"].(string); ok && origin != "" {
				sb.WriteString(fmt.Sprintf(" | OriginHost: %s", origin))
			}
			if imsi, ok := f.Metrics["imsi"].(string); ok && imsi != "" {
				sb.WriteString(fmt.Sprintf(" | IMSI: %s", imsi))
			}
			if msisdn, ok := f.Metrics["msisdn"].(string); ok && msisdn != "" {
				sb.WriteString(fmt.Sprintf(" | MSISDN: %s", msisdn))
			}
			if isErr, ok := f.Metrics["is_error"].(bool); ok && isErr {
				sb.WriteString(" | ERROR")
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	// GTP Flows — decoder stores: message_type, teid, is_gtpu, is_error, cause_code, imsi, msisdn, apn,
	// mei, pdn_type, pdn_address, serving_network, rat_type, ambr_uplink_kbps, ambr_downlink_kbps,
	// tai, ecgi, bearer_count, bearers, fteids, recovery, charging_id
	if gtpFlows, ok := flowsByType[domain.FlowGTP]; ok && len(gtpFlows) > 0 {
		sb.WriteString("## GTP Flows\n")
		for _, f := range gtpFlows {
			sb.WriteString(fmt.Sprintf("- Flow %s | %s -> %s", f.FlowID, f.SrcIP, f.DstIP))
			if msgType, ok := f.Metrics["message_type"].(string); ok && msgType != "" {
				sb.WriteString(fmt.Sprintf(" | MessageType: %s", msgType))
			}
			if teid, ok := f.Metrics["teid"]; ok {
				sb.WriteString(fmt.Sprintf(" | TEID: %v", teid))
			}
			if isGTPU, ok := f.Metrics["is_gtpu"].(bool); ok {
				if isGTPU {
					sb.WriteString(" | GTP-U")
				} else {
					sb.WriteString(" | GTP-C")
				}
			}
			if cause, ok := f.Metrics["cause_code"]; ok {
				sb.WriteString(fmt.Sprintf(" | CauseCode: %v", cause))
			}
			if imsi, ok := f.Metrics["imsi"].(string); ok && imsi != "" {
				sb.WriteString(fmt.Sprintf(" | IMSI: %s", imsi))
			}
			if msisdn, ok := f.Metrics["msisdn"].(string); ok && msisdn != "" {
				sb.WriteString(fmt.Sprintf(" | MSISDN: %s", msisdn))
			}
			if mei, ok := f.Metrics["mei"].(string); ok && mei != "" {
				sb.WriteString(fmt.Sprintf(" | MEI/IMEI: %s", mei))
			}
			if apn, ok := f.Metrics["apn"].(string); ok && apn != "" {
				sb.WriteString(fmt.Sprintf(" | APN: %s", apn))
			}
			if pdnType, ok := f.Metrics["pdn_type"].(string); ok && pdnType != "" {
				sb.WriteString(fmt.Sprintf(" | PDNType: %s", pdnType))
			}
			if pdnAddr, ok := f.Metrics["pdn_address"].(string); ok && pdnAddr != "" {
				sb.WriteString(fmt.Sprintf(" | PDNAddr: %s", pdnAddr))
			}
			if sn, ok := f.Metrics["serving_network"].(string); ok && sn != "" {
				sb.WriteString(fmt.Sprintf(" | ServingNetwork: %s", sn))
			}
			if rat, ok := f.Metrics["rat_type"].(string); ok && rat != "" {
				sb.WriteString(fmt.Sprintf(" | RAT: %s", rat))
			}
			if ambrUL, ok := f.Metrics["ambr_uplink_kbps"]; ok {
				sb.WriteString(fmt.Sprintf(" | AMBR_UL: %vkbps", ambrUL))
			}
			if ambrDL, ok := f.Metrics["ambr_downlink_kbps"]; ok {
				sb.WriteString(fmt.Sprintf(" | AMBR_DL: %vkbps", ambrDL))
			}
			if tai, ok := f.Metrics["tai"].(string); ok && tai != "" {
				sb.WriteString(fmt.Sprintf(" | TAI: %s", tai))
			}
			if ecgi, ok := f.Metrics["ecgi"].(string); ok && ecgi != "" {
				sb.WriteString(fmt.Sprintf(" | ECGI: %s", ecgi))
			}
			if bc, ok := f.Metrics["bearer_count"]; ok {
				sb.WriteString(fmt.Sprintf(" | Bearers: %v", bc))
			}
			if bearers, ok := f.Metrics["bearers"].([]map[string]any); ok {
				for i, b := range bearers {
					sb.WriteString(fmt.Sprintf(" | Bearer[%d]{EBI:%v", i, b["ebi"]))
					if qci, ok := b["qci"]; ok {
						sb.WriteString(fmt.Sprintf(" QCI:%v", qci))
					}
					if qciName, ok := b["qci_name"].(string); ok && qciName != "" {
						sb.WriteString(fmt.Sprintf("(%s)", qciName))
					}
					if mbrUL, ok := b["mbr_uplink_kbps"]; ok {
						sb.WriteString(fmt.Sprintf(" MBR_UL:%vkbps", mbrUL))
					}
					if mbrDL, ok := b["mbr_downlink_kbps"]; ok {
						sb.WriteString(fmt.Sprintf(" MBR_DL:%vkbps", mbrDL))
					}
					sb.WriteString("}")
				}
			}
			if fteids, ok := f.Metrics["fteids"].([]map[string]any); ok {
				for _, ft := range fteids {
					sb.WriteString(fmt.Sprintf(" | FTEID{%s TEID:%v", ft["interface"], ft["teid"]))
					if ip, ok := ft["ipv4"].(string); ok && ip != "" {
						sb.WriteString(fmt.Sprintf(" IP:%s", ip))
					}
					sb.WriteString("}")
				}
			}
			if isErr, ok := f.Metrics["is_error"].(bool); ok && isErr {
				sb.WriteString(" | ERROR")
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	// PFCP Flows — decoder stores: message_type, seid, cause_code, is_error
	if pfcpFlows, ok := flowsByType[domain.FlowPFCP]; ok && len(pfcpFlows) > 0 {
		sb.WriteString("## PFCP Flows\n")
		for _, f := range pfcpFlows {
			sb.WriteString(fmt.Sprintf("- Flow %s | %s -> %s", f.FlowID, f.SrcIP, f.DstIP))
			if msgType, ok := f.Metrics["message_type"].(string); ok && msgType != "" {
				sb.WriteString(fmt.Sprintf(" | MessageType: %s", msgType))
			}
			if seid, ok := f.Metrics["seid"]; ok {
				sb.WriteString(fmt.Sprintf(" | SEID: %v", seid))
			}
			if cause, ok := f.Metrics["cause_code"]; ok {
				sb.WriteString(fmt.Sprintf(" | CauseCode: %v", cause))
			}
			if isErr, ok := f.Metrics["is_error"].(bool); ok && isErr {
				sb.WriteString(" | ERROR")
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	// S1AP Flows — decoder stores: pdu_type, procedure_code, procedure_name
	if s1apFlows, ok := flowsByType[domain.FlowS1AP]; ok && len(s1apFlows) > 0 {
		sb.WriteString("## S1AP Flows\n")
		for _, f := range s1apFlows {
			sb.WriteString(fmt.Sprintf("- Flow %s | %s -> %s", f.FlowID, f.SrcIP, f.DstIP))
			if pduType, ok := f.Metrics["pdu_type"].(string); ok && pduType != "" {
				sb.WriteString(fmt.Sprintf(" | PDUType: %s", pduType))
			}
			if procName, ok := f.Metrics["procedure_name"].(string); ok && procName != "" {
				sb.WriteString(fmt.Sprintf(" | Procedure: %s", procName))
			}
			if procCode, ok := f.Metrics["procedure_code"]; ok {
				sb.WriteString(fmt.Sprintf(" | ProcedureCode: %v", procCode))
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	// NGAP Flows — decoder stores: pdu_type, procedure_code, procedure_name, imsi
	if ngapFlows, ok := flowsByType[domain.FlowNGAP]; ok && len(ngapFlows) > 0 {
		sb.WriteString("## NGAP Flows\n")
		for _, f := range ngapFlows {
			sb.WriteString(fmt.Sprintf("- Flow %s | %s -> %s", f.FlowID, f.SrcIP, f.DstIP))
			if pduType, ok := f.Metrics["pdu_type"].(string); ok && pduType != "" {
				sb.WriteString(fmt.Sprintf(" | PDUType: %s", pduType))
			}
			if procName, ok := f.Metrics["procedure_name"].(string); ok && procName != "" {
				sb.WriteString(fmt.Sprintf(" | Procedure: %s", procName))
			}
			if procCode, ok := f.Metrics["procedure_code"]; ok {
				sb.WriteString(fmt.Sprintf(" | ProcedureCode: %v", procCode))
			}
			if imsi, ok := f.Metrics["imsi"].(string); ok && imsi != "" {
				sb.WriteString(fmt.Sprintf(" | IMSI: %s", imsi))
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	// SCTP Flows (generic — no dedicated decoder, used as transport)
	if sctpFlows, ok := flowsByType[domain.FlowSCTP]; ok && len(sctpFlows) > 0 {
		sb.WriteString("## SCTP Flows\n")
		for _, f := range sctpFlows {
			sb.WriteString(fmt.Sprintf("- Flow %s | %s -> %s", f.FlowID, f.SrcIP, f.DstIP))
			for k, v := range f.Metrics {
				sb.WriteString(fmt.Sprintf(" | %s: %v", k, v))
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	// Calls
	if len(calls) > 0 {
		sb.WriteString("## Calls\n")
		for _, c := range calls {
			fromURI := ""
			toURI := ""
			if c.SIPMetrics != nil {
				fromURI, _ = c.SIPMetrics["from"].(string)
				toURI, _ = c.SIPMetrics["to"].(string)
			}
			sb.WriteString(fmt.Sprintf("- Call %s | From: %s | To: %s | MOS: %.3f | Quality: %s | EndType: %s | RootCause: %s\n",
				c.CallID, fromURI, toURI, c.MOS, c.Quality, c.EndType, c.RootCause))
		}
		sb.WriteString("\n")
	}

	// Events/Alerts
	if len(events) > 0 {
		sb.WriteString("## Events/Alerts\n")
		for _, e := range events {
			sb.WriteString(fmt.Sprintf("- [%s] %s: %s - %s\n", e.Severity, e.Protocol, e.Title, e.Description))
		}
		sb.WriteString("\n")
	}

	// Packets grouped by protocol
	if len(packets) > 0 {
		pktsByProto := make(map[string][]storage.PacketRecord)
		for _, p := range packets {
			proto := p.AppProtocol
			if proto == "" {
				proto = p.Protocol
			}
			pktsByProto[proto] = append(pktsByProto[proto], p)
		}

		sb.WriteString("## Packets (per-frame details)\n")
		for proto, pkts := range pktsByProto {
			sb.WriteString(fmt.Sprintf("### %s Packets (%d total)\n", proto, len(pkts)))
			for _, p := range pkts {
				sb.WriteString(fmt.Sprintf("- Frame #%d [%s] %s:%d -> %s:%d | %s | %s",
					p.FrameNumber, p.Timestamp, p.SrcIP, p.SrcPort, p.DstIP, p.DstPort, proto, p.Summary))
				if p.ErrorsJSON != "" && p.ErrorsJSON != "null" && p.ErrorsJSON != "[]" {
					sb.WriteString(fmt.Sprintf(" | errors: %s", p.ErrorsJSON))
				}
				sb.WriteString("\n")
			}
		}
		sb.WriteString("\n")
	}

	// Summary counts
	sb.WriteString(fmt.Sprintf("## Summary\n- Total Flows: %d\n- Total Calls: %d\n- Total Events: %d\n- Total Packets: %d\n",
		len(flows), len(calls), len(events), len(packets)))

	return sb.String()
}
