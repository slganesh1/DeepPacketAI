package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"unicode"

	"DeepPacketAI/internal/storage"

	"github.com/go-chi/chi/v5"
)

type PacketHandler struct {
	store storage.Store
}

func NewPacketHandler(db storage.Store) *PacketHandler {
	return &PacketHandler{store: db}
}

// ListPackets returns packets with optional filtering.
func (h *PacketHandler) ListPackets(w http.ResponseWriter, r *http.Request) {
	filters := make(map[string]string)

	if v := r.URL.Query().Get("protocol"); v != "" {
		filters["protocol"] = v
	}
	if v := r.URL.Query().Get("src_ip"); v != "" {
		filters["src_ip"] = v
	}
	if v := r.URL.Query().Get("dst_ip"); v != "" {
		filters["dst_ip"] = v
	}
	if v := r.URL.Query().Get("job_id"); v != "" {
		filters["job_id"] = v
	}
	if v := r.URL.Query().Get("session_id"); v != "" {
		filters["session_id"] = v
	}

	limit := 1000
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	offset := 0
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			offset = n
		}
	}

	packets, err := h.store.QueryPackets(filters, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if packets == nil {
		packets = []storage.PacketRecord{}
	}

	writeJSON(w, http.StatusOK, packets)
}

// GetPacket returns a single packet with full details.
func (h *PacketHandler) GetPacket(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid packet id"})
		return
	}

	pkt, err := h.store.GetPacketByID(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "packet not found"})
		return
	}

	writeJSON(w, http.StatusOK, pkt)
}

// hexRow is one 16-byte row in a hex dump.
type hexRow struct {
	Offset string `json:"offset"` // e.g. "0000"
	Hex    string `json:"hex"`    // space-separated hex bytes, gap after 8th: "45 00 00 28  00 01 00 00  40 01 f4 fb ..."
	ASCII  string `json:"ascii"`  // printable ASCII, "." for non-printable
}

// buildHexRows converts raw bytes into Wireshark-style hex rows (16 bytes per row).
func buildHexRows(data []byte) []hexRow {
	const rowWidth = 16
	rows := make([]hexRow, 0) // never nil; marshals as [] not null
	for i := 0; i < len(data); i += rowWidth {
		end := i + rowWidth
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]

		hexParts := make([]byte, 0, rowWidth*3+2)
		asciiParts := make([]byte, 0, rowWidth)
		for j, b := range chunk {
			if j == 8 {
				hexParts = append(hexParts, ' ', ' ')
			} else if j > 0 {
				hexParts = append(hexParts, ' ')
			}
			hexParts = append(hexParts, fmt.Sprintf("%02x", b)...)
			if unicode.IsPrint(rune(b)) && b < 0x7f {
				asciiParts = append(asciiParts, b)
			} else {
				asciiParts = append(asciiParts, '.')
			}
		}
		// Pad hex section to fixed width so columns align
		for j := len(chunk); j < rowWidth; j++ {
			if j == 8 {
				hexParts = append(hexParts, ' ', ' ')
			} else if j > 0 {
				hexParts = append(hexParts, ' ')
			}
			hexParts = append(hexParts, ' ', ' ')
		}

		rows = append(rows, hexRow{
			Offset: fmt.Sprintf("%04x", i),
			Hex:    string(hexParts),
			ASCII:  string(asciiParts),
		})
	}
	return rows
}

// GetPacketHex returns a structured hex dump of the raw packet bytes.
func (h *PacketHandler) GetPacketHex(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid packet id"})
		return
	}

	pkt, err := h.store.GetPacketByID(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "packet not found"})
		return
	}

	raw := pkt.RawPacket
	// Fall back to summary bytes if raw packet was not captured
	if len(raw) == 0 {
		raw = []byte(pkt.Summary)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":          pkt.ID,
		"total_bytes": pkt.Length,
		"has_raw":     len(pkt.RawPacket) > 0,
		"rows":        buildHexRows(raw),
	})
}

// GetPacketLayers returns a parsed layer tree from the packet metadata.
// This powers the Wireshark-style protocol tree in the UI.
func (h *PacketHandler) GetPacketLayers(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid packet id"})
		return
	}

	pkt, err := h.store.GetPacketByID(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "packet not found"})
		return
	}

	var meta map[string]any
	if pkt.MetadataJSON != "" {
		_ = json.Unmarshal([]byte(pkt.MetadataJSON), &meta)
	}
	if meta == nil {
		meta = map[string]any{}
	}

	layers := buildLayerTree(pkt, meta)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":     pkt.ID,
		"layers": layers,
	})
}

// layerField is a decoded field within a protocol layer.
type layerField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// protocolLayer represents one decoded protocol layer (Frame, Ethernet, IP, TCP, App).
type protocolLayer struct {
	Name   string       `json:"name"`
	Color  string       `json:"color"`
	Fields []layerField `json:"fields"`
}

func buildLayerTree(pkt *storage.PacketRecord, meta map[string]any) []protocolLayer {
	layers := make([]protocolLayer, 0)

	// Frame
	layers = append(layers, protocolLayer{
		Name:  fmt.Sprintf("Frame %d", pkt.FrameNumber),
		Color: "#94a3b8",
		Fields: []layerField{
			{Name: "Arrival Time", Value: pkt.Timestamp},
			{Name: "Frame Number", Value: fmt.Sprintf("%d", pkt.FrameNumber)},
			{Name: "Frame Length", Value: fmt.Sprintf("%d bytes", pkt.Length)},
			{Name: "Protocols in Frame", Value: buildProtoChain(pkt)},
		},
	})

	// IP layer
	ipProto := pkt.Protocol
	if ipProto == "" {
		ipProto = "Unknown"
	}
	ipFields := []layerField{
		{Name: "Source Address", Value: pkt.SrcIP},
		{Name: "Destination Address", Value: pkt.DstIP},
		{Name: "Protocol", Value: ipProto},
	}
	if ttl, ok := meta["ttl"]; ok {
		ipFields = append(ipFields, layerField{Name: "Time to Live", Value: fmt.Sprintf("%v", ttl)})
	}
	layers = append(layers, protocolLayer{Name: "Internet Protocol Version 4", Color: "#818cf8", Fields: ipFields})

	// Transport layer
	transportFields := []layerField{
		{Name: "Source Port", Value: fmt.Sprintf("%d", pkt.SrcPort)},
		{Name: "Destination Port", Value: fmt.Sprintf("%d", pkt.DstPort)},
	}
	transportName := "Transmission Control Protocol"
	transportColor := "#38bdf8"
	switch pkt.Protocol {
	case "UDP":
		transportName = "User Datagram Protocol"
	case "SCTP":
		transportName = "Stream Control Transmission Protocol"
	}
	layers = append(layers, protocolLayer{Name: transportName, Color: transportColor, Fields: transportFields})

	// Application layer
	appProto := pkt.AppProtocol
	if appProto != "" && appProto != pkt.Protocol {
		appColor := appLayerColor(appProto)
		appFields := metaToFields(meta, appProto)
		layers = append(layers, protocolLayer{Name: appProtoFullName(appProto), Color: appColor, Fields: appFields})
	}

	return layers
}

func buildProtoChain(pkt *storage.PacketRecord) string {
	chain := "eth:ip"
	switch pkt.Protocol {
	case "TCP":
		chain += ":tcp"
	case "UDP":
		chain += ":udp"
	case "SCTP":
		chain += ":sctp"
	}
	if pkt.AppProtocol != "" {
		chain += ":" + pkt.AppProtocol
	}
	return chain
}

func appLayerColor(proto string) string {
	colors := map[string]string{
		"SIP": "#34d399", "RTP": "#22d3ee", "HTTP": "#f59e0b",
		"DNS": "#818cf8", "TLS": "#84cc16", "Diameter": "#f472b6",
		"GTP": "#fb923c", "GTP-C": "#fb923c", "GTP-U": "#fbbf24",
		"PFCP": "#a78bfa", "S1AP": "#38bdf8", "NGAP": "#4ade80",
		"WebSocket": "#a3e635",
	}
	if c, ok := colors[proto]; ok {
		return c
	}
	return "#94a3b8"
}

func appProtoFullName(proto string) string {
	names := map[string]string{
		"SIP": "Session Initiation Protocol", "RTP": "Real-time Transport Protocol",
		"HTTP": "Hypertext Transfer Protocol", "DNS": "Domain Name System",
		"TLS": "Transport Layer Security", "Diameter": "Diameter Protocol",
		"GTP": "GPRS Tunnelling Protocol", "GTP-C": "GTP Control Plane",
		"GTP-U": "GTP User Plane", "PFCP": "Packet Forwarding Control Protocol",
		"S1AP": "S1 Application Protocol (LTE)", "NGAP": "NG Application Protocol (5G)",
		"WebSocket": "WebSocket Protocol",
	}
	if n, ok := names[proto]; ok {
		return n
	}
	return proto
}

func metaToFields(meta map[string]any, proto string) []layerField {
	// Priority field ordering per protocol
	priority := map[string][]string{
		"SIP":      {"method", "uri", "status_code", "status_text", "from", "to", "call_id", "via", "contact", "content_type", "content_length"},
		"DNS":      {"query_name", "query_type", "reply_code", "answers"},
		"HTTP":     {"method", "uri", "status_code", "host", "user_agent", "content_type", "content_length"},
		"Diameter": {"command_code", "command", "app_id", "is_request", "origin_host", "result_code"},
		"GTP":      {"message_type", "teid", "imsi", "apn", "rat_type"},
		"NGAP":     {"procedure_name", "pdu_type", "cause"},
	}

	fields := make([]layerField, 0)
	seen := map[string]bool{}

	if ordered, ok := priority[proto]; ok {
		for _, k := range ordered {
			if v, exists := meta[k]; exists {
				fields = append(fields, layerField{Name: formatFieldName(k), Value: fmt.Sprintf("%v", v)})
				seen[k] = true
			}
		}
	}
	// Remaining fields
	for k, v := range meta {
		if seen[k] {
			continue
		}
		valStr := fmt.Sprintf("%v", v)
		if len(valStr) > 200 {
			valStr = valStr[:200] + "…"
		}
		fields = append(fields, layerField{Name: formatFieldName(k), Value: valStr})
	}
	return fields
}

func formatFieldName(k string) string {
	result := make([]byte, 0, len(k))
	upperNext := true
	for i := 0; i < len(k); i++ {
		c := k[i]
		if c == '_' || c == '-' {
			result = append(result, ' ')
			upperNext = true
			continue
		}
		if upperNext {
			if c >= 'a' && c <= 'z' {
				c -= 32
			}
			upperNext = false
		}
		result = append(result, c)
	}
	return string(result)
}
