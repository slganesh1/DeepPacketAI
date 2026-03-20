package handlers

import (
	"net/http"

	"DeepPacketAI/internal/storage"
)

type StatsHandler struct {
	store storage.Store
}

func NewStatsHandler(db storage.Store) *StatsHandler {
	return &StatsHandler{store: db}
}

// Summary returns aggregate statistics.
func (h *StatsHandler) Summary(w http.ResponseWriter, r *http.Request) {
	totalPackets, _ := h.store.GetPacketCount(nil)
	events, _ := h.store.QueryEvents(nil, 0)

	protoCounts := make(map[string]int)
	sevCounts := make(map[string]int)
	for _, e := range events {
		protoCounts[e.Protocol]++
		sevCounts[e.Severity]++
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total_packets":    totalPackets,
		"total_alerts":     len(events),
		"protocol_alerts":  protoCounts,
		"severity_counts":  sevCounts,
	})
}

// Protocols returns protocol distribution.
func (h *StatsHandler) Protocols(w http.ResponseWriter, r *http.Request) {
	result, err := h.store.GetProtocolCounts(nil)
	if err != nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}

	if result == nil {
		result = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, result)
}

// TopTalkers returns top IPs by packet count.
func (h *StatsHandler) TopTalkers(w http.ResponseWriter, r *http.Request) {
	result, err := h.store.GetTopTalkers(nil, 10)
	if err != nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}

	if result == nil {
		result = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, result)
}

// Bandwidth returns time-series bandwidth data.
// If session_id is provided, filters to that session; otherwise returns the latest 300 records.
func (h *StatsHandler) Bandwidth(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	records, err := h.store.QueryTrafficStats(sessionID, 300)
	if err != nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}

	writeJSON(w, http.StatusOK, records)
}
