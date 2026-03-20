package handlers

import (
	"net/http"
	"strconv"

	"DeepPacketAI/internal/storage"
)

type AlertHandler struct {
	store storage.Store
}

func NewAlertHandler(db storage.Store) *AlertHandler {
	return &AlertHandler{store: db}
}

// ListAlerts returns alerts with optional filtering.
func (h *AlertHandler) ListAlerts(w http.ResponseWriter, r *http.Request) {
	filters := make(map[string]string)

	if v := r.URL.Query().Get("severity"); v != "" {
		filters["severity"] = v
	}
	if v := r.URL.Query().Get("protocol"); v != "" {
		filters["protocol"] = v
	}
	if v := r.URL.Query().Get("job_id"); v != "" {
		filters["job_id"] = v
	}

	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	events, err := h.store.QueryEvents(filters, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if events == nil {
		events = []storage.EventRecord{}
	}

	writeJSON(w, http.StatusOK, events)
}
