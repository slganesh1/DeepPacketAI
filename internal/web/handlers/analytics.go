package handlers

import (
	"encoding/json"
	"net/http"

	"DeepPacketAI/internal/analytics"
	"DeepPacketAI/internal/storage"
)

type AnalyticsHandler struct {
	db storage.Store
}

func NewAnalyticsHandler(db storage.Store) *AnalyticsHandler {
	return &AnalyticsHandler{db: db}
}

// GetKPIs returns computed KPI metrics.
// GET /api/v1/analytics/kpis
func (h *AnalyticsHandler) GetKPIs(w http.ResponseWriter, r *http.Request) {
	flows, err := h.db.GetAllFlows()
	if err != nil {
		http.Error(w, `{"error":"failed to load flows"}`, http.StatusInternalServerError)
		return
	}

	calls, err := h.db.GetAllCalls()
	if err != nil {
		http.Error(w, `{"error":"failed to load calls"}`, http.StatusInternalServerError)
		return
	}

	report := analytics.ComputeKPIs(flows, calls)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

// GetReport returns a comprehensive analysis report.
// GET /api/v1/analytics/report
func (h *AnalyticsHandler) GetReport(w http.ResponseWriter, r *http.Request) {
	flows, err := h.db.GetAllFlows()
	if err != nil {
		http.Error(w, `{"error":"failed to load flows"}`, http.StatusInternalServerError)
		return
	}

	calls, err := h.db.GetAllCalls()
	if err != nil {
		http.Error(w, `{"error":"failed to load calls"}`, http.StatusInternalServerError)
		return
	}

	report := analytics.GenerateReport(flows, calls)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}
