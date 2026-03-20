package handlers

import (
	"net/http"
	"strings"

	"DeepPacketAI/internal/storage"
	"DeepPacketAI/internal/web/api"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

type EntityMetricsHandler struct {
	DB storage.Store
}

func NewEntityMetricsHandler(db storage.Store) *EntityMetricsHandler {
	return &EntityMetricsHandler{DB: db}
}

func (h *EntityMetricsHandler) GetEntityMetrics(w http.ResponseWriter, r *http.Request) {

	rawID := chi.URLParam(r, "id")

	if !strings.HasPrefix(rawID, "call:") {
		http.Error(w, "unsupported entity type", http.StatusBadRequest)
		return
	}

	callID := strings.TrimPrefix(rawID, "call:")

	metrics, err := h.DB.GetMetricsForCall(callID)
	if err != nil {
		http.Error(w, "failed to load metrics", http.StatusInternalServerError)
		return
	}

	if metrics.Metrics == nil {
		metrics.Metrics = map[string][]api.MetricPoint{}
	}

	render.JSON(w, r, metrics)
}
