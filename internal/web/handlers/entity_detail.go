package handlers

import (
	"net/http"
	"strings"

	"DeepPacketAI/internal/storage"
	"DeepPacketAI/internal/web/api"

	"github.com/go-chi/chi/v5"
)

type EntityDetailHandler struct {
	store storage.Store
}

func NewEntityDetailHandler(store storage.Store) *EntityDetailHandler {
	return &EntityDetailHandler{store: store}
}

func (h *EntityDetailHandler) GetEntity(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	callID := strings.TrimPrefix(id, "call:")

	entity, rtpLegs, err := h.store.GetEntityWithRTPLegs(callID)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	resp := api.EntityDetailResponse{
		Entity: api.EntityItem{
			EntityID:   entity.EntityID,
			EntityType: entity.EntityType,
			StartTime:  entity.StartTime,
			EndTime:    entity.EndTime,
			Summary:    entity.Summary,
		},
		RTPLegs: rtpLegs,
	}

	// Attach SIP setup latency if available
	if sipMetrics, err := h.store.GetSIPFlowMetrics(callID); err == nil && sipMetrics != nil {
		if latency, ok := sipMetrics["setup_latency_ms"].(float64); ok {
			resp.SetupLatencyMs = &latency
		}
	}

	writeJSON(w, http.StatusOK, resp)
}
