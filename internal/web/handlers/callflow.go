package handlers

import (
	"encoding/json"
	"net/http"

	"DeepPacketAI/internal/storage"

	"github.com/go-chi/chi/v5"
)

type CallFlowHandler struct {
	db storage.Store
}

func NewCallFlowHandler(db storage.Store) *CallFlowHandler {
	return &CallFlowHandler{db: db}
}

// GetCallFlow returns the call flow events for a given entity (call).
// GET /api/v1/entities/{id}/callflow
func (h *CallFlowHandler) GetCallFlow(w http.ResponseWriter, r *http.Request) {
	entityID := chi.URLParam(r, "id")
	if entityID == "" {
		http.Error(w, `{"error":"missing entity id"}`, http.StatusBadRequest)
		return
	}

	result, err := h.db.GetCallFlow(entityID)
	if err != nil {
		http.Error(w, `{"error":"failed to get call flow"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
