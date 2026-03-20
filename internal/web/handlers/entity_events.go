package handlers

import (
	"net/http"
	"strings"

	"DeepPacketAI/internal/storage"
  "DeepPacketAI/internal/web/api"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

type EntityEventHandler struct {
	DB storage.Store
}

func NewEntityEventHandler(db storage.Store) *EntityEventHandler {
	return &EntityEventHandler{DB: db}
}

func (h *EntityEventHandler) ListEntityEvents(w http.ResponseWriter, r *http.Request) {

	rawID := chi.URLParam(r, "id")

	if !strings.HasPrefix(rawID, "call:") {
		http.Error(w, "unsupported entity type", http.StatusBadRequest)
		return
	}

	callID := strings.TrimPrefix(rawID, "call:")

	events, err := h.DB.GetEventsForCall(callID)
	if err != nil {
		http.Error(w, "failed to load events", http.StatusInternalServerError)
		return
	}

	if events == nil {
	events = []api.TimelineEvent{}
}

	render.JSON(w, r, events)
}
