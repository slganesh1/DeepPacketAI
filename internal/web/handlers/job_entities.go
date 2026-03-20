package handlers

import (
	"net/http"
	"strconv"

	"DeepPacketAI/internal/storage"

	"github.com/go-chi/chi/v5"
)

type JobEntityHandler struct {
	db storage.Store
}

func NewJobEntityHandler(db storage.Store) *JobEntityHandler {
	return &JobEntityHandler{db: db}
}

func (h *JobEntityHandler) ListJobEntities(w http.ResponseWriter, r *http.Request) {
	jobIDStr := chi.URLParam(r, "id")

	jobID, err := strconv.ParseInt(jobIDStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid job id", http.StatusBadRequest)
		return
	}

	entities, err := h.db.ListEntitiesForJob(jobID, 0, "")
	if err != nil {
		http.Error(w, "failed to load entities", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, entities)
}
