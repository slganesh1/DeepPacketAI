package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"DeepPacketAI/internal/storage"

	"github.com/go-chi/chi/v5"
)

// TelecomHandler serves telecom session (call trace) endpoints.
type TelecomHandler struct {
	db storage.Store
}

func NewTelecomHandler(db storage.Store) *TelecomHandler {
	return &TelecomHandler{db: db}
}

// ListTelecomSessions godoc
// GET /api/v1/telecom-sessions?job_id=<n>
// If job_id is omitted, returns sessions across all jobs.
func (h *TelecomHandler) ListTelecomSessions(w http.ResponseWriter, r *http.Request) {
	jobIDStr := r.URL.Query().Get("job_id")

	var (
		sessions interface{}
		err      error
	)

	if jobIDStr != "" {
		jobID, parseErr := strconv.ParseInt(jobIDStr, 10, 64)
		if parseErr != nil {
			http.Error(w, "invalid job_id", http.StatusBadRequest)
			return
		}
		sessions, err = h.db.ListTelecomSessions(jobID)
	} else {
		sessions, err = h.db.ListAllTelecomSessions()
	}

	if err != nil {
		http.Error(w, "failed to list telecom sessions: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions)
}

// GetTelecomSession godoc
// GET /api/v1/telecom-sessions/{sessionID}?job_id=<n>
func (h *TelecomHandler) GetTelecomSession(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "sessionID")
	jobIDStr := r.URL.Query().Get("job_id")

	if jobIDStr == "" {
		http.Error(w, "job_id query param required", http.StatusBadRequest)
		return
	}
	jobID, err := strconv.ParseInt(jobIDStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid job_id", http.StatusBadRequest)
		return
	}

	sess, err := h.db.GetTelecomSession(jobID, sessionID)
	if err != nil {
		http.Error(w, "failed to get telecom session: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if sess == nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sess)
}
