package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"DeepPacketAI/internal/alerting"
	"DeepPacketAI/internal/storage"
)

// AlertTargetHandler provides CRUD endpoints for alert notification targets.
type AlertTargetHandler struct {
	store      storage.Store
	dispatcher *alerting.Dispatcher
}

func NewAlertTargetHandler(db storage.Store, d *alerting.Dispatcher) *AlertTargetHandler {
	return &AlertTargetHandler{store: db, dispatcher: d}
}

// ListAlertTargets GET /api/v1/alert-targets
func (h *AlertTargetHandler) List(w http.ResponseWriter, r *http.Request) {
	targets, err := h.store.ListAlertTargets()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if targets == nil {
		targets = []storage.AlertTarget{}
	}
	writeJSON(w, http.StatusOK, targets)
}

// CreateAlertTarget POST /api/v1/alert-targets
func (h *AlertTargetHandler) Create(w http.ResponseWriter, r *http.Request) {
	var t storage.AlertTarget
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if t.Name == "" || t.Type == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and type are required"})
		return
	}
	if t.ConfigJSON == "" {
		t.ConfigJSON = "{}"
	}
	if t.MinSeverity == "" {
		t.MinSeverity = "warning"
	}
	id, err := h.store.CreateAlertTarget(t)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	t.ID = id
	writeJSON(w, http.StatusCreated, t)
}

// UpdateAlertTarget PUT /api/v1/alert-targets/{id}
func (h *AlertTargetHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var t storage.AlertTarget
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	t.ID = id
	if t.ConfigJSON == "" {
		t.ConfigJSON = "{}"
	}
	if err := h.store.UpdateAlertTarget(t); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// DeleteAlertTarget DELETE /api/v1/alert-targets/{id}
func (h *AlertTargetHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	if err := h.store.DeleteAlertTarget(id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// TestAlertTarget POST /api/v1/alert-targets/{id}/test  — sends a synthetic test event
func (h *AlertTargetHandler) Test(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	target, err := h.store.GetAlertTarget(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "target not found"})
		return
	}
	// Temporarily enable so the dispatcher always fires the test
	original := target.Enabled
	target.Enabled = true
	if err := h.store.UpdateAlertTarget(*target); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer func() {
		target.Enabled = original
		_ = h.store.UpdateAlertTarget(*target)
	}()

	testEvent := storage.EventRecord{
		Timestamp:   "now",
		Severity:    "warning",
		Protocol:    "TEST",
		Title:       "Test Alert",
		Description: "This is a test notification from DeepPacketAI.",
	}
	h.dispatcher.Dispatch(r.Context(), []storage.EventRecord{testEvent})
	writeJSON(w, http.StatusOK, map[string]string{"status": "test notification sent"})
}
