package handlers

import (
	"encoding/json"
	"net/http"

	"DeepPacketAI/internal/capture"
)

type CaptureHandler struct {
	engine *capture.Engine
}

func NewCaptureHandler(engine *capture.Engine) *CaptureHandler {
	return &CaptureHandler{engine: engine}
}

// ListInterfaces returns available network interfaces.
func (h *CaptureHandler) ListInterfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := capture.ListInterfaces()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, ifaces)
}

// StartCapture starts a live capture session.
func (h *CaptureHandler) StartCapture(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Interface string `json:"interface"`
		Filter    string `json:"filter"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Interface == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "interface is required"})
		return
	}

	session, err := h.engine.StartCapture(req.Interface, req.Filter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": session.ID,
		"status":     session.Status,
		"interface":  session.InterfaceName,
		"filter":     session.BPFFilter,
		"started_at": session.StartedAt,
		"job_id":     session.JobID,
	})
}

// StopCapture stops a running capture session.
func (h *CaptureHandler) StopCapture(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.SessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session_id is required"})
		return
	}

	jobID, err := h.engine.StopCapture(req.SessionID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "stopped",
		"session_id": req.SessionID,
		"job_id":     jobID,
	})
}

// ListSessions returns all capture sessions.
func (h *CaptureHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	sessions := h.engine.ListSessions()
	writeJSON(w, http.StatusOK, sessions)
}
