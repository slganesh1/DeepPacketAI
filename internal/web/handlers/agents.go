package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"DeepPacketAI/internal/stream"
)

// AgentHandler serves the live agent registry over HTTP.
type AgentHandler struct {
	registry *stream.AgentRegistry
}

// NewAgentHandler creates an AgentHandler. registry may be nil (standalone mode),
// in which case all endpoints return empty/not-found responses.
func NewAgentHandler(registry *stream.AgentRegistry) *AgentHandler {
	return &AgentHandler{registry: registry}
}

// ListAgents — GET /api/v1/agents
// Returns all currently-connected capture agents and their live stats.
func (h *AgentHandler) ListAgents(w http.ResponseWriter, r *http.Request) {
	if h.registry == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, h.registry.List())
}

// UpdateFilter — PUT /api/v1/agents/{id}/filter
// Hot-swaps the BPF capture filter on a connected agent without restarting it.
//
//	Request body: {"bpf_filter": "port 5060"}
func (h *AgentHandler) UpdateFilter(w http.ResponseWriter, r *http.Request) {
	if h.registry == nil {
		http.Error(w, "agent mode not enabled", http.StatusServiceUnavailable)
		return
	}
	agentID := chi.URLParam(r, "id")

	var req struct {
		BPFFilter string `json:"bpf_filter"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if !h.registry.SendFilter(agentID, req.BPFFilter) {
		http.Error(w, "agent not found or filter channel full", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"agent_id":   agentID,
		"bpf_filter": req.BPFFilter,
		"status":     "queued",
	})
}
