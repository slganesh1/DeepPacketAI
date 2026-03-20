package handlers

import (
	"net/http"

	"DeepPacketAI/internal/plugin"

	"github.com/go-chi/chi/v5"
)

// PluginHandler serves the plugin management REST API.
type PluginHandler struct{}

// NewPluginHandler creates a PluginHandler backed by the global plugin registries.
func NewPluginHandler() *PluginHandler {
	return &PluginHandler{}
}

// GetAll returns every registered plugin grouped by category.
// GET /api/v1/plugins
func (h *PluginHandler) GetAll(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, plugin.AllPlugins{
		Protocol:  plugin.Protocols.List(),
		Detection: plugin.Detection.List(),
		AI:        plugin.AI.List(),
	})
}

// GetProtocol returns all protocol plugins.
// GET /api/v1/plugins/protocol
func (h *PluginHandler) GetProtocol(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, plugin.Protocols.List())
}

// GetDetection returns all detection rule plugins.
// GET /api/v1/plugins/detection
func (h *PluginHandler) GetDetection(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, plugin.Detection.List())
}

// GetAI returns all AI provider plugins.
// GET /api/v1/plugins/ai
func (h *PluginHandler) GetAI(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, plugin.AI.List())
}

// EnableProtocol enables a protocol plugin by name.
// POST /api/v1/plugins/protocol/{name}/enable
func (h *PluginHandler) EnableProtocol(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := plugin.Protocols.Enable(name); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "enabled", "name": name})
}

// DisableProtocol disables a protocol plugin by name.
// POST /api/v1/plugins/protocol/{name}/disable
func (h *PluginHandler) DisableProtocol(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := plugin.Protocols.Disable(name); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "disabled", "name": name})
}

// EnableDetection enables a detection rule plugin by name.
// POST /api/v1/plugins/detection/{name}/enable
func (h *PluginHandler) EnableDetection(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := plugin.Detection.Enable(name); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "enabled", "name": name})
}

// DisableDetection disables a detection rule plugin by name.
// POST /api/v1/plugins/detection/{name}/disable
func (h *PluginHandler) DisableDetection(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := plugin.Detection.Disable(name); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "disabled", "name": name})
}

// ActivateAI sets the named AI provider as the active one.
// POST /api/v1/plugins/ai/{name}/activate
func (h *PluginHandler) ActivateAI(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := plugin.AI.Activate(name); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "activated", "name": name})
}
