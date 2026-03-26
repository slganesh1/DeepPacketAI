package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"DeepPacketAI/internal/detection"
	"DeepPacketAI/internal/storage"
)

// DetectionRulesHandler provides CRUD for user-defined detection rules.
type DetectionRulesHandler struct {
	store storage.Store
}

func NewDetectionRulesHandler(db storage.Store) *DetectionRulesHandler {
	return &DetectionRulesHandler{store: db}
}

// ListRules GET /api/v1/detection-rules
func (h *DetectionRulesHandler) List(w http.ResponseWriter, r *http.Request) {
	rules, err := h.store.ListUserRules()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if rules == nil {
		rules = []storage.UserDetectionRule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

// CreateRule POST /api/v1/detection-rules
func (h *DetectionRulesHandler) Create(w http.ResponseWriter, r *http.Request) {
	var rule storage.UserDetectionRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if rule.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	if rule.ConditionJSON == "" {
		rule.ConditionJSON = "{}"
	}
	if rule.Protocol == "" {
		rule.Protocol = "ANY"
	}
	if rule.Severity == "" {
		rule.Severity = "warning"
	}
	// Validate the condition JSON is parseable
	if err := validateConditionJSON(rule.ConditionJSON); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	id, err := h.store.CreateUserRule(rule)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	rule.ID = id
	writeJSON(w, http.StatusCreated, rule)
}

// UpdateRule PUT /api/v1/detection-rules/{id}
func (h *DetectionRulesHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var rule storage.UserDetectionRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	rule.ID = id
	if rule.ConditionJSON == "" {
		rule.ConditionJSON = "{}"
	}
	if err := validateConditionJSON(rule.ConditionJSON); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := h.store.UpdateUserRule(rule); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

// DeleteRule DELETE /api/v1/detection-rules/{id}
func (h *DetectionRulesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	if err := h.store.DeleteUserRule(id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// validateConditionJSON parses and validates rule condition JSON.
func validateConditionJSON(s string) error {
	_, err := detection.UserRuleFromJSON(0, "validate", "", "ANY", "warning", s)
	return err
}
