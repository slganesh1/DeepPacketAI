package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"DeepPacketAI/internal/ai"
	"DeepPacketAI/internal/storage"

	"github.com/go-chi/chi/v5"
)

// AIAnalysisHandler serves on-demand AI analysis endpoints.
type AIAnalysisHandler struct {
	db         storage.Store
	aiRegistry *ai.ProviderRegistry
}

func NewAIAnalysisHandler(db storage.Store, aiRegistry *ai.ProviderRegistry) *AIAnalysisHandler {
	return &AIAnalysisHandler{db: db, aiRegistry: aiRegistry}
}

// AnalyzeSession godoc
// POST /api/v1/ai/analyze/session/{sessionID}?job_id=<n>
// Sends a telecom session to the LLM for threat/fraud analysis.
func (h *AIAnalysisHandler) AnalyzeSession(w http.ResponseWriter, r *http.Request) {
	provider, ok := h.aiRegistry.Active()
	if !ok {
		http.Error(w, "no AI provider configured (set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GEMINI_API_KEY)", http.StatusServiceUnavailable)
		return
	}

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
	if err != nil || sess == nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()

	result, err := ai.AnalyzeTelecomSession(ctx, provider, *sess)
	if err != nil {
		http.Error(w, "AI analysis failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
