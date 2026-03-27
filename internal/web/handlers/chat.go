package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"DeepPacketAI/internal/ai"
	"DeepPacketAI/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type ChatHandler struct {
	store    storage.Store
	registry *ai.ProviderRegistry
}

func NewChatHandler(db storage.Store, registry *ai.ProviderRegistry) *ChatHandler {
	return &ChatHandler{store: db, registry: registry}
}

// CreateConversation creates a new chat conversation.
func (h *ChatHandler) CreateConversation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Title string `json:"title"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Title = "New Conversation"
	}
	if req.Title == "" {
		req.Title = "New Conversation"
	}

	conv := storage.Conversation{
		ID:       uuid.New().String(),
		Title:    req.Title,
		Provider: h.registry.ActiveName(),
	}

	if err := h.store.CreateConversation(conv); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusCreated, conv)
}

// ListConversations returns all conversations.
func (h *ChatHandler) ListConversations(w http.ResponseWriter, r *http.Request) {
	convs, err := h.store.ListConversations()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if convs == nil {
		convs = []storage.Conversation{}
	}
	writeJSON(w, http.StatusOK, convs)
}

// GetConversation returns a conversation with messages.
func (h *ChatHandler) GetConversation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	conv, messages, err := h.store.GetConversation(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "conversation not found"})
		return
	}
	if messages == nil {
		messages = []storage.ChatMessage{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"conversation": conv,
		"messages":     messages,
	})
}

// SendMessage sends a message and streams the AI response via SSE.
func (h *ChatHandler) SendMessage(w http.ResponseWriter, r *http.Request) {
	convID := chi.URLParam(r, "id")

	var req struct {
		Content      string `json:"content"`
		PacketContext string `json:"packet_context,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	// Truncate packet context to ~12000 chars (~3K tokens) before storing.
	// Raw flow JSON from large PCAPs can easily exceed 200K tokens otherwise.
	ctx := req.PacketContext
	if len(ctx) > 12000 {
		ctx = ctx[:12000] + "\n...[truncated for token limit]"
	}

	// Store user message
	userMsg := storage.ChatMessage{
		ConversationID:    convID,
		Role:              "user",
		Content:           req.Content,
		PacketContextJSON: ctx,
	}
	if err := h.store.AddChatMessage(userMsg); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to store message"})
		return
	}

	// Get conversation history
	_, messages, err := h.store.GetConversation(convID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "conversation not found"})
		return
	}

	// Build LLM messages. Attach packet context only to the FIRST user message that
	// had it — re-attaching on every message multiplies token usage with each turn.
	var llmMessages []ai.Message
	contextAttached := false
	for _, m := range messages {
		content := m.Content
		if m.PacketContextJSON != "" && !contextAttached {
			pcapCtx := m.PacketContextJSON
			if len(pcapCtx) > 12000 {
				pcapCtx = pcapCtx[:12000] + "\n...[truncated]"
			}
			content = "Network capture context:\n" + pcapCtx + "\n\nQuestion:\n" + content
			contextAttached = true
		}
		llmMessages = append(llmMessages, ai.Message{
			Role:    m.Role,
			Content: content,
		})
	}

	// If new packet context provided with this request, prepend to the latest user message
	if req.PacketContext != "" {
		lastIdx := len(llmMessages) - 1
		if lastIdx >= 0 && messages[lastIdx].PacketContextJSON == "" {
			llmMessages[lastIdx].Content = "Context:\n" + req.PacketContext + "\n\nQuestion:\n" + llmMessages[lastIdx].Content
		}
	}

	// Get active provider
	provider, ok := h.registry.Active()
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no AI provider configured. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GEMINI_API_KEY"})
		return
	}

	// Stream response via SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming not supported"})
		return
	}

	stream, err := provider.Stream(r.Context(), ai.CompletionRequest{
		Messages: llmMessages,
	})
	if err != nil {
		fmt.Fprintf(w, "data: {\"error\": %q}\n\n", err.Error())
		flusher.Flush()
		return
	}

	var fullContent string
	for chunk := range stream {
		if chunk.Error != nil {
			fmt.Fprintf(w, "data: {\"error\": %q}\n\n", chunk.Error.Error())
			flusher.Flush()
			break
		}
		if chunk.Content != "" {
			fullContent += chunk.Content
			data, _ := json.Marshal(map[string]string{"content": chunk.Content})
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
		if chunk.Done {
			fmt.Fprintf(w, "data: {\"done\": true}\n\n")
			flusher.Flush()
			break
		}
	}

	// Store assistant response
	if fullContent != "" {
		assistantMsg := storage.ChatMessage{
			ConversationID: convID,
			Role:           "assistant",
			Content:        fullContent,
		}
		h.store.AddChatMessage(assistantMsg)
	}
}

// DeleteConversation deletes a conversation.
func (h *ChatHandler) DeleteConversation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.store.DeleteConversation(id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ListProviders returns available AI providers.
func (h *ChatHandler) ListProviders(w http.ResponseWriter, r *http.Request) {
	providers := h.registry.List()
	active := h.registry.ActiveName()

	writeJSON(w, http.StatusOK, map[string]any{
		"providers": providers,
		"active":    active,
	})
}

// SetSettings updates chat settings.
func (h *ChatHandler) SetSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider string `json:"provider"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	if !h.registry.SetActive(req.Provider) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider not available"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"active": req.Provider})
}
