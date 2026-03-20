package storage

import "time"

// Conversation represents a chat conversation.
type Conversation struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Provider  string `json:"provider"`
	Model     string `json:"model"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// ChatMessage represents a message in a conversation.
type ChatMessage struct {
	ID                int64  `json:"id"`
	ConversationID    string `json:"conversation_id"`
	Role              string `json:"role"`
	Content           string `json:"content"`
	PacketContextJSON string `json:"packet_context_json,omitempty"`
	CreatedAt         string `json:"created_at"`
}

// CreateConversation creates a new conversation.
func (s *SQLiteStore) CreateConversation(conv Conversation) error {
	ctx, cancel := writeCtx()
	defer cancel()
	now := time.Now().Format(time.RFC3339)
	if conv.CreatedAt == "" {
		conv.CreatedAt = now
	}
	if conv.UpdatedAt == "" {
		conv.UpdatedAt = now
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO conversations (id, title, provider, model, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, conv.ID, conv.Title, conv.Provider, conv.Model, conv.CreatedAt, conv.UpdatedAt)
	return err
}

// ListConversations returns all conversations.
func (s *SQLiteStore) ListConversations() ([]Conversation, error) {
	ctx, cancel := queryCtx()
	defer cancel()
	rows, err := s.db.QueryContext(ctx, "SELECT id, title, provider, model, created_at, updated_at FROM conversations ORDER BY updated_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var convs []Conversation
	for rows.Next() {
		var c Conversation
		if err := rows.Scan(&c.ID, &c.Title, &c.Provider, &c.Model, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		convs = append(convs, c)
	}
	return convs, nil
}

// GetConversation returns a conversation with its messages.
func (s *SQLiteStore) GetConversation(id string) (*Conversation, []ChatMessage, error) {
	ctx, cancel := queryCtx()
	defer cancel()
	var c Conversation
	err := s.db.QueryRowContext(ctx, "SELECT id, title, provider, model, created_at, updated_at FROM conversations WHERE id = ?", id).
		Scan(&c.ID, &c.Title, &c.Provider, &c.Model, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, nil, err
	}

	rows, err := s.db.QueryContext(ctx, "SELECT id, conversation_id, role, content, packet_context_json, created_at FROM chat_messages WHERE conversation_id = ? ORDER BY created_at ASC", id)
	if err != nil {
		return &c, nil, err
	}
	defer rows.Close()

	var messages []ChatMessage
	for rows.Next() {
		var m ChatMessage
		var ctxJSON *string
		if err := rows.Scan(&m.ID, &m.ConversationID, &m.Role, &m.Content, &ctxJSON, &m.CreatedAt); err != nil {
			return &c, nil, err
		}
		if ctxJSON != nil {
			m.PacketContextJSON = *ctxJSON
		}
		messages = append(messages, m)
	}

	return &c, messages, nil
}

// AddChatMessage adds a message to a conversation.
func (s *SQLiteStore) AddChatMessage(msg ChatMessage) error {
	ctx, cancel := writeCtx()
	defer cancel()
	now := time.Now().Format(time.RFC3339)
	if msg.CreatedAt == "" {
		msg.CreatedAt = now
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO chat_messages (conversation_id, role, content, packet_context_json, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, msg.ConversationID, msg.Role, msg.Content, msg.PacketContextJSON, msg.CreatedAt)
	if err != nil {
		return err
	}

	// Update conversation timestamp
	_, err = s.db.ExecContext(ctx, "UPDATE conversations SET updated_at = ? WHERE id = ?", now, msg.ConversationID)
	return err
}

// DeleteConversation deletes a conversation and its messages.
func (s *SQLiteStore) DeleteConversation(id string) error {
	ctx, cancel := writeCtx()
	defer cancel()
	_, err := s.db.ExecContext(ctx, "DELETE FROM conversations WHERE id = ?", id)
	return err
}
