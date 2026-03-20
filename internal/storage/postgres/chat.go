package postgres

import (
	"time"

	"DeepPacketAI/internal/storage"
)

func (s *PostgresStore) CreateConversation(conv storage.Conversation) error {
	ctx, cancel := writeCtx()
	defer cancel()

	now := time.Now()
	createdAt := now
	updatedAt := now

	if conv.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, conv.CreatedAt); err == nil {
			createdAt = t
		}
	}
	if conv.UpdatedAt != "" {
		if t, err := time.Parse(time.RFC3339, conv.UpdatedAt); err == nil {
			updatedAt = t
		}
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO conversations (id, title, provider, model, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, conv.ID, conv.Title, conv.Provider, conv.Model, createdAt, updatedAt)
	return err
}

func (s *PostgresStore) ListConversations() ([]storage.Conversation, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	rows, err := s.pool.Query(ctx,
		"SELECT id, title, provider, model, created_at, updated_at FROM conversations ORDER BY updated_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var convs []storage.Conversation
	for rows.Next() {
		var c storage.Conversation
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&c.ID, &c.Title, &c.Provider, &c.Model, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		c.CreatedAt = createdAt.Format(time.RFC3339)
		c.UpdatedAt = updatedAt.Format(time.RFC3339)
		convs = append(convs, c)
	}
	return convs, nil
}

func (s *PostgresStore) GetConversation(id string) (*storage.Conversation, []storage.ChatMessage, error) {
	ctx, cancel := queryCtx()
	defer cancel()

	var c storage.Conversation
	var createdAt, updatedAt time.Time
	err := s.pool.QueryRow(ctx,
		"SELECT id, title, provider, model, created_at, updated_at FROM conversations WHERE id = $1", id).
		Scan(&c.ID, &c.Title, &c.Provider, &c.Model, &createdAt, &updatedAt)
	if err != nil {
		return nil, nil, err
	}
	c.CreatedAt = createdAt.Format(time.RFC3339)
	c.UpdatedAt = updatedAt.Format(time.RFC3339)

	rows, err := s.pool.Query(ctx,
		"SELECT id, conversation_id, role, content, packet_context_json, created_at FROM chat_messages WHERE conversation_id = $1 ORDER BY created_at ASC", id)
	if err != nil {
		return &c, nil, err
	}
	defer rows.Close()

	var messages []storage.ChatMessage
	for rows.Next() {
		var m storage.ChatMessage
		var ctxJSON []byte
		var msgCreatedAt time.Time
		if err := rows.Scan(&m.ID, &m.ConversationID, &m.Role, &m.Content, &ctxJSON, &msgCreatedAt); err != nil {
			return &c, nil, err
		}
		m.CreatedAt = msgCreatedAt.Format(time.RFC3339)
		if len(ctxJSON) > 0 {
			m.PacketContextJSON = string(ctxJSON)
		}
		messages = append(messages, m)
	}

	return &c, messages, nil
}

func (s *PostgresStore) AddChatMessage(msg storage.ChatMessage) error {
	ctx, cancel := writeCtx()
	defer cancel()

	now := time.Now()
	if msg.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, msg.CreatedAt); err == nil {
			now = t
		}
	}

	var ctxJSON []byte
	if msg.PacketContextJSON != "" {
		ctxJSON = []byte(msg.PacketContextJSON)
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO chat_messages (conversation_id, role, content, packet_context_json, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`, msg.ConversationID, msg.Role, msg.Content, ctxJSON, now)
	if err != nil {
		return err
	}

	_, err = s.pool.Exec(ctx,
		"UPDATE conversations SET updated_at = $1 WHERE id = $2", now, msg.ConversationID)
	return err
}

func (s *PostgresStore) DeleteConversation(id string) error {
	ctx, cancel := writeCtx()
	defer cancel()
	_, err := s.pool.Exec(ctx, "DELETE FROM conversations WHERE id = $1", id)
	return err
}
