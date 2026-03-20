package web

import (
	"context"
	"log"
	"net/http"

	"DeepPacketAI/internal/ai"
	"DeepPacketAI/internal/capture"
	"DeepPacketAI/internal/storage"
	"DeepPacketAI/internal/ws"
)

// Config holds server configuration
type Config struct {
	Address       string
	DB            storage.Store
	Hub           *ws.Hub
	CaptureEngine *capture.Engine
	AIRegistry    *ai.ProviderRegistry
}

// Server wraps the HTTP server
type Server struct {
	addr          string
	db            storage.Store
	hub           *ws.Hub
	captureEngine *capture.Engine
	aiRegistry    *ai.ProviderRegistry
}

// NewServer creates a new API server
func NewServer(cfg Config) *Server {
	return &Server{
		addr:          cfg.Address,
		db:            cfg.DB,
		hub:           cfg.Hub,
		captureEngine: cfg.CaptureEngine,
		aiRegistry:    cfg.AIRegistry,
	}
}

// Start starts the HTTP server (BLOCKING)
func (s *Server) Start(ctx context.Context) error {
	router := NewRouter(s.db, s.hub, s.captureEngine, s.aiRegistry)

	log.Printf("API server listening on %s", s.addr)

	return http.ListenAndServe(s.addr, router)
}
