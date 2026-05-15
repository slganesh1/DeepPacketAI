package web

import (
	"context"
	"io/fs"
	"log"
	"net/http"
	"time"

	"DeepPacketAI/internal/ai"
	"DeepPacketAI/internal/alerting"
	"DeepPacketAI/internal/capture"
	"DeepPacketAI/internal/geoip"
	"DeepPacketAI/internal/storage"
	"DeepPacketAI/internal/stream"
	"DeepPacketAI/internal/ws"
)

// Config holds server configuration
type Config struct {
	Address       string
	DB            storage.Store
	Hub           *ws.Hub
	CaptureEngine *capture.Engine
	AIRegistry    *ai.ProviderRegistry
	Dispatcher    *alerting.Dispatcher
	GeoEnricher   *geoip.Enricher
	// AgentRegistry is the live registry of connected capture agents.
	// Nil in standalone mode — the /agents endpoint returns an empty list.
	AgentRegistry *stream.AgentRegistry
	// UIAssets is the embedded React production build. If nil, no UI is served.
	UIAssets fs.FS
	// UploadsDir is the directory where uploaded PCAP files are stored.
	UploadsDir string
}

// Server wraps the HTTP server
type Server struct {
	addr          string
	db            storage.Store
	hub           *ws.Hub
	captureEngine *capture.Engine
	aiRegistry    *ai.ProviderRegistry
	dispatcher    *alerting.Dispatcher
	geoEnricher   *geoip.Enricher
	agentRegistry *stream.AgentRegistry
	uiAssets      fs.FS
	uploadsDir    string
}

// NewServer creates a new API server
func NewServer(cfg Config) *Server {
	return &Server{
		addr:          cfg.Address,
		db:            cfg.DB,
		hub:           cfg.Hub,
		captureEngine: cfg.CaptureEngine,
		aiRegistry:    cfg.AIRegistry,
		dispatcher:    cfg.Dispatcher,
		geoEnricher:   cfg.GeoEnricher,
		agentRegistry: cfg.AgentRegistry,
		uiAssets:      cfg.UIAssets,
		uploadsDir:    cfg.UploadsDir,
	}
}

// Start starts the HTTP server. It blocks until ctx is cancelled, then performs
// a graceful shutdown (allowing in-flight requests up to 30 s to complete).
func (s *Server) Start(ctx context.Context) error {
	router := NewRouter(s.db, s.hub, s.captureEngine, s.aiRegistry, s.dispatcher, s.geoEnricher, s.agentRegistry, s.uiAssets, s.uploadsDir)

	srv := &http.Server{
		Addr:         s.addr,
		Handler:      router,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Shutdown when context is cancelled.
	go func() {
		<-ctx.Done()
		log.Println("HTTP server: context cancelled — shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			log.Printf("HTTP server: shutdown error: %v", err)
		}
	}()

	log.Printf("API server listening on %s", s.addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
