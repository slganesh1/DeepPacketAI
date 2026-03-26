package web

import (
	"context"
	"io/fs"
	"log"
	"net/http"

	"DeepPacketAI/internal/ai"
	"DeepPacketAI/internal/alerting"
	"DeepPacketAI/internal/capture"
	"DeepPacketAI/internal/geoip"
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
	Dispatcher    *alerting.Dispatcher
	GeoEnricher   *geoip.Enricher
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
		uiAssets:      cfg.UIAssets,
		uploadsDir:    cfg.UploadsDir,
	}
}

// Start starts the HTTP server (BLOCKING)
func (s *Server) Start(ctx context.Context) error {
	router := NewRouter(s.db, s.hub, s.captureEngine, s.aiRegistry, s.dispatcher, s.geoEnricher, s.uiAssets, s.uploadsDir)

	log.Printf("API server listening on %s", s.addr)

	return http.ListenAndServe(s.addr, router)
}
