package main

import (
	"context"
	"flag"
	"log"
	"os"

	"DeepPacketAI/internal/ai"
	"DeepPacketAI/internal/capture"
	"DeepPacketAI/internal/execution"
	"DeepPacketAI/internal/storage"
	_ "DeepPacketAI/internal/storage/postgres"
	"DeepPacketAI/internal/web"
	"DeepPacketAI/internal/ws"
)

func main() {
	// ---- Flags ----
	pcapFile := flag.String("pcap", "", "PCAP file to analyze")
	server := flag.Bool("server", false, "Start API server on :8080")
	flag.Parse()

	if *pcapFile == "" && !*server {
		log.Fatal("Usage: deeppacketai -pcap <file.pcap> [-server]")
	}

	// ---- Init database ----
	cfg := storage.Config{
		Backend: "sqlite",
		DSN:     "deeppacketai.db",
	}
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		cfg.Backend = "postgres"
		cfg.DSN = dsn
	}

	db, err := storage.New(cfg)
	if err != nil {
		log.Fatalf("failed to init database: %v", err)
	}
	defer db.Close()

	// ---- Initialize AI provider registry ----
	aiRegistry := ai.NewProviderRegistry()

	// ---- Run PCAP analysis if requested ----
	if *pcapFile != "" {
		exec := execution.NewExecutor(db).WithAIRegistry(aiRegistry)

		if err := exec.RunPCAP(*pcapFile); err != nil {
			log.Fatalf("pcap analysis failed: %v", err)
		}

		log.Println("PCAP analysis completed successfully")
	}

	// ---- Start API server if requested ----
	if *server {
		log.Println("Starting API server on :8080")

		// Initialize WebSocket hub
		hub := ws.NewHub()
		go hub.Run()

		// Initialize capture engine (creates per-session decoders internally)
		captureEngine := capture.NewEngine(hub, db)

		// AI registry already initialized above
		providers := aiRegistry.List()
		if len(providers) > 0 {
			log.Printf("AI providers available: %v (active: %s)", providers, aiRegistry.ActiveName())
		} else {
			log.Println("No AI providers configured. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GEMINI_API_KEY for AI chat.")
		}

		app := web.NewServer(web.Config{
			Address:       ":8080",
			DB:            db,
			Hub:           hub,
			CaptureEngine: captureEngine,
			AIRegistry:    aiRegistry,
		})

		// BLOCKS forever (this keeps port 8080 alive)
		if err := app.Start(context.Background()); err != nil {
			log.Fatalf("server failed: %v", err)
		}
	}
}
