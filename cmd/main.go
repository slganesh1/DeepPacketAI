package main

import (
	"context"
	"flag"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"DeepPacketAI/internal/ai"
	"DeepPacketAI/internal/alerting"
	"DeepPacketAI/internal/capture"
	"DeepPacketAI/internal/execution"
	"DeepPacketAI/internal/geoip"
	"DeepPacketAI/internal/storage"
	_ "DeepPacketAI/internal/storage/postgres"
	"DeepPacketAI/internal/stream"
	"DeepPacketAI/internal/web"
	"DeepPacketAI/internal/ws"
	uidist "DeepPacketAI/deeppacketai-ui"
)

func main() {
	// ---- Load .env file ----
	loadDotEnv()

	// ---- Flags ----
	pcapFile   := flag.String("pcap", "", "PCAP file to analyze")
	serverOnly := flag.Bool("server", false, "Start API server (default when no -pcap flag)")
	noBrowser  := flag.Bool("no-browser", false, "Do not open browser on startup")

	// Operation mode
	mode        := flag.String("mode", "standalone", "Operation mode: standalone | agent | central")
	streamPort  := flag.String("stream-port", ":9090", "TCP port for central to receive agent streams")
	listIfaces  := flag.Bool("list-interfaces", false, "List available network interfaces and exit")
	useXDP      := flag.Bool("xdp", false, "Use AF_XDP + eBPF capture backend (Linux 5.10+, faster; requires CAP_BPF)")

	// Agent capture flags
	iface     := flag.String("iface", "", "Network interface(s) for agent mode — comma-separated for multi-interface (e.g. eth0,eth1)")
	bpfFilter := flag.String("filter", "", "BPF filter expression (e.g. 'port 5060 or port 443')")
	centralAddr := flag.String("central", "", "Central node address for agent mode (host:port)")
	agentID   := flag.String("agent-id", "", "Agent identifier (default: hostname-iface)")
	maxMbps   := flag.Float64("max-mbps", 0, "Agent outbound bandwidth cap in Mbit/s (0 = unlimited)")

	// Stream security flags
	streamToken   := flag.String("stream-token", "", "Pre-shared token for agent authentication (env: STREAM_TOKEN)")
	streamTLS     := flag.Bool("tls", false, "Agent: enable TLS for the agent→central stream")
	streamTLSSkip := flag.Bool("tls-skip-verify", false, "Agent: skip TLS server certificate verification (use with self-signed certs)")
	streamTLSCA   := flag.String("tls-ca", "", "Agent: path to CA certificate PEM file for verifying central")
	streamTLSCert := flag.String("stream-tls-cert", "", "Central: TLS certificate PEM file")
	streamTLSKey  := flag.String("stream-tls-key", "", "Central: TLS private key PEM file")

	// Service installer flags
	installAgent   := flag.Bool("install-agent", false, "Install deeppacketai-agent as a system service and exit")
	uninstallAgent := flag.Bool("uninstall-agent", false, "Uninstall the deeppacketai-agent system service and exit")

	flag.Parse()

	// ---- Resolve token (flag takes priority; fall back to env) ----
	token := *streamToken
	if token == "" {
		token = os.Getenv("STREAM_TOKEN")
	}

	// ---- List interfaces ----
	if *listIfaces {
		listInterfaces()
		return
	}

	// ---- Service installer ----
	if *installAgent {
		if err := installAgentService(); err != nil {
			log.Fatalf("install-agent: %v", err)
		}
		return
	}
	if *uninstallAgent {
		if err := uninstallAgentService(); err != nil {
			log.Fatalf("uninstall-agent: %v", err)
		}
		return
	}

	// ---- Agent mode ----
	if *mode == "agent" {
		runAgent(AgentFlags{
			Ifaces:      *iface,
			BPFFilter:   *bpfFilter,
			CentralAddr: *centralAddr,
			AgentID:     *agentID,
			Token:       token,
			UseTLS:      *streamTLS,
			TLSSkipVfy:  *streamTLSSkip,
			TLSCA:       *streamTLSCA,
			MaxMbps:     *maxMbps,
		})
		return
	}

	startServer := *serverOnly || *pcapFile == "" || *mode == "central"

	// ---- App data directory ----
	appDataDir := appDataPath("DeepPacketAI")
	if err := os.MkdirAll(appDataDir, 0755); err != nil {
		log.Fatalf("failed to create app data directory: %v", err)
	}

	setupLogging(appDataDir)

	if runtime.GOOS == "windows" && !isNpcapInstalled() {
		log.Println("WARNING: Npcap not found. Live packet capture will be unavailable.")
		log.Println("         Download Npcap from https://npcap.com and install it.")
	}

	// ---- Init database ----
	dbPath := filepath.Join(appDataDir, "deeppacketai.db")
	cfg := storage.Config{Backend: "sqlite", DSN: dbPath}
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		cfg.Backend = "postgres"
		cfg.DSN = dsn
	}
	db, err := storage.New(cfg)
	if err != nil {
		log.Fatalf("failed to init database: %v", err)
	}
	defer db.Close()
	db.ResetStaleJobs()

	aiRegistry := ai.NewProviderRegistry()
	alertDispatcher := alerting.New(db)
	geoEnricher := geoip.New(db)

	if *pcapFile != "" {
		exec := execution.NewExecutor(db).WithAIRegistry(aiRegistry).WithDispatcher(alertDispatcher).WithGeoEnricher(geoEnricher)
		if err := exec.RunPCAP(*pcapFile); err != nil {
			log.Fatalf("pcap analysis failed: %v", err)
		}
		log.Println("PCAP analysis completed successfully")
	}

	if startServer {
		log.Println("Starting DeepPacketAI server on :8080")

		hub := ws.NewHub()
		go hub.Run()

		capCfg := capture.DefaultCaptureConfig()
		capCfg.UseXDP = *useXDP
		captureEngine := capture.NewEngineWithConfig(hub, db, capCfg)
		captureEngine.SetAIRegistry(aiRegistry)
		captureEngine.SetDispatcher(alertDispatcher)
		captureEngine.SetGeoEnricher(geoEnricher)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Graceful shutdown on SIGTERM / SIGINT.
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		go func() {
			sig := <-sigCh
			log.Printf("received signal %s — shutting down gracefully", sig)
			// 1. Stop all active capture sessions (triggers analyzeAndStore goroutines).
			captureEngine.StopAll()
			// 2. Wait for all in-flight flush goroutines to finish writing to DB.
			log.Println("waiting for in-flight capture jobs to finish...")
			captureEngine.WaitIdle()
			log.Println("all capture jobs done")
			// 3. Cancel context → triggers HTTP server graceful shutdown.
			cancel()
		}()

		// Central mode: start TCP receiver for agent streams
		var agentRegistry *stream.AgentRegistry
		if *mode == "central" {
			centralCfg := stream.CentralConfig{
				Token:   token,
				TLSCert: *streamTLSCert,
				TLSKey:  *streamTLSKey,
			}
			agentRegistry = startCentralReceiver(ctx, *streamPort, captureEngine, centralCfg)
		}

		providers := aiRegistry.List()
		if len(providers) > 0 {
			log.Printf("AI providers available: %v (active: %s)", providers, aiRegistry.ActiveName())
		} else {
			log.Println("No AI providers configured. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GEMINI_API_KEY.")
		}

		var uiFS fs.FS = uidist.FS

		if !*noBrowser {
			go func() {
				time.Sleep(1500 * time.Millisecond)
				openBrowser("http://localhost:8080")
			}()
		}

		uploadsDir := filepath.Join(appDataDir, "uploads")

		app := web.NewServer(web.Config{
			Address:       ":8080",
			DB:            db,
			Hub:           hub,
			CaptureEngine: captureEngine,
			AIRegistry:    aiRegistry,
			Dispatcher:    alertDispatcher,
			GeoEnricher:   geoEnricher,
			AgentRegistry: agentRegistry,
			UIAssets:      uiFS,
			UploadsDir:    uploadsDir,
		})

		if err := app.Start(ctx); err != nil {
			log.Fatalf("server failed: %v", err)
		}
	}
}

func appDataPath(name string) string {
	if dir := os.Getenv("APPDATA"); dir != "" {
		return filepath.Join(dir, name)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return name
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support", name)
	}
	return filepath.Join(home, ".local", "share", name)
}

func isNpcapInstalled() bool {
	for _, p := range []string{
		`C:\Windows\System32\Npcap\wpcap.dll`,
		`C:\Windows\System32\wpcap.dll`,
	} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("could not open browser: %v", err)
	}
}
