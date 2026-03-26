package main

import (
	"context"
	"flag"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"DeepPacketAI/internal/ai"
	"DeepPacketAI/internal/alerting"
	"DeepPacketAI/internal/capture"
	"DeepPacketAI/internal/execution"
	"DeepPacketAI/internal/geoip"
	"DeepPacketAI/internal/storage"
	_ "DeepPacketAI/internal/storage/postgres"
	"DeepPacketAI/internal/web"
	"DeepPacketAI/internal/ws"
	uidist "DeepPacketAI/deeppacketai-ui"
)

func main() {
	// ---- Load .env file (before anything else so flags/config can use the vars) ----
	loadDotEnv()

	// ---- Flags ----
	pcapFile   := flag.String("pcap", "", "PCAP file to analyze")
	serverOnly := flag.Bool("server", false, "Start API server (default when no -pcap flag)")
	noBrowser  := flag.Bool("no-browser", false, "Do not open browser on startup")

	// Distributed mode flags
	mode           := flag.String("mode", "standalone", "Operation mode: standalone | agent | central")
	centralAddr    := flag.String("central", "", "Central node address for agent mode (host:port, e.g. 192.168.1.10:9090)")
	agentID        := flag.String("agent-id", "", "Agent identifier (default: hostname-iface)")
	iface          := flag.String("iface", "", "Network interface for agent mode capture")
	bpfFilter      := flag.String("filter", "", "BPF filter expression for agent mode (e.g. 'port 5060')")
	streamPort     := flag.String("stream-port", ":9090", "TCP port for central to receive agent streams")
	listIfaces     := flag.Bool("list-interfaces", false, "List available network interfaces and exit")

	flag.Parse()

	// ---- List interfaces and exit (useful for finding Windows device names) ----
	if *listIfaces {
		listInterfaces()
		return
	}

	// ---- Agent mode: capture-only, no UI, no DB ----
	if *mode == "agent" {
		runAgent(*iface, *bpfFilter, *centralAddr, *agentID)
		return
	}

	// Default: start server if no PCAP file provided, or alongside PCAP analysis
	startServer := *serverOnly || *pcapFile == "" || *mode == "central"

	// ---- App data directory (%APPDATA%\DeepPacketAI on Windows) ----
	appDataDir := appDataPath("DeepPacketAI")
	if err := os.MkdirAll(appDataDir, 0755); err != nil {
		log.Fatalf("failed to create app data directory: %v", err)
	}

	// ---- Redirect logs to file when running without a console (windowsgui build) ----
	setupLogging(appDataDir)

	// ---- Npcap check (Windows live capture requires Npcap/WinPcap) ----
	if runtime.GOOS == "windows" && !isNpcapInstalled() {
		log.Println("WARNING: Npcap not found. Live packet capture will be unavailable.")
		log.Println("         Download Npcap from https://npcap.com and install it.")
	}

	// ---- Init database ----
	dbPath := filepath.Join(appDataDir, "deeppacketai.db")
	cfg := storage.Config{
		Backend: "sqlite",
		DSN:     dbPath,
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

	// ---- Initialize alert dispatcher ----
	alertDispatcher := alerting.New(db)

	// ---- Initialize GeoIP enricher ----
	geoEnricher := geoip.New(db)

	// ---- Run PCAP analysis if requested ----
	if *pcapFile != "" {
		exec := execution.NewExecutor(db).WithAIRegistry(aiRegistry).WithDispatcher(alertDispatcher).WithGeoEnricher(geoEnricher)
		if err := exec.RunPCAP(*pcapFile); err != nil {
			log.Fatalf("pcap analysis failed: %v", err)
		}
		log.Println("PCAP analysis completed successfully")
	}

	// ---- Start API server ----
	if startServer {
		log.Println("Starting DeepPacketAI server on :8080")

		// Initialize WebSocket hub
		hub := ws.NewHub()
		go hub.Run()

		// Initialize capture engine
		captureEngine := capture.NewEngine(hub, db)
		captureEngine.SetAIRegistry(aiRegistry)
		captureEngine.SetDispatcher(alertDispatcher)
		captureEngine.SetGeoEnricher(geoEnricher)

		// Central mode: start TCP receiver for agent streams
		if *mode == "central" {
			startCentralReceiver(*streamPort, captureEngine)
		}

		providers := aiRegistry.List()
		if len(providers) > 0 {
			log.Printf("AI providers available: %v (active: %s)", providers, aiRegistry.ActiveName())
		} else {
			log.Println("No AI providers configured. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GEMINI_API_KEY.")
		}

		// Resolve embedded UI
		var uiFS fs.FS = uidist.FS

		// Open browser after a short delay to let the server bind
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
			UIAssets:      uiFS,
			UploadsDir:    uploadsDir,
		})

		// BLOCKS forever
		if err := app.Start(context.Background()); err != nil {
			log.Fatalf("server failed: %v", err)
		}
	}
}

// appDataPath returns the OS-appropriate user data directory for the app.
// Windows: %APPDATA%\<name>   macOS/Linux: ~/.local/share/<name>
func appDataPath(name string) string {
	if dir := os.Getenv("APPDATA"); dir != "" {
		return filepath.Join(dir, name)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return name // fallback: relative directory
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support", name)
	}
	return filepath.Join(home, ".local", "share", name)
}

// isNpcapInstalled checks for Npcap or WinPcap DLLs on Windows.
func isNpcapInstalled() bool {
	candidates := []string{
		`C:\Windows\System32\Npcap\wpcap.dll`,
		`C:\Windows\System32\wpcap.dll`,
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// openBrowser opens the given URL in the system default browser.
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
