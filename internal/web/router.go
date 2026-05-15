package web

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"DeepPacketAI/internal/ai"
	"DeepPacketAI/internal/alerting"
	"DeepPacketAI/internal/capture"
	"DeepPacketAI/internal/geoip"
	"DeepPacketAI/internal/metrics"
	"DeepPacketAI/internal/storage"
	"DeepPacketAI/internal/stream"
	"DeepPacketAI/internal/web/handlers"
	"DeepPacketAI/internal/ws"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func NewRouter(db storage.Store, hub *ws.Hub, captureEngine *capture.Engine, aiRegistry *ai.ProviderRegistry, dispatcher *alerting.Dispatcher, geoEnricher *geoip.Enricher, agentRegistry *stream.AgentRegistry, uiAssets fs.FS, uploadsDir string) http.Handler {
	r := chi.NewRouter()

	// ---- CORS ----
	allowedOrigins := []string{
		"http://localhost:5173", // local dev (vite)
		"http://localhost:8080", // embedded UI (installer mode)
	}
	// DPAI_ALLOWED_ORIGINS is a comma-separated list of additional origins
	// (e.g. "https://app.example.com,https://64.227.168.88").
	if extra := os.Getenv("DPAI_ALLOWED_ORIGINS"); extra != "" {
		for _, o := range strings.Split(extra, ",") {
			if o = strings.TrimSpace(o); o != "" {
				allowedOrigins = append(allowedOrigins, o)
			}
		}
	}
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Propagate the same allowed-origins list into the WebSocket upgrader so
	// it rejects cross-origin upgrade attempts just like CORS does for REST.
	hub.SetAllowedOrigins(allowedOrigins)

	// ---- Middlewares ----
	r.Use(middleware.RequestID) // injects X-Request-Id header into every request
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(prometheusMiddleware)

	// ---- Create Handlers ----
	jobHandler := handlers.NewJobHandler(db)
	jobEntityHandler := handlers.NewJobEntityHandler(db)
	entityHandler := handlers.NewEntityHandler(db)
	entityDetailHandler := handlers.NewEntityDetailHandler(db)
	entityEventHandler := handlers.NewEntityEventHandler(db)
	entityMetricsHandler := handlers.NewEntityMetricsHandler(db)
	uploadHandler := handlers.NewUploadHandler(db, uploadsDir)
	captureHandler := handlers.NewCaptureHandler(captureEngine)
	statsHandler := handlers.NewStatsHandler(db)
	alertHandler := handlers.NewAlertHandler(db)
	packetHandler := handlers.NewPacketHandler(db)
	chatHandler := handlers.NewChatHandler(db, aiRegistry)
	callFlowHandler := handlers.NewCallFlowHandler(db)
	analyticsHandler := handlers.NewAnalyticsHandler(db)
	telecomHandler := handlers.NewTelecomHandler(db)
	aiAnalysisHandler := handlers.NewAIAnalysisHandler(db, aiRegistry)
	alertTargetHandler := handlers.NewAlertTargetHandler(db, dispatcher)
	detectionRulesHandler := handlers.NewDetectionRulesHandler(db)
	geoHandler := handlers.NewGeoHandler(db, geoEnricher)
	pluginHandler := handlers.NewPluginHandler(aiRegistry)
	reportHandler := handlers.NewReportHandler(db)
	authHandler := handlers.NewAuthHandler(db)
	// Wire the package-level RequireAuth shim so all middleware references
	// the same handler instance (and therefore the same DB session store).
	handlers.RequireAuth = authHandler.RequireAuth
	agentHandler := handlers.NewAgentHandler(agentRegistry)

	// ---- Health / readiness (unauthenticated — for load balancers and k8s) ----
	startTime := time.Now()
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":   "ok",
			"uptime_s": int(time.Since(startTime).Seconds()),
		})
	})
	r.Get("/ready", func(w http.ResponseWriter, r *http.Request) {
		// Probe the DB: if it can list jobs it is reachable.
		if _, err := db.ListJobs(1, ""); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"status": "unavailable", "error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	})

	// ---- Prometheus metrics scrape endpoint ----
	r.Get("/metrics", promhttp.Handler().ServeHTTP)

	// ---- WebSocket (requires valid session cookie) ----
	r.With(handlers.RequireAuth).Get("/ws", hub.HandleWS)

	// ---- API v1 ----
	r.Route("/api/v1", func(r chi.Router) {
		// Auth (public — no session required)
		r.Post("/auth/login", authHandler.Login)
		r.Post("/auth/logout", authHandler.Logout)
		r.Get("/auth/me", authHandler.Me)

		// Everything below requires a valid session
		r.Group(func(r chi.Router) {
			r.Use(handlers.RequireAuth)

		// Jobs
		r.Get("/jobs", jobHandler.ListJobs)
		r.Get("/jobs/{id}", jobHandler.GetJob)
		r.Get("/jobs/{id}/context", jobHandler.GetJobContext)
		r.Get("/jobs/{id}/summary", jobHandler.GetJobSummary)
		r.Get("/jobs/{id}/flows", jobHandler.ListJobFlows)
		r.Get("/jobs/{id}/events", jobHandler.ListJobEvents)
		r.Get("/jobs/{id}/entities", jobEntityHandler.ListJobEntities)
		r.Get("/jobs/{id}/report/rfc2544", reportHandler.GetRFC2544Report)
		r.Get("/jobs/{id}/report/y1564", reportHandler.GetY1564Report)
		r.Get("/jobs/{id}/cdr", reportHandler.GetCDRExport)

		// Upload & Reprocess
		r.Post("/jobs/upload", uploadHandler.UploadPCAP)
		r.Post("/jobs/{id}/reprocess", uploadHandler.ReprocessJob)
		r.Delete("/jobs/packets", jobHandler.PurgePackets)
		r.Delete("/jobs/{id}", jobHandler.DeleteJob)

		// Entities
		r.Get("/entities", entityHandler.ListEntities)
		r.Get("/entities/{id}", entityDetailHandler.GetEntity)
		r.Get("/entities/{id}/events", entityEventHandler.ListEntityEvents)
		r.Get("/entities/{id}/metrics", entityMetricsHandler.GetEntityMetrics)

		// Agents (connected capture nodes in central mode)
		r.Get("/agents", agentHandler.ListAgents)
		r.Put("/agents/{id}/filter", agentHandler.UpdateFilter)

		// Capture
		r.Get("/capture/interfaces", captureHandler.ListInterfaces)
		r.Post("/capture/start", captureHandler.StartCapture)
		r.Post("/capture/stop", captureHandler.StopCapture)
		r.Get("/capture/sessions", captureHandler.ListSessions)

		// Stats
		r.Get("/stats/summary", statsHandler.Summary)
		r.Get("/stats/bandwidth", statsHandler.Bandwidth)
		r.Get("/stats/protocols", statsHandler.Protocols)
		r.Get("/stats/top-talkers", statsHandler.TopTalkers)

		// Alerts
		r.Get("/alerts", alertHandler.ListAlerts)

		// Alert targets (notification rules)
		r.Get("/alert-targets", alertTargetHandler.List)
		r.Post("/alert-targets", alertTargetHandler.Create)
		r.Put("/alert-targets/{id}", alertTargetHandler.Update)
		r.Delete("/alert-targets/{id}", alertTargetHandler.Delete)
		r.Post("/alert-targets/{id}/test", alertTargetHandler.Test)

		// User-defined detection rules
		r.Get("/detection-rules", detectionRulesHandler.List)
		r.Post("/detection-rules", detectionRulesHandler.Create)
		r.Put("/detection-rules/{id}", detectionRulesHandler.Update)
		r.Delete("/detection-rules/{id}", detectionRulesHandler.Delete)

		// GeoIP / IP reputation
		r.Get("/geo/ip/{ip}", geoHandler.LookupIP)
		r.Get("/geo/summary", geoHandler.Summary)
		r.Post("/geo/enrich", geoHandler.EnrichIPs)

		// Packets
		r.Get("/packets", packetHandler.ListPackets)
		r.Get("/packets/{id}", packetHandler.GetPacket)
		r.Get("/packets/{id}/hex", packetHandler.GetPacketHex)
		r.Get("/packets/{id}/layers", packetHandler.GetPacketLayers)

		// Call Flow
		r.Get("/entities/{id}/callflow", callFlowHandler.GetCallFlow)

		// Analytics
		r.Get("/analytics/kpis", analyticsHandler.GetKPIs)
		r.Get("/analytics/report", analyticsHandler.GetReport)

		// Telecom Sessions (5G/4G call trace)
		r.Get("/telecom-sessions", telecomHandler.ListTelecomSessions)
		r.Get("/telecom-sessions/{sessionID}", telecomHandler.GetTelecomSession)

		// AI Analysis
		r.Post("/ai/analyze/session/{sessionID}", aiAnalysisHandler.AnalyzeSession)

		// Plugins
		r.Get("/plugins", pluginHandler.GetAll)
		r.Get("/plugins/protocol", pluginHandler.GetProtocol)
		r.Get("/plugins/detection", pluginHandler.GetDetection)
		r.Get("/plugins/ai", pluginHandler.GetAI)
		r.Post("/plugins/protocol/{name}/enable", pluginHandler.EnableProtocol)
		r.Post("/plugins/protocol/{name}/disable", pluginHandler.DisableProtocol)
		r.Post("/plugins/detection/{name}/enable", pluginHandler.EnableDetection)
		r.Post("/plugins/detection/{name}/disable", pluginHandler.DisableDetection)
		r.Post("/plugins/ai/{name}/activate", pluginHandler.ActivateAI)

		// Chat
		r.Post("/chat/conversations", chatHandler.CreateConversation)
		r.Get("/chat/conversations", chatHandler.ListConversations)
		r.Get("/chat/conversations/{id}", chatHandler.GetConversation)
		r.Post("/chat/conversations/{id}/messages", chatHandler.SendMessage)
		r.Delete("/chat/conversations/{id}", chatHandler.DeleteConversation)
		r.Get("/chat/providers", chatHandler.ListProviders)
		r.Put("/chat/settings", chatHandler.SetSettings)
		}) // end RequireAuth group
	}) // end /api/v1

	// ---- Embedded React SPA (installer / standalone mode) ----
	// Only mounted when UIAssets is provided (i.e. built with go:embed).
	if uiAssets != nil {
		distFS, err := fs.Sub(uiAssets, "dist")
		if err == nil {
			fileServer := http.FileServer(http.FS(distFS))
			r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
				// Serve the file if it exists; otherwise return index.html
				// so React Router handles client-side navigation.
				filePath := strings.TrimPrefix(r.URL.Path, "/")
				if _, statErr := fs.Stat(distFS, filePath); statErr != nil {
					r.URL.Path = "/"
				}
				fileServer.ServeHTTP(w, r)
			})
		}
	}

	return r
}

// prometheusMiddleware records HTTP request duration and status for every
// request, using the route pattern as the path label to avoid high cardinality.
func prometheusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip the /metrics scrape endpoint itself to avoid self-observation noise
		if r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		// Use chi's route pattern if available (e.g. "/api/v1/jobs/{id}")
		// to keep the path label low-cardinality.
		path := chi.RouteContext(r.Context()).RoutePattern()
		if path == "" {
			path = r.URL.Path
		}

		metrics.HTTPRequestDuration.WithLabelValues(
			r.Method,
			path,
			strconv.Itoa(ww.Status()),
		).Observe(time.Since(start).Seconds())
	})
}
