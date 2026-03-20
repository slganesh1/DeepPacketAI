package plugin

import (
	"os"

	"DeepPacketAI/internal/ai"
	"DeepPacketAI/internal/detection"
	"DeepPacketAI/internal/flowengine"
	"DeepPacketAI/internal/protocols"
	"DeepPacketAI/internal/protocols/diameter"
	"DeepPacketAI/internal/protocols/dns"
	"DeepPacketAI/internal/protocols/gtp"
	"DeepPacketAI/internal/protocols/http1"
	"DeepPacketAI/internal/protocols/ngap"
	"DeepPacketAI/internal/protocols/pfcp"
	"DeepPacketAI/internal/protocols/rtp"
	"DeepPacketAI/internal/protocols/s1ap"
	"DeepPacketAI/internal/protocols/sip"
	"DeepPacketAI/internal/protocols/tls"
	"DeepPacketAI/internal/protocols/websocket"
)

func init() {
	registerProtocolPlugins()
	registerDetectionPlugins()
	registerAIPlugins()
}

// ─── Protocol plugins ────────────────────────────────────────────────────────

func registerProtocolPlugins() {
	RegisterProtocol(&ProtocolPlugin{
		Manifest: Manifest{
			Name:        "sip",
			Version:     "1.0.0",
			Author:      "builtin",
			Description: "SIP (Session Initiation Protocol) decoder — IMS/VoIP call signalling",
			Category:    CategoryProtocol,
			Tags:        []string{"voip", "ims", "sip", "telecom"},
			Protocols:   []string{"SIP"},
			Ports:       []int{5060, 5061},
		},
		Enabled: true,
		NewDecoder: func() protocols.Decoder {
			return sip.NewDecoder()
		},
	})

	RegisterProtocol(&ProtocolPlugin{
		Manifest: Manifest{
			Name:        "rtp",
			Version:     "1.0.0",
			Author:      "builtin",
			Description: "RTP (Real-time Transport Protocol) decoder — voice/video media streams",
			Category:    CategoryProtocol,
			Tags:        []string{"voip", "media", "rtp", "telecom"},
			Protocols:   []string{"RTP"},
			Ports:       []int{},
		},
		Enabled: true,
		NewDecoder: func() protocols.Decoder {
			return rtp.NewDecoder()
		},
	})

	RegisterProtocol(&ProtocolPlugin{
		Manifest: Manifest{
			Name:        "dns",
			Version:     "1.0.0",
			Author:      "builtin",
			Description: "DNS (Domain Name System) decoder — query/response analysis",
			Category:    CategoryProtocol,
			Tags:        []string{"dns", "resolution", "network"},
			Protocols:   []string{"DNS"},
			Ports:       []int{53},
		},
		Enabled: true,
		NewDecoder: func() protocols.Decoder {
			return dns.NewDecoder()
		},
	})

	RegisterProtocol(&ProtocolPlugin{
		Manifest: Manifest{
			Name:        "http1",
			Version:     "1.0.0",
			Author:      "builtin",
			Description: "HTTP/1.x decoder — request/response header and body analysis",
			Category:    CategoryProtocol,
			Tags:        []string{"http", "web", "api"},
			Protocols:   []string{"HTTP"},
			Ports:       []int{80, 8080},
		},
		Enabled: true,
		NewDecoder: func() protocols.Decoder {
			return http1.NewDecoder()
		},
	})

	RegisterProtocol(&ProtocolPlugin{
		Manifest: Manifest{
			Name:        "tls",
			Version:     "1.0.0",
			Author:      "builtin",
			Description: "TLS/SSL decoder — handshake analysis, cipher suite and certificate inspection",
			Category:    CategoryProtocol,
			Tags:        []string{"tls", "ssl", "security", "encryption"},
			Protocols:   []string{"TLS"},
			Ports:       []int{443, 8443},
		},
		Enabled: true,
		NewDecoder: func() protocols.Decoder {
			return tls.NewDecoder()
		},
	})

	RegisterProtocol(&ProtocolPlugin{
		Manifest: Manifest{
			Name:        "diameter",
			Version:     "1.0.0",
			Author:      "builtin",
			Description: "Diameter protocol decoder — 4G/5G authentication, policy, and accounting",
			Category:    CategoryProtocol,
			Tags:        []string{"diameter", "4g", "ims", "aaa", "telecom"},
			Protocols:   []string{"Diameter"},
			Ports:       []int{3868},
		},
		Enabled: true,
		NewDecoder: func() protocols.Decoder {
			return diameter.NewDecoder()
		},
	})

	RegisterProtocol(&ProtocolPlugin{
		Manifest: Manifest{
			Name:        "gtp",
			Version:     "1.0.0",
			Author:      "builtin",
			Description: "GTP (GPRS Tunnelling Protocol) decoder — 4G/5G user and control plane tunnels",
			Category:    CategoryProtocol,
			Tags:        []string{"gtp", "4g", "5g", "tunneling", "telecom"},
			Protocols:   []string{"GTP"},
			Ports:       []int{2123, 2152},
		},
		Enabled: true,
		NewDecoder: func() protocols.Decoder {
			return gtp.NewDecoder()
		},
	})

	RegisterProtocol(&ProtocolPlugin{
		Manifest: Manifest{
			Name:        "pfcp",
			Version:     "1.0.0",
			Author:      "builtin",
			Description: "PFCP (Packet Forwarding Control Protocol) decoder — 5G UPF session management",
			Category:    CategoryProtocol,
			Tags:        []string{"pfcp", "5g", "upf", "telecom"},
			Protocols:   []string{"PFCP"},
			Ports:       []int{8805},
		},
		Enabled: true,
		NewDecoder: func() protocols.Decoder {
			return pfcp.NewDecoder()
		},
	})

	RegisterProtocol(&ProtocolPlugin{
		Manifest: Manifest{
			Name:        "s1ap",
			Version:     "1.0.0",
			Author:      "builtin",
			Description: "S1AP decoder — 4G LTE eNB-to-MME interface signalling",
			Category:    CategoryProtocol,
			Tags:        []string{"s1ap", "4g", "lte", "enb", "mme", "telecom"},
			Protocols:   []string{"S1AP"},
			Ports:       []int{36412},
		},
		Enabled: true,
		NewDecoder: func() protocols.Decoder {
			return s1ap.NewDecoder()
		},
	})

	RegisterProtocol(&ProtocolPlugin{
		Manifest: Manifest{
			Name:        "ngap",
			Version:     "1.0.0",
			Author:      "builtin",
			Description: "NGAP decoder — 5G NR gNB-to-AMF N2 interface signalling",
			Category:    CategoryProtocol,
			Tags:        []string{"ngap", "5g", "gnb", "amf", "telecom"},
			Protocols:   []string{"NGAP"},
			Ports:       []int{38412},
		},
		Enabled: true,
		NewDecoder: func() protocols.Decoder {
			return ngap.NewDecoder()
		},
	})

	RegisterProtocol(&ProtocolPlugin{
		Manifest: Manifest{
			Name:        "websocket",
			Version:     "1.0.0",
			Author:      "builtin",
			Description: "WebSocket decoder — full-duplex browser/server communication over HTTP upgrade",
			Category:    CategoryProtocol,
			Tags:        []string{"websocket", "web", "realtime"},
			Protocols:   []string{"WebSocket"},
			Ports:       []int{80, 443},
		},
		Enabled: true,
		NewDecoder: func() protocols.Decoder {
			return websocket.NewDecoder()
		},
	})

	// flowengine tracker must be LAST — it catches all unmatched flows
	RegisterProtocol(&ProtocolPlugin{
		Manifest: Manifest{
			Name:        "flowengine",
			Version:     "1.0.0",
			Author:      "builtin",
			Description: "Generic 5-tuple flow tracker — TCP/UDP metrics, RTT, retransmissions (catch-all)",
			Category:    CategoryProtocol,
			Tags:        []string{"flow", "tcp", "udp", "metrics"},
			Protocols:   []string{"ALL"},
			Ports:       []int{},
		},
		Enabled: true,
		NewDecoder: func() protocols.Decoder {
			return flowengine.NewTracker()
		},
	})
}

// ─── Detection rule plugins ──────────────────────────────────────────────────

func registerDetectionPlugins() {
	allRules := detection.BuiltinRules()

	// Metadata for each rule keyed by rule name
	type ruleMeta struct {
		tags     []string
		severity string
		version  string
	}
	meta := map[string]ruleMeta{
		"SIP Error Responses":            {[]string{"sip", "voip", "errors"}, "warning", "1.0.0"},
		"RTP Packet Loss":                {[]string{"rtp", "media", "quality"}, "warning", "1.0.0"},
		"RTP High Jitter":                {[]string{"rtp", "media", "quality"}, "warning", "1.0.0"},
		"DNS Errors":                     {[]string{"dns", "resolution", "errors"}, "warning", "1.0.0"},
		"Diameter Non-Success":           {[]string{"diameter", "aaa", "errors"}, "error", "1.0.0"},
		"GTP Failures":                   {[]string{"gtp", "tunneling", "errors"}, "error", "1.0.0"},
		"PFCP Failures":                  {[]string{"pfcp", "upf", "errors"}, "error", "1.0.0"},
		"One-Way Audio":                  {[]string{"rtp", "voip", "quality"}, "warning", "1.0.0"},
		"Packet Volume Spike":            {[]string{"volume", "anomaly"}, "warning", "1.0.0"},
		"Oversized Packets":              {[]string{"volume", "anomaly"}, "warning", "1.0.0"},
		"Packet Flood":                   {[]string{"flood", "dos", "security"}, "error", "1.0.0"},
		"Unusual Port":                   {[]string{"port", "anomaly", "security"}, "warning", "1.0.0"},
		"Protocol Mismatch":              {[]string{"protocol", "anomaly", "security"}, "error", "1.0.0"},
		"Source Fan-Out (Scanning)":      {[]string{"scanning", "security", "anomaly"}, "warning", "1.0.0"},
		"Traffic Concentration":          {[]string{"traffic", "anomaly"}, "warning", "1.0.0"},
		"Repeated Failures":              {[]string{"errors", "anomaly"}, "warning", "1.0.0"},
		"SIP REGISTER Flood":             {[]string{"sip", "flood", "security"}, "warning", "1.0.0"},
		"DNS Query Flood":                {[]string{"dns", "flood", "security"}, "warning", "1.0.0"},
		"Long Duration Flow":             {[]string{"duration", "anomaly"}, "warning", "1.0.0"},
		"Traffic Burst":                  {[]string{"burst", "anomaly"}, "warning", "1.0.0"},
		"RTP Jitter Variance":            {[]string{"rtp", "jitter", "quality"}, "warning", "1.0.0"},
		"DNS Slow Response":              {[]string{"dns", "latency", "quality"}, "warning", "1.0.0"},
		"SIP Slow Setup":                 {[]string{"sip", "latency", "quality"}, "warning", "1.0.0"},
		"QoS Degradation":               {[]string{"rtp", "qos", "quality"}, "warning", "1.0.0"},
		"SIP Registration Brute Force":   {[]string{"sip", "bruteforce", "security"}, "critical", "1.0.0"},
		"DNS Tunneling":                  {[]string{"dns", "tunneling", "security"}, "critical", "1.0.0"},
		"VoIP Call Drop":                 {[]string{"sip", "voip", "reliability"}, "warning", "1.0.0"},
		"TLS Downgrade":                  {[]string{"tls", "security", "crypto"}, "error", "1.0.0"},
		"SIP OPTIONS Scanning":           {[]string{"sip", "scanning", "security"}, "warning", "1.0.0"},
		"SIP INVITE Flood / Toll Fraud":  {[]string{"sip", "flood", "fraud", "security"}, "critical", "1.0.0"},
		"SIP Call Hijack":                {[]string{"sip", "hijack", "security"}, "critical", "1.0.0"},
		"DNS DGA / C2 Domain":            {[]string{"dns", "dga", "c2", "security"}, "critical", "1.0.0"},
		"DNS Fast-Flux":                  {[]string{"dns", "fastflux", "security"}, "error", "1.0.0"},
		"TLS Weak Cipher":                {[]string{"tls", "cipher", "security"}, "error", "1.0.0"},
		"TLS JA3 Fingerprint":            {[]string{"tls", "ja3", "fingerprint", "security"}, "warning", "1.0.0"},
		"TLS Self-Signed Certificate":    {[]string{"tls", "certificate", "security"}, "warning", "1.0.0"},
	}

	for _, rule := range allRules {
		m, ok := meta[rule.Name]
		if !ok {
			m = ruleMeta{[]string{"detection"}, "warning", "1.0.0"}
		}
		RegisterDetection(&DetectionPlugin{
			Manifest: Manifest{
				Name:        rule.Name,
				Version:     m.version,
				Author:      "builtin",
				Description: "Built-in detection rule: " + rule.Name,
				Category:    CategoryDetection,
				Tags:        m.tags,
				Severity:    m.severity,
				Protocols:   []string{rule.Protocol},
			},
			Enabled: true,
			Rule:    rule,
		})
	}
}

// ─── AI provider plugins ─────────────────────────────────────────────────────

func registerAIPlugins() {
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		provider := ai.NewClaudeProvider(key, "")
		RegisterAI(&AIPlugin{
			Manifest: Manifest{
				Name:         "claude",
				Version:      "1.0.0",
				Author:       "builtin",
				Description:  "Anthropic Claude — state-of-the-art LLM for traffic analysis and chat",
				Category:     CategoryAI,
				Tags:         []string{"anthropic", "claude", "llm"},
				CostTier:     "paid",
				MaxTokens:    200000,
				Capabilities: []string{"chat", "stream", "analysis"},
			},
			Enabled:  true,
			Provider: provider,
		})
	}

	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		provider := ai.NewOpenAIProvider(key, "")
		RegisterAI(&AIPlugin{
			Manifest: Manifest{
				Name:         "openai",
				Version:      "1.0.0",
				Author:       "builtin",
				Description:  "OpenAI GPT — versatile language model for traffic analysis and chat",
				Category:     CategoryAI,
				Tags:         []string{"openai", "gpt", "llm"},
				CostTier:     "paid",
				MaxTokens:    128000,
				Capabilities: []string{"chat", "stream", "analysis"},
			},
			Enabled:  true,
			Provider: provider,
		})
	}

	if key := os.Getenv("GEMINI_API_KEY"); key != "" {
		provider := ai.NewGeminiProvider(key, "")
		RegisterAI(&AIPlugin{
			Manifest: Manifest{
				Name:         "gemini",
				Version:      "1.0.0",
				Author:       "builtin",
				Description:  "Google Gemini — multimodal LLM for traffic analysis and chat",
				Category:     CategoryAI,
				Tags:         []string{"google", "gemini", "llm"},
				CostTier:     "paid",
				MaxTokens:    1000000,
				Capabilities: []string{"chat", "stream", "analysis"},
			},
			Enabled:  true,
			Provider: provider,
		})
	}
}
