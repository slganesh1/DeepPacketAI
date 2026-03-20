package plugin

import "time"

// Category identifies the class of plugin.
type Category string

const (
	CategoryProtocol  Category = "protocol"
	CategoryDetection Category = "detection"
	CategoryAI        Category = "ai"
)

// Manifest describes a plugin's identity and capabilities.
type Manifest struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Author      string   `json:"author"`
	Description string   `json:"description"`
	Category    Category `json:"category"`
	Tags        []string `json:"tags,omitempty"`

	// Protocol-specific
	Protocols []string `json:"protocols,omitempty"` // which protocols it decodes
	Ports     []int    `json:"ports,omitempty"`     // well-known ports

	// Detection-specific
	Severity string `json:"severity,omitempty"` // default alert severity

	// AI-specific
	CostTier     string   `json:"cost_tier,omitempty"`    // "free", "paid"
	MaxTokens    int      `json:"max_tokens,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"` // "chat","stream","analysis"
}

// Status is the runtime view of a plugin (manifest + live state).
type Status struct {
	Manifest
	Enabled  bool      `json:"enabled"`
	Active   bool      `json:"active,omitempty"` // for AI: currently active provider
	LoadedAt time.Time `json:"loaded_at"`
	Error    string    `json:"error,omitempty"`
}

// AllPlugins is the combined response for GET /api/v1/plugins.
type AllPlugins struct {
	Protocol  []Status `json:"protocol"`
	Detection []Status `json:"detection"`
	AI        []Status `json:"ai"`
}
