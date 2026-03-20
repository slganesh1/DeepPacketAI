package plugin

import "os"

// Global registries — initialized once at startup, used everywhere.
var (
	Protocols = NewProtocolRegistry()
	Detection = NewDetectionRegistry()
	AI        = NewAIRegistry()
)

// RegisterProtocol is a convenience helper for use in init() functions.
func RegisterProtocol(p *ProtocolPlugin) {
	Protocols.Register(p)
}

// RegisterDetection is a convenience helper for use in init() functions.
func RegisterDetection(p *DetectionPlugin) {
	Detection.Register(p)
}

// RegisterAI is a convenience helper for use in init() functions.
func RegisterAI(p *AIPlugin) {
	AI.Register(p)
}

// HasEnv returns true if the named environment variable is set and non-empty.
func HasEnv(key string) bool {
	return os.Getenv(key) != ""
}
