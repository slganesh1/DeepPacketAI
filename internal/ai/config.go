package ai

import (
	"os"
	"sync"
)

// ProviderRegistry manages available LLM providers.
type ProviderRegistry struct {
	providers map[string]LLMProvider
	active    string
	mu        sync.RWMutex
}

// NewProviderRegistry creates a registry and auto-detects available providers.
func NewProviderRegistry() *ProviderRegistry {
	r := &ProviderRegistry{
		providers: make(map[string]LLMProvider),
	}

	// Auto-detect available providers from environment variables
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		r.Register(NewClaudeProvider(key, ""))
		if r.active == "" {
			r.active = "claude"
		}
	}

	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		r.Register(NewOpenAIProvider(key, ""))
		if r.active == "" {
			r.active = "openai"
		}
	}

	if key := os.Getenv("GEMINI_API_KEY"); key != "" {
		r.Register(NewGeminiProvider(key, ""))
		if r.active == "" {
			r.active = "gemini"
		}
	}

	return r
}

// Register adds a provider to the registry.
func (r *ProviderRegistry) Register(p LLMProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[p.Name()] = p
}

// Get returns a provider by name.
func (r *ProviderRegistry) Get(name string) (LLMProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	return p, ok
}

// Active returns the currently active provider.
func (r *ProviderRegistry) Active() (LLMProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.active == "" {
		return nil, false
	}
	p, ok := r.providers[r.active]
	return p, ok
}

// SetActive sets the active provider.
func (r *ProviderRegistry) SetActive(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.providers[name]; ok {
		r.active = name
		return true
	}
	return false
}

// List returns the names of all registered providers.
func (r *ProviderRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var names []string
	for name := range r.providers {
		names = append(names, name)
	}
	return names
}

// ActiveName returns the name of the active provider.
func (r *ProviderRegistry) ActiveName() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.active
}
