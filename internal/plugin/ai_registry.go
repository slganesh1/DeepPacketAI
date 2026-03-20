package plugin

import (
	"fmt"
	"sync"
	"time"

	"DeepPacketAI/internal/ai"
)

// AIPlugin wraps an ai.LLMProvider with plugin metadata.
type AIPlugin struct {
	Manifest
	Enabled  bool
	Provider ai.LLMProvider
	LoadedAt time.Time
}

// AIRegistry is a thread-safe registry of AI provider plugins.
type AIRegistry struct {
	mu     sync.RWMutex
	items  map[string]*AIPlugin
	order  []string
	active string // name of the currently active provider
}

// NewAIRegistry creates an empty AIRegistry.
func NewAIRegistry() *AIRegistry {
	return &AIRegistry{items: make(map[string]*AIPlugin)}
}

// Register adds or replaces an AIPlugin.
// The first registered enabled provider becomes the active one automatically.
func (r *AIRegistry) Register(p *AIPlugin) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p.LoadedAt = time.Now()
	if _, exists := r.items[p.Name]; !exists {
		r.order = append(r.order, p.Name)
	}
	r.items[p.Name] = p
	// Auto-select first enabled provider
	if p.Enabled && r.active == "" {
		r.active = p.Name
	}
}

// Activate sets the named provider as active.
func (r *AIRegistry) Activate(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.items[name]
	if !ok {
		return fmt.Errorf("AI plugin %q not found", name)
	}
	if !p.Enabled {
		return fmt.Errorf("AI plugin %q is disabled", name)
	}
	r.active = name
	return nil
}

// Enable marks the named plugin as enabled.
// If no provider is currently active, this one becomes active.
func (r *AIRegistry) Enable(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.items[name]
	if !ok {
		return fmt.Errorf("AI plugin %q not found", name)
	}
	p.Enabled = true
	if r.active == "" {
		r.active = name
	}
	return nil
}

// Disable marks the named plugin as disabled.
// If this was the active provider, another enabled provider is auto-selected.
func (r *AIRegistry) Disable(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.items[name]
	if !ok {
		return fmt.Errorf("AI plugin %q not found", name)
	}
	p.Enabled = false
	if r.active == name {
		r.active = ""
		for _, n := range r.order {
			if r.items[n].Enabled && n != name {
				r.active = n
				break
			}
		}
	}
	return nil
}

// Active returns the currently active LLMProvider, if any.
func (r *AIRegistry) Active() (ai.LLMProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.active == "" {
		return nil, false
	}
	p, ok := r.items[r.active]
	if !ok || !p.Enabled {
		return nil, false
	}
	return p.Provider, true
}

// ActiveName returns the name of the currently active provider.
func (r *AIRegistry) ActiveName() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.active
}

// List returns a snapshot of all registered plugin statuses.
func (r *AIRegistry) List() []Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Status, 0, len(r.order))
	for _, name := range r.order {
		p := r.items[name]
		result = append(result, Status{
			Manifest: p.Manifest,
			Enabled:  p.Enabled,
			Active:   name == r.active,
			LoadedAt: p.LoadedAt,
		})
	}
	return result
}

// Count returns the total number of registered plugins.
func (r *AIRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.items)
}
