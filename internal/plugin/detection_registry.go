package plugin

import (
	"fmt"
	"sync"
	"time"

	"DeepPacketAI/internal/detection"
)

// DetectionPlugin wraps a detection.Rule with plugin metadata.
type DetectionPlugin struct {
	Manifest
	Enabled  bool
	Rule     detection.Rule
	LoadedAt time.Time
}

// DetectionRegistry is a thread-safe registry of detection rule plugins.
type DetectionRegistry struct {
	mu    sync.RWMutex
	items map[string]*DetectionPlugin
	order []string
}

// NewDetectionRegistry creates an empty DetectionRegistry.
func NewDetectionRegistry() *DetectionRegistry {
	return &DetectionRegistry{items: make(map[string]*DetectionPlugin)}
}

// Register adds or replaces a DetectionPlugin.
func (r *DetectionRegistry) Register(p *DetectionPlugin) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p.LoadedAt = time.Now()
	if _, exists := r.items[p.Name]; !exists {
		r.order = append(r.order, p.Name)
	}
	r.items[p.Name] = p
}

// Enable marks the named plugin as enabled.
func (r *DetectionRegistry) Enable(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.items[name]
	if !ok {
		return fmt.Errorf("detection plugin %q not found", name)
	}
	p.Enabled = true
	return nil
}

// Disable marks the named plugin as disabled.
func (r *DetectionRegistry) Disable(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.items[name]
	if !ok {
		return fmt.Errorf("detection plugin %q not found", name)
	}
	p.Enabled = false
	return nil
}

// ActiveRules returns only the rules from enabled plugins, in registration order.
func (r *DetectionRegistry) ActiveRules() []detection.Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var rules []detection.Rule
	for _, name := range r.order {
		p := r.items[name]
		if p.Enabled {
			rules = append(rules, p.Rule)
		}
	}
	return rules
}

// List returns a snapshot of all registered plugin statuses.
func (r *DetectionRegistry) List() []Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Status, 0, len(r.order))
	for _, name := range r.order {
		p := r.items[name]
		result = append(result, Status{
			Manifest: p.Manifest,
			Enabled:  p.Enabled,
			LoadedAt: p.LoadedAt,
		})
	}
	return result
}

// Count returns the total number of registered plugins.
func (r *DetectionRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.items)
}
