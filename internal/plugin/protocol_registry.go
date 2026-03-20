package plugin

import (
	"fmt"
	"sync"
	"time"

	"DeepPacketAI/internal/pipeline"
	"DeepPacketAI/internal/protocols"
)

// ProtocolPlugin holds a decoder factory and its metadata.
type ProtocolPlugin struct {
	Manifest
	Enabled    bool
	NewDecoder func() protocols.Decoder // called once per pipeline worker
	LoadedAt   time.Time
}

// ProtocolRegistry is a thread-safe registry of protocol decoder plugins.
type ProtocolRegistry struct {
	mu    sync.RWMutex
	items map[string]*ProtocolPlugin
	order []string // insertion order for deterministic pipeline construction
}

// NewProtocolRegistry creates an empty ProtocolRegistry.
func NewProtocolRegistry() *ProtocolRegistry {
	return &ProtocolRegistry{items: make(map[string]*ProtocolPlugin)}
}

// Register adds or replaces a ProtocolPlugin.
func (r *ProtocolRegistry) Register(p *ProtocolPlugin) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p.LoadedAt = time.Now()
	if _, exists := r.items[p.Name]; !exists {
		r.order = append(r.order, p.Name)
	}
	r.items[p.Name] = p
}

// Enable marks the named plugin as enabled.
func (r *ProtocolRegistry) Enable(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.items[name]
	if !ok {
		return fmt.Errorf("protocol plugin %q not found", name)
	}
	p.Enabled = true
	return nil
}

// Disable marks the named plugin as disabled.
func (r *ProtocolRegistry) Disable(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.items[name]
	if !ok {
		return fmt.Errorf("protocol plugin %q not found", name)
	}
	p.Enabled = false
	return nil
}

// BuildDecoderFactory returns a pipeline.DecoderFactory that creates one fresh
// decoder instance per enabled plugin, in registration order, for each worker.
func (r *ProtocolRegistry) BuildDecoderFactory() pipeline.DecoderFactory {
	return func() []protocols.Decoder {
		r.mu.RLock()
		defer r.mu.RUnlock()
		var decoders []protocols.Decoder
		for _, name := range r.order {
			p := r.items[name]
			if p.Enabled && p.NewDecoder != nil {
				decoders = append(decoders, p.NewDecoder())
			}
		}
		return decoders
	}
}

// List returns a snapshot of all registered plugin statuses.
func (r *ProtocolRegistry) List() []Status {
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
func (r *ProtocolRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.items)
}
