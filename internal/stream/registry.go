package stream

import (
	"context"
	"sync"
	"time"
)

// AgentStatus represents a currently-connected capture agent.
type AgentStatus struct {
	AgentID        string    `json:"agent_id"`
	Hostname       string    `json:"hostname"`
	Interface      string    `json:"interface"`
	RemoteAddr     string    `json:"remote_addr"`
	SessionID      string    `json:"session_id"`
	ConnectedAt    time.Time `json:"connected_at"`
	LastBatchAt    time.Time `json:"last_batch_at,omitempty"`
	Stale          bool      `json:"stale"`
	PacketsRx      uint64    `json:"packets_rx"`
	BytesRx        uint64    `json:"bytes_rx"`
	BatchCount     uint64    `json:"batch_count"`
	DroppedPkts    uint64    `json:"dropped_pkts"`
	CurrentFilter  string    `json:"current_filter,omitempty"`
}

// AgentRegistry tracks all currently-connected capture agents in memory.
// It is safe for concurrent use.
type AgentRegistry struct {
	mu         sync.RWMutex
	agents     map[string]*AgentStatus
	filterChans map[string]chan string // per-agent channel for BPF filter updates
}

// NewAgentRegistry creates an empty AgentRegistry.
func NewAgentRegistry() *AgentRegistry {
	return &AgentRegistry{
		agents:      make(map[string]*AgentStatus),
		filterChans: make(map[string]chan string),
	}
}

func (r *AgentRegistry) register(s AgentStatus) {
	r.mu.Lock()
	r.agents[s.AgentID] = &s
	r.filterChans[s.AgentID] = make(chan string, 4)
	r.mu.Unlock()
}

func (r *AgentRegistry) update(agentID string, packets int, bytes int, dropped int) {
	r.mu.Lock()
	if e, ok := r.agents[agentID]; ok {
		e.PacketsRx += uint64(packets)
		e.BytesRx += uint64(bytes)
		e.BatchCount++
		e.DroppedPkts += uint64(dropped)
		e.LastBatchAt = time.Now()
		e.Stale = false // receiving data means the agent is alive
	}
	r.mu.Unlock()
}

func (r *AgentRegistry) unregister(agentID string) {
	r.mu.Lock()
	delete(r.agents, agentID)
	if ch, ok := r.filterChans[agentID]; ok {
		close(ch)
		delete(r.filterChans, agentID)
	}
	r.mu.Unlock()
}

// FilterCh returns the channel central uses to push BPF filter updates to a
// connected agent handler goroutine. Returns nil if the agent is not found.
func (r *AgentRegistry) FilterCh(agentID string) <-chan string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.filterChans[agentID]
}

// SendFilter queues a new BPF filter for the named agent.
// Returns false if the agent is not connected or the channel is full.
func (r *AgentRegistry) SendFilter(agentID, filter string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	ch, ok := r.filterChans[agentID]
	if !ok {
		return false
	}
	// Update displayed current filter immediately.
	if e, ok2 := r.agents[agentID]; ok2 {
		e.CurrentFilter = filter
	}
	select {
	case ch <- filter:
		return true
	default:
		return false // channel full — agent will pick up the next update
	}
}

// List returns a snapshot of all currently-connected agents.
func (r *AgentRegistry) List() []AgentStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]AgentStatus, 0, len(r.agents))
	for _, v := range r.agents {
		out = append(out, *v)
	}
	return out
}

// StartStalenessChecker runs in the background and marks agents whose
// LastBatchAt is older than StaleTimeout. Call from a goroutine.
func (r *AgentRegistry) StartStalenessChecker(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			r.mu.Lock()
			for _, e := range r.agents {
				if !e.LastBatchAt.IsZero() && now.Sub(e.LastBatchAt) > StaleTimeout {
					e.Stale = true
				}
			}
			r.mu.Unlock()
		}
	}
}
