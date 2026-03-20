package capture

import (
	"sync"
	"time"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/pipeline"
)

// Session represents a live capture session.
type Session struct {
	ID            string    `json:"id"`
	InterfaceName string    `json:"interface_name"`
	BPFFilter     string    `json:"bpf_filter"`
	Status        string    `json:"status"` // running, stopped, analyzing, completed
	StartedAt     time.Time `json:"started_at"`
	StoppedAt     time.Time `json:"stopped_at,omitempty"`
	PacketCount   uint64    `json:"packet_count"`
	ByteCount     uint64    `json:"byte_count"`
	JobID         int64     `json:"job_id,omitempty"`

	mu         sync.Mutex
	stopCh     chan struct{}
	workers    []*CaptureWorker // per-session capture workers (each owns its decoders)
	decodePool *pipeline.Pool   // decode pool for single-source captures (nil when using per-worker decoders)
	packets    []*domain.Packet // buffered for persistence
}

// NewSession creates a new capture session.
func NewSession(id, iface, filter string) *Session {
	return &Session{
		ID:            id,
		InterfaceName: iface,
		BPFFilter:     filter,
		Status:        "running",
		StartedAt:     time.Now(),
		stopCh:        make(chan struct{}),
	}
}

// Stop signals the session to stop.
func (s *Session) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Status == "running" {
		s.Status = "stopped"
		s.StoppedAt = time.Now()
		close(s.stopCh)
	}
}

// StopCh returns the channel that is closed when session stops.
func (s *Session) StopCh() <-chan struct{} {
	return s.stopCh
}

// IncrementCounters atomically increments packet and byte counts.
func (s *Session) IncrementCounters(bytes int) {
	s.mu.Lock()
	s.PacketCount++
	s.ByteCount += uint64(bytes)
	s.mu.Unlock()
}

// BufferPacket adds a packet to the in-memory buffer for later persistence.
func (s *Session) BufferPacket(pkt *domain.Packet) {
	s.mu.Lock()
	s.packets = append(s.packets, pkt)
	s.mu.Unlock()
}

// GetPackets returns buffered packets.
func (s *Session) GetPackets() []*domain.Packet {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]*domain.Packet, len(s.packets))
	copy(result, s.packets)
	return result
}

// SetStatus sets the session status.
func (s *Session) SetStatus(status string) {
	s.mu.Lock()
	s.Status = status
	s.mu.Unlock()
}

// FlushAllWorkers collects flows from all workers' decoders.
func (s *Session) FlushAllWorkers() []domain.Flow {
	var all []domain.Flow
	for _, w := range s.workers {
		all = append(all, w.Flush()...)
	}
	return all
}
