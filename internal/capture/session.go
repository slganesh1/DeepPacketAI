package capture

import (
	"sync"
	"sync/atomic"
	"time"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/pipeline"
)

const (
	// defaultMaxBuffered is the maximum number of packets held in the in-memory
	// buffer before incoming packets are dropped on the floor. The periodic flush
	// drains this every 10 seconds so under normal conditions it never fills.
	// At 100k pps this gives ~10s of headroom. Raise via CaptureConfig if needed.
	defaultMaxBuffered = 2_000_000
)

// Session represents a live capture session.
type Session struct {
	ID            string    `json:"id"`
	InterfaceName string    `json:"interface_name"`
	BPFFilter     string    `json:"bpf_filter"`
	Status        string    `json:"status"` // running, stopped, analyzing, completed
	StartedAt     time.Time `json:"started_at"`
	StoppedAt     time.Time `json:"stopped_at,omitempty"`
	PacketCount   uint64    `json:"packet_count"` // updated via atomic
	ByteCount     uint64    `json:"byte_count"`   // updated via atomic
	JobID         int64     `json:"job_id,omitempty"`

	maxBuffered int // max len(packets) before incoming packets are dropped

	mu         sync.Mutex
	statusMu   sync.Mutex
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
		maxBuffered:   defaultMaxBuffered,
	}
}

// Stop signals the session to stop.
func (s *Session) Stop() {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
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
// Using atomics here eliminates the hot mutex contention at high pps.
func (s *Session) IncrementCounters(bytes int) {
	atomic.AddUint64(&s.PacketCount, 1)
	atomic.AddUint64(&s.ByteCount, uint64(bytes))
}

// BufferPacket adds a packet to the in-memory buffer for later persistence.
// Drops the packet (without blocking) when the buffer cap is reached, so the
// capture goroutine is never stalled waiting for the DB flush goroutine.
func (s *Session) BufferPacket(pkt *domain.Packet) {
	s.mu.Lock()
	if len(s.packets) < s.maxBuffered {
		s.packets = append(s.packets, pkt)
	}
	s.mu.Unlock()
}

// GetPackets returns a copy of all buffered packets without clearing the buffer.
func (s *Session) GetPackets() []*domain.Packet {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]*domain.Packet, len(s.packets))
	copy(result, s.packets)
	return result
}

// DrainPackets returns all buffered packets and clears the internal buffer.
// Used by the periodic flush goroutine so long sessions do not accumulate
// unbounded RAM — each flush interval claims and stores the current batch.
func (s *Session) DrainPackets() []*domain.Packet {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.packets) == 0 {
		return nil
	}
	out := s.packets
	s.packets = make([]*domain.Packet, 0, 256)
	return out
}

// SetStatus sets the session status.
func (s *Session) SetStatus(status string) {
	s.statusMu.Lock()
	s.Status = status
	s.statusMu.Unlock()
}

// FlushAllWorkers collects flows from all workers' decoders.
func (s *Session) FlushAllWorkers() []domain.Flow {
	var all []domain.Flow
	for _, w := range s.workers {
		all = append(all, w.Flush()...)
	}
	return all
}
