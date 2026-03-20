package capture

import (
	"sync"
	"time"

	"DeepPacketAI/internal/metrics"
)

// Stats tracks real-time capture statistics.
type Stats struct {
	mu             sync.RWMutex
	TotalPackets   uint64            `json:"total_packets"`
	TotalBytes     uint64            `json:"total_bytes"`
	PacketsPerSec  uint64            `json:"packets_per_sec"`
	BytesPerSec    uint64            `json:"bytes_per_sec"`
	ProtocolCounts map[string]uint64 `json:"protocol_counts"`

	// internal counters for rate calculation
	lastPackets uint64
	lastBytes   uint64
	lastTick    time.Time
}

// NewStats creates a new Stats tracker.
func NewStats() *Stats {
	return &Stats{
		ProtocolCounts: make(map[string]uint64),
		lastTick:       time.Now(),
	}
}

// Record records a packet for statistics.
func (s *Stats) Record(protocol string, size int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TotalPackets++
	s.TotalBytes += uint64(size)
	s.ProtocolCounts[protocol]++
}

// Tick calculates per-second rates. Call every second.
func (s *Stats) Tick() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(s.lastTick).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}

	s.PacketsPerSec = uint64(float64(s.TotalPackets-s.lastPackets) / elapsed)
	s.BytesPerSec = uint64(float64(s.TotalBytes-s.lastBytes) / elapsed)
	s.lastPackets = s.TotalPackets
	s.lastBytes = s.TotalBytes
	s.lastTick = now

	// Publish live gauges to Prometheus
	metrics.PacketsPerSecond.WithLabelValues("live").Set(float64(s.PacketsPerSec))
	metrics.BytesPerSecond.WithLabelValues("live").Set(float64(s.BytesPerSec))
}

// Snapshot returns a copy of current stats.
func (s *Stats) Snapshot() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	counts := make(map[string]uint64, len(s.ProtocolCounts))
	for k, v := range s.ProtocolCounts {
		counts[k] = v
	}

	return Stats{
		TotalPackets:   s.TotalPackets,
		TotalBytes:     s.TotalBytes,
		PacketsPerSec:  s.PacketsPerSec,
		BytesPerSec:    s.BytesPerSec,
		ProtocolCounts: counts,
	}
}

// Reset clears all counters.
func (s *Stats) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TotalPackets = 0
	s.TotalBytes = 0
	s.PacketsPerSec = 0
	s.BytesPerSec = 0
	s.ProtocolCounts = make(map[string]uint64)
	s.lastPackets = 0
	s.lastBytes = 0
	s.lastTick = time.Now()
}
