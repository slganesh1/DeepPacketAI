package execution

import (
	"sync"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/metrics"
	"DeepPacketAI/internal/pcap"
	"DeepPacketAI/internal/pipeline"
)

// Pipeline processes PCAP files using a pool of decode workers with flow-affinity routing.
type Pipeline struct {
	factory pipeline.DecoderFactory
}

// NewPipeline creates a pipeline that uses the given factory to create
// per-worker decoder sets for parallel processing.
func NewPipeline(factory pipeline.DecoderFactory) *Pipeline {
	return &Pipeline{factory: factory}
}

// Run reads a PCAP file and decodes packets in parallel using a worker pool.
// Flow-affinity routing ensures all packets of the same flow go to the same worker.
// The third return value is the raw packet count read from the file (before any filtering).
func (p *Pipeline) Run(pcapPath string) ([]domain.Flow, []*domain.Packet, int64, error) {
	pool := pipeline.NewPool(0, 4096, p.factory)

	var mu sync.Mutex
	var packets []*domain.Packet
	pool.SetOnPacket(func(pkt *domain.Packet) {
		mu.Lock()
		packets = append(packets, pkt)
		mu.Unlock()
	})

	pool.Start()

	var pcapCount int64
	err := pcap.ReadPCAP(pcapPath, func(pkt *domain.Packet) error {
		pool.Submit(pkt)
		pcapCount++
		metrics.PacketsTotal.WithLabelValues("pcap", pkt.Protocol).Inc()
		metrics.BytesTotal.WithLabelValues("pcap").Add(float64(pkt.Length))
		metrics.PCAPPacketsProcessed.Inc()
		return nil
	})

	pool.CloseAndWait()

	flows := pool.Flush()

	// Count flows by protocol
	for _, f := range flows {
		metrics.FlowsTotal.WithLabelValues("pcap", string(f.Type)).Inc()
	}

	return flows, packets, pcapCount, err
}
