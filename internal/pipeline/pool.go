package pipeline

import (
	"runtime"
	"sync"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/protocols"
)

// DecoderFactory creates a fresh set of decoders for one worker.
type DecoderFactory func() []protocols.Decoder

// Pool manages a set of DecodeWorkers with flow-affinity routing.
type Pool struct {
	workers   []*DecodeWorker
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// NewPool creates N decode workers, each with its own decoder set.
// If n <= 0, defaults to min(NumCPU, 8). If bufSize <= 0, defaults to 4096.
// TCP reassembly is enabled by default.
func NewPool(n int, bufSize int, factory DecoderFactory) *Pool {
	return NewPoolWithOptions(n, bufSize, factory, true)
}

// NewPoolWithOptions creates N decode workers with optional TCP reassembly.
func NewPoolWithOptions(n int, bufSize int, factory DecoderFactory, enableReassembly bool) *Pool {
	if n <= 0 {
		n = runtime.NumCPU()
		if n > 8 {
			n = 8
		}
	}
	if bufSize <= 0 {
		bufSize = 4096
	}

	p := &Pool{
		workers: make([]*DecodeWorker, n),
	}

	for i := 0; i < n; i++ {
		decoders := factory()
		p.wg.Add(1)
		if enableReassembly {
			p.workers[i] = NewDecodeWorkerWithAssembler(i, decoders, bufSize, &p.wg)
		} else {
			p.workers[i] = NewDecodeWorker(i, decoders, bufSize, &p.wg)
		}
	}

	return p
}

// Start launches all workers as goroutines.
func (p *Pool) Start() {
	for _, w := range p.workers {
		go w.Run()
	}
}

// Submit routes a packet to the appropriate worker by flow hash.
func (p *Pool) Submit(pkt *domain.Packet) {
	idx := Route(pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort, len(p.workers))
	p.workers[idx].Send(pkt)
}

// SetOnPacket sets a per-packet callback on all workers.
func (p *Pool) SetOnPacket(fn func(pkt *domain.Packet)) {
	for _, w := range p.workers {
		w.onPacket = fn
	}
}

// Close closes all worker channels. Safe to call multiple times.
func (p *Pool) Close() {
	p.closeOnce.Do(func() {
		for _, w := range p.workers {
			w.Close()
		}
	})
}

// Wait blocks until all workers have finished processing.
func (p *Pool) Wait() {
	p.wg.Wait()
}

// CloseAndWait closes all worker channels and waits for them to finish.
func (p *Pool) CloseAndWait() {
	p.Close()
	p.Wait()
}

// Flush collects flows from all workers' decoders.
func (p *Pool) Flush() []domain.Flow {
	var all []domain.Flow
	for _, w := range p.workers {
		all = append(all, w.Flush()...)
	}
	return all
}

// WorkerCount returns the number of workers in the pool.
func (p *Pool) WorkerCount() int {
	return len(p.workers)
}
