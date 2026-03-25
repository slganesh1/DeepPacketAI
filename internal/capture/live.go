package capture

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	"DeepPacketAI/internal/analysis"
	"DeepPacketAI/internal/correlation"
	"DeepPacketAI/internal/detection"
	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/flowengine"
	"DeepPacketAI/internal/pipeline"
	"DeepPacketAI/internal/protocols"
	"DeepPacketAI/internal/protocols/diameter"
	"DeepPacketAI/internal/protocols/dns"
	"DeepPacketAI/internal/protocols/gtp"
	"DeepPacketAI/internal/protocols/http1"
	"DeepPacketAI/internal/protocols/ngap"
	"DeepPacketAI/internal/protocols/pfcp"
	"DeepPacketAI/internal/protocols/rtp"
	"DeepPacketAI/internal/protocols/s1ap"
	"DeepPacketAI/internal/protocols/sip"
	"DeepPacketAI/internal/protocols/tls"
	"DeepPacketAI/internal/protocols/websocket"
	"DeepPacketAI/internal/storage"
	"DeepPacketAI/internal/ws"

	"github.com/google/gopacket/pcap"
	"github.com/google/uuid"
)

// Engine manages live packet capture sessions.
type Engine struct {
	hub      *ws.Hub
	db       storage.Store
	sessions map[string]*Session
	mu       sync.RWMutex
	cfg      CaptureConfig
	factory  CaptureSourceFactory
}

// NewEngine creates a new capture engine.
func NewEngine(hub *ws.Hub, db storage.Store) *Engine {
	cfg := DefaultCaptureConfig()
	return &Engine{
		hub:      hub,
		db:       db,
		sessions: make(map[string]*Session),
		cfg:      cfg,
		factory:  selectFactory(cfg),
	}
}

// ListInterfaces returns available network interfaces.
func ListInterfaces() ([]InterfaceInfo, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("find interfaces: %w", err)
	}

	var result []InterfaceInfo
	for _, d := range devs {
		info := InterfaceInfo{
			Name:        d.Name,
			Description: d.Description,
		}
		for _, addr := range d.Addresses {
			info.Addresses = append(info.Addresses, addr.IP.String())
		}
		result = append(result, info)
	}
	return result, nil
}

// InterfaceInfo describes a network interface.
type InterfaceInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Addresses   []string `json:"addresses"`
}

// createSessionDecoders creates fresh decoder instances for a capture session.
func createSessionDecoders() []protocols.StreamingDecoder {
	decoders := []protocols.Decoder{
		sip.NewDecoder(),
		rtp.NewDecoder(),
		dns.NewDecoder(),
		http1.NewDecoder(),
		tls.NewDecoder(),
		diameter.NewDecoder(),
		gtp.NewDecoder(),
		pfcp.NewDecoder(),
		s1ap.NewDecoder(),
		ngap.NewDecoder(),
		websocket.NewDecoder(),
		flowengine.NewTracker(),
	}
	return protocols.WrapAllStreaming(decoders)
}

// createSessionDecodersRaw creates fresh base decoder instances (not streaming-wrapped).
// Used by the decode pool, which works with protocols.Decoder directly.
func createSessionDecodersRaw() []protocols.Decoder {
	return []protocols.Decoder{
		sip.NewDecoder(),
		rtp.NewDecoder(),
		dns.NewDecoder(),
		http1.NewDecoder(),
		tls.NewDecoder(),
		diameter.NewDecoder(),
		gtp.NewDecoder(),
		pfcp.NewDecoder(),
		s1ap.NewDecoder(),
		ngap.NewDecoder(),
		websocket.NewDecoder(),
		flowengine.NewTracker(),
	}
}

// normalizeBPFFilter converts user-friendly shorthand into valid BPF syntax.
// Examples:
//
//	"5060"       -> "port 5060"
//	"5060,5061"  -> "port 5060 or port 5061"
//	"port 5060"  -> "port 5060"  (already valid, unchanged)
//	""           -> ""           (no filter)
var barePortRe = regexp.MustCompile(`^\d+$`)

func normalizeBPFFilter(f string) string {
	f = strings.TrimSpace(f)
	if f == "" {
		return f
	}
	// If it's a single bare number, wrap it as "port <n>"
	if barePortRe.MatchString(f) {
		return "port " + f
	}
	// If it's a comma-separated list of bare numbers, expand each one
	parts := strings.Split(f, ",")
	allPorts := true
	for _, p := range parts {
		if !barePortRe.MatchString(strings.TrimSpace(p)) {
			allPorts = false
			break
		}
	}
	if allPorts && len(parts) > 1 {
		var exprs []string
		for _, p := range parts {
			exprs = append(exprs, "port "+strings.TrimSpace(p))
		}
		return strings.Join(exprs, " or ")
	}
	return f
}

// StartCapture begins live packet capture on the given interface.
func (e *Engine) StartCapture(iface, bpfFilter string) (*Session, error) {
	bpfFilter = normalizeBPFFilter(bpfFilter)
	sources, err := e.factory.CreateSources(iface, bpfFilter, e.cfg.WorkerCount, e.cfg)
	if err != nil {
		return nil, fmt.Errorf("create capture sources: %w", err)
	}

	sessionID := uuid.New().String()
	session := NewSession(sessionID, iface, bpfFilter)

	// Create a job for this capture session
	jobID := time.Now().UnixMilli()
	if e.db != nil {
		if err := e.db.CreateJob(jobID, "live-capture:"+iface); err != nil {
			log.Printf("warning: failed to create job for capture: %v", err)
		}
	}
	session.JobID = jobID

	e.mu.Lock()
	e.sessions[sessionID] = session
	e.mu.Unlock()

	stats := NewStats()

	var frameGen uint64
	var wg sync.WaitGroup
	workers := make([]*CaptureWorker, len(sources))

	if len(sources) == 1 {
		// Single source (pcap on Windows/macOS): use reader goroutine + decode pool
		decodePool := pipeline.NewPool(e.cfg.WorkerCount, e.cfg.PipelineBufferSize, func() []protocols.Decoder {
			return createSessionDecodersRaw()
		})
		decodePool.SetOnPacket(func(pkt *domain.Packet) {
			buffered := &domain.Packet{
				Timestamp:   pkt.Timestamp,
				SrcIP:       pkt.SrcIP,
				DstIP:       pkt.DstIP,
				SrcPort:     pkt.SrcPort,
				DstPort:     pkt.DstPort,
				Protocol:    pkt.Protocol,
				FrameNumber: pkt.FrameNumber,
				Length:      pkt.Length,
				AppProtocol: pkt.AppProtocol,
				Summary:     pkt.Summary,
				Metadata:    pkt.Metadata,
				Errors:      pkt.Errors,
			}
			session.BufferPacket(buffered)

			e.hub.Broadcast(ws.Message{
				Type: ws.MsgPacket,
				Payload: map[string]any{
					"frame":        pkt.FrameNumber,
					"timestamp":    pkt.Timestamp,
					"src_ip":       pkt.SrcIP,
					"dst_ip":       pkt.DstIP,
					"src_port":     pkt.SrcPort,
					"dst_port":     pkt.DstPort,
					"protocol":     pkt.Protocol,
					"app_protocol": pkt.AppProtocol,
					"length":       pkt.Length,
					"summary":      pkt.Summary,
					"metadata":     pkt.Metadata,
					"errors":       pkt.Errors,
				},
			})

			if len(pkt.Errors) > 0 {
				for _, pe := range pkt.Errors {
					e.hub.Broadcast(ws.Message{
						Type: ws.MsgAlert,
						Payload: map[string]any{
							"frame":       pkt.FrameNumber,
							"timestamp":   pkt.Timestamp,
							"severity":    pe.Severity,
							"protocol":    pkt.AppProtocol,
							"title":       pe.Title,
							"description": pe.Description,
							"src_ip":      pkt.SrcIP,
							"dst_ip":      pkt.DstIP,
						},
					})
				}
			}
		})
		decodePool.Start()
		session.decodePool = decodePool

		wg.Add(1)
		w := NewCaptureWorker(0, sources[0], nil, session, stats, e.hub, &frameGen, &wg)
		workers[0] = w
		go w.RunWithPool(decodePool)
	} else {
		// Multiple sources (AF_PACKET): each worker has its own decoders
		for i, src := range sources {
			decoders := createSessionDecoders()
			wg.Add(1)
			w := NewCaptureWorker(i, src, decoders, session, stats, e.hub, &frameGen, &wg)
			workers[i] = w
			go w.Run()
		}
	}
	session.workers = workers

	go e.statsLoop(session, stats, sources)

	// Wait for all workers to finish in background, then close sources
	go func() {
		wg.Wait()
		for _, src := range sources {
			src.Close()
		}
	}()

	log.Printf("capture started: session=%s iface=%s filter=%q jobID=%d workers=%d",
		sessionID, iface, bpfFilter, jobID, len(workers))

	e.hub.Broadcast(ws.Message{
		Type: ws.MsgCaptureState,
		Payload: map[string]any{
			"session_id": sessionID,
			"status":     "running",
			"interface":  iface,
			"job_id":     jobID,
			"workers":    len(workers),
		},
	})

	return session, nil
}

// StopCapture stops a running capture session and triggers analysis.
func (e *Engine) StopCapture(sessionID string) (int64, error) {
	e.mu.RLock()
	session, ok := e.sessions[sessionID]
	e.mu.RUnlock()

	if !ok {
		return 0, fmt.Errorf("session not found: %s", sessionID)
	}

	session.Stop()

	e.hub.Broadcast(ws.Message{
		Type: ws.MsgCaptureState,
		Payload: map[string]any{
			"session_id": sessionID,
			"status":     "stopped",
			"job_id":     session.JobID,
		},
	})

	// Run analysis and persistence in background
	go e.analyzeAndStore(session)

	return session.JobID, nil
}

// GetSession returns a session by ID.
func (e *Engine) GetSession(id string) (*Session, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	s, ok := e.sessions[id]
	return s, ok
}

// ListSessions returns all capture sessions.
func (e *Engine) ListSessions() []*Session {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*Session, 0, len(e.sessions))
	for _, s := range e.sessions {
		result = append(result, s)
	}
	return result
}

func (e *Engine) statsLoop(session *Session, stats *Stats, sources []CaptureSource) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-session.StopCh():
			return
		case <-ticker.C:
			stats.Tick()
			snap := stats.Snapshot()

			// Aggregate kernel-level stats from all sources
			var kernelReceived, kernelDropped uint64
			for _, src := range sources {
				ss := src.Stats()
				kernelReceived += ss.Received
				kernelDropped += ss.Dropped
			}

			var dropPct float64
			if kernelReceived > 0 {
				dropPct = float64(kernelDropped) / float64(kernelReceived) * 100.0
			}

			payload := map[string]any{
				"total_packets":   snap.TotalPackets,
				"total_bytes":     snap.TotalBytes,
				"packets_per_sec": snap.PacketsPerSec,
				"bytes_per_sec":   snap.BytesPerSec,
				"protocol_counts": snap.ProtocolCounts,
				"kernel_received": kernelReceived,
				"kernel_dropped":  kernelDropped,
				"drop_pct":        dropPct,
			}

			e.hub.Broadcast(ws.Message{
				Type:    ws.MsgStats,
				Payload: payload,
			})

			// Persist this tick to the database for the bandwidth chart
			if e.db != nil && snap.PacketsPerSec > 0 {
				protoJSON, _ := json.Marshal(snap.ProtocolCounts)
				_ = e.db.StoreTrafficStats([]storage.TrafficStatsRecord{{
					JobID:              &session.JobID,
					SessionID:          session.ID,
					Timestamp:          time.Now().UTC().Format("15:04:05"),
					IntervalSec:        1,
					PacketsPerSec:      int(snap.PacketsPerSec),
					BytesPerSec:        int(snap.BytesPerSec),
					ProtocolCountsJSON: string(protoJSON),
				}})
			}
		}
	}
}

// analyzeAndStore runs the batch analysis pipeline on captured packets and stores results.
func (e *Engine) analyzeAndStore(session *Session) {
	if e.db == nil {
		return
	}

	session.SetStatus("analyzing")
	log.Printf("analyzing capture session %s (jobID=%d, packets=%d)", session.ID, session.JobID, session.PacketCount)

	e.hub.Broadcast(ws.Message{
		Type: ws.MsgCaptureState,
		Payload: map[string]any{
			"session_id": session.ID,
			"status":     "analyzing",
			"job_id":     session.JobID,
		},
	})

	// 1. Flush decoders to get flows — from decode pool or per-worker decoders
	bufferedPackets := session.GetPackets()
	log.Printf("session %s: %d buffered packets before flush", session.ID, len(bufferedPackets))

	var flows []domain.Flow
	if session.decodePool != nil {
		// Pool channels are closed by RunWithPool when the reader exits.
		// Just wait for decode workers to drain remaining packets, then flush.
		session.decodePool.Wait()
		flows = session.decodePool.Flush()
	} else {
		flows = session.FlushAllWorkers()
	}
	log.Printf("session %s: %d flows from workers", session.ID, len(flows))

	// 2. Run detection engine
	detector := detection.NewEngine()
	alerts := detector.RunOnFlows(flows)
	if len(alerts) > 0 {
		log.Printf("capture session %s: %d detection alerts", session.ID, len(alerts))
		var eventRecords []storage.EventRecord
		for _, a := range alerts {
			jobID := session.JobID
			eventRecords = append(eventRecords, storage.EventRecord{
				JobID:       &jobID,
				SessionID:   session.ID,
				Timestamp:   a.Timestamp.Format(time.RFC3339),
				Severity:    a.Severity,
				Protocol:    a.Protocol,
				Title:       a.Title,
				Description: a.Description,
			})
		}
		if err := e.db.StoreEvents(eventRecords); err != nil {
			log.Printf("warning: failed to store events for session %s: %v", session.ID, err)
		}
	}

	// 3. Correlate SIP/RTP
	calls := correlation.CorrelateSIPRTP(flows)

	// 4. Compute MOS and analyze calls
	for i := range calls {
		worstMOS := 5.0
		for _, leg := range calls[i].RTPLegs {
			packetCount, _ := leg["packet_count"].(int)
			jitterMs, _ := leg["jitter_ms"].(float64)
			maxSeqGap, _ := leg["max_seq_gap"].(int)
			if packetCount == 0 {
				continue
			}
			lossPct := float64(maxSeqGap) / float64(packetCount) * 100
			mos := analysis.ComputeMOS(lossPct, jitterMs, 0.0)
			if mos < worstMOS {
				worstMOS = mos
			}
		}
		if worstMOS < 5.0 {
			calls[i].MOS = worstMOS
			calls[i].Quality = analysis.QualityFromMOS(worstMOS)
		}
		analysis.AnalyzeCall(&calls[i])
	}

	// 5. Store flows
	log.Printf("session %s: storing %d flows", session.ID, len(flows))
	if err := e.db.StoreFlows(session.JobID, flows); err != nil {
		log.Printf("warning: failed to store flows for session %s: %v", session.ID, err)
		e.db.FailJob(session.JobID, err.Error())
		return
	}

	// 6. Store calls
	log.Printf("session %s: storing %d calls", session.ID, len(calls))
	if err := e.db.StoreCalls(session.JobID, calls); err != nil {
		log.Printf("warning: failed to store calls for session %s: %v", session.ID, err)
		e.db.FailJob(session.JobID, err.Error())
		return
	}

	// 7. Store RTP legs
	if err := e.db.StoreRTPLegs(session.JobID, calls); err != nil {
		log.Printf("warning: failed to store RTP legs for session %s: %v", session.ID, err)
	}

	// 8. Store buffered packets
	pkts := session.GetPackets()
	log.Printf("session %s: storing %d packets", session.ID, len(pkts))
	if err := e.db.StorePackets(session.JobID, session.ID, pkts); err != nil {
		log.Printf("warning: failed to store packets for session %s: %v", session.ID, err)
	}

	// 9. Complete the job
	if err := e.db.CompleteJob(session.JobID); err != nil {
		log.Printf("warning: failed to complete job for session %s: %v", session.ID, err)
	}

	session.SetStatus("completed")
	log.Printf("capture session %s analysis complete: %d flows, %d calls", session.ID, len(flows), len(calls))

	e.hub.Broadcast(ws.Message{
		Type: ws.MsgCaptureState,
		Payload: map[string]any{
			"session_id": session.ID,
			"status":     "completed",
			"job_id":     session.JobID,
		},
	})
}
