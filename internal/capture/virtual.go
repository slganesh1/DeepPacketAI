package capture

import (
	"io"
	"log"
	"strings"
	"sync"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/pipeline"
	"DeepPacketAI/internal/protocols"
	"DeepPacketAI/internal/ws"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/uuid"
)

// channelSource is a CaptureSource backed by a packet channel.
// Used by central mode to inject packets received from remote agents into the
// existing capture/analysis pipeline without any changes to that pipeline.
type channelSource struct {
	ch       <-chan RawPacket
	stopCh   <-chan struct{}
	drained  bool
	linkType layers.LinkType
}

func newChannelSource(ch <-chan RawPacket, stopCh <-chan struct{}, linkType int) *channelSource {
	lt := layers.LinkType(linkType)
	if lt == 0 {
		lt = layers.LinkTypeEthernet
	}
	return &channelSource{ch: ch, stopCh: stopCh, linkType: lt}
}

// ReadPacket blocks until a packet arrives, the channel is closed, or the
// session is stopped. Once the packet channel drains, ReadPacket blocks on
// stopCh so the worker does not spin-loop on a closed channel.
func (s *channelSource) ReadPacket() (RawPacket, error) {
	ch := s.ch
	if s.drained {
		ch = nil // nil channel blocks forever in select
	}
	select {
	case pkt, ok := <-ch:
		if !ok {
			s.drained = true
			// Channel closed (agent disconnected). Block until the session is
			// explicitly stopped so we don't spin; StopCapture will close stopCh.
			<-s.stopCh
			return RawPacket{}, io.EOF
		}
		return pkt, nil
	case <-s.stopCh:
		return RawPacket{}, io.EOF
	}
}

func (s *channelSource) Stats() SourceStats        { return SourceStats{} }
func (s *channelSource) Decoder() gopacket.Decoder { return s.linkType }
func (s *channelSource) Close() error              { return nil }

// StartVirtualCapture creates a capture session fed by an external packet
// channel. Packets sent to the returned channel flow through the full
// decode / analysis / storage pipeline, identical to a live local capture.
//
// linkType is the gopacket/layers.LinkType of the agent's capture interface
// (e.g. int(layers.LinkTypeEthernet)). Pass 0 to default to Ethernet.
//
// Call StopCapture(session.ID) when the remote agent disconnects — this closes
// the session's stop channel, unblocks the worker, and triggers analyzeAndStore.
func (e *Engine) StartVirtualCapture(agentID, agentHost, iface string, linkType int) (*Session, chan<- RawPacket, error) {
	// Include a short random suffix so reconnecting agents get a fresh session
	// ID, preventing the deferred StopCapture of the old handler from
	// accidentally stopping the new session.
	sessionID := "agent-" + agentID + "-" + iface + "-" + uuid.New().String()[:8]
	session := NewSession(sessionID, iface, "")

	var jobID int64
	if e.db != nil {
		var jobErr error
		jobID, jobErr = e.db.CreateJob("agent:" + agentID + ":" + iface)
		if jobErr != nil {
			log.Printf("warning: failed to create job for agent session: %v", jobErr)
		}
	}
	session.JobID = jobID

	e.mu.Lock()
	e.sessions[sessionID] = session
	e.mu.Unlock()

	ch := make(chan RawPacket, 100_000)
	src := newChannelSource(ch, session.StopCh(), linkType)

	stats := NewStats()
	var frameGen uint64
	var wg sync.WaitGroup

	// Virtual sessions always use the single-source path (decode pool).
	decodePool := pipeline.NewPool(e.cfg.WorkerCount, e.cfg.PipelineBufferSize, func() []protocols.Decoder {
		return createSessionDecodersRaw()
	})
	decodePool.SetOnPacket(func(pkt *domain.Packet) {
		// Tag packet with its originating agent so queries can filter by source.
		meta := pkt.Metadata
		if meta == nil {
			meta = make(map[string]any)
		}
		meta["agent_id"] = agentID
		meta["agent_host"] = agentHost

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
			Metadata:    meta,
			Errors:      pkt.Errors,
		}
		session.BufferPacket(buffered)

		// Sample 1-in-10; always forward decoded app-layer traffic to the UI.
		if pkt.AppProtocol != "" || pkt.FrameNumber%10 == 0 {
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
		}

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
	w := NewCaptureWorker(0, src, nil, session, stats, e.hub, &frameGen, &wg)
	session.workers = []*CaptureWorker{w}
	go w.RunWithPool(decodePool)

	go e.statsLoop(session, stats, []CaptureSource{src})
	go e.periodicFlush(session)

	go func() {
		wg.Wait()
		src.Close()
	}()

	log.Printf("virtual capture: session=%s agent=%s iface=%s jobID=%d",
		sessionID, agentID, iface, jobID)

	e.hub.Broadcast(ws.Message{
		Type: ws.MsgCaptureState,
		Payload: map[string]any{
			"session_id": sessionID,
			"status":     "running",
			"interface":  iface + "@" + agentID,
			"job_id":     jobID,
			"agent_id":   agentID,
		},
	})

	return session, ch, nil
}

// NormalizeBPFFilter is the exported form of normalizeBPFFilter for use
// outside the capture package (e.g., agent mode in cmd/).
func NormalizeBPFFilter(f string) string {
	return normalizeBPFFilter(f)
}

// NewSourceFactory returns the platform-appropriate capture source factory.
// Used by agent mode to create capture sources without starting a full Engine.
func NewSourceFactory(cfg CaptureConfig) CaptureSourceFactory {
	return selectFactory(cfg)
}

// ResolveInterfaceName resolves a user-supplied interface name (e.g. "Ethernet",
// "Wi-Fi") to the actual pcap device name (e.g. \Device\NPF_{GUID} on Windows).
//
//   - If the name matches a device name exactly, it is returned as-is.
//   - If it matches a device description (case-insensitive), the device name is returned.
//   - Otherwise the original value is returned so pcap can produce its own error.
func ResolveInterfaceName(name string) string {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return name
	}
	nameLower := strings.ToLower(name)
	// Pass 1 — exact device name
	for _, d := range devs {
		if d.Name == name {
			return name
		}
	}
	// Pass 2 — exact description match
	for _, d := range devs {
		if strings.EqualFold(d.Description, name) {
			return d.Name
		}
	}
	// Pass 3 — description contains the supplied name (e.g. "Ethernet" → "Ethernet 2")
	for _, d := range devs {
		if strings.Contains(strings.ToLower(d.Description), nameLower) {
			return d.Name
		}
	}
	return name
}
