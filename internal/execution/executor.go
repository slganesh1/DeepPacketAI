package execution

import (
	"context"
	"fmt"
	"log"
	"time"

	"DeepPacketAI/internal/ai"
	"DeepPacketAI/internal/analysis"
	"DeepPacketAI/internal/correlation"
	"DeepPacketAI/internal/detection"
	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/flowengine"
	"DeepPacketAI/internal/metrics"
	"DeepPacketAI/internal/plugin"
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
)

type Executor struct {
	db           storage.Store
	aiRegistry   *ai.ProviderRegistry   // optional; nil = no AI analysis
	protocolReg  *plugin.ProtocolRegistry  // optional; nil = use built-in factory
	detectionReg *plugin.DetectionRegistry // optional; nil = use BuiltinRules
}

func NewExecutor(db storage.Store) *Executor {
	return &Executor{db: db}
}

// WithAIRegistry attaches an AI provider registry to enable LLM-based analysis.
func (e *Executor) WithAIRegistry(r *ai.ProviderRegistry) *Executor {
	e.aiRegistry = r
	return e
}

// WithPluginRegistries attaches the global plugin registries so that
// enabled/disabled protocol decoders and detection rules take effect.
func (e *Executor) WithPluginRegistries() *Executor {
	e.protocolReg = plugin.Protocols
	e.detectionReg = plugin.Detection
	return e
}

func (e *Executor) RunPCAPForJob(jobID int64, pcapPath string) error {
	return e.runPCAP(jobID, pcapPath)
}

func (e *Executor) RunPCAP(pcapPath string) error {
	jobID := time.Now().UnixMilli()

	if err := e.db.CreateJob(jobID, pcapPath); err != nil {
		return err
	}

	return e.runPCAP(jobID, pcapPath)
}

// BuiltinDecoderFactory returns the hard-coded decoder set used when no
// protocol plugin registry is attached. Exported for use in tests.
func BuiltinDecoderFactory() []protocols.Decoder {
	return builtinDecoderFactory()
}

// builtinDecoderFactory is the internal implementation.
func builtinDecoderFactory() []protocols.Decoder {
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

func (e *Executor) runPCAP(jobID int64, pcapPath string) error {
	// Choose decoder factory: plugin-registry-driven or built-in hard-coded.
	var factory func() []protocols.Decoder
	if e.protocolReg != nil {
		factory = e.protocolReg.BuildDecoderFactory()
	} else {
		factory = builtinDecoderFactory
	}

	pipeline := NewPipeline(factory)

	flows, packets, err := pipeline.Run(pcapPath)
	log.Println("---- Decoded Flows ----")
	for _, f := range flows {
		log.Printf(
			"[%s] %s:%d -> %s:%d  start=%s end=%s  metrics=%v",
			f.Type,
			f.SrcIP,
			f.SrcPort,
			f.DstIP,
			f.DstPort,
			f.StartTime.Format(time.RFC3339),
			f.EndTime.Format(time.RFC3339),
			f.Metrics,
		)
	}
	log.Println("-----------------------")

	if err != nil {
		metrics.PCAPJobsTotal.WithLabelValues("failed").Inc()
		e.db.FailJob(jobID, err.Error())
		return err
	}

	// Guard: if no TCP/UDP/SCTP packets were extracted, the PCAP contains only
	// unsupported traffic (e.g. pure ICMP, ARP, or non-IP frames).
	if len(packets) == 0 {
		msg := "no supported traffic found: PCAP contains no TCP/UDP/SCTP over IPv4/IPv6 " +
			"(pure ICMP, ARP, or non-IP captures are not analysed)"
		metrics.PCAPJobsTotal.WithLabelValues("failed").Inc()
		e.db.FailJob(jobID, msg)
		return fmt.Errorf("%s", msg)
	}

	metrics.PCAPJobsTotal.WithLabelValues("completed").Inc()

	// ── Rule-based detection ──────────────────────────────────────────────────
	var detector *detection.Engine
	if e.detectionReg != nil {
		detector = detection.NewEngineWithRules(e.detectionReg.ActiveRules())
	} else {
		detector = detection.NewEngine()
	}
	alerts := detector.RunOnFlows(flows)
	if len(alerts) > 0 {
		log.Printf("---- Detection: %d alerts found ----", len(alerts))
		var eventRecords []storage.EventRecord
		for _, a := range alerts {
			log.Printf("[%s] %s: %s - %s", a.Severity, a.Protocol, a.Title, a.Description)
			eventRecords = append(eventRecords, storage.EventRecord{
				JobID:       &jobID,
				Timestamp:   a.Timestamp.Format(time.RFC3339),
				Severity:    a.Severity,
				Protocol:    a.Protocol,
				Title:       a.Title,
				Description: a.Description,
			})
		}
		if err := e.db.StoreEvents(eventRecords); err != nil {
			log.Printf("warning: failed to store events: %v", err)
		}
	}

	// ── AI traffic analysis (holistic anomaly detection) ─────────────────────
	if e.aiRegistry != nil {
		if provider, ok := e.aiRegistry.Active(); ok {
			go func() {
				aiCtx, aiCancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer aiCancel()

				var summaries []ai.AlertSummary
				for _, a := range alerts {
					summaries = append(summaries, ai.AlertSummary{
						Severity:    a.Severity,
						Protocol:    a.Protocol,
						Title:       a.Title,
						Description: a.Description,
					})
				}

				stats := ai.TrafficStats{TotalFlows: len(flows)}
				for _, f := range flows {
					switch string(f.Type) {
					case "SIP":
						stats.SIPFlows++
					case "RTP":
						stats.RTPFlows++
					case "DNS":
						stats.DNSFlows++
						stats.DNSQueryCount++
					case "GTP":
						stats.GTPFlows++
					case "NGAP":
						stats.NGAPFlows++
					case "TLS":
						stats.TLSFlows++
					case "Diameter":
						if isErr, _ := f.Metrics["is_error"].(bool); isErr {
							stats.DiameterErrors++
						}
					}
					if pkts, ok := f.Metrics["packets"].(int); ok {
						stats.TotalPackets += pkts
					}
				}

				result, err := ai.AnalyzeTrafficAnomalies(aiCtx, provider, summaries, stats)
				if err != nil {
					log.Printf("AI traffic analysis: %v", err)
					return
				}
				log.Printf("---- AI Traffic Analysis ----")
				log.Printf("Summary: %s", result.Summary)
				for _, t := range result.Threats {
					log.Printf("  [AI THREAT]  %s", t)
				}
				for _, a := range result.Anomalies {
					log.Printf("  [AI ANOMALY] %s", a)
				}
				for _, f := range result.Frauds {
					log.Printf("  [AI FRAUD]   %s", f)
				}
			}()
		}
	}

	// ── Telecom session correlation ───────────────────────────────────────────
	telecomSessions := correlation.NewTelecomTracer().Trace(flows)
	for _, s := range telecomSessions {
		if s.IsComplete {
			metrics.TelecomSessionsTotal.WithLabelValues("true").Inc()
		} else {
			metrics.TelecomSessionsTotal.WithLabelValues("false").Inc()
		}
	}
	if len(telecomSessions) > 0 {
		log.Printf("---- Telecom Sessions (%d) ----", len(telecomSessions))
		for _, s := range telecomSessions {
			log.Printf("[%s] IMSI=%s APN=%s UE=%s SIP=%s Complete=%v MOS=%.2f Layers=NGAP:%v GTP-C:%v GTP-U:%v SIP:%v RTP:%v Diameter:%v",
				s.SessionID, s.IMSI, s.APN, s.UEIP, s.SIPCallID,
				s.IsComplete, s.MOS,
				s.HasNGAP, s.HasGTPC, s.HasGTPU, s.HasSIP, s.HasRTP, s.HasDiameter,
			)
		}
		if err := e.db.StoreTelecomSessions(jobID, telecomSessions); err != nil {
			log.Printf("warning: failed to store telecom sessions: %v", err)
		}

		// AI per-session threat analysis
		if e.aiRegistry != nil {
			if provider, ok := e.aiRegistry.Active(); ok {
				for _, sess := range telecomSessions {
					if len(sess.Events) == 0 {
						continue
					}
					go func(s domain.TelecomSession) {
						aiCtx, aiCancel := context.WithTimeout(context.Background(), 60*time.Second)
						defer aiCancel()
						result, err := ai.AnalyzeTelecomSession(aiCtx, provider, s)
						if err != nil {
							log.Printf("AI session %s analysis: %v", s.SessionID, err)
							return
						}
						if result != nil && result.Summary != "" {
							log.Printf("[AI Session %s] %s", s.SessionID, result.Summary)
							for _, t := range result.Threats {
								log.Printf("  [THREAT] %s", t)
							}
						}
					}(sess)
				}
			}
		}
	}

	// ── SIP/RTP call correlation ──────────────────────────────────────────────
	calls := correlation.CorrelateSIPRTP(flows)

	// Compute MOS + Quality
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
	}

	for i := range calls {
		analysis.AnalyzeCall(&calls[i])
	}

	log.Println("---- Correlated Calls (With Analytics) ----")
	for _, c := range calls {
		log.Printf(
			`CALL %s
  Start      : %s
  End        : %s
  RTP Legs   : %v
  MOS        : %.3f
  Quality    : %s
  IsOnHold   : %v
  EndType    : %s
  RootCause  : %s
  Confidence : %.2f
`,
			c.CallID,
			c.StartTime.Format(time.RFC3339),
			c.EndTime.Format(time.RFC3339),
			c.RTPLegs,
			c.MOS,
			c.Quality,
			c.IsOnHold,
			c.EndType,
			c.RootCause,
			c.Confidence,
		)
	}

	if err := e.db.StoreFlows(jobID, flows); err != nil {
		e.db.FailJob(jobID, err.Error())
		return err
	}
	if err := e.db.StoreCalls(jobID, calls); err != nil {
		e.db.FailJob(jobID, err.Error())
		return err
	}

	if err := e.db.StoreRTPLegs(jobID, calls); err != nil {
		e.db.FailJob(jobID, err.Error())
		return err
	}

	// Store individual packets for the packets tab and protocol distribution
	if len(packets) > 0 {
		log.Printf("Storing %d packets...", len(packets))
		if err := e.db.StorePackets(jobID, "", packets); err != nil {
			log.Printf("warning: failed to store packets: %v", err)
		}
	}

	return e.db.CompleteJob(jobID)
}
