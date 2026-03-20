// Package flowengine implements a protocol-agnostic 5-tuple flow tracker.
// It implements protocols.Decoder so it can be dropped into any decoder pipeline.
//
// Per-flow metrics:
//   - src_ip, dst_ip, src_port, dst_port, protocol
//   - packets and bytes (total and per-direction)
//   - start_time, end_time, duration_ms
//   - tcp_flags, close_reason (FIN/RST/timeout)
//   - handshake_rtt_ms, data_rtt_ms, rtt_ms
//   - rtt_samples        []{"t": secs_from_start, "ms": value}
//   - retransmissions, packet_loss_pct
//   - throughput_bps, fwd_throughput_bps, rev_throughput_bps
//   - throughput_trend   []{"t": secs_from_start, "bps": value}  (max 60 points)
//   - sla_verdict, sla_score, sla_details
package flowengine

import (
	"fmt"
	"math"
	"strings"
	"time"

	"DeepPacketAI/internal/analysis"
	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/metrics"
)

// TCP flag bit positions (same encoding as domain.Packet.TCPFlags)
const (
	flagFIN uint16 = 0x01
	flagSYN uint16 = 0x02
	flagRST uint16 = 0x04
	flagPSH uint16 = 0x08
	flagACK uint16 = 0x10
	flagURG uint16 = 0x20
)

// Tracker accumulates per-flow state and emits domain.Flow records on Flush().
// Not safe for concurrent use — intended for single-worker pipelines.
type Tracker struct {
	flows map[flowKey]*flowRecord
}

// NewTracker creates a new Tracker.
func NewTracker() *Tracker {
	return &Tracker{flows: make(map[flowKey]*flowRecord)}
}

func (t *Tracker) Name() string { return "flowengine" }

// flowKey is the canonical (normalised) 5-tuple for a bidirectional flow.
type flowKey struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	Protocol         string
}

func makeKey(srcIP, dstIP string, srcPort, dstPort uint16, proto string) (flowKey, bool) {
	if srcIP < dstIP || (srcIP == dstIP && srcPort <= dstPort) {
		return flowKey{srcIP, dstIP, srcPort, dstPort, proto}, false
	}
	return flowKey{dstIP, srcIP, dstPort, srcPort, proto}, true
}

// pendingSeg tracks a sent TCP data segment awaiting acknowledgement.
type pendingSeg struct {
	ackExpected uint32
	sentAt      time.Time
}

// rttMeasurement holds one data-RTT sample with its observation time.
type rttMeasurement struct {
	observedAt time.Time
	durationMs float64
}

// flowRecord holds all accumulated state for one bidirectional flow.
type flowRecord struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	Protocol         string

	start, end time.Time

	// Volume
	fwdPackets, revPackets int64
	fwdBytes, revBytes     int64

	// Throughput trend: 1-second byte buckets (index = whole seconds from bucketStart)
	bucketStart time.Time
	bucketBytes []int64

	// TCP aggregated flags
	tcpFlags uint16

	// TCP close tracking
	closedFIN bool
	closedRST bool

	// Handshake RTT
	synTime    time.Time
	synAckTime time.Time
	rttMs      float64
	hasRTT     bool

	// Retransmission detection
	fwdHiSeq, revHiSeq     uint32
	fwdHiInit, revHiInit   bool
	fwdRetrans, revRetrans int64

	// Data RTT samples (PSH → ACK)
	fwdPending  []pendingSeg
	revPending  []pendingSeg
	rttSamples  []rttMeasurement // all measured data-RTT samples with timestamps
}

// HandlePacket updates flow state. Called for every packet in the pipeline.
func (t *Tracker) HandlePacket(pkt *domain.Packet) {
	if pkt.SrcIP == "" || pkt.DstIP == "" {
		return
	}

	key, reversed := makeKey(pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort, pkt.Protocol)
	ts := pkt.Timestamp

	rec, ok := t.flows[key]
	if !ok {
		rec = &flowRecord{
			SrcIP:    key.SrcIP,
			DstIP:    key.DstIP,
			SrcPort:  key.SrcPort,
			DstPort:  key.DstPort,
			Protocol: pkt.Protocol,
			start:    ts,
			end:      ts,
		}
		t.flows[key] = rec
	}

	if ts.After(rec.end) {
		rec.end = ts
	}

	payloadLen := int64(len(pkt.Payload))
	if !reversed {
		rec.fwdPackets++
		rec.fwdBytes += payloadLen
	} else {
		rec.revPackets++
		rec.revBytes += payloadLen
	}

	// ── Throughput bucket ────────────────────────────────────────────────────────
	if payloadLen > 0 {
		if rec.bucketStart.IsZero() {
			rec.bucketStart = ts
		}
		idx := int(ts.Sub(rec.bucketStart).Seconds())
		if idx >= 0 && idx < 3600 { // cap at 1 hour
			for len(rec.bucketBytes) <= idx {
				rec.bucketBytes = append(rec.bucketBytes, 0)
			}
			rec.bucketBytes[idx] += payloadLen
		}
	}

	if pkt.Protocol != "TCP" {
		return
	}

	flags := pkt.TCPFlags
	rec.tcpFlags |= flags

	isSYN := flags&flagSYN != 0
	isACK := flags&flagACK != 0
	isPSH := flags&flagPSH != 0
	isFIN := flags&flagFIN != 0
	isRST := flags&flagRST != 0

	if isFIN {
		rec.closedFIN = true
	}
	if isRST {
		rec.closedRST = true
	}

	seq := pkt.TCPSeq
	payLen := uint32(len(pkt.Payload))

	// ── Handshake RTT ────────────────────────────────────────────────────────────
	if isSYN && !isACK && !reversed && rec.synTime.IsZero() {
		rec.synTime = ts
	}
	if isSYN && isACK && reversed && !rec.synTime.IsZero() && rec.synAckTime.IsZero() {
		rec.synAckTime = ts
		rec.rttMs = round2(rec.synAckTime.Sub(rec.synTime).Seconds() * 1000 * 2)
		rec.hasRTT = true
	}

	// ── Retransmission detection ─────────────────────────────────────────────────
	if payLen > 0 {
		nextSeq := seq + payLen
		if !reversed {
			if !rec.fwdHiInit {
				rec.fwdHiSeq, rec.fwdHiInit = nextSeq, true
			} else if seqBefore(seq, rec.fwdHiSeq) {
				rec.fwdRetrans++
			} else {
				rec.fwdHiSeq = nextSeq
			}
		} else {
			if !rec.revHiInit {
				rec.revHiSeq, rec.revHiInit = nextSeq, true
			} else if seqBefore(seq, rec.revHiSeq) {
				rec.revRetrans++
			} else {
				rec.revHiSeq = nextSeq
			}
		}
	}

	// ── Data RTT (PSH → ACK) ────────────────────────────────────────────────────
	if isPSH && payLen > 0 {
		seg := pendingSeg{ackExpected: seq + payLen, sentAt: ts}
		if !reversed {
			rec.fwdPending = append(rec.fwdPending, seg)
		} else {
			rec.revPending = append(rec.revPending, seg)
		}
	}
	if isACK && pkt.TCPAck != 0 {
		ack := pkt.TCPAck
		if !reversed {
			rec.revPending = drainPending(rec.revPending, ack, ts, &rec.rttSamples)
		} else {
			rec.fwdPending = drainPending(rec.fwdPending, ack, ts, &rec.rttSamples)
		}
	}
}

// Flush converts all accumulated flow records to domain.Flow and resets state.
func (t *Tracker) Flush() []domain.Flow {
	flows := make([]domain.Flow, 0, len(t.flows))
	for _, rec := range t.flows {
		flows = append(flows, rec.toFlow())
	}
	metrics.FlowsActive.Set(float64(len(t.flows)))
	t.flows = make(map[flowKey]*flowRecord)
	return flows
}

// ── flowRecord → domain.Flow ──────────────────────────────────────────────────

func (rec *flowRecord) toFlow() domain.Flow {
	totalPkts := rec.fwdPackets + rec.revPackets
	totalBytes := rec.fwdBytes + rec.revBytes
	totalRetrans := rec.fwdRetrans + rec.revRetrans
	durationSec := rec.end.Sub(rec.start).Seconds()

	// Throughput
	var throughputBps, fwdThroughputBps, revThroughputBps float64
	if durationSec > 0 {
		throughputBps = float64(totalBytes*8) / durationSec
		fwdThroughputBps = float64(rec.fwdBytes*8) / durationSec
		revThroughputBps = float64(rec.revBytes*8) / durationSec
	}

	// Packet loss
	var lossRatePct float64
	if totalPkts > 0 {
		lossRatePct = float64(totalRetrans) / float64(totalPkts+totalRetrans) * 100
	}

	// Average data RTT
	var avgDataRTTMs float64
	for _, s := range rec.rttSamples {
		avgDataRTTMs += s.durationMs
	}
	if len(rec.rttSamples) > 0 {
		avgDataRTTMs = round2(avgDataRTTMs / float64(len(rec.rttSamples)))
	}

	// Best RTT
	effectiveRTT := rec.rttMs
	if avgDataRTTMs > 0 {
		effectiveRTT = avgDataRTTMs
	}

	// ── Throughput trend (downsample to max 60 points) ────────────────────────
	var throughputTrend []map[string]any
	if n := len(rec.bucketBytes); n > 0 {
		step := 1
		if n > 60 {
			step = (n + 59) / 60
		}
		for i := 0; i < n; i += step {
			end := min(i+step, n)
			var sum int64
			for j := i; j < end; j++ {
				sum += rec.bucketBytes[j]
			}
			bps := float64(sum) * 8 / float64(end-i)
			throughputTrend = append(throughputTrend, map[string]any{
				"t":   i,
				"bps": math.Round(bps),
			})
		}
	}

	// ── RTT samples ───────────────────────────────────────────────────────────
	var rttSamples []map[string]any
	for _, s := range rec.rttSamples {
		offsetSec := round2(s.observedAt.Sub(rec.start).Seconds())
		rttSamples = append(rttSamples, map[string]any{
			"t":  offsetSec,
			"ms": round2(s.durationMs),
		})
	}

	// ── Build metrics map ─────────────────────────────────────────────────────
	m := map[string]any{
		"packets":             totalPkts,
		"bytes":               totalBytes,
		"fwd_packets":         rec.fwdPackets,
		"rev_packets":         rec.revPackets,
		"fwd_bytes":           rec.fwdBytes,
		"rev_bytes":           rec.revBytes,
		"duration_ms":         round2(durationSec * 1000),
		"throughput_bps":      math.Round(throughputBps),
		"fwd_throughput_bps":  math.Round(fwdThroughputBps),
		"rev_throughput_bps":  math.Round(revThroughputBps),
		"retransmissions":     totalRetrans,
		"fwd_retransmissions": rec.fwdRetrans,
		"rev_retransmissions": rec.revRetrans,
		"packet_loss_pct":     round2(lossRatePct),
	}

	if len(throughputTrend) > 0 {
		m["throughput_trend"] = throughputTrend
	}
	if len(rttSamples) > 0 {
		m["rtt_samples"] = rttSamples
	}

	// TCP-specific
	var sla analysis.SLAResult
	if rec.Protocol == "TCP" {
		m["tcp_flags"] = tcpFlagsString(rec.tcpFlags)

		closeReason := "timeout"
		if rec.closedRST {
			closeReason = "RST"
		} else if rec.closedFIN {
			closeReason = "FIN"
		}
		m["close_reason"] = closeReason

		if rec.hasRTT {
			m["handshake_rtt_ms"] = round2(rec.rttMs)
		}
		if avgDataRTTMs > 0 {
			m["data_rtt_ms"] = avgDataRTTMs
		}
		if effectiveRTT > 0 {
			m["rtt_ms"] = effectiveRTT
		}

		retransPct := 0.0
		if totalPkts > 0 {
			retransPct = float64(totalRetrans) / float64(totalPkts) * 100
		}
		sla = analysis.ClassifyTCP(effectiveRTT, retransPct)
	} else {
		sla = analysis.ClassifyUDP()
	}

	m["sla_verdict"] = string(sla.Verdict)
	m["sla_score"] = sla.Score
	m["sla_details"] = sla.Details

	flowType := domain.FlowTCP
	switch rec.Protocol {
	case "UDP":
		flowType = domain.FlowUDP
	case "SCTP":
		flowType = domain.FlowSCTP
	}

	return domain.Flow{
		FlowID:    fmt.Sprintf("flow-%s:%d-%s:%d-%s", rec.SrcIP, rec.SrcPort, rec.DstIP, rec.DstPort, rec.Protocol),
		Type:      flowType,
		SrcIP:     rec.SrcIP,
		DstIP:     rec.DstIP,
		SrcPort:   rec.SrcPort,
		DstPort:   rec.DstPort,
		StartTime: rec.start,
		EndTime:   rec.end,
		Metrics:   m,
	}
}

// ── TCP helpers ───────────────────────────────────────────────────────────────

func seqBefore(a, b uint32) bool {
	return int32(b-a) > 0
}

func drainPending(pending []pendingSeg, ack uint32, now time.Time, samples *[]rttMeasurement) []pendingSeg {
	remaining := pending[:0]
	for _, s := range pending {
		if !seqBefore(ack, s.ackExpected) {
			ms := now.Sub(s.sentAt).Seconds() * 1000
			if ms > 0 {
				*samples = append(*samples, rttMeasurement{
					observedAt: now,
					durationMs: round2(ms),
				})
			}
		} else {
			remaining = append(remaining, s)
		}
	}
	return remaining
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

func tcpFlagsString(flags uint16) string {
	var parts []string
	if flags&flagSYN != 0 {
		parts = append(parts, "SYN")
	}
	if flags&flagACK != 0 {
		parts = append(parts, "ACK")
	}
	if flags&flagPSH != 0 {
		parts = append(parts, "PSH")
	}
	if flags&flagFIN != 0 {
		parts = append(parts, "FIN")
	}
	if flags&flagRST != 0 {
		parts = append(parts, "RST")
	}
	if flags&flagURG != 0 {
		parts = append(parts, "URG")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " ")
}
