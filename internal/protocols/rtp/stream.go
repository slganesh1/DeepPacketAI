package rtp

import (
	"math"
	"time"

	"DeepPacketAI/internal/analysis"
	"DeepPacketAI/internal/domain"
)

type RTPStream struct {
	SrcIP   string
	SrcPort int
	DstIP   string
	DstPort int

	SSRC uint32

	StartTime time.Time
	EndTime   time.Time

	lastSeq     uint16
	seenPackets int
	lastArrival time.Time
	lastTS      uint32

	PacketCount int
	MaxSeqGap   int
	lostPackets int // cumulative missing sequence numbers (= actual loss count)

	// RFC 3550 running average jitter
	JitterMs      float64
	jitterRunning float64
	JitterMin     float64
	JitterMax     float64
	JitterSum     float64
	JitterCount   int
	JitterAvgMs   float64

	// Jitter trend: one sample per packet, capped at 300
	jitterHistory []float64

	// Packet size tracking
	MaxPacketLen    int
	TotalPayloadLen int
}

func NewRTPStream(pkt *domain.Packet, hdr *RTPHeader) *RTPStream {
	return &RTPStream{
		SrcIP:       pkt.SrcIP,
		SrcPort:     int(pkt.SrcPort),
		DstIP:       pkt.DstIP,
		DstPort:     int(pkt.DstPort),
		SSRC:        hdr.SSRC,
		StartTime:   pkt.Timestamp,
		EndTime:     pkt.Timestamp,
		lastSeq:     hdr.Sequence,
		lastArrival: pkt.Timestamp,
		lastTS:      hdr.Timestamp,
		JitterMin:   math.MaxFloat64,
	}
}

func (s *RTPStream) AddPacket(pkt *domain.Packet, hdr *RTPHeader) {
	s.PacketCount++
	s.EndTime = pkt.Timestamp

	// Sequence gap tracking (unsigned subtraction handles 16-bit wraparound)
	if s.seenPackets > 0 {
		gap := int(uint16(hdr.Sequence - s.lastSeq))
		if gap > 1 {
			s.lostPackets += gap - 1 // packets missing in this gap
		}
		if gap > s.MaxSeqGap {
			s.MaxSeqGap = gap
		}
	}
	s.lastSeq = hdr.Sequence
	s.seenPackets++

	// RFC 3550 jitter
	if !s.lastArrival.IsZero() {
		arrivalDiff := pkt.Timestamp.Sub(s.lastArrival).Milliseconds()
		tsDiff := int64(hdr.Timestamp - s.lastTS)

		d := math.Abs(float64(arrivalDiff - tsDiff))
		s.jitterRunning += (d - s.jitterRunning) / 16.0
		s.JitterMs = s.jitterRunning

		if s.jitterRunning < s.JitterMin {
			s.JitterMin = s.jitterRunning
		}
		if s.jitterRunning > s.JitterMax {
			s.JitterMax = s.jitterRunning
		}
		s.JitterSum += s.jitterRunning
		s.JitterCount++
		if s.JitterCount > 0 {
			s.JitterAvgMs = s.JitterSum / float64(s.JitterCount)
		}

		// Jitter trend history (capped at 300 samples)
		if len(s.jitterHistory) < 300 {
			s.jitterHistory = append(s.jitterHistory, math.Round(s.jitterRunning*100)/100)
		}
	}

	// Packet size
	payloadLen := len(pkt.Payload)
	if payloadLen > s.MaxPacketLen {
		s.MaxPacketLen = payloadLen
	}
	s.TotalPayloadLen += payloadLen

	s.lastArrival = pkt.Timestamp
	s.lastTS = hdr.Timestamp
}

// ToFlow converts the RTP stream into a domain.Flow.
func (s *RTPStream) ToFlow() domain.Flow {
	avgPacketSize := 0
	if s.PacketCount > 0 {
		avgPacketSize = s.TotalPayloadLen / s.PacketCount
	}

	jitterMin := s.JitterMin
	if s.JitterCount == 0 {
		jitterMin = 0
	}

	// Packet loss rate
	total := s.PacketCount + s.lostPackets
	lossRatePct := 0.0
	if total > 0 {
		lossRatePct = math.Round(float64(s.lostPackets)/float64(total)*10000) / 100
	}

	// SLA classification
	sla := analysis.ClassifyRTP(s.JitterMs, lossRatePct)

	// Jitter trend
	var jitterTrend []map[string]any
	if len(s.jitterHistory) > 0 {
		step := 1
		n := len(s.jitterHistory)
		if n > 60 {
			step = (n + 59) / 60
		}
		for i := 0; i < n; i += step {
			jitterTrend = append(jitterTrend, map[string]any{
				"i":  i,
				"ms": s.jitterHistory[i],
			})
		}
	}

	m := map[string]any{
		"src_ip":   s.SrcIP,
		"src_port": s.SrcPort,
		"dst_ip":   s.DstIP,
		"dst_port": s.DstPort,

		"ssrc":          s.SSRC,
		"packet_count":  s.PacketCount,
		"lost_packets":  s.lostPackets,
		"loss_rate_pct": lossRatePct,
		"max_seq_gap":   s.MaxSeqGap,

		"jitter_ms":     s.JitterMs,
		"jitter_min_ms": jitterMin,
		"jitter_max_ms": s.JitterMax,
		"jitter_avg_ms": s.JitterAvgMs,

		"max_packet_size": s.MaxPacketLen,
		"avg_packet_size": avgPacketSize,

		"start_time": s.StartTime,
		"end_time":   s.EndTime,

		"sla_verdict": string(sla.Verdict),
		"sla_score":   sla.Score,
		"sla_details": sla.Details,
	}
	if len(jitterTrend) > 0 {
		m["jitter_trend"] = jitterTrend
	}

	return domain.Flow{
		Type:      domain.FlowRTP,
		SrcIP:     s.SrcIP,
		SrcPort:   uint16(s.SrcPort),
		DstIP:     s.DstIP,
		DstPort:   uint16(s.DstPort),
		StartTime: s.StartTime,
		EndTime:   s.EndTime,
		Metrics:   m,
	}
}
