package handlers

import (
	"encoding/csv"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"time"

	"DeepPacketAI/internal/storage"

	"github.com/go-chi/chi/v5"
)

// ReportHandler provides Spirent-inspired report endpoints.
type ReportHandler struct {
	store storage.Store
}

func NewReportHandler(store storage.Store) *ReportHandler {
	return &ReportHandler{store: store}
}

// ---- helper type assertions ----

func floatMetric(m map[string]any, key string) float64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch t := v.(type) {
	case float64:
		return t
	case int64:
		return float64(t)
	case int:
		return float64(t)
	}
	return 0
}

func int64Metric(m map[string]any, key string) int64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch t := v.(type) {
	case int64:
		return t
	case float64:
		return int64(t)
	case int:
		return int64(t)
	}
	return 0
}

func stringMetric(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// ---- RFC 2544 types ----

type RFC2544Report struct {
	JobID       int64            `json:"job_id"`
	GeneratedAt string           `json:"generated_at"`
	Throughput  ThroughputResult `json:"throughput"`
	Latency     LatencyResult    `json:"latency"`
	FrameLoss   FrameLossResult  `json:"frame_loss"`
	BackToBack  BackToBackResult `json:"back_to_back"`
	ByProtocol  []ProtocolResult `json:"by_protocol"`
	LoadSweep   []LoadSweepRow   `json:"load_sweep"`
}

// LoadSweepRow is one row of the RFC 2544 frame-loss-at-load-level table.
// OfferedLoadPct is the percentile bucket (0–20, 20–40, …, 80–100) of
// per-flow throughput, used as a proxy for "offered load level".
type LoadSweepRow struct {
	BucketLabel    string  `json:"bucket_label"`     // e.g. "0–20%"
	OfferedLoadPct float64 `json:"offered_load_pct"` // midpoint of bucket
	FlowCount      int     `json:"flow_count"`
	AvgThroughput  float64 `json:"avg_throughput_bps"`
	LossRatePct    float64 `json:"loss_rate_pct"`
	AvgLatencyMs   float64 `json:"avg_latency_ms"`
}

type ThroughputResult struct {
	MaxBps     float64 `json:"max_bps"`
	AvgBps     float64 `json:"avg_bps"`
	TotalBytes int64   `json:"total_bytes"`
}

type LatencyResult struct {
	MinMs float64 `json:"min_ms"`
	AvgMs float64 `json:"avg_ms"`
	MaxMs float64 `json:"max_ms"`
	P95Ms float64 `json:"p95_ms"`
	P99Ms float64 `json:"p99_ms"`
}

type FrameLossResult struct {
	TotalPackets    int64   `json:"total_packets"`
	LostPackets     int64   `json:"lost_packets"`
	LossRatePct     float64 `json:"loss_rate_pct"`
	RetransmitCount int64   `json:"retransmit_count"`
}

type BackToBackResult struct {
	MaxBurstPackets int64   `json:"max_burst_packets"`
	AvgBurstPackets float64 `json:"avg_burst_packets"`
}

type ProtocolResult struct {
	Protocol    string         `json:"protocol"`
	FlowCount   int            `json:"flow_count"`
	AvgBps      float64        `json:"avg_bps"`
	AvgLossPct  float64        `json:"avg_loss_pct"`
	AvgRttMs    float64        `json:"avg_rtt_ms"`
	SLAVerdicts map[string]int `json:"sla_verdicts"`
}

// GetRFC2544Report — GET /jobs/{id}/report/rfc2544
func (h *ReportHandler) GetRFC2544Report(w http.ResponseWriter, r *http.Request) {
	id, err := parseJobID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid job id"})
		return
	}

	flows, err := h.store.GetFlowsByJob(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load flows"})
		return
	}

	// Aggregate metrics
	var totalBps float64
	var maxBps float64
	var totalBytes int64
	var rttValues []float64
	var totalPackets int64
	var totalLostPackets int64
	var totalLossRate float64
	var lossRateCount int
	var totalRetransmit int64
	var packetCounts []int64

	// per-protocol aggregation
	type protoAccum struct {
		flowCount   int
		totalBps    float64
		totalLoss   float64
		lossCount   int
		totalRtt    float64
		rttCount    int
		slaVerdicts map[string]int
	}
	protoMap := make(map[string]*protoAccum)

	for _, f := range flows {
		m := f.Metrics
		if m == nil {
			m = map[string]any{}
		}

		bps := floatMetric(m, "throughput_bps")
		totalBps += bps
		if bps > maxBps {
			maxBps = bps
		}

		bytes := int64Metric(m, "bytes")
		totalBytes += bytes

		rtt := floatMetric(m, "rtt_ms")
		if rtt > 0 {
			rttValues = append(rttValues, rtt)
		}

		pktLossPct := floatMetric(m, "packet_loss_pct")
		totalLossRate += pktLossPct
		lossRateCount++

		pkts := int64Metric(m, "packets")
		totalPackets += pkts
		if pkts > 0 {
			packetCounts = append(packetCounts, pkts)
		}

		retx := int64Metric(m, "retransmissions")
		totalRetransmit += retx

		// Estimate lost packets from loss_pct * total_packets
		lostEst := int64(math.Round(pktLossPct / 100.0 * float64(pkts)))
		totalLostPackets += lostEst

		// per-protocol
		proto := string(f.Type)
		if _, exists := protoMap[proto]; !exists {
			protoMap[proto] = &protoAccum{slaVerdicts: make(map[string]int)}
		}
		pa := protoMap[proto]
		pa.flowCount++
		pa.totalBps += bps
		if pktLossPct > 0 || lossRateCount > 0 {
			pa.totalLoss += pktLossPct
			pa.lossCount++
		}
		if rtt > 0 {
			pa.totalRtt += rtt
			pa.rttCount++
		}
		verdict := stringMetric(m, "sla_verdict")
		if verdict != "" {
			pa.slaVerdicts[verdict]++
		}
	}

	// Compute avg bps
	avgBps := 0.0
	if len(flows) > 0 {
		avgBps = totalBps / float64(len(flows))
	}

	// Compute avg loss rate pct
	avgLossRate := 0.0
	if lossRateCount > 0 {
		avgLossRate = totalLossRate / float64(lossRateCount)
	}

	// Compute latency stats
	latency := LatencyResult{}
	if len(rttValues) > 0 {
		sort.Float64s(rttValues)
		sum := 0.0
		for _, v := range rttValues {
			sum += v
		}
		latency.MinMs = rttValues[0]
		latency.MaxMs = rttValues[len(rttValues)-1]
		latency.AvgMs = sum / float64(len(rttValues))
		p95idx := int(0.95 * float64(len(rttValues)))
		if p95idx >= len(rttValues) {
			p95idx = len(rttValues) - 1
		}
		p99idx := int(0.99 * float64(len(rttValues)))
		if p99idx >= len(rttValues) {
			p99idx = len(rttValues) - 1
		}
		latency.P95Ms = rttValues[p95idx]
		latency.P99Ms = rttValues[p99idx]
	}

	// Back-to-back burst
	backToBack := BackToBackResult{}
	if len(packetCounts) > 0 {
		sort.Slice(packetCounts, func(i, j int) bool { return packetCounts[i] > packetCounts[j] })
		backToBack.MaxBurstPackets = packetCounts[0]
		sum := int64(0)
		for _, v := range packetCounts {
			sum += v
		}
		backToBack.AvgBurstPackets = float64(sum) / float64(len(packetCounts))
	}

	// Build per-protocol results (sorted by flow count desc)
	byProtocol := make([]ProtocolResult, 0, len(protoMap))
	for proto, pa := range protoMap {
		avgProtoBps := 0.0
		if pa.flowCount > 0 {
			avgProtoBps = pa.totalBps / float64(pa.flowCount)
		}
		avgLoss := 0.0
		if pa.lossCount > 0 {
			avgLoss = pa.totalLoss / float64(pa.lossCount)
		}
		avgRtt := 0.0
		if pa.rttCount > 0 {
			avgRtt = pa.totalRtt / float64(pa.rttCount)
		}
		byProtocol = append(byProtocol, ProtocolResult{
			Protocol:    proto,
			FlowCount:   pa.flowCount,
			AvgBps:      avgProtoBps,
			AvgLossPct:  avgLoss,
			AvgRttMs:    avgRtt,
			SLAVerdicts: pa.slaVerdicts,
		})
	}
	sort.Slice(byProtocol, func(i, j int) bool {
		return byProtocol[i].FlowCount > byProtocol[j].FlowCount
	})

	// ---- RFC 2544 load sweep ----
	// Collect (throughput_bps, loss_pct, rtt_ms) per flow, then bucket into
	// five 20-percentile bands of offered load.
	type flowSample struct {
		bps  float64
		loss float64
		rtt  float64
	}
	samples := make([]flowSample, 0, len(flows))
	for _, f := range flows {
		m := f.Metrics
		if m == nil {
			m = map[string]any{}
		}
		bps := floatMetric(m, "throughput_bps")
		if bps <= 0 {
			continue
		}
		samples = append(samples, flowSample{
			bps:  bps,
			loss: floatMetric(m, "packet_loss_pct"),
			rtt:  floatMetric(m, "rtt_ms"),
		})
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i].bps < samples[j].bps })

	loadSweep := make([]LoadSweepRow, 0, 5)
	buckets := [][2]int{{0, 20}, {20, 40}, {40, 60}, {60, 80}, {80, 100}}
	n := len(samples)
	for _, b := range buckets {
		lo := int(float64(b[0]) / 100.0 * float64(n))
		hi := int(float64(b[1]) / 100.0 * float64(n))
		if b[1] == 100 {
			hi = n
		}
		if lo >= hi {
			continue
		}
		slice := samples[lo:hi]
		var sumBps, sumLoss, sumRtt float64
		rttCount := 0
		for _, s := range slice {
			sumBps += s.bps
			sumLoss += s.loss
			if s.rtt > 0 {
				sumRtt += s.rtt
				rttCount++
			}
		}
		cnt := float64(len(slice))
		avgRttMs := 0.0
		if rttCount > 0 {
			avgRttMs = sumRtt / float64(rttCount)
		}
		loadSweep = append(loadSweep, LoadSweepRow{
			BucketLabel:    fmt.Sprintf("%d–%d%%", b[0], b[1]),
			OfferedLoadPct: float64(b[0]+b[1]) / 2.0,
			FlowCount:      len(slice),
			AvgThroughput:  sumBps / cnt,
			LossRatePct:    sumLoss / cnt,
			AvgLatencyMs:   avgRttMs,
		})
	}

	report := RFC2544Report{
		JobID:       id,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Throughput: ThroughputResult{
			MaxBps:     maxBps,
			AvgBps:     avgBps,
			TotalBytes: totalBytes,
		},
		Latency: latency,
		FrameLoss: FrameLossResult{
			TotalPackets:    totalPackets,
			LostPackets:     totalLostPackets,
			LossRatePct:     avgLossRate,
			RetransmitCount: totalRetransmit,
		},
		BackToBack: backToBack,
		ByProtocol: byProtocol,
		LoadSweep:  loadSweep,
	}

	writeJSON(w, http.StatusOK, report)
}

// ---- Y.1564 types ----

type Y1564Report struct {
	JobID       int64           `json:"job_id"`
	GeneratedAt string          `json:"generated_at"`
	Overall     string          `json:"overall"`
	Services    []ServiceResult `json:"services"`
}

// ServiceResult holds per-service, per-direction Y.1564 measurements.
type ServiceResult struct {
	Service       string            `json:"service"`
	Protocol      string            `json:"protocol"`
	FlowCount     int               `json:"flow_count"`
	MaxLatencyMs  float64           `json:"max_latency_ms"`
	MaxJitterMs   float64           `json:"max_jitter_ms"`
	MaxLossPct    float64           `json:"max_loss_pct"`
	MeasLatencyMs float64           `json:"meas_latency_ms"`
	MeasJitterMs  float64           `json:"meas_jitter_ms"`
	MeasLossPct   float64           `json:"meas_loss_pct"`
	LatencyPass   bool              `json:"latency_pass"`
	JitterPass    bool              `json:"jitter_pass"`
	LossPass      bool              `json:"loss_pass"`
	Overall       string            `json:"overall"`
	Violations    []string          `json:"violations"`
	Directions    []DirectionResult `json:"directions,omitempty"`
}

// DirectionResult holds UL or DL measurements for a service.
type DirectionResult struct {
	Direction     string   `json:"direction"` // "UL" or "DL"
	FlowCount     int      `json:"flow_count"`
	MeasLatencyMs float64  `json:"meas_latency_ms"`
	MeasJitterMs  float64  `json:"meas_jitter_ms"`
	MeasLossPct   float64  `json:"meas_loss_pct"`
	Overall       string   `json:"overall"`
	Violations    []string `json:"violations"`
}

type serviceThreshold struct {
	name         string
	protocol     string
	maxLatencyMs float64
	maxJitterMs  float64
	maxLossPct   float64
}

// defaultThresholds are ITU-T / MEF 23 reference values.
var defaultThresholds = []serviceThreshold{
	{"Voice (RTP)", "RTP", 150, 30, 1.0},
	{"SIP Signaling", "SIP", 500, 0, 0.1},
	{"Data (TCP)", "TCP", 500, 0, 0.5},
	{"DNS", "DNS", 100, 0, 0.0},
}

// parseFloat64 parses a query param float, returning def on any error.
func parseFloat64(r *http.Request, key string, def float64) float64 {
	if v := r.URL.Query().Get(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 {
			return f
		}
	}
	return def
}

// GetY1564Report — GET /jobs/{id}/report/y1564
//
// Optional query params to override per-service thresholds (applied uniformly
// across all services when provided):
//
//	latency_ms=50   — override max latency for all services
//	jitter_ms=20    — override max jitter for RTP
//	loss_pct=0.1    — override max packet loss for all services
func (h *ReportHandler) GetY1564Report(w http.ResponseWriter, r *http.Request) {
	id, err := parseJobID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid job id"})
		return
	}

	flows, err := h.store.GetFlowsByJob(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load flows"})
		return
	}

	// Apply query-param overrides to a copy of the default thresholds.
	thresholds := make([]serviceThreshold, len(defaultThresholds))
	copy(thresholds, defaultThresholds)
	if v := parseFloat64(r, "latency_ms", -1); v >= 0 {
		for i := range thresholds {
			thresholds[i].maxLatencyMs = v
		}
	}
	if v := parseFloat64(r, "jitter_ms", -1); v >= 0 {
		for i := range thresholds {
			if thresholds[i].maxJitterMs > 0 {
				thresholds[i].maxJitterMs = v
			}
		}
	}
	if v := parseFloat64(r, "loss_pct", -1); v >= 0 {
		for i := range thresholds {
			thresholds[i].maxLossPct = v
		}
	}

	// Determine a "reference IP" per protocol family to classify UL vs DL.
	// The most-common source IP for each protocol is treated as the network side (DL src).
	srcIPCount := make(map[string]map[string]int) // proto -> srcIP -> count
	for _, f := range flows {
		proto := string(f.Type)
		if srcIPCount[proto] == nil {
			srcIPCount[proto] = make(map[string]int)
		}
		srcIPCount[proto][f.SrcIP]++
	}
	refIP := make(map[string]string) // proto -> dominant srcIP (network/DL direction)
	for proto, counts := range srcIPCount {
		best, bestN := "", 0
		for ip, n := range counts {
			if n > bestN {
				best, bestN = ip, n
			}
		}
		refIP[proto] = best
	}

	// Accumulate per (protocol, direction).
	type dirKey struct{ proto, dir string }
	type measAccum struct {
		count        int
		totalLatency float64
		totalJitter  float64
		totalLoss    float64
	}
	accumMap := make(map[dirKey]*measAccum)

	extractMetrics := func(proto string, m map[string]any) (latency, jitter, loss float64, ok bool) {
		switch proto {
		case "RTP":
			return floatMetric(m, "rtt_ms"), floatMetric(m, "jitter_ms"), floatMetric(m, "loss_rate_pct"), true
		case "SIP":
			return floatMetric(m, "rtt_ms"), 0, floatMetric(m, "packet_loss_pct"), true
		case "TCP":
			return floatMetric(m, "rtt_ms"), 0, floatMetric(m, "packet_loss_pct"), true
		case "DNS":
			return floatMetric(m, "latency_ms"), 0, floatMetric(m, "packet_loss_pct"), true
		}
		return 0, 0, 0, false
	}

	for _, f := range flows {
		m := f.Metrics
		if m == nil {
			m = map[string]any{}
		}
		proto := string(f.Type)
		latency, jitter, loss, ok := extractMetrics(proto, m)
		if !ok {
			continue
		}

		// Classify direction: if srcIP matches the dominant source, it's DL; otherwise UL.
		dir := "UL"
		if f.SrcIP == refIP[proto] {
			dir = "DL"
		}

		// Accumulate combined (for overall row) and per-direction.
		for _, d := range []string{"ALL", dir} {
			k := dirKey{proto, d}
			if accumMap[k] == nil {
				accumMap[k] = &measAccum{}
			}
			a := accumMap[k]
			a.count++
			a.totalLatency += latency
			a.totalJitter += jitter
			a.totalLoss += loss
		}
	}

	buildVerdict := func(avgLatency, avgJitter, avgLoss float64, thr serviceThreshold) (string, bool, bool, bool, []string) {
		const warnMult = 1.2
		latencyPass := avgLatency <= thr.maxLatencyMs
		jitterPass := thr.maxJitterMs == 0 || avgJitter <= thr.maxJitterMs
		lossPass := avgLoss <= thr.maxLossPct

		var violations []string
		verdict := "PASS"

		applyCheck := func(pass bool, val, threshold float64, label, unit string) {
			if pass {
				return
			}
			if val <= threshold*warnMult {
				if verdict == "PASS" {
					verdict = "WARN"
				}
				violations = append(violations, fmt.Sprintf("%s %.2f%s > %.g%s", label, val, unit, threshold, unit))
			} else {
				verdict = "FAIL"
				violations = append(violations, fmt.Sprintf("%s %.2f%s >> %.g%s", label, val, unit, threshold, unit))
			}
		}

		applyCheck(latencyPass, avgLatency, thr.maxLatencyMs, "latency", "ms")
		if thr.maxJitterMs > 0 {
			applyCheck(jitterPass, avgJitter, thr.maxJitterMs, "jitter", "ms")
		}
		applyCheck(lossPass, avgLoss, thr.maxLossPct, "loss", "%")

		return verdict, latencyPass, jitterPass, lossPass, violations
	}

	services := make([]ServiceResult, 0, len(thresholds))
	overallPass := true

	for _, thr := range thresholds {
		allKey := dirKey{thr.protocol, "ALL"}
		a, exists := accumMap[allKey]
		if !exists {
			continue
		}

		avgLatency := a.totalLatency / float64(a.count)
		avgJitter := a.totalJitter / float64(a.count)
		avgLoss := a.totalLoss / float64(a.count)

		verdict, latencyPass, jitterPass, lossPass, violations := buildVerdict(avgLatency, avgJitter, avgLoss, thr)
		if violations == nil {
			violations = []string{}
		}
		if verdict == "FAIL" {
			overallPass = false
		}

		// Per-direction rows
		dirs := make([]DirectionResult, 0, 2)
		for _, d := range []string{"UL", "DL"} {
			da, ok := accumMap[dirKey{thr.protocol, d}]
			if !ok {
				continue
			}
			dAvgLat := da.totalLatency / float64(da.count)
			dAvgJit := da.totalJitter / float64(da.count)
			dAvgLoss := da.totalLoss / float64(da.count)
			dVerdict, _, _, _, dViol := buildVerdict(dAvgLat, dAvgJit, dAvgLoss, thr)
			if dViol == nil {
				dViol = []string{}
			}
			dirs = append(dirs, DirectionResult{
				Direction:     d,
				FlowCount:     da.count,
				MeasLatencyMs: dAvgLat,
				MeasJitterMs:  dAvgJit,
				MeasLossPct:   dAvgLoss,
				Overall:       dVerdict,
				Violations:    dViol,
			})
		}

		services = append(services, ServiceResult{
			Service:       thr.name,
			Protocol:      thr.protocol,
			FlowCount:     a.count,
			MaxLatencyMs:  thr.maxLatencyMs,
			MaxJitterMs:   thr.maxJitterMs,
			MaxLossPct:    thr.maxLossPct,
			MeasLatencyMs: avgLatency,
			MeasJitterMs:  avgJitter,
			MeasLossPct:   avgLoss,
			LatencyPass:   latencyPass,
			JitterPass:    jitterPass,
			LossPass:      lossPass,
			Overall:       verdict,
			Violations:    violations,
			Directions:    dirs,
		})
	}

	overall := "PASS"
	if !overallPass {
		overall = "FAIL"
	}

	writeJSON(w, http.StatusOK, Y1564Report{
		JobID:       id,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Overall:     overall,
		Services:    services,
	})
}

// GetCDRExport — GET /jobs/{id}/cdr
// Returns a CSV of all calls for the job with per-call metrics.
func (h *ReportHandler) GetCDRExport(w http.ResponseWriter, r *http.Request) {
	id, err := parseJobID(r)
	if err != nil {
		http.Error(w, "invalid job id", http.StatusBadRequest)
		return
	}

	calls, err := h.store.GetCallsByJob(id)
	if err != nil {
		http.Error(w, "failed to load calls", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="cdr_job_%d.csv"`, id))

	cw := csv.NewWriter(w)
	defer cw.Flush()

	// Header row
	_ = cw.Write([]string{
		"call_id", "from_uri", "to_uri",
		"start_time", "end_time", "duration_sec",
		"mos", "quality", "jitter_ms", "max_seq_gap",
		"packet_loss_pct", "end_type", "root_cause", "confidence",
	})

	for _, call := range calls {
		// SIP metadata
		fromURI := ""
		toURI := ""
		if call.SIPMetrics != nil {
			fromURI, _ = call.SIPMetrics["from"].(string)
			toURI, _ = call.SIPMetrics["to"].(string)
		}

		startStr := call.StartTime.Format(time.RFC3339)
		endStr := call.EndTime.Format(time.RFC3339)
		durationSec := call.EndTime.Sub(call.StartTime).Seconds()
		if durationSec < 0 {
			durationSec = 0
		}

		// Get RTP legs and compute avg jitter
		legs, _ := h.store.GetRTPLegsForCall(call.CallID)
		avgJitter := 0.0
		maxSeqGap := int64(0)
		if len(legs) > 0 {
			jitterSum := 0.0
			jitterCount := 0
			for _, leg := range legs {
				j := floatMetric(leg, "jitter_ms")
				if j > 0 {
					jitterSum += j
					jitterCount++
				}
				sg := int64Metric(leg, "max_seq_gap")
				if sg > maxSeqGap {
					maxSeqGap = sg
				}
			}
			if jitterCount > 0 {
				avgJitter = jitterSum / float64(jitterCount)
			}
		}

		// packet_loss_pct from SIP metrics or default 0
		pktLossPct := 0.0
		if call.SIPMetrics != nil {
			pktLossPct = floatMetric(call.SIPMetrics, "packet_loss_pct")
		}

		row := []string{
			call.CallID,
			fromURI,
			toURI,
			startStr,
			endStr,
			fmt.Sprintf("%.2f", durationSec),
			fmt.Sprintf("%.3f", call.MOS),
			call.Quality,
			fmt.Sprintf("%.2f", avgJitter),
			strconv.FormatInt(maxSeqGap, 10),
			fmt.Sprintf("%.2f", pktLossPct),
			call.EndType,
			call.RootCause,
			fmt.Sprintf("%.4f", call.Confidence),
		}
		_ = cw.Write(row)
	}
}

// parseJobID extracts and parses the {id} URL parameter.
func parseJobID(r *http.Request) (int64, error) {
	return strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
}
