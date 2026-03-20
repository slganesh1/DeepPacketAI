// Package metrics defines all Prometheus metrics for DeepPacketAI.
//
// Usage from any package:
//
//	metrics.PacketsTotal.WithLabelValues("live", "TCP").Inc()
//	metrics.DecodeErrors.WithLabelValues("sip").Inc()
//
// The /metrics HTTP endpoint is wired up in the web router.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const ns = "deeppacketai"

// ── Packet counters ────────────────────────────────────────────────────────────

// PacketsTotal counts every packet seen, labelled by source ("live" / "pcap")
// and transport protocol ("TCP", "UDP", "SCTP").
var PacketsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: ns, Name: "packets_total",
		Help: "Total packets processed.",
	},
	[]string{"source", "protocol"},
)

// BytesTotal counts payload bytes, labelled by source.
var BytesTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: ns, Name: "bytes_total",
		Help: "Total bytes processed.",
	},
	[]string{"source"},
)

// PacketsDropped counts packets dropped (channel full, parse error before
// handing to decoders, etc.), labelled by reason.
var PacketsDropped = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: ns, Name: "packets_dropped_total",
		Help: "Packets dropped before decoding.",
	},
	[]string{"reason"},
)

// PacketsPerSecond is a gauge that the stats ticker updates every second.
var PacketsPerSecond = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Namespace: ns, Name: "packets_per_second",
		Help: "Current packet rate (packets/s) from the live capture ticker.",
	},
	[]string{"source"},
)

// BytesPerSecond mirrors the live bandwidth gauge.
var BytesPerSecond = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Namespace: ns, Name: "bytes_per_second",
		Help: "Current byte throughput (bytes/s) from the live capture ticker.",
	},
	[]string{"source"},
)

// ── Decode errors ──────────────────────────────────────────────────────────────

// DecodeErrors counts protocol decode failures, labelled by protocol name.
var DecodeErrors = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: ns, Name: "decode_errors_total",
		Help: "Protocol decode errors reported by decoders.",
	},
	[]string{"protocol", "error_type"},
)

// ── Flow metrics ───────────────────────────────────────────────────────────────

// FlowsTotal counts completed flows flushed, labelled by protocol and source.
var FlowsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: ns, Name: "flows_total",
		Help: "Total flows completed and flushed.",
	},
	[]string{"source", "protocol"},
)

// FlowsActive is the current number of in-progress flows tracked by the
// flowengine (updated by the Tracker at Flush time).
var FlowsActive = promauto.NewGauge(prometheus.GaugeOpts{
	Namespace: ns, Name: "flows_active",
	Help: "Number of flows currently open in the flow tracker.",
})

// ── Job / PCAP pipeline counters ───────────────────────────────────────────────

// PCAPJobsTotal counts PCAP analysis jobs, labelled by status.
var PCAPJobsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: ns, Name: "pcap_jobs_total",
		Help: "PCAP analysis jobs processed.",
	},
	[]string{"status"}, // "completed", "failed"
)

// PCAPPacketsProcessed counts total packets read from PCAP files.
var PCAPPacketsProcessed = promauto.NewCounter(prometheus.CounterOpts{
	Namespace: ns, Name: "pcap_packets_processed_total",
	Help: "Total packets read from all PCAP files.",
})

// ── Protocol layer counters ────────────────────────────────────────────────────

// ProtocolPackets counts packets per application-layer protocol (SIP, GTP, DNS…).
var ProtocolPackets = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: ns, Name: "protocol_packets_total",
		Help: "Packets decoded per application-layer protocol.",
	},
	[]string{"protocol"},
)

// ── HTTP server metrics ────────────────────────────────────────────────────────

// HTTPRequestDuration tracks API endpoint latency as a histogram.
var HTTPRequestDuration = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Namespace: ns, Name: "http_request_duration_seconds",
		Help:    "HTTP request durations.",
		Buckets: prometheus.DefBuckets,
	},
	[]string{"method", "path", "status"},
)

// ── WebSocket ─────────────────────────────────────────────────────────────────

// WSClients is the current number of connected WebSocket clients.
var WSClients = promauto.NewGauge(prometheus.GaugeOpts{
	Namespace: ns, Name: "websocket_clients",
	Help: "Number of currently connected WebSocket clients.",
})

// ── Telecom session counters ──────────────────────────────────────────────────

// TelecomSessionsTotal counts completed telecom (5G/4G) sessions traced.
var TelecomSessionsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: ns, Name: "telecom_sessions_total",
		Help: "Telecom sessions traced.",
	},
	[]string{"complete"}, // "true" / "false"
)
