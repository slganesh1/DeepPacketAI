package api

import "time"

type EntityDetailResponse struct {
	Entity         EntityItem        `json:"entity"`
	RTPLegs        []map[string]any  `json:"rtp_legs"`
	Events         []EntityEvent     `json:"events"`
	Metrics        []EntityMetric    `json:"metrics"`
	SetupLatencyMs *float64          `json:"setup_latency_ms,omitempty"`
}

type EntityEvent struct {
	Timestamp time.Time         `json:"timestamp"`
	Type      string            `json:"type"`
	Attrs     map[string]any    `json:"attributes"`
}

type EntityMetric struct {
	Name  string      `json:"name"`
	Value interface{} `json:"value"`
	Unit  string      `json:"unit,omitempty"`
}
