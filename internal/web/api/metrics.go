package api

import "time"

type MetricPoint struct {
	Timestamp time.Time `json:"ts"`
	Value     float64   `json:"value"`
}

type EntityMetrics struct {
	EntityID string                         `json:"entity_id"`
	Metrics  map[string][]MetricPoint       `json:"metrics"`
}
