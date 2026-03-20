package api

import "time"

type EntitySummary struct {
	MOS        float64 `json:"mos"`
	Quality    string  `json:"quality"`
	RootCause  string  `json:"root_cause"`
	Confidence float64 `json:"confidence"`
}

type EntityItem struct {
	EntityID   string        `json:"entity_id"`
	EntityType string        `json:"entity_type"`
	Protocols  []string      `json:"protocols"`
	StartTime  time.Time     `json:"start_time"`
	EndTime    time.Time     `json:"end_time"`
	Summary    EntitySummary `json:"summary"`
}

type EntityListResponse struct {
	Total int          `json:"total"`
	Items []EntityItem `json:"items"`
}
