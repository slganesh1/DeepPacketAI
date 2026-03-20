package api

import "time"

type TimelineEvent struct {
	Timestamp time.Time      `json:"timestamp"`
	Protocol  string         `json:"protocol"`
	Direction string         `json:"direction"`
	Method    string         `json:"method"`
	Src       string         `json:"src"`
	Dst       string         `json:"dst"`
	Details   map[string]any `json:"details,omitempty"`
}
