package api

import "time"

type JobItem struct {
	JobID       int64      `json:"job_id"`
	PCAPPath    string     `json:"pcap_path"`
	Status      string     `json:"status"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Error       string     `json:"error,omitempty"`
}

