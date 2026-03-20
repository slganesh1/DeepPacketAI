package domain

import "time"

type Call struct {
	CallID    string
	StartTime time.Time
	EndTime   time.Time

	SIPMetrics map[string]any
	RTPLegs []map[string]any

	MOS     float64
	Quality string

	IsOnHold   bool
	EndType    string
	RootCause string
	Confidence float64
}


