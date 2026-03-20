package events

import "time"

// EventType identifies the kind of pipeline event.
type EventType string

const (
	EventRTCPReport EventType = "rtcp_report"
)

// Event is a generic pipeline event emitted by protocol decoders.
type Event struct {
	Type      EventType         `json:"type"`
	SessionID string            `json:"session_id"`
	Timestamp time.Time         `json:"timestamp"`
	Source    string            `json:"source"`
	Fields    map[string]string `json:"fields,omitempty"`
}
