package sip

import (
	"fmt"
	"time"

	"DeepPacketAI/internal/domain"
)

// HoldEvent records a single hold or unhold transition.
type HoldEvent struct {
	Timestamp time.Time
	Direction string // "sendonly", "inactive", "sendrecv", "recvonly"
	IsHold    bool   // true if this is a hold, false if unhold
}

type SIPSession struct {
	CallID       string
	SrcIP        string
	DstIP        string
	StartTime    time.Time
	InviteTime  time.Time
	ByeTime           time.Time
	FirstResponseTime time.Time // timestamp of first 200 OK response
	Method            string
	From         string
	To           string
	LastResponse string
	MediaIP      string
	MediaPort    string
	Direction    string
	HoldEvents  []HoldEvent
	HoldCount   int
}

// trackDirectionChange detects hold/unhold transitions and records them.
func (s *SIPSession) trackDirectionChange(newDirection string, ts time.Time) {
	oldDir := s.Direction
	s.Direction = newDirection

	isHold := newDirection == "sendonly" || newDirection == "inactive"
	wasHold := oldDir == "sendonly" || oldDir == "inactive"

	// Only record transitions (not the initial direction setting)
	if oldDir != "" && isHold != wasHold {
		s.HoldEvents = append(s.HoldEvents, HoldEvent{
			Timestamp: ts,
			Direction: newDirection,
			IsHold:    isHold,
		})
		if isHold {
			s.HoldCount++
		}
	} else if oldDir == "" && isHold {
		// First SDP is already a hold
		s.HoldEvents = append(s.HoldEvents, HoldEvent{
			Timestamp: ts,
			Direction: newDirection,
			IsHold:    true,
		})
		s.HoldCount++
	}
}

// holdEventStrings returns human-readable hold event descriptions.
func (s *SIPSession) holdEventStrings() []string {
	var events []string
	for _, e := range s.HoldEvents {
		action := "HOLD"
		if !e.IsHold {
			action = "UNHOLD"
		}
		events = append(events, fmt.Sprintf("%s at %s (direction=%s)",
			action, e.Timestamp.Format(time.RFC3339), e.Direction))
	}
	return events
}

func (d *SIPDecoder) getSession(callID string, pkt *domain.Packet) *SIPSession {
	if s, ok := d.sessions[callID]; ok {
		return s
	}

	s := &SIPSession{
		CallID:    callID,
		SrcIP:     pkt.SrcIP,
		DstIP:     pkt.DstIP,
		StartTime: pkt.Timestamp,
	}

	d.sessions[callID] = s
	return s
}
