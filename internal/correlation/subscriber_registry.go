// Package correlation — subscriber tracking registry.
//
// SubscriberRegistry maintains a live index of all known subscribers,
// keyed by IMSI, MSISDN, UE IP, and TEID for fast cross-protocol lookup.
package correlation

import (
	"sync"
	"time"

	"DeepPacketAI/internal/domain"
)

// SubscriberProfile is a fully enriched subscriber record built from one or
// more TelecomSessions.
type SubscriberProfile struct {
	IMSI           string    `json:"imsi"`
	MSISDN         string    `json:"msisdn,omitempty"`
	UEIPs          []string  `json:"ue_ips,omitempty"`
	TEIDs          []string  `json:"teids,omitempty"`        // all GTP TEIDs (header + bearer)
	BearerTEIDs    []string  `json:"bearer_teids,omitempty"` // GTP-U data-plane TEIDs
	SEIDs          []string  `json:"seids,omitempty"`
	APN            string    `json:"apn,omitempty"`
	PDNType        string    `json:"pdn_type,omitempty"`
	RATType        string    `json:"rat_type,omitempty"`
	ServingNetwork string    `json:"serving_network,omitempty"`
	Location       string    `json:"location,omitempty"`
	State          string    `json:"state"` // last known UE state
	SessionIDs     []string  `json:"session_ids,omitempty"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
}

// SubscriberRegistry indexes subscribers from completed TelecomSessions for
// fast lookup by any identifier.
type SubscriberRegistry struct {
	mu       sync.RWMutex
	byIMSI   map[string]*SubscriberProfile
	byMSISDN map[string]*SubscriberProfile
	byUEIP   map[string]*SubscriberProfile
	byTEID   map[string]*SubscriberProfile
}

// NewSubscriberRegistry creates an empty registry.
func NewSubscriberRegistry() *SubscriberRegistry {
	return &SubscriberRegistry{
		byIMSI:   make(map[string]*SubscriberProfile),
		byMSISDN: make(map[string]*SubscriberProfile),
		byUEIP:   make(map[string]*SubscriberProfile),
		byTEID:   make(map[string]*SubscriberProfile),
	}
}

// Update upserts a TelecomSession into the registry, enriching the subscriber
// profile with any new identifiers found in the session.
func (r *SubscriberRegistry) Update(sess domain.TelecomSession) {
	if sess.IMSI == "" {
		return // only track IMSI-anchored subscribers
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	prof, exists := r.byIMSI[sess.IMSI]
	if !exists {
		prof = &SubscriberProfile{
			IMSI:      sess.IMSI,
			FirstSeen: sess.StartTime,
		}
		r.byIMSI[sess.IMSI] = prof
	}

	// Enrich scalar fields
	if prof.MSISDN == "" && sess.MSISDN != "" {
		prof.MSISDN = sess.MSISDN
	}
	if prof.APN == "" && sess.APN != "" {
		prof.APN = sess.APN
	}
	if prof.PDNType == "" && sess.PDNType != "" {
		prof.PDNType = sess.PDNType
	}
	if prof.RATType == "" && sess.RATType != "" {
		prof.RATType = sess.RATType
	}
	if prof.ServingNetwork == "" && sess.ServingNetwork != "" {
		prof.ServingNetwork = sess.ServingNetwork
	}
	if sess.Location != "" {
		prof.Location = sess.Location // always update to latest
	}

	// State: always reflect latest
	if sess.UEState != "" {
		prof.State = string(sess.UEState)
	}

	// Session ID list
	prof.SessionIDs = appendUniq(prof.SessionIDs, sess.SessionID)

	// UE IPs
	if sess.UEIP != "" {
		if appendUniq(prof.UEIPs, sess.UEIP) != nil {
			prof.UEIPs = appendUniq(prof.UEIPs, sess.UEIP)
		}
		r.byUEIP[sess.UEIP] = prof
	}

	// TEIDs
	for _, teid := range sess.TEIDs {
		prof.TEIDs = appendUniq(prof.TEIDs, teid)
		r.byTEID[teid] = prof
	}
	for _, teid := range sess.BearerTEIDs {
		prof.BearerTEIDs = appendUniq(prof.BearerTEIDs, teid)
	}
	for _, seid := range sess.SEIDs {
		prof.SEIDs = appendUniq(prof.SEIDs, seid)
	}

	// Timestamps
	if !sess.StartTime.IsZero() && (prof.FirstSeen.IsZero() || sess.StartTime.Before(prof.FirstSeen)) {
		prof.FirstSeen = sess.StartTime
	}
	if !sess.EndTime.IsZero() && sess.EndTime.After(prof.LastSeen) {
		prof.LastSeen = sess.EndTime
	}

	// Secondary index: MSISDN
	if prof.MSISDN != "" {
		r.byMSISDN[prof.MSISDN] = prof
	}
}

// UpdateAll updates the registry from a slice of sessions (e.g. after Trace()).
func (r *SubscriberRegistry) UpdateAll(sessions []domain.TelecomSession) {
	for _, s := range sessions {
		r.Update(s)
	}
}

// LookupByIMSI returns the subscriber profile for the given IMSI.
func (r *SubscriberRegistry) LookupByIMSI(imsi string) (*SubscriberProfile, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byIMSI[imsi]
	return p, ok
}

// LookupByMSISDN returns the subscriber profile for the given MSISDN.
func (r *SubscriberRegistry) LookupByMSISDN(msisdn string) (*SubscriberProfile, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byMSISDN[msisdn]
	return p, ok
}

// LookupByUEIP returns the subscriber associated with a UE data-plane IP address.
func (r *SubscriberRegistry) LookupByUEIP(ueIP string) (*SubscriberProfile, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byUEIP[ueIP]
	return p, ok
}

// LookupByTEID returns the subscriber associated with a GTP TEID (hex string "0x...").
func (r *SubscriberRegistry) LookupByTEID(teid string) (*SubscriberProfile, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byTEID[teid]
	return p, ok
}

// All returns a snapshot of all registered subscriber profiles.
func (r *SubscriberRegistry) All() []*SubscriberProfile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*SubscriberProfile, 0, len(r.byIMSI))
	for _, p := range r.byIMSI {
		cp := *p
		result = append(result, &cp)
	}
	return result
}

// Count returns the number of known subscribers.
func (r *SubscriberRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byIMSI)
}
