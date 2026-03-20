package domain

import "time"

// UEState represents the current state in the UE lifecycle state machine.
type UEState string

const (
	UEStateIdle           UEState = "idle"
	UEStateAttaching      UEState = "attaching"
	UEStateRegistered     UEState = "registered"
	UEStatePDUEstablishing UEState = "pdu_establishing"
	UEStateActive         UEState = "active"
	UEStateReleasing      UEState = "releasing"
)

// UELifecycleStep is a key milestone in the UE session lifecycle with timing.
type UELifecycleStep struct {
	Step      string    `json:"step"`       // e.g. "UE_Attach", "PDU_Session_Up", "SIP_Registered"
	Protocol  string    `json:"protocol"`
	Timestamp time.Time `json:"timestamp"`
	DeltaMs   int64     `json:"delta_ms"`   // ms since session start
	Details   string    `json:"details"`
}

// TelecomSession represents a fully traced UE call across the 5G/4G stack.
//
// Correlation hierarchy:
//
//	IMSI (primary key from NGAP/GTP-C/Diameter)
//	  ├── NGAP     : UE ↔ AMF (registration, NAS transport)
//	  ├── GTP-C    : AMF/SMF ↔ UPF (session establishment)
//	  ├── PFCP     : SMF ↔ UPF (user-plane rule setup)
//	  ├── GTP-U    : UPF data tunnel (matched by TEID or time)
//	  ├── Diameter : HSS/AAA authentication
//	  └── SIP      : IMS call (matched by UE IP or time)
//	      └── RTP  : media streams (matched by SIP SDP media endpoint)
type TelecomSession struct {
	SessionID string `json:"session_id"` // "ue-<IMSI>" or "ims-<CallID>"

	// Subscriber identity
	IMSI   string `json:"imsi,omitempty"`
	MSISDN string `json:"msisdn,omitempty"`
	APN    string `json:"apn,omitempty"`
	UEIP   string `json:"ue_ip,omitempty"` // PDN/data-plane IP assigned by UPF

	// Network context
	RATType        string `json:"rat_type,omitempty"`         // e.g. "E-UTRAN", "NR"
	ServingNetwork string `json:"serving_network,omitempty"`  // MCC-MNC e.g. "310-260"
	Location       string `json:"location,omitempty"`         // TAI or ECGI
	PDNType        string `json:"pdn_type,omitempty"`         // IPv4, IPv6, IPv4v6

	// IMS call identity
	SIPCallID string `json:"sip_call_id,omitempty"`
	SIPFrom   string `json:"sip_from,omitempty"`
	SIPTo     string `json:"sip_to,omitempty"`

	// Per-layer hops (each hop = one decoded flow)
	NGAP       []TraceHop `json:"ngap,omitempty"`       // UE ↔ AMF
	GTPControl []TraceHop `json:"gtp_control,omitempty"` // GTP-C  (SMF ↔ UPF)
	PFCP       []TraceHop `json:"pfcp,omitempty"`        // PFCP   (SMF ↔ UPF)
	GTPUser    []TraceHop `json:"gtp_user,omitempty"`    // GTP-U  (UPF tunnel)
	SIP        []TraceHop `json:"sip,omitempty"`         // IMS signalling
	RTP        []TraceHop `json:"rtp,omitempty"`         // Media streams
	Diameter   []TraceHop `json:"diameter,omitempty"`    // HSS / AAA

	// Correlation identifiers collected from flows
	TEIDs       []string `json:"teids,omitempty"`        // All GTP TEIDs (header + bearer F-TEIDs)
	BearerTEIDs []string `json:"bearer_teids,omitempty"` // GTP-U bearer F-TEIDs specifically
	SEIDs       []string `json:"seids,omitempty"`        // PFCP SEIDs seen

	// Chronological event timeline (all layers merged and sorted)
	Events []TraceEvent `json:"events,omitempty"`

	// UE lifecycle state machine
	UEState   UEState           `json:"ue_state,omitempty"`
	Lifecycle []UELifecycleStep `json:"lifecycle,omitempty"`

	// Session timing
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`

	// Voice quality
	MOS     float64 `json:"mos,omitempty"`
	Quality string  `json:"quality,omitempty"` // "good", "fair", "poor"

	// Completeness flags
	HasNGAP     bool `json:"has_ngap"`
	HasGTPC     bool `json:"has_gtpc"`
	HasPFCP     bool `json:"has_pfcp"`
	HasGTPU     bool `json:"has_gtpu"`
	HasSIP      bool `json:"has_sip"`
	HasRTP      bool `json:"has_rtp"`
	HasDiameter bool `json:"has_diameter"`
	IsComplete  bool `json:"is_complete"` // true when NGAP+GTP-C+SIP+RTP all present
}

// TraceHop is a single decoded flow contribution within a TelecomSession.
type TraceHop struct {
	Protocol  string         `json:"protocol"`
	FlowID    string         `json:"flow_id"`
	SrcIP     string         `json:"src_ip"`
	DstIP     string         `json:"dst_ip"`
	SrcPort   uint16         `json:"src_port"`
	DstPort   uint16         `json:"dst_port"`
	StartTime time.Time      `json:"start_time"`
	EndTime   time.Time      `json:"end_time"`
	Metrics   map[string]any `json:"metrics,omitempty"`
}

// TraceEvent is one timestamped signalling step in the session timeline.
type TraceEvent struct {
	Timestamp time.Time      `json:"timestamp"`
	Protocol  string         `json:"protocol"`
	Step      string         `json:"step"`    // e.g. "UE_Registration", "PDU_Session_Establish"
	Summary   string         `json:"summary"` // human-readable one-liner
	SrcIP     string         `json:"src_ip"`
	DstIP     string         `json:"dst_ip"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}
