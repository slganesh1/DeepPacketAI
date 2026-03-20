package domain

import "time"

type FlowType string

const (
	FlowHTTP      FlowType = "HTTP"
	FlowTLS       FlowType = "TLS"
	FlowSIP       FlowType = "SIP"
	FlowRTP       FlowType = "RTP"
	FlowDNS       FlowType = "DNS"
	FlowDiameter  FlowType = "Diameter"
	FlowGTP       FlowType = "GTP"
	FlowPFCP      FlowType = "PFCP"
	FlowSCTP      FlowType = "SCTP"
	FlowS1AP      FlowType = "S1AP"
	FlowNGAP      FlowType = "NGAP"
	FlowWebSocket FlowType = "WebSocket"
	FlowTCP       FlowType = "TCP"
	FlowUDP       FlowType = "UDP"
)

type Flow struct {
	FlowID    string
	Type      FlowType
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	StartTime time.Time
	EndTime   time.Time
	Metrics   map[string]any
}
