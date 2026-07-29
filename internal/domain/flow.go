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
	FlowHTTP2     FlowType = "HTTP2"
	FlowSBI       FlowType = "SBI"   // 3GPP Service Based Interface
	FlowNAS5G     FlowType = "NAS5G" // 5G NAS
	FlowGTPU      FlowType = "GTPU"  // GTP-U with inner packet info
	FlowAJP       FlowType = "AJP"   // Apache JServ Protocol (mod_jk/mod_proxy_ajp <-> servlet container)
	FlowSNMP      FlowType = "SNMP"  // Simple Network Management Protocol (v1/v2c)
	FlowICMP      FlowType = "ICMP"
	FlowICMPv6    FlowType = "ICMPv6"
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
