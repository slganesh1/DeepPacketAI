package domain

import "time"

// PacketError represents a detected protocol error in a packet.
type PacketError struct {
	Code        string
	Title       string
	Description string
	Severity    string // critical, error, warning, info
}

type Packet struct {
	Timestamp   time.Time
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	Protocol    string // TCP / UDP / SCTP
	Payload     []byte
	FrameNumber uint64
	Length      int
	AppProtocol string // SIP, RTP, DNS, HTTP, Diameter, GTP, PFCP, S1AP, NGAP
	Summary     string
	Metadata    map[string]any
	Errors      []PacketError
	RawPacket   []byte // full raw packet bytes for hex dump
	TCPSeq      uint32 // TCP sequence number (for reassembly)
	TCPAck      uint32 // TCP acknowledgment number
	TCPFlags    uint16 // SYN=0x02, FIN=0x01, RST=0x04, PSH=0x08, ACK=0x10
	Reassembled bool   // true if this packet was synthesized from reassembled TCP data
	TTL         uint8  // IPv4 TTL / IPv6 Hop Limit
	IPID        uint16 // IPv4 Identification field (0 for IPv6, which has no base-header ID)
}
