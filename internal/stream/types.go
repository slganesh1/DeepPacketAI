// Package stream implements the agent→central packet streaming protocol.
// Agents capture packets locally and stream them over TCP (optionally TLS) to
// a central node for analysis, storage, and UI display.
package stream

import "time"

// AgentInfo identifies a capture agent node.
type AgentInfo struct {
	ID        string `json:"id"`
	Hostname  string `json:"hostname"`
	Interface string `json:"iface"`
}

// RawPacketMsg is a single captured packet as transmitted over the wire.
type RawPacketMsg struct {
	TimestampNs   int64  `json:"ts_ns"`
	CaptureLength int    `json:"cap_len"`
	Length        int    `json:"len"`
	LinkType      int    `json:"link_type"` // layers.LinkType value
	Data          []byte `json:"data"`
}

// PacketBatch is a batch of raw packets sent from an agent to central.
// When Packets is empty the batch acts as a heartbeat — central updates
// LastBatchAt so staleness detection stays accurate on quiet interfaces.
type PacketBatch struct {
	AgentID string         `json:"agent_id"`
	SeqNum  uint64         `json:"seq"`
	Drops   uint64         `json:"drops,omitempty"` // packets dropped due to backpressure since last batch
	Packets []RawPacketMsg `json:"packets"`
}

// Handshake is sent by the agent immediately after connecting.
type Handshake struct {
	Version     string    `json:"version"`
	Agent       AgentInfo `json:"agent"`
	Token       string    `json:"token,omitempty"`        // pre-shared auth token
	CanCompress bool      `json:"can_compress,omitempty"` // agent supports zlib compression
	LinkType    int       `json:"link_type,omitempty"`    // gopacket/layers.LinkType of the capture interface (0 → Ethernet)
}

// HandshakeAck is sent by central in response to Handshake.
type HandshakeAck struct {
	OK          bool   `json:"ok"`
	SessionID   string `json:"session_id,omitempty"`
	Message     string `json:"message,omitempty"`
	UseCompress bool   `json:"use_compress,omitempty"` // central requests zlib for batches
}

// FilterUpdate is sent from central to agent to hot-swap the BPF capture filter
// without restarting the agent process.
type FilterUpdate struct {
	AgentID   string `json:"agent_id"`
	BPFFilter string `json:"bpf_filter"`
}

// AgentConfig holds optional configuration for an AgentStreamer.
type AgentConfig struct {
	Token         string  // pre-shared auth token sent in Handshake
	UseTLS        bool    // wrap the TCP connection in TLS
	TLSSkipVerify bool    // skip server cert verification (useful with self-signed certs)
	TLSCA         string  // path to CA cert PEM file (for verifying central's cert)
	MaxMbps       float64 // outbound bandwidth cap in Mbit/s (0 = unlimited)
}

// HeartbeatInterval is how often the agent sends an empty batch when idle.
const HeartbeatInterval = 10 * time.Second

// StaleTimeout is how long central waits before marking an agent as stale.
const StaleTimeout = 30 * time.Second
