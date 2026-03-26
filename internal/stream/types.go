// Package stream implements the agent→central packet streaming protocol.
// Agents capture packets locally and stream them over TCP to a central node
// for analysis, storage, and UI display — without requiring a full DeepPacketAI
// stack on each capture machine.
package stream

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
type PacketBatch struct {
	AgentID string         `json:"agent_id"`
	SeqNum  uint64         `json:"seq"`
	Packets []RawPacketMsg `json:"packets"`
}

// Handshake is sent by the agent immediately after connecting.
type Handshake struct {
	Version string    `json:"version"`
	Agent   AgentInfo `json:"agent"`
}

// HandshakeAck is sent by central in response to Handshake.
type HandshakeAck struct {
	OK        bool   `json:"ok"`
	SessionID string `json:"session_id,omitempty"`
	Message   string `json:"message,omitempty"`
}
