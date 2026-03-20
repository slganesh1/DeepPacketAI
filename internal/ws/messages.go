package ws

// MessageType identifies the kind of WebSocket message.
type MessageType string

const (
	MsgPacket       MessageType = "packet"
	MsgStats        MessageType = "stats"
	MsgAlert        MessageType = "alert"
	MsgCaptureState MessageType = "capture_state"
	MsgChatChunk    MessageType = "chat_chunk"
)

// Message is the envelope sent over WebSocket.
type Message struct {
	Type    MessageType `json:"type"`
	Payload any         `json:"payload"`
}

// ClientCommand is a command received from a WebSocket client.
type ClientCommand struct {
	Action string         `json:"action"` // start_capture, stop_capture, set_filter
	Params map[string]any `json:"params,omitempty"`
}
