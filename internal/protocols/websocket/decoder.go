package websocket

import (
	"encoding/binary"
	"fmt"
	"strings"

	"DeepPacketAI/internal/domain"
	"DeepPacketAI/internal/protocols"
)

// WebSocket opcodes
const (
	OpContinuation = 0
	OpText         = 1
	OpBinary       = 2
	OpClose        = 8
	OpPing         = 9
	OpPong         = 10
)

var opcodeNames = map[byte]string{
	OpContinuation: "continuation",
	OpText:         "text",
	OpBinary:       "binary",
	OpClose:        "close",
	OpPing:         "ping",
	OpPong:         "pong",
}

// Decoder decodes WebSocket frames and tracks connections.
type Decoder struct {
	connections map[string]*wsConnection
}

type wsConnection struct {
	ID        string
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Upgraded  bool
	Frames    int
	TextBytes int
	BinBytes  int
	StartTime interface{}
	EndTime   interface{}
}

func NewDecoder() *Decoder {
	return &Decoder{
		connections: make(map[string]*wsConnection),
	}
}

func (d *Decoder) Name() string { return "websocket" }

func (d *Decoder) HandlePacket(pkt *domain.Packet) {
	if pkt.Protocol != "TCP" {
		return
	}
	if len(pkt.Payload) < 2 {
		return
	}

	// Check for HTTP upgrade to WebSocket
	if isWebSocketUpgrade(pkt.Payload) {
		key := connKey(pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort)
		conn := d.getOrCreateConn(key, pkt)
		conn.Upgraded = true
		pkt.AppProtocol = "WebSocket"
		pkt.Summary = "WebSocket Upgrade"
		return
	}

	if isWebSocketUpgradeResponse(pkt.Payload) {
		key := connKey(pkt.DstIP, pkt.SrcIP, pkt.DstPort, pkt.SrcPort)
		conn := d.getOrCreateConn(key, pkt)
		conn.Upgraded = true
		pkt.AppProtocol = "WebSocket"
		pkt.Summary = "101 Switching Protocols"
		return
	}

	// Try to parse as WebSocket frame
	frame := parseFrame(pkt.Payload)
	if frame == nil {
		return
	}

	// Only decode if we've seen an upgrade for this connection, or if it looks
	// like a valid WebSocket frame on common HTTP ports
	key := connKey(pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort)
	rkey := connKey(pkt.DstIP, pkt.SrcIP, pkt.DstPort, pkt.SrcPort)
	conn, ok := d.connections[key]
	if !ok {
		conn, ok = d.connections[rkey]
	}
	if !ok {
		// No upgrade seen — only accept on HTTP ports
		if !isHTTPPort(pkt.SrcPort, pkt.DstPort) {
			return
		}
		conn = d.getOrCreateConn(key, pkt)
	}

	conn.Frames++
	conn.EndTime = pkt.Timestamp

	opName := opcodeNames[frame.Opcode]
	if opName == "" {
		opName = fmt.Sprintf("opcode_%d", frame.Opcode)
	}

	switch frame.Opcode {
	case OpText:
		conn.TextBytes += frame.PayloadLen
	case OpBinary:
		conn.BinBytes += frame.PayloadLen
	}

	pkt.AppProtocol = "WebSocket"
	summary := fmt.Sprintf("[%s] len=%d", opName, frame.PayloadLen)
	if frame.FIN {
		summary += " FIN"
	}
	if frame.Opcode == OpText && frame.PayloadLen > 0 && frame.PayloadLen <= 120 {
		preview := frame.PayloadPreview
		if len(preview) > 80 {
			preview = preview[:80] + "..."
		}
		summary += " " + preview
	}
	if frame.Opcode == OpClose && frame.PayloadLen >= 2 {
		closeCode := binary.BigEndian.Uint16(pkt.Payload[frame.HeaderLen : frame.HeaderLen+2])
		summary = fmt.Sprintf("[close] code=%d", closeCode)
	}
	pkt.Summary = summary
}

func (d *Decoder) HandlePacketLive(pkt *domain.Packet) *protocols.DecodedPacket {
	oldProto := pkt.AppProtocol
	oldSummary := pkt.Summary

	d.HandlePacket(pkt)

	if pkt.AppProtocol == "WebSocket" && pkt.AppProtocol != oldProto {
		return &protocols.DecodedPacket{
			Packet:   pkt,
			Protocol: "WebSocket",
			Summary:  pkt.Summary,
			Metadata: pkt.Metadata,
			Errors:   pkt.Errors,
		}
	}

	pkt.AppProtocol = oldProto
	pkt.Summary = oldSummary
	return nil
}

func (d *Decoder) Flush() []domain.Flow {
	var flows []domain.Flow

	for _, conn := range d.connections {
		metrics := map[string]any{
			"frames":     conn.Frames,
			"text_bytes": conn.TextBytes,
			"bin_bytes":  conn.BinBytes,
			"upgraded":   conn.Upgraded,
		}

		flows = append(flows, domain.Flow{
			FlowID:  conn.ID,
			Type:    domain.FlowWebSocket,
			SrcIP:   conn.SrcIP,
			DstIP:   conn.DstIP,
			SrcPort: conn.SrcPort,
			DstPort: conn.DstPort,
			Metrics: metrics,
		})
	}

	return flows
}

func (d *Decoder) getOrCreateConn(key string, pkt *domain.Packet) *wsConnection {
	if conn, ok := d.connections[key]; ok {
		return conn
	}
	conn := &wsConnection{
		ID:        fmt.Sprintf("ws-%s-%d", key, pkt.FrameNumber),
		SrcIP:     pkt.SrcIP,
		DstIP:     pkt.DstIP,
		SrcPort:   pkt.SrcPort,
		DstPort:   pkt.DstPort,
		StartTime: pkt.Timestamp,
	}
	d.connections[key] = conn
	return conn
}

// wsFrame holds parsed WebSocket frame info.
type wsFrame struct {
	FIN            bool
	Opcode         byte
	Masked         bool
	PayloadLen     int
	HeaderLen      int
	PayloadPreview string
}

func parseFrame(data []byte) *wsFrame {
	if len(data) < 2 {
		return nil
	}

	fin := (data[0] & 0x80) != 0
	opcode := data[0] & 0x0F

	// Validate opcode
	if opcode > 10 || (opcode >= 3 && opcode <= 7) {
		return nil
	}

	masked := (data[1] & 0x80) != 0
	payloadLen := int(data[1] & 0x7F)
	headerLen := 2

	if payloadLen == 126 {
		if len(data) < 4 {
			return nil
		}
		payloadLen = int(binary.BigEndian.Uint16(data[2:4]))
		headerLen = 4
	} else if payloadLen == 127 {
		if len(data) < 10 {
			return nil
		}
		payloadLen = int(binary.BigEndian.Uint64(data[2:10]))
		headerLen = 10
	}

	if masked {
		headerLen += 4
	}

	if len(data) < headerLen {
		return nil
	}

	// Extract payload preview for text frames
	var preview string
	if opcode == OpText && payloadLen > 0 {
		payloadStart := headerLen
		end := payloadStart + payloadLen
		if end > len(data) {
			end = len(data)
		}
		if masked && end > payloadStart && headerLen >= 4 {
			// Unmask for preview
			maskKey := data[headerLen-4 : headerLen]
			maxPreview := 120
			if payloadLen < maxPreview {
				maxPreview = payloadLen
			}
			if end-payloadStart < maxPreview {
				maxPreview = end - payloadStart
			}
			unmasked := make([]byte, maxPreview)
			for i := 0; i < maxPreview; i++ {
				unmasked[i] = data[payloadStart+i] ^ maskKey[i%4]
			}
			preview = string(unmasked)
		} else if end > payloadStart {
			maxPreview := 120
			if end-payloadStart < maxPreview {
				maxPreview = end - payloadStart
			}
			preview = string(data[payloadStart : payloadStart+maxPreview])
		}
	}

	return &wsFrame{
		FIN:            fin,
		Opcode:         opcode,
		Masked:         masked,
		PayloadLen:     payloadLen,
		HeaderLen:      headerLen,
		PayloadPreview: preview,
	}
}

func isWebSocketUpgrade(payload []byte) bool {
	if len(payload) < 20 {
		return false
	}
	s := string(payload[:min(len(payload), 512)])
	return strings.HasPrefix(s, "GET ") &&
		strings.Contains(strings.ToLower(s), "upgrade: websocket")
}

func isWebSocketUpgradeResponse(payload []byte) bool {
	if len(payload) < 20 {
		return false
	}
	s := string(payload[:min(len(payload), 512)])
	return strings.HasPrefix(s, "HTTP/1.1 101") &&
		strings.Contains(strings.ToLower(s), "upgrade: websocket")
}

func isHTTPPort(src, dst uint16) bool {
	switch src {
	case 80, 8080, 8000, 8888, 3000:
		return true
	}
	switch dst {
	case 80, 8080, 8000, 8888, 3000:
		return true
	}
	return false
}

func connKey(srcIP, dstIP string, srcPort, dstPort uint16) string {
	return fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var _ protocols.StreamingDecoder = (*Decoder)(nil)
