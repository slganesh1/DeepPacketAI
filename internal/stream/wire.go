package stream

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
)

const maxMsgSize = 8 * 1024 * 1024 // 8 MB safety limit

// writeMsg serialises v as JSON and writes it as a length-prefixed frame.
// Frame format: [4-byte big-endian length][JSON payload]
func writeMsg(conn net.Conn, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err = conn.Write(data)
	return err
}

// readMsg reads a length-prefixed JSON frame and unmarshals it into v.
func readMsg(conn net.Conn, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return fmt.Errorf("empty message")
	}
	if n > maxMsgSize {
		return fmt.Errorf("message too large: %d bytes (max %d)", n, maxMsgSize)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, v)
}
