package stream

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
)

const maxMsgSize = 8 * 1024 * 1024 // 8 MB safety limit

// writeMsg serialises v as JSON and writes it as a length-prefixed frame.
// Frame format: [4-byte big-endian length][JSON payload]
// Header and payload are combined into a single Write to prevent partial
// frames if the connection fails between the two calls.
func writeMsg(conn net.Conn, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	out := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(out, uint32(len(data)))
	copy(out[4:], data)
	_, err = conn.Write(out)
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

// writeMsgZlib serialises v as JSON, compresses the payload with zlib, and
// writes it as a length-prefixed frame. Used for PacketBatch after the central
// confirms compression in HandshakeAck.UseCompress.
func writeMsgZlib(conn net.Conn, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		return fmt.Errorf("zlib write: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("zlib close: %w", err)
	}

	compressed := buf.Bytes()
	out := make([]byte, 4+len(compressed))
	binary.BigEndian.PutUint32(out, uint32(len(compressed)))
	copy(out[4:], compressed)
	_, err = conn.Write(out)
	return err
}

// readMsgZlib reads a length-prefixed zlib-compressed JSON frame and
// unmarshals it into v.
func readMsgZlib(conn net.Conn, v any) error {
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

	zr, err := zlib.NewReader(bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("zlib reader: %w", err)
	}
	defer zr.Close()

	decompressed, err := io.ReadAll(zr)
	if err != nil {
		return fmt.Errorf("zlib decompress: %w", err)
	}
	return json.Unmarshal(decompressed, v)
}
