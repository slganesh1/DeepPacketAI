// database.go
// This file manages the storage of processed network packets in the DeepPacketAI application.
// It provides a way to store packet data in memory for analysis.
// Example scenarios:
// - Storing HTTP/2 frame data for real-time analysis
// - Accumulating network traffic data for batch processing
// - Preparing data for AI model analysis

// Package database provides functionality for storing and managing processed network packets
package storage

// AI_Input is a slice that stores all processed network messages
// Example: When a HTTP/2 frame is processed, its details are appended to this slice
// Usage: AI_Input[0].Message might contain {"method": "GET", "path": "/api"}
var AI_Input []ProcessedMessage

// Insert adds a new processed message to the AI_Input slice
// Parameters:
//   - Src_IpAddr: Source IP address (e.g., "192.168.1.1")
//   - Dst_IpAddr: Destination IP address (e.g., "10.0.0.1")
//   - Time_Stamp: Timestamp of the packet (e.g., "2024-03-20T15:04:05Z")
//   - Frame_Number: Sequential frame number for packet ordering
//   - Message: Map containing decoded packet content
//     Example: {"method": "GET", "path": "/api", "content": "request data"}
func Insert(src_addr, dst_addr, protocol, time string, frame uint64, message map[string]string) {
	AI_Input = append(AI_Input, ProcessedMessage{
		Src_IpAddr:   src_addr,
		Dst_IpAddr:   dst_addr,
		Protocol:     protocol,
		Frame_Number: frame,
		Time_Stamp:   time,
		Message:      message,
	})
}
