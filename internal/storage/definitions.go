// definitions.go
// This file defines the core data structures for storing processed network packets.
// These structures are used throughout the DeepPacketAI application for:
// - Storing HTTP/2 frame data
// - Tracking packet relationships
// - Preparing data for AI analysis
//
// Example scenarios:
// 1. HTTP/2 Request Storage:
//    {
//      Src_IpAddr: "192.168.1.1",
//      Dst_IpAddr: "10.0.0.1",
//      Frame_Number: 1,
//      Time_Stamp: "2024-03-20T15:04:05Z",
//      Message: {"method": "GET", "path": "/api/v1/users"}
//    }
//
// 2. Response Tracking:
//    {
//      Src_IpAddr: "10.0.0.1",
//      Dst_IpAddr: "192.168.1.1",
//      Frame_Number: 2,
//      Time_Stamp: "2024-03-20T15:04:06Z",
//      Message: {"status": "200", "content": "{\"data\": [...]}"}
//    }

package storage

// ProcessedMessage represents a single processed network packet with its metadata and content.
// Fields:
// - Src_IpAddr: Source IP address (e.g., "192.168.1.1")
// - Dst_IpAddr: Destination IP address (e.g., "10.0.0.1")
// - Frame_Number: Sequential number for packet ordering
// - Time_Stamp: When the packet was processed (RFC3339 format)
// - Message: Decoded packet content (headers, payloads)
type ProcessedMessage struct {
	Src_IpAddr   string            // Source IP of the packet
	Dst_IpAddr   string            // Destination IP of the packet
	Protocol     string            // Protocol of the packet
	Frame_Number uint64            // Frame sequence number
	Time_Stamp   string            // Processing timestamp
	Message      map[string]string // Decoded packet content
}
