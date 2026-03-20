// http2.go
// This file implements HTTP/2 protocol processing for DeepPacketAI.
// Core functionalities:
// - Decodes HTTP/2 frames (HEADERS, DATA)
// - Handles HPACK header compression
// - Processes JSON payloads
//
// Example scenarios:
// 1. HEADERS Frame Processing:
//    Input: HTTP/2 HEADERS frame
//    Output: Decoded headers {"method": "GET", "path": "/api"}
//
// 2. DATA Frame Processing:
//    Input: HTTP/2 DATA frame with JSON
//    Output: Formatted payload for analysis

// Package decode_http provides HTTP/2 frame processing capabilities
package decode_http

// Import required packages for HTTP/2 processing
import (
	database "DeepPacketAI/internal/storage" // Database operations for storing processed frames
	"bytes"                                  // Byte manipulation utilities
	"encoding/json"                          // JSON encoding/decoding
	"regexp"                                 // Regular expression for payload formatting
	"strings"                                // String manipulation utilities

	"golang.org/x/net/http2"       // HTTP/2 protocol implementation
	"golang.org/x/net/http2/hpack" // HPACK header compression
)

// Process handles HTTP/2 frame processing and analysis
// Parameters:
// - p: Raw frame payload bytes
// - src_ipaddr: Source IP (e.g., "192.168.1.1")
// - dst_ipaddr: Destination IP (e.g., "10.0.0.1")
// - time: Timestamp (e.g., "2024-03-20T15:04:05Z")
// - frame_num: Sequential frame identifier
func Process(p []byte, src_ipaddr string, dst_ipaddr string, time string, frame_num uint64) {
	// Create a byte reader for processing HTTP/2 frames
	// Used by framer to read frame data sequentially
	r := bytes.NewReader(p)

	// Initialize HTTP/2 framer for decoding frames
	// nil writer as we're only reading frames
	framer := http2.NewFramer(nil, r)
	frame, err := framer.ReadFrame()
	if err != nil {
		return // Skip processing if frame is invalid
	}

	// Initialize map to store processed frame content
	// Keys: header fields, Values: corresponding values
	var message = make(map[string]string)

	// Process frame based on its type (HEADERS or DATA)
	if frame.Header().Type.String() == "HEADERS" {
		// Process HEADERS frame using HPACK decoder
		message = processHeader(frame, dst_ipaddr)
	} else if frame.Header().Type.String() == "DATA" {
		// Extract and process DATA frame payload
		dataframe := frame.(*http2.DataFrame)
		p = dataframe.Data()
		data := formatPayload(p)
		message = extractMsgContent(data, message)
	}

	// Attempt to read next frame if present
	// Handles multi-frame messages (e.g., HEADERS followed by DATA)
	frame, err = framer.ReadFrame()
	if err != nil {
		// Continue with existing message if no more frames
	} else if frame.Header().Type.String() == "DATA" {
		// Process additional DATA frame
		dataframe := (frame.(*http2.DataFrame))
		p = dataframe.Data()
		data := formatPayload(p)
		message = extractMsgContent(data, message)
	} else if frame.Header().Type.String() == "HEADERS" {
		// Process additional HEADERS frame
		message = processHeader(frame, src_ipaddr)
	}

	// Format JSON content if present in message
	if content, ok := message["content"]; ok {
		// Create buffer for formatted JSON
		var formattedJSON bytes.Buffer
		// Add indentation for readability
		json.Indent(&formattedJSON, []byte(content), "", "  ")
		// Update message with formatted JSON
		message["content"] = formattedJSON.String()
	}

	// Store processed frame data in database
	if len(message) != 0 {
		database.Insert(src_ipaddr, dst_ipaddr, "http", time, frame_num, message)
	}
}

// Map to store HPACK decoders for different connections
// Key: IP address identifies the connection
// Value: HPACK decoder instance for that connection
var hpackDecoder = make(map[string]*hpack.Decoder)

// processHeader decodes HTTP/2 HEADERS frames using HPACK
// Parameters:
// - frame: HTTP/2 frame containing headers
// - ip_addr: IP address for decoder lookup
// Returns: Map of decoded headers
func processHeader(frame http2.Frame, ip_addr string) map[string]string {
	// Convert generic frame to HeadersFrame type
	headersframe := frame.(*http2.HeadersFrame)

	// Get existing decoder or create new one for this connection
	decoder, ok := hpackDecoder[ip_addr]
	if !ok {
		// Initialize new decoder with 4KB dynamic table size
		decoder = hpack.NewDecoder(4096, func(f hpack.HeaderField) {})
		// Store decoder for future use
		hpackDecoder[ip_addr] = decoder
	}

	// Decode HPACK-encoded headers
	// Returns error if header block is malformed
	headerFields, err := decoder.DecodeFull(headersframe.HeaderBlockFragment())
	if err != nil {
		// Return empty map if decoding fails
		return map[string]string{}
	}

	// Convert decoded header fields to map
	headers := make(map[string]string)
	for _, hf := range headerFields {
		headers[hf.Name] = hf.Value
	}

	return headers
}

// formatPayload cleans and standardizes raw payload data
// Parameters:
// - p: Raw payload bytes to format
// Returns: Formatted string with consistent spacing
func formatPayload(p []byte) string {
	// Keywords to search for
	keywords := []string{":path", "content-type", "location"}

	// Convert input []byte to string
	str := string(p)

	// Replace non-printable characters and control characters with newline
	data := bytes.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return '\n'
		}
		return r
	}, []byte(str))

	// Convert back to string
	cleaned_str := string(data)

	// Remove leading and trailing whitespace
	trimmed_str := strings.TrimSpace(cleaned_str)

	// Split the string by newlines
	lines := strings.Split(trimmed_str, "\n")

	// Filter out empty lines
	var non_empty_lines []string
	for _, line := range lines {
		if line != "" {
			non_empty_lines = append(non_empty_lines, line)
		}
	}

	// Search for keywords and replace the next character with newline if a keyword is found
	for i, line := range non_empty_lines {
		for _, keyword := range keywords {
			index := strings.Index(line, keyword)
			if index != -1 && index+len(keyword) < len(line) {
				if line[index+len(keyword)] != '\n' && line[index+len(keyword)] != ' ' {
					non_empty_lines[i] = line[:index+len(keyword)] + "\n" + line[index+len(keyword)+1:]
				}
			}
		}
	}

	// Join the non-empty lines with new lines
	result := strings.Join(non_empty_lines, "\n")

	return result
}

// extractMsgContent processes a string payload to extract JSON content
// Parameters:
// - p: Input string containing potential JSON content
// - result: Map to store extracted content
// Returns: Updated map with JSON content if found
func extractMsgContent(p string, result map[string]string) map[string]string {
	// Find JSON objects or arrays in content
	pattern := regexp.MustCompile(`(?s){[\s\S]*}|(?s)\[[\s\S]*\]`)
	matches := pattern.FindString(p)

	// Store valid JSON content
	if len(matches) > 3 {
		result["content"] = matches
	}
	return result
}
