package sip

import (
	"strconv"
	"strings"
)

func extractHeader(payload, header string) string {
	header = strings.ToLower(header) + ":"

	for _, line := range strings.Split(payload, "\r\n") {
		l := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(l, header) {
			return strings.TrimSpace(line[len(header):])
		}
	}
	return ""
}

func firstLine(payload string) string {
	if idx := strings.Index(payload, "\r\n"); idx > 0 {
		return payload[:idx]
	}
	return payload
}

// extractStatusCode parses the SIP status code from a response line like "SIP/2.0 404 Not Found".
func extractStatusCode(payload string) int {
	// Format: "SIP/2.0 <code> <reason>"
	parts := strings.SplitN(payload, " ", 3)
	if len(parts) < 2 {
		return 0
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0
	}
	return code
}

func parseSDP(payload string) map[string]string {
	lines := strings.Split(payload, "\r\n")

	var mediaIP, mediaPort, direction string

	for _, l := range lines {
		l = strings.TrimSpace(l)

		if strings.HasPrefix(l, "c=IN IP4 ") {
			mediaIP = strings.TrimPrefix(l, "c=IN IP4 ")
		}
		if strings.HasPrefix(l, "m=audio ") {
			parts := strings.Fields(l)
			if len(parts) >= 2 {
				mediaPort = parts[1]
			}
		}
		if strings.HasPrefix(l, "a=sendonly") ||
			strings.HasPrefix(l, "a=recvonly") ||
			strings.HasPrefix(l, "a=sendrecv") ||
			strings.HasPrefix(l, "a=inactive") {
			direction = strings.TrimPrefix(l, "a=")
		}
	}

	if mediaIP == "" || mediaPort == "" {
		return nil
	}

	if direction == "" {
		direction = "sendrecv"
	}

	return map[string]string{
		"media_ip":   mediaIP,
		"media_port": mediaPort,
		"direction":  direction,
	}
}
