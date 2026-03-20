package gtp

import "DeepPacketAI/internal/domain"

// DetectErrors checks a GTP message for error conditions.
func DetectErrors(hdr *GTPHeader, causeCode uint8) []domain.PacketError {
	var errs []domain.PacketError

	// Check for non-success cause codes
	if causeCode != 0 && causeCode != 16 {
		causeName, ok := CauseCodes[causeCode]
		if !ok {
			causeName = "Unknown"
		}

		severity := "warning"
		if causeCode == 73 || causeCode == 74 || causeCode == 94 || causeCode == 95 || causeCode == 96 {
			severity = "error"
		}

		msgType := MessageTypes[hdr.MessageType]
		errs = append(errs, domain.PacketError{
			Code:        "GTP_FAILURE",
			Title:       "GTP " + msgType + " Failed",
			Description: "Cause: " + causeName,
			Severity:    severity,
		})
	}

	// Echo failure detection
	if hdr.MessageType == 1 {
		// Echo requests without responses are tracked at the flow level
	}

	return errs
}
