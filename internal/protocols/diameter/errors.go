package diameter

import (
	"fmt"

	"DeepPacketAI/internal/domain"
)

// DetectErrors checks a Diameter message for error conditions.
func DetectErrors(msg *DiameterMessage) []domain.PacketError {
	var errs []domain.PacketError

	// Only check responses (answers)
	if msg.Header.IsRequest {
		return errs
	}

	// Error bit set in flags
	if msg.Header.Flags&0x20 != 0 {
		errs = append(errs, domain.PacketError{
			Code:        "DIAMETER_ERROR_BIT",
			Title:       "Diameter Error Flag Set",
			Description: fmt.Sprintf("%s response has error bit set", msg.CommandName),
			Severity:    "error",
		})
	}

	// Non-success result codes
	if msg.ResultCode != 0 && msg.ResultCode != 2001 && msg.ResultCode != 2002 {
		severity := "warning"
		if msg.ResultCode >= 4000 && msg.ResultCode < 5000 {
			severity = "error"
		} else if msg.ResultCode >= 5000 {
			severity = "critical"
		}

		errs = append(errs, domain.PacketError{
			Code:        fmt.Sprintf("DIAMETER_%d", msg.ResultCode),
			Title:       "Diameter " + ResultCodeName(msg.ResultCode),
			Description: fmt.Sprintf("%s failed with result code %d (%s), Session: %s", msg.CommandName, msg.ResultCode, ResultCodeName(msg.ResultCode), msg.SessionID),
			Severity:    severity,
		})
	}

	return errs
}
