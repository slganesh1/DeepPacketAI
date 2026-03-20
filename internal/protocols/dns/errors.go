package dns

import (
	"fmt"

	"DeepPacketAI/internal/domain"
)

// DetectErrors checks a DNS transaction for common errors.
func DetectErrors(tx *Transaction) []domain.PacketError {
	var errs []domain.PacketError

	if !tx.HasReply {
		errs = append(errs, domain.PacketError{
			Code:        "DNS_TIMEOUT",
			Title:       "DNS Query Timeout",
			Description: "DNS query for " + tx.QueryName + " received no response",
			Severity:    "warning",
		})
		return errs
	}

	switch tx.ReplyCode {
	case "NXDOMAIN":
		errs = append(errs, domain.PacketError{
			Code:        "DNS_NXDOMAIN",
			Title:       "Domain Not Found",
			Description: tx.QueryName + " does not exist (NXDOMAIN)",
			Severity:    "warning",
		})
	case "SERVFAIL":
		errs = append(errs, domain.PacketError{
			Code:        "DNS_SERVFAIL",
			Title:       "DNS Server Failure",
			Description: "DNS server failed to resolve " + tx.QueryName + " (SERVFAIL)",
			Severity:    "error",
		})
	case "REFUSED":
		errs = append(errs, domain.PacketError{
			Code:        "DNS_REFUSED",
			Title:       "DNS Query Refused",
			Description: "DNS server refused query for " + tx.QueryName,
			Severity:    "error",
		})
	case "FORMERR":
		errs = append(errs, domain.PacketError{
			Code:        "DNS_FORMERR",
			Title:       "DNS Format Error",
			Description: "Malformed DNS query for " + tx.QueryName,
			Severity:    "error",
		})
	}

	if tx.Latency > 500 {
		errs = append(errs, domain.PacketError{
			Code:        "DNS_SLOW",
			Title:       "Slow DNS Resolution",
			Description: tx.QueryName + " took " + formatMs(tx.Latency) + "ms to resolve",
			Severity:    "warning",
		})
	}

	return errs
}

func formatMs(ms float64) string {
	if ms >= 1000 {
		return fmt.Sprintf("%.1fs", ms/1000)
	}
	return fmt.Sprintf("%.0f", ms)
}
