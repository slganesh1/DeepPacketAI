package dns

import "time"

// Transaction tracks a DNS query and its response.
type Transaction struct {
	TxID       uint16
	QueryName  string
	QueryType  string
	SrcIP      string
	DstIP      string
	SrcPort    uint16
	DstPort    uint16
	QueryTime  time.Time
	ReplyTime  time.Time
	ReplyCode  string
	Answers    []string
	Latency    float64 // milliseconds
	HasReply   bool
	IsError    bool
	ErrorType  string // NXDOMAIN, SERVFAIL, REFUSED, TIMEOUT
}

// Common DNS record type codes.
var RecordTypes = map[uint16]string{
	1:   "A",
	2:   "NS",
	5:   "CNAME",
	6:   "SOA",
	12:  "PTR",
	15:  "MX",
	16:  "TXT",
	28:  "AAAA",
	33:  "SRV",
	35:  "NAPTR",
	255: "ANY",
}

// DNS response codes (the 4-bit RCODE field in the header, RFC 1035 §4.1.1
// extended by RFC 2136 and RFC 6895's IANA registry). Codes 12-15 are
// unassigned in the registry as of RFC 6895 and are left to the decoder's
// "RCODE_N" fallback; codes 16+ (BADVERS, BADSIG, BADKEY, ...) require the
// EDNS0 8-bit extended-RCODE from the OPT pseudo-RR, which this decoder does
// not parse, so they can never appear here.
var ResponseCodes = map[uint8]string{
	0:  "NOERROR",
	1:  "FORMERR",
	2:  "SERVFAIL",
	3:  "NXDOMAIN",
	4:  "NOTIMP",
	5:  "REFUSED",
	6:  "YXDOMAIN",  // name exists when it should not (RFC 2136)
	7:  "YXRRSET",   // RRset exists when it should not (RFC 2136)
	8:  "NXRRSET",   // RRset that should exist does not (RFC 2136)
	9:  "NOTAUTH",   // server not authoritative for the zone / not authorized (RFC 2136/2845)
	10: "NOTZONE",   // name not contained in the zone (RFC 2136)
	11: "DSOTYPENI", // DSO-TYPE not implemented (RFC 8490)
}
