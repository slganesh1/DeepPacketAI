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

// DNS response codes.
var ResponseCodes = map[uint8]string{
	0: "NOERROR",
	1: "FORMERR",
	2: "SERVFAIL",
	3: "NXDOMAIN",
	4: "NOTIMP",
	5: "REFUSED",
}
