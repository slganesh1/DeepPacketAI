// Package snmp decodes SNMP v1/v2c messages (RFC 1157, RFC 1905) — read-only,
// BER/ASN.1 parsing of the community string, PDU type, and variable bindings.
// SNMPv3 (encrypted/authenticated) messages are detected but not decoded.
package snmp

// BER/ASN.1 tags used in SNMP messages.
const (
	tagInteger     = 0x02
	tagOctetString = 0x04
	tagNull        = 0x05
	tagOID         = 0x06
	tagSequence    = 0x30

	// Application-specific tags (RFC 1155).
	tagIPAddress  = 0x40
	tagCounter32  = 0x41
	tagGauge32    = 0x42
	tagTimeTicks  = 0x43
	tagOpaque     = 0x44
	tagCounter64  = 0x46

	// Exception values used in SNMPv2c varbind values (RFC 1905).
	tagNoSuchObject   = 0x80
	tagNoSuchInstance = 0x81
	tagEndOfMibView   = 0x82
)

// PDU type tags (context-specific, constructed).
const (
	PDUGetRequest     = 0xA0
	PDUGetNextRequest = 0xA1
	PDUGetResponse    = 0xA2
	PDUSetRequest     = 0xA3
	PDUTrap           = 0xA4 // SNMPv1 Trap-PDU (own format — no request-id/error-status)
	PDUGetBulkRequest = 0xA5
	PDUInformRequest  = 0xA6
	PDUSNMPv2Trap     = 0xA7
	PDUReport         = 0xA8
)

// PDUNames maps a PDU type tag to its RFC name.
var PDUNames = map[byte]string{
	PDUGetRequest:     "GetRequest",
	PDUGetNextRequest: "GetNextRequest",
	PDUGetResponse:    "GetResponse",
	PDUSetRequest:     "SetRequest",
	PDUTrap:           "Trap-v1",
	PDUGetBulkRequest: "GetBulkRequest",
	PDUInformRequest:  "InformRequest",
	PDUSNMPv2Trap:     "SNMPv2-Trap",
	PDUReport:         "Report",
}

// VersionNames maps the SNMP version field to its common name.
var VersionNames = map[int64]string{
	0: "v1",
	1: "v2c",
	3: "v3",
}

// ErrorStatusNames maps the PDU error-status field (RFC 1157 §4.1.1, extended by RFC 1905).
var ErrorStatusNames = map[int64]string{
	0:  "noError",
	1:  "tooBig",
	2:  "noSuchName",
	3:  "badValue",
	4:  "readOnly",
	5:  "genErr",
	6:  "noAccess",
	7:  "wrongType",
	8:  "wrongLength",
	9:  "wrongEncoding",
	10: "wrongValue",
	11: "noCreation",
	12: "inconsistentValue",
	13: "resourceUnavailable",
	14: "commitFailed",
	15: "undoFailed",
	16: "authorizationError",
	17: "notWritable",
	18: "inconsistentName",
}

// GenericTrapNames maps the SNMPv1 Trap-PDU generic-trap field (RFC 1157 §4.1.6).
var GenericTrapNames = map[int64]string{
	0: "coldStart",
	1: "warmStart",
	2: "linkDown",
	3: "linkUp",
	4: "authenticationFailure",
	5: "egpNeighborLoss",
	6: "enterpriseSpecific",
}

// VarBind is one name/value pair from a varbind list.
type VarBind struct {
	OID   string
	Value string
}
