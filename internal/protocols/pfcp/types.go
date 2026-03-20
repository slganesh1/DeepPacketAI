package pfcp

// PFCP message types (3GPP TS 29.244).
var MessageTypes = map[uint8]string{
	// Node related
	1:  "Heartbeat Request",
	2:  "Heartbeat Response",
	3:  "PFD Management Request",
	4:  "PFD Management Response",
	5:  "Association Setup Request",
	6:  "Association Setup Response",
	7:  "Association Update Request",
	8:  "Association Update Response",
	9:  "Association Release Request",
	10: "Association Release Response",
	// Session related
	50: "Session Establishment Request",
	51: "Session Establishment Response",
	52: "Session Modification Request",
	53: "Session Modification Response",
	54: "Session Deletion Request",
	55: "Session Deletion Response",
	56: "Session Report Request",
	57: "Session Report Response",
}

// PFCP cause values.
var CauseValues = map[uint8]string{
	1:  "Request accepted",
	64: "Request rejected",
	65: "Session context not found",
	66: "Mandatory IE missing",
	67: "Conditional IE missing",
	68: "Invalid length",
	69: "Mandatory IE incorrect",
	70: "Invalid Forwarding Policy",
	71: "Invalid F-TEID allocation option",
	72: "No established PFCP Association",
	73: "Rule creation/modification failure",
	74: "PFCP entity in congestion",
	75: "No resources available",
	76: "Service not supported",
	77: "System failure",
}

// PFCPHeader represents a parsed PFCP message header.
type PFCPHeader struct {
	Version     uint8
	MessageType uint8
	Length      uint16
	SEID       uint64
	SequenceNo uint32
	HasSEID    bool
}
