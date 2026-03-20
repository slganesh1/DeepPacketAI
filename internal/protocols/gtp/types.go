package gtp

// GTP message types
var MessageTypes = map[uint8]string{
	// GTPv1-C
	1:   "Echo Request",
	2:   "Echo Response",
	16:  "Create PDP Context Request",
	17:  "Create PDP Context Response",
	18:  "Update PDP Context Request",
	19:  "Update PDP Context Response",
	20:  "Delete PDP Context Request",
	21:  "Delete PDP Context Response",
	// GTPv2-C
	32:  "Create Session Request",
	33:  "Create Session Response",
	34:  "Modify Bearer Request",
	35:  "Modify Bearer Response",
	36:  "Delete Session Request",
	37:  "Delete Session Response",
	38:  "Change Notification Request",
	39:  "Change Notification Response",
	64:  "Modify Bearer Command",
	65:  "Modify Bearer Failure Indication",
	66:  "Delete Bearer Command",
	67:  "Delete Bearer Failure Indication",
	68:  "Bearer Resource Command",
	69:  "Bearer Resource Failure Indication",
	70:  "Downlink Data Notification Failure Indication",
	71:  "Trace Session Activation",
	72:  "Trace Session Deactivation",
	73:  "Stop Paging Indication",
	95:  "Create Bearer Request",
	96:  "Create Bearer Response",
	97:  "Update Bearer Request",
	98:  "Update Bearer Response",
	99:  "Delete Bearer Request",
	100: "Delete Bearer Response",
	162: "Create Indirect Data Forwarding Tunnel Request",
	163: "Create Indirect Data Forwarding Tunnel Response",
	164: "Delete Indirect Data Forwarding Tunnel Request",
	165: "Delete Indirect Data Forwarding Tunnel Response",
	170: "Release Access Bearers Request",
	171: "Release Access Bearers Response",
	176: "Downlink Data Notification",
	177: "Downlink Data Notification Acknowledgement",
	200: "Update PDN Connection Set Request",
	201: "Update PDN Connection Set Response",
	// GTP-U
	255: "G-PDU",
}

// GTP cause codes
var CauseCodes = map[uint8]string{
	16:  "Request Accepted",
	64:  "Context Not Found",
	65:  "Invalid Message Format",
	66:  "Version Not Supported",
	67:  "Invalid Length",
	68:  "Service Not Supported",
	69:  "Mandatory IE Incorrect",
	70:  "Mandatory IE Missing",
	73:  "System Failure",
	74:  "No Resources Available",
	75:  "Semantic Error in TFT",
	76:  "Syntactic Error in TFT",
	92:  "Unable to Page UE",
	93:  "No Memory Available",
	94:  "User Authentication Failed",
	95:  "APN Access Denied",
	96:  "Request Rejected",
	110: "Temporarily Rejected",
}

// GTPHeader represents a parsed GTP header.
type GTPHeader struct {
	Version     uint8
	MessageType uint8
	Length      uint16
	TEID       uint32
	SequenceNo uint16
	IsGTPU     bool
}
