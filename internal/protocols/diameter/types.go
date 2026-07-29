package diameter

import "time"

// DiameterHeader represents a parsed Diameter message header (20 bytes).
type DiameterHeader struct {
	Version    uint8
	Length     uint32
	Flags      uint8
	CommandCode uint32
	AppID      uint32
	HopByHopID uint32
	EndToEndID uint32
	IsRequest  bool
}

// DiameterMessage contains a parsed header and key extracted fields.
type DiameterMessage struct {
	Timestamp       time.Time
	Header          DiameterHeader
	SessionID       string
	ResultCode      uint32
	OriginHost      string
	OriginRealm     string
	DestinationHost string
	CCRequestType   uint32
	UserName        string
	CommandName     string
	AppName         string
	IsError         bool
	IMSI            string
	MSISDN          string
}
