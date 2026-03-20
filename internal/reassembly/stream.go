package reassembly

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

// MessageCallback is called when a complete protocol message is extracted
// from a reassembled TCP stream.
type MessageCallback func(payload []byte, srcIP, dstIP string, srcPort, dstPort uint16, ts time.Time)

// StreamFactory creates tcpStream instances for the gopacket reassembly engine.
type StreamFactory struct {
	OnMessage MessageCallback
}

// New creates a new stream for a TCP connection. It selects the appropriate
// framer based on the ports. If no framer matches, returns an ignoreStream.
func (f *StreamFactory) New(netFlow, transportFlow gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)

	framer := SelectFramer(srcPort, dstPort)
	if framer == nil {
		return &ignoreStream{}
	}

	return &tcpStream{
		srcIP:     netFlow.Src().String(),
		dstIP:     netFlow.Dst().String(),
		srcPort:   srcPort,
		dstPort:   dstPort,
		framer:    framer,
		onMessage: f.OnMessage,
	}
}

// tcpStream implements reassembly.Stream by feeding data through a MessageFramer.
type tcpStream struct {
	srcIP, dstIP     string
	srcPort, dstPort uint16
	framer           MessageFramer
	onMessage        MessageCallback
}

func (s *tcpStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	return true
}

func (s *tcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	length, _ := sg.Lengths()
	if length == 0 {
		return
	}

	data := sg.Fetch(length)
	dir, _, _, skip := sg.Info()

	// Determine actual src/dst based on direction
	srcIP, dstIP := s.srcIP, s.dstIP
	srcPort, dstPort := s.srcPort, s.dstPort
	if dir == reassembly.TCPDirServerToClient {
		srcIP, dstIP = s.dstIP, s.srcIP
		srcPort, dstPort = s.dstPort, s.srcPort
	}

	if skip > 0 {
		// Gap in stream — flush partial data
		s.framer.Flush()
		return
	}

	msgs := s.framer.Feed(data)
	ts := ac.GetCaptureInfo().Timestamp
	for _, msg := range msgs {
		if s.onMessage != nil {
			s.onMessage(msg, srcIP, dstIP, srcPort, dstPort, ts)
		}
	}
}

func (s *tcpStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	if remaining := s.framer.Flush(); len(remaining) > 0 {
		if s.onMessage != nil {
			s.onMessage(remaining, s.srcIP, s.dstIP, s.srcPort, s.dstPort, time.Time{})
		}
	}
	return false // do not remove from pool
}

// ignoreStream discards all data for connections we don't need to reassemble.
type ignoreStream struct{}

func (s *ignoreStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	return true
}

func (s *ignoreStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
}

func (s *ignoreStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	return true // remove from pool immediately
}
