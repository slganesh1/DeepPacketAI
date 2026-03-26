package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"DeepPacketAI/internal/domain"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type PacketHandler func(pkt *domain.Packet) error

func ReadPCAP(pcapPath string, handler PacketHandler) error {
	f, err := os.Open(pcapPath)
	if err != nil {
		return fmt.Errorf("failed to open pcap: %w", err)
	}
	defer f.Close()

	// Detect format by magic bytes instead of file extension.
	// pcapng Section Header Block magic: 0x0A0D0D0A
	// Classic pcap magic: 0xA1B2C3D4 or 0xD4C3B2A1 (swapped)
	isPcapng, err := detectPcapng(f)
	if err != nil {
		return fmt.Errorf("failed to detect pcap format: %w", err)
	}

	var source *gopacket.PacketSource

	if isPcapng {
		ngReader, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return fmt.Errorf("failed to read pcapng: %w", err)
		}
		source = gopacket.NewPacketSource(ngReader, ngReader.LinkType())
	} else {
		reader, err := pcapgo.NewReader(f)
		if err != nil {
			return fmt.Errorf("failed to read pcap: %w", err)
		}
		source = gopacket.NewPacketSource(reader, reader.LinkType())
	}

	var frameNum uint64

	for packet := range source.Packets() {
		frameNum++

		net := packet.NetworkLayer()
		if net == nil {
			continue // non-IP (ARP, etc.)
		}

		var srcIP, dstIP string
		switch ip := net.(type) {
		case *layers.IPv4:
			srcIP = ip.SrcIP.String()
			dstIP = ip.DstIP.String()
		case *layers.IPv6:
			srcIP = ip.SrcIP.String()
			dstIP = ip.DstIP.String()
		default:
			continue
		}

		var srcPort, dstPort uint16
		var proto string
		var payload []byte
		var tcpSeq, tcpAck uint32
		var tcpFlags uint16

		tr := packet.TransportLayer()
		if tr != nil {
			switch t := tr.(type) {
			case *layers.TCP:
				srcPort = uint16(t.SrcPort)
				dstPort = uint16(t.DstPort)
				proto = "TCP"
				payload = t.LayerPayload()
				tcpSeq = t.Seq
				tcpAck = t.Ack
				tcpFlags = tcpFlagsFromLayer(t)
			case *layers.UDP:
				srcPort = uint16(t.SrcPort)
				dstPort = uint16(t.DstPort)
				proto = "UDP"
				payload = t.LayerPayload()
			default:
				// Check for SCTP (gopacket may not surface it as TransportLayer)
				if sctp := packet.Layer(layers.LayerTypeSCTP); sctp != nil {
					sctpLayer := sctp.(*layers.SCTP)
					srcPort = uint16(sctpLayer.SrcPort)
					dstPort = uint16(sctpLayer.DstPort)
					proto = "SCTP"
					payload = sctpLayer.LayerPayload()
				} else {
					continue
				}
			}
		} else {
			// No transport layer — handle ICMP/ICMPv6 (gopacket does not classify
			// these as transport; they sit directly above the network layer).
			if l := packet.Layer(layers.LayerTypeICMPv4); l != nil {
				t := l.(*layers.ICMPv4)
				proto = "ICMP"
				srcPort = uint16(t.TypeCode >> 8)   // ICMP type
				dstPort = uint16(t.TypeCode & 0xFF) // ICMP code
				payload = t.LayerPayload()
			} else if l := packet.Layer(layers.LayerTypeICMPv6); l != nil {
				t := l.(*layers.ICMPv6)
				proto = "ICMPv6"
				srcPort = uint16(t.TypeCode >> 8)
				dstPort = uint16(t.TypeCode & 0xFF)
				payload = t.LayerPayload()
			} else {
				continue // other non-TCP/UDP/SCTP/ICMP (OSPF, IGMP, etc.) — skip
			}
		}

		p := &domain.Packet{
			Timestamp:   packet.Metadata().Timestamp,
			SrcIP:       srcIP,
			DstIP:       dstIP,
			DstPort:     dstPort,
			SrcPort:     srcPort,
			Protocol:    proto,
			Payload:     payload,
			FrameNumber: frameNum,
			Length:      len(packet.Data()),
			RawPacket:   packet.Data(),
			TCPSeq:      tcpSeq,
			TCPAck:      tcpAck,
			TCPFlags:    tcpFlags,
		}

		if err := handler(p); err != nil {
			return err
		}
	}

	return nil
}

func tcpFlagsFromLayer(t *layers.TCP) uint16 {
	var f uint16
	if t.SYN {
		f |= 0x02
	}
	if t.FIN {
		f |= 0x01
	}
	if t.RST {
		f |= 0x04
	}
	if t.PSH {
		f |= 0x08
	}
	if t.ACK {
		f |= 0x10
	}
	return f
}

// detectPcapng reads the first 4 bytes to check for pcapng magic (0x0A0D0D0A),
// then seeks back to the start so the file can be read normally.
func detectPcapng(r io.ReadSeeker) (bool, error) {
	var magic uint32
	if err := binary.Read(r, binary.LittleEndian, &magic); err != nil {
		return false, err
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	// pcapng Section Header Block type = 0x0A0D0D0A
	return magic == 0x0A0D0D0A, nil
}
