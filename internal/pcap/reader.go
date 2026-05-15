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

// linuxSLL2RawLinkType is the pcap link type 276 for Linux cooked capture v2.
// layers.LinkType is uint8 and cannot hold 276, so we read the raw uint32
// directly from the pcap file header before pcapgo truncates it.
const linuxSLL2RawLinkType uint32 = 276

type PacketHandler func(pkt *domain.Packet) error

func ReadPCAP(pcapPath string, handler PacketHandler) error {
	f, err := os.Open(pcapPath)
	if err != nil {
		return fmt.Errorf("failed to open pcap: %w", err)
	}
	defer f.Close()

	isPcapng, err := detectPcapng(f)
	if err != nil {
		return fmt.Errorf("failed to detect pcap format: %w", err)
	}

	if isPcapng {
		ngReader, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return fmt.Errorf("failed to read pcapng: %w", err)
		}
		source := gopacket.NewPacketSource(ngReader, ngReader.LinkType())
		return readFromSource(source, handler)
	}

	// Read the raw 32-bit link type from the pcap global header BEFORE creating
	// the pcapgo reader, which truncates it to uint8 (losing values > 255).
	rawLinkType, _ := readRawPcapLinkType(f)

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		return fmt.Errorf("failed to read pcap: %w", err)
	}

	// Linux cooked v2 (tcpdump -i any on Linux 5.x+): gopacket v1.1.19 has no
	// decoder for link type 276, so we strip the 20-byte SLL2 header manually
	// and decode the inner IPv4/IPv6 payload directly.
	if rawLinkType == linuxSLL2RawLinkType {
		return readSLL2(reader, handler)
	}

	source := gopacket.NewPacketSource(reader, reader.LinkType())
	return readFromSource(source, handler)
}

// readSLL2 handles Linux cooked capture v2 (link type 276).
// SLL2 header: 2B EtherType | 2B reserved | 4B ifindex | 2B arphrd | 1B pkttype | 1B addrlen | 8B addr = 20 bytes
func readSLL2(reader *pcapgo.Reader, handler PacketHandler) error {
	var frameNum uint64
	for {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			continue
		}
		frameNum++
		if len(data) < 20 {
			continue
		}
		etype := binary.BigEndian.Uint16(data[0:2])
		inner := data[20:]
		var pkt gopacket.Packet
		switch etype {
		case 0x0800:
			pkt = gopacket.NewPacket(inner, layers.LayerTypeIPv4, gopacket.Default)
		case 0x86DD:
			pkt = gopacket.NewPacket(inner, layers.LayerTypeIPv6, gopacket.Default)
		default:
			continue // ARP, etc.
		}
		pkt.Metadata().Timestamp = ci.Timestamp
		pkt.Metadata().Length = ci.Length
		if err := processPacket(pkt, frameNum, data, handler); err != nil {
			return err
		}
	}
}

func readFromSource(source *gopacket.PacketSource, handler PacketHandler) error {
	var frameNum uint64
	for packet := range source.Packets() {
		frameNum++
		if err := processPacket(packet, frameNum, packet.Data(), handler); err != nil {
			return err
		}
	}
	return nil
}

func processPacket(packet gopacket.Packet, frameNum uint64, rawData []byte, handler PacketHandler) error {
	net := packet.NetworkLayer()
	if net == nil {
		return nil
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
		return nil
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
			if sctp := packet.Layer(layers.LayerTypeSCTP); sctp != nil {
				sctpLayer := sctp.(*layers.SCTP)
				srcPort = uint16(sctpLayer.SrcPort)
				dstPort = uint16(sctpLayer.DstPort)
				proto = "SCTP"
				payload = sctpLayer.LayerPayload()
			} else {
				return nil
			}
		}
	} else {
		if l := packet.Layer(layers.LayerTypeICMPv4); l != nil {
			t := l.(*layers.ICMPv4)
			proto = "ICMP"
			srcPort = uint16(t.TypeCode >> 8)
			dstPort = uint16(t.TypeCode & 0xFF)
			payload = t.LayerPayload()
		} else if l := packet.Layer(layers.LayerTypeICMPv6); l != nil {
			t := l.(*layers.ICMPv6)
			proto = "ICMPv6"
			srcPort = uint16(t.TypeCode >> 8)
			dstPort = uint16(t.TypeCode & 0xFF)
			payload = t.LayerPayload()
		} else {
			return nil
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
		Length:      len(rawData),
		RawPacket:   rawData,
		TCPSeq:      tcpSeq,
		TCPAck:      tcpAck,
		TCPFlags:    tcpFlags,
	}

	return handler(p)
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

// readRawPcapLinkType reads the 32-bit link type from bytes 20-23 of the classic
// pcap global header without truncating to uint8 as pcapgo does. Seeks back to
// position 0 so the file can be read normally afterwards.
func readRawPcapLinkType(r io.ReadSeeker) (uint32, error) {
	// Read magic to determine endianness
	var magic uint32
	if err := binary.Read(r, binary.LittleEndian, &magic); err != nil {
		return 0, err
	}
	// Magic is always read with LittleEndian above.
	// 0xA1B2C3D4 / 0xA1B23C4D = bytes D4C3B2A1 / 4D3CB2A1 on disk → little-endian file
	// 0xD4C3B2A1 / 0x4D3CB2A1 = bytes A1B2C3D4 / A1B23C4D on disk → big-endian file
	var order binary.ByteOrder
	switch magic {
	case 0xA1B2C3D4, 0xA1B23C4D: // little-endian file (microseconds and nanoseconds)
		order = binary.LittleEndian
	default:
		order = binary.BigEndian
	}
	// Seek to link type field (offset 20)
	if _, err := r.Seek(20, io.SeekStart); err != nil {
		return 0, err
	}
	var linkType uint32
	if err := binary.Read(r, order, &linkType); err != nil {
		return 0, err
	}
	// Seek back so the caller (pcapgo.NewReader) reads from the beginning
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	return linkType, nil
}
