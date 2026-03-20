package pipeline

import (
	"encoding/binary"
	"hash/fnv"
	"net"
)

// FlowHash computes a symmetric FNV-32a hash of a 5-tuple.
// Both directions of a flow produce the same hash value by sorting
// IPs and ports before hashing.
func FlowHash(srcIP, dstIP string, srcPort, dstPort uint16) uint32 {
	// Sort IPs lexicographically, then ports, to ensure symmetry
	ip1, ip2 := srcIP, dstIP
	p1, p2 := srcPort, dstPort
	if srcIP > dstIP || (srcIP == dstIP && srcPort > dstPort) {
		ip1, ip2 = dstIP, srcIP
		p1, p2 = dstPort, srcPort
	}

	h := fnv.New32a()
	h.Write(net.ParseIP(ip1))
	h.Write(net.ParseIP(ip2))
	binary.Write(h, binary.BigEndian, p1)
	binary.Write(h, binary.BigEndian, p2)
	return h.Sum32()
}

// Route returns the worker index for a packet based on its flow hash.
func Route(srcIP, dstIP string, srcPort, dstPort uint16, workerCount int) int {
	return int(FlowHash(srcIP, dstIP, srcPort, dstPort) % uint32(workerCount))
}
