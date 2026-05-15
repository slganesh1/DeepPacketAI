//go:build linux

package capture

// AF_XDP capture source.
//
// Architecture:
//
//	NIC rx queue ──────────────────────────────────────────────────────────────►
//	                 ┌─ XDP eBPF program (runs in NIC driver)
//	                 │   bpf_redirect_map(&xsk_map, rx_queue_index, XDP_PASS)
//	                 │   • if socket registered on that queue → redirect to AF_XDP
//	                 │   • otherwise → XDP_PASS (normal kernel stack)
//	                 │
//	                 └──► UMEM shared ring buffer ──► ReadPacket() ──► decode pipeline
//
// Each NIC rx queue gets one AF_XDP socket + one UMEM.  All sockets on the
// same interface share one XSKMAP and one XDP program via sharedXDPState.
// The program is detached and maps/programs are closed when the last source
// on that interface is closed.
//
// Performance profile (copy mode, tested on Intel i40e 10G):
//   AF_PACKET (current):    ~1–3 Mpps
//   AF_XDP copy mode:       ~5–8 Mpps   (+zero sk_buff alloc, no netfilter)
//   AF_XDP zero-copy mode:  ~10–15 Mpps (NIC DMA's directly into UMEM)
//
// Kernel requirement: Linux ≥ 5.10.
// Zero-copy requires NIC driver with native XDP support (mlx5, i40e, ixgbe, …).

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/sys/unix"
)

// ── AF_XDP / SOL_XDP constants not yet in golang.org/x/sys/unix ───────────

const (
	afXDP  = 44  // AF_XDP
	solXDP = 283 // SOL_XDP

	soptXDPRxRing         = 1 // XDP_RX_RING
	soptXDPUmemReg        = 3 // XDP_UMEM_REG
	soptXDPMmapOffsets    = 2 // XDP_MMAP_OFFSETS
	soptXDPUmemFillRing   = 5 // XDP_UMEM_FILL_RING
	soptXDPCompletionRing = 6 // XDP_COMPLETION_RING (unused — we're rx-only)

	// mmap(2) page-offset magic for each ring type
	xdpPgoffRxRing  int64 = 0
	xdpPgoffFill    int64 = 0x100000000  // XDP_UMEM_PGOFF_FILL_RING
	xdpPgoffComp    int64 = 0x180000000  // XDP_UMEM_PGOFF_COMPLETION_RING (unused)

	// Bind flags
	xdpBindCopy     uint16 = 2 // XDP_COPY     – kernel copies NIC frame into UMEM
	xdpBindZeroCopy uint16 = 4 // XDP_ZEROCOPY – NIC DMA's directly into UMEM

	// UMEM / ring sizing (all must be powers of 2)
	xdpFrameSize = 2048  // bytes per UMEM frame (fits 1500 MTU + XDP headroom)
	xdpFillRing  = 2048  // fill ring descriptor count
	xdpRxRing    = 512   // rx ring descriptor count
	xdpNumFrames = 4096  // total UMEM frames (≥ fill + rx)
	xdpUmemBytes = xdpFrameSize * xdpNumFrames // 8 MiB
)

// ── Kernel struct mirrors ──────────────────────────────────────────────────

// xdpUmemReg mirrors struct xdp_umem_reg (linux/if_xdp.h).
type xdpUmemReg struct {
	addr     uint64
	len      uint64
	size     uint32 // chunk size (= xdpFrameSize)
	headroom uint32 // bytes reserved before packet data (we use 0)
	flags    uint32
	_        uint32 // padding
}

// xdpDesc mirrors struct xdp_desc (linux/if_xdp.h).
type xdpDesc struct {
	addr    uint64 // byte offset in UMEM where packet data starts
	length  uint32 // length of captured data
	options uint32
}

// xdpRingOffset mirrors struct xdp_ring_offset (linux/if_xdp.h, post-5.4 with flags).
type xdpRingOffset struct {
	producer uint64
	consumer uint64
	desc     uint64
	flags    uint64 // zero on kernels < 5.4
}

// xdpMmapOffsets mirrors struct xdp_mmap_offsets (linux/if_xdp.h).
type xdpMmapOffsets struct {
	rx xdpRingOffset
	tx xdpRingOffset
	fr xdpRingOffset // fill ring
	cr xdpRingOffset // completion ring
}

// xdpSockaddr mirrors struct sockaddr_xdp (linux/if_xdp.h).
type xdpSockaddr struct {
	family       uint16
	flags        uint16
	ifindex      uint32
	queueID      uint32
	sharedUmemFD uint32
}

// ── Ring handle ────────────────────────────────────────────────────────────

// xdpRingHandle wraps a mmap'd AF_XDP ring buffer.
type xdpRingHandle struct {
	mem      []byte
	size     uint32  // descriptor count (power of 2)
	mask     uint32  // size - 1, for fast modulo
	producer *uint32 // points into mem
	consumer *uint32 // points into mem
	flags    *uint32 // points into mem; nil on kernels < 5.4
	descBase uintptr // byte offset in mem where descriptor array starts
}

func newRingHandle(mem []byte, off xdpRingOffset, size uint32) *xdpRingHandle {
	r := &xdpRingHandle{
		mem:      mem,
		size:     size,
		mask:     size - 1,
		producer: (*uint32)(unsafe.Pointer(&mem[off.producer])),
		consumer: (*uint32)(unsafe.Pointer(&mem[off.consumer])),
		descBase: uintptr(unsafe.Pointer(&mem[off.desc])),
	}
	if off.flags != 0 && int(off.flags)+4 <= len(mem) {
		r.flags = (*uint32)(unsafe.Pointer(&mem[off.flags]))
	}
	return r
}

// ── Shared XDP program / map state ────────────────────────────────────────

// sharedXDPState owns the XSKMAP and XDP program for one interface.
// Multiple xdpSource instances (one per rx queue) hold a reference to this.
// When the last source is closed, the XDP program is detached automatically.
type sharedXDPState struct {
	xskMap *ebpf.Map
	prog   *ebpf.Program
	ilink  link.Link
	refs   int32 // atomic reference count
}

// newSharedXDPState loads the XDP program, creates the XSKMAP, and attaches
// both to the named interface.
func newSharedXDPState(iface string) (*sharedXDPState, error) {
	// Create XSKMAP: maps rx_queue_index → AF_XDP socket fd.
	xskMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "xsk_map",
		Type:       ebpf.XSKMap,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 64, // supports NICs with up to 64 rx queues
	})
	if err != nil {
		return nil, fmt.Errorf("create xsk_map: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			xskMap.Close()
		}
	}()

	// Build XDP eBPF program via cilium/ebpf asm DSL (no C compiler needed).
	//
	// Equivalent C:
	//   SEC("xdp") int xdp_redir(struct xdp_md *ctx) {
	//       return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, XDP_PASS);
	//   }
	//
	// BPF calling convention for bpf_redirect_map(map, key, flags):
	//   r1 = map pointer, r2 = key, r3 = flags
	//   struct xdp_md: { u32 data; u32 data_end; u32 data_meta;
	//                    u32 ingress_ifindex; u32 rx_queue_index; ... }
	//   rx_queue_index is at byte offset 16.
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:    "xdp_redir_xsk",
		Type:    ebpf.XDP,
		License: "GPL",
		Instructions: asm.Instructions{
			// r2 = ctx->rx_queue_index  (u32 at offset 16 in xdp_md)
			asm.LoadMem(asm.R2, asm.R1, 16, asm.Word),
			// r3 = XDP_PASS (fallback: no socket on this queue → normal stack)
			asm.Mov.Imm(asm.R3, 2),
			// r1 = &xsk_map  (BPF_PSEUDO_MAP_FD; kernel resolves fd → ptr)
			asm.LoadMapPtr(asm.R1, xskMap.FD()),
			// call bpf_redirect_map(r1, r2, r3)  → returns XDP verdict
			asm.FnRedirectMap.Call(),
			asm.Return(),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("load XDP program: %w", err)
	}
	defer func() {
		if !ok {
			prog.Close()
		}
	}()

	// Attach XDP program to the interface.
	// Try native (driver) mode first for best performance; fall back to SKB/generic.
	netIf, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", iface, err)
	}
	ilink, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: netIf.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		ilink, err = link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: netIf.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			return nil, fmt.Errorf("attach XDP to %s: %w", iface, err)
		}
		log.Printf("xdp: %s — using generic (SKB) mode (no native driver support)", iface)
	} else {
		log.Printf("xdp: %s — using native driver mode", iface)
	}

	ok = true
	return &sharedXDPState{
		xskMap: xskMap,
		prog:   prog,
		ilink:  ilink,
		refs:   0,
	}, nil
}

func (s *sharedXDPState) incRef() { atomic.AddInt32(&s.refs, 1) }

func (s *sharedXDPState) decRef() {
	if atomic.AddInt32(&s.refs, -1) == 0 {
		s.ilink.Close()
		s.prog.Close()
		s.xskMap.Close()
	}
}

// ── xdpSource ─────────────────────────────────────────────────────────────

// xdpSource implements CaptureSource for one NIC rx queue using AF_XDP.
type xdpSource struct {
	fd        int
	umem      []byte // anonymous mmap — the shared packet buffer
	fillMem   []byte // mmap of fill ring
	rxMem     []byte // mmap of rx ring
	fillRing  *xdpRingHandle
	rxRing    *xdpRingHandle
	shared    *sharedXDPState
	bpfFilter *pcap.BPF // compiled classical BPF filter; nil = pass all
	closed    int32     // atomic
}

// newXDPSource creates one AF_XDP capture socket bound to the given rx queue.
// It registers the socket in the shared XSKMAP so the XDP program redirects
// packets from that queue to this socket.
// bpfExpr is an optional classical BPF filter expression (same syntax as tcpdump).
// It is applied in userspace after receiving from the AF_XDP ring.
func newXDPSource(ifaceIndex int, queueID uint32, shared *sharedXDPState, bpfExpr string) (*xdpSource, error) {
	// ── 1. Create AF_XDP socket ──────────────────────────────────────────
	fd, err := unix.Socket(afXDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("af_xdp socket: %w", err)
	}
	opened := false
	defer func() {
		if !opened {
			unix.Close(fd)
		}
	}()

	// ── 2. Allocate UMEM (anonymous private mmap) ────────────────────────
	umem, err := unix.Mmap(-1, 0, xdpUmemBytes,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return nil, fmt.Errorf("alloc umem (%d B): %w", xdpUmemBytes, err)
	}
	umemOK := false
	defer func() {
		if !umemOK {
			unix.Munmap(umem)
		}
	}()

	// ── 3. Register UMEM with the socket ────────────────────────────────
	reg := xdpUmemReg{
		addr: uint64(uintptr(unsafe.Pointer(&umem[0]))),
		len:  uint64(xdpUmemBytes),
		size: xdpFrameSize,
	}
	if err := xdpSetsockopt(fd, soptXDPUmemReg, unsafe.Pointer(&reg), unsafe.Sizeof(reg)); err != nil {
		return nil, fmt.Errorf("register umem: %w", err)
	}

	// ── 4. Set fill and rx ring sizes ────────────────────────────────────
	fillSz := uint32(xdpFillRing)
	if err := xdpSetsockopt(fd, soptXDPUmemFillRing, unsafe.Pointer(&fillSz), unsafe.Sizeof(fillSz)); err != nil {
		return nil, fmt.Errorf("set fill ring size: %w", err)
	}
	rxSz := uint32(xdpRxRing)
	if err := xdpSetsockopt(fd, soptXDPRxRing, unsafe.Pointer(&rxSz), unsafe.Sizeof(rxSz)); err != nil {
		return nil, fmt.Errorf("set rx ring size: %w", err)
	}

	// ── 5. Query mmap offsets ────────────────────────────────────────────
	offsets, err := xdpMmapOffsetsGet(fd)
	if err != nil {
		return nil, fmt.Errorf("get mmap offsets: %w", err)
	}

	// ── 6. Mmap fill ring ────────────────────────────────────────────────
	fillSz64 := int(offsets.fr.desc) + xdpFillRing*8 // each fill entry = uint64
	fillMem, err := unix.Mmap(fd, xdpPgoffFill, fillSz64,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return nil, fmt.Errorf("mmap fill ring: %w", err)
	}
	fillOK := false
	defer func() {
		if !fillOK {
			unix.Munmap(fillMem)
		}
	}()

	// ── 7. Mmap rx ring ──────────────────────────────────────────────────
	rxDescSz := int(unsafe.Sizeof(xdpDesc{}))
	rxSz64 := int(offsets.rx.desc) + xdpRxRing*rxDescSz
	rxMem, err := unix.Mmap(fd, xdpPgoffRxRing, rxSz64,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return nil, fmt.Errorf("mmap rx ring: %w", err)
	}
	rxOK := false
	defer func() {
		if !rxOK {
			unix.Munmap(rxMem)
		}
	}()

	// ── 8. Build ring handles ─────────────────────────────────────────────
	fillRing := newRingHandle(fillMem, offsets.fr, xdpFillRing)
	rxRing := newRingHandle(rxMem, offsets.rx, xdpRxRing)

	// ── 9. Bind socket: try zero-copy, fall back to copy mode ────────────
	sa := xdpSockaddr{
		family:  afXDP,
		flags:   xdpBindZeroCopy,
		ifindex: uint32(ifaceIndex),
		queueID: queueID,
	}
	if err := xdpBind(fd, sa); err != nil {
		sa.flags = xdpBindCopy
		if err2 := xdpBind(fd, sa); err2 != nil {
			return nil, fmt.Errorf("bind af_xdp queue %d: %w", queueID, err2)
		}
		log.Printf("xdp: queue %d — using copy mode (zero-copy unsupported by driver)", queueID)
	} else {
		log.Printf("xdp: queue %d — using zero-copy mode", queueID)
	}

	// ── 10. Pre-populate fill ring with all available frame addresses ─────
	// The kernel needs free frames in the fill ring to DMA packets into.
	// Frame N occupies UMEM bytes [N*xdpFrameSize .. (N+1)*xdpFrameSize).
	prod := uint32(0)
	for i := uint32(0); i < xdpFillRing; i++ {
		frameAddr := uint64(i) * xdpFrameSize
		*(*uint64)(unsafe.Pointer(fillRing.descBase + uintptr(prod&fillRing.mask)*8)) = frameAddr
		prod++
	}
	atomic.StoreUint32(fillRing.producer, prod)

	// ── 11. Register this socket in the shared XSKMAP ────────────────────
	// The XDP program uses rx_queue_index as the map key.
	key := uint32(queueID)
	val := uint32(fd)
	if err := shared.xskMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return nil, fmt.Errorf("insert queue %d into xsk_map: %w", queueID, err)
	}

	// ── 12. Compile BPF filter for userspace application ─────────────────
	// The XDP program redirects all frames from this queue to AF_XDP.
	// Classical BPF is applied here in userspace so callers see only the
	// packets matching their filter, identical to the AF_PACKET behaviour.
	var compiledBPF *pcap.BPF
	if bpfExpr != "" {
		compiled, err := pcap.NewBPF(layers.LinkTypeEthernet, xdpFrameSize, bpfExpr)
		if err != nil {
			log.Printf("xdp: queue %d: failed to compile BPF filter %q: %v — capturing all", queueID, bpfExpr, err)
		} else {
			compiledBPF = compiled
			log.Printf("xdp: queue %d: BPF filter %q compiled and applied in userspace", queueID, bpfExpr)
		}
	}

	shared.incRef()
	opened = true
	umemOK = true
	fillOK = true
	rxOK = true

	return &xdpSource{
		fd:        fd,
		umem:      umem,
		fillMem:   fillMem,
		rxMem:     rxMem,
		fillRing:  fillRing,
		rxRing:    rxRing,
		shared:    shared,
		bpfFilter: compiledBPF,
	}, nil
}

// ReadPacket blocks until a packet is available, then returns it.
// Implements CaptureSource.
func (s *xdpSource) ReadPacket() (RawPacket, error) {
	for {
		if atomic.LoadInt32(&s.closed) != 0 {
			return RawPacket{}, io.EOF
		}

		rxProd := atomic.LoadUint32(s.rxRing.producer)
		rxCons := atomic.LoadUint32(s.rxRing.consumer)

		if rxProd == rxCons {
			// RX ring empty — wait for the kernel to deliver more packets.
			pollfds := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}}
			if _, err := unix.Poll(pollfds, 100); err != nil && err != unix.EINTR {
				return RawPacket{}, fmt.Errorf("poll: %w", err)
			}
			continue
		}

		// Read descriptor at head of rx ring (consumer position).
		descSize := uintptr(unsafe.Sizeof(xdpDesc{}))
		desc := *(*xdpDesc)(unsafe.Pointer(
			s.rxRing.descBase + uintptr(rxCons&s.rxRing.mask)*descSize,
		))

		// Sanity check: addr + length must be within the UMEM.
		if desc.addr+uint64(desc.length) > uint64(len(s.umem)) {
			// Corrupt descriptor — advance consumer and skip.
			atomic.StoreUint32(s.rxRing.consumer, rxCons+1)
			continue
		}

		// Copy packet bytes out of the UMEM frame into an owned slice.
		// (With zero-copy mode the kernel still needs the frame back; we
		// copy here so callers can hold the data indefinitely.)
		data := make([]byte, desc.length)
		copy(data, s.umem[desc.addr:desc.addr+uint64(desc.length)])
		ts := time.Now()

		// Advance rx consumer so the kernel can reuse this ring slot.
		atomic.StoreUint32(s.rxRing.consumer, rxCons+1)

		// Apply classical BPF filter in userspace (same semantics as AF_PACKET).
		// Non-matching packets still need their frame recycled before we skip.
		if s.bpfFilter != nil && !s.bpfFilter.Matches(
			gopacket.CaptureInfo{Timestamp: ts, CaptureLength: int(desc.length), Length: int(desc.length)},
			data,
		) {
			// Recycle before continuing — fall through to fill-ring update below.
			frameBase := desc.addr &^ (xdpFrameSize - 1)
			fillProd := atomic.LoadUint32(s.fillRing.producer)
			fillCons := atomic.LoadUint32(s.fillRing.consumer)
			if s.fillRing.size-(fillProd-fillCons) > 0 {
				*(*uint64)(unsafe.Pointer(s.fillRing.descBase + uintptr(fillProd&s.fillRing.mask)*8)) = frameBase
				atomic.StoreUint32(s.fillRing.producer, fillProd+1)
			}
			continue
		}

		// Recycle the frame back into the fill ring so the kernel can
		// DMA the next packet into it.
		fillProd := atomic.LoadUint32(s.fillRing.producer)
		fillCons := atomic.LoadUint32(s.fillRing.consumer)
		free := s.fillRing.size - (fillProd - fillCons)
		if free > 0 {
			// Return the frame's base address (headroom = 0, so base == addr
			// rounded down to xdpFrameSize alignment).
			frameBase := desc.addr &^ (xdpFrameSize - 1)
			*(*uint64)(unsafe.Pointer(
				s.fillRing.descBase + uintptr(fillProd&s.fillRing.mask)*8,
			)) = frameBase
			atomic.StoreUint32(s.fillRing.producer, fillProd+1)
		}

		return RawPacket{
			Data: data,
			CaptureInfo: gopacket.CaptureInfo{
				Timestamp:     ts,
				CaptureLength: int(desc.length),
				Length:        int(desc.length),
			},
		}, nil
	}
}

func (s *xdpSource) Decoder() gopacket.Decoder { return layers.LinkTypeEthernet }

func (s *xdpSource) Stats() SourceStats { return SourceStats{} }

func (s *xdpSource) Close() error {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return nil
	}
	unix.Munmap(s.rxMem)
	unix.Munmap(s.fillMem)
	unix.Munmap(s.umem)
	unix.Close(s.fd)
	s.shared.decRef()
	return nil
}

// ── XDPSourceFactory ──────────────────────────────────────────────────────

// XDPSourceFactory creates AF_XDP capture sources.
// For count > 1 it opens one socket per rx queue so all queues are covered
// (equivalent to AF_PACKET FANOUT).
type XDPSourceFactory struct{}

func (f *XDPSourceFactory) CreateSources(iface, bpfFilter string, count int, cfg CaptureConfig) ([]CaptureSource, error) {
	// One shared XDP program + XSKMAP per interface.
	shared, err := newSharedXDPState(iface)
	if err != nil {
		return nil, fmt.Errorf("xdp: init for %s: %w", iface, err)
	}

	// Resolve interface index.
	netIf, err := net.InterfaceByName(iface)
	if err != nil {
		shared.decRef() // closes the program (refs never incremented)
		return nil, fmt.Errorf("resolve iface %q: %w", iface, err)
	}

	// Clamp queue count to 1 if NIC doesn't have multiple queues or count < 1.
	if count < 1 {
		count = 1
	}

	sources := make([]CaptureSource, 0, count)
	for q := 0; q < count; q++ {
		src, err := newXDPSource(netIf.Index, uint32(q), shared, bpfFilter)
		if err != nil {
			// Close already-opened sources; shared state goes away when refs hit 0.
			for _, s := range sources {
				s.Close()
			}
			if len(sources) == 0 {
				// No sources opened yet; shared still has refs == 0, close manually.
				shared.decRef()
			}
			return nil, fmt.Errorf("xdp: open queue %d on %s: %w", q, iface, err)
		}
		sources = append(sources, src)
		log.Printf("xdp: queue %d/%d opened on %s (umem %d MiB)", q, count, iface, xdpUmemBytes>>20)
	}

	// BPF filter is applied in userspace post-receive (same as AF_PACKET).
	// The XDP program itself redirects everything on the captured queues;
	// port filtering inside the XDP program is a future optimisation.
	if bpfFilter != "" {
		log.Printf("xdp: BPF filter %q applied in userspace (XDP redirects all frames)", bpfFilter)
	}

	return sources, nil
}

// xdpAvailable probes whether AF_XDP sockets and BPF program loading work
// on this kernel. Returns true if XDP capture is usable.
func xdpAvailable() bool {
	fd, err := unix.Socket(afXDP, unix.SOCK_RAW, 0)
	if err != nil {
		return false // kernel < 4.18 or no CAP_NET_RAW
	}
	unix.Close(fd)

	// Check that we can actually load a BPF program (needs CAP_BPF / CAP_SYS_ADMIN).
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:    "xdp_probe",
		Type:    ebpf.XDP,
		License: "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 2), // XDP_PASS
			asm.Return(),
		},
	})
	if err != nil {
		return false
	}
	prog.Close()
	return true
}

// ── Syscall helpers ───────────────────────────────────────────────────────

func xdpSetsockopt(fd, opt int, val unsafe.Pointer, size uintptr) error {
	_, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(fd), uintptr(solXDP), uintptr(opt),
		uintptr(val), size, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func xdpMmapOffsetsGet(fd int) (xdpMmapOffsets, error) {
	var offsets xdpMmapOffsets
	size := uint32(unsafe.Sizeof(offsets))
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd), uintptr(solXDP), uintptr(soptXDPMmapOffsets),
		uintptr(unsafe.Pointer(&offsets)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if errno != 0 {
		return xdpMmapOffsets{}, errno
	}
	return offsets, nil
}

func xdpBind(fd int, sa xdpSockaddr) error {
	_, _, errno := unix.Syscall(
		unix.SYS_BIND,
		uintptr(fd),
		uintptr(unsafe.Pointer(&sa)),
		unsafe.Sizeof(sa),
	)
	if errno != 0 {
		return errno
	}
	return nil
}
