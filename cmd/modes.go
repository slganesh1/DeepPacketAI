package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"DeepPacketAI/internal/capture"
	"DeepPacketAI/internal/stream"
)

// listInterfaces prints all available network interfaces and exits.
// Useful on Windows where pcap device names differ from friendly display names.
func listInterfaces() {
	ifaces, err := capture.ListInterfaces()
	if err != nil {
		log.Fatalf("list interfaces: %v", err)
	}
	fmt.Println("Available network interfaces:")
	fmt.Println()
	for _, iface := range ifaces {
		fmt.Printf("  Name:        %s\n", iface.Name)
		if iface.Description != "" {
			fmt.Printf("  Description: %s\n", iface.Description)
		}
		if len(iface.Addresses) > 0 {
			fmt.Printf("  Addresses:   %v\n", iface.Addresses)
		}
		fmt.Println()
	}
	fmt.Println("Use the Name value with --iface.")
	fmt.Println("On Windows, friendly names like 'Ethernet' are also accepted and auto-resolved.")
}

// runAgent starts a lightweight capture-only agent that streams all packets to
// a central DeepPacketAI node for analysis. No database, no UI, no AI — just
// capture and stream.
//
// Usage:
//
//	deeppacketai --mode=agent --iface=eth0 --central=192.168.1.10:9090
//	deeppacketai --mode=agent --iface=eth0 --filter="port 5060" --central=192.168.1.10:9090
func runAgent(iface, bpfFilter, centralAddr, agentID string) {
	if centralAddr == "" {
		log.Fatal("agent mode: --central <host:port> is required")
	}
	if iface == "" {
		log.Fatal("agent mode: --iface <interface> is required")
	}
	if agentID == "" {
		host, _ := os.Hostname()
		agentID = host + "-" + iface
	}

	hostname, _ := os.Hostname()

	// Resolve Windows-friendly names (e.g. "Ethernet") to pcap device names
	resolvedIface := capture.ResolveInterfaceName(iface)
	if resolvedIface != iface {
		log.Printf("agent: resolved interface %q → %q", iface, resolvedIface)
	}

	log.Printf("agent: id=%s iface=%s filter=%q central=%s", agentID, resolvedIface, bpfFilter, centralAddr)

	cfg := capture.DefaultCaptureConfig()
	factory := capture.NewSourceFactory(cfg)

	normalizedFilter := capture.NormalizeBPFFilter(bpfFilter)
	sources, err := factory.CreateSources(resolvedIface, normalizedFilter, 1, cfg)
	if err != nil {
		log.Printf("agent: failed to open interface %q: %v", resolvedIface, err)
		log.Println()
		log.Println("Run with --list-interfaces to see all available interface names.")
		os.Exit(1)
	}
	defer sources[0].Close()

	info := stream.AgentInfo{
		ID:        agentID,
		Hostname:  hostname,
		Interface: iface,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	streamer := stream.NewAgentStreamer(info, sources[0], centralAddr)
	log.Printf("agent: streaming packets to central %s", centralAddr)
	streamer.Run(ctx)
	log.Println("agent: stopped")
}

// startCentralReceiver starts the TCP listener that receives agent streams.
// It is called alongside the normal HTTP server in central mode.
func startCentralReceiver(streamAddr string, engine *capture.Engine) {
	receiver := stream.NewCentralReceiver(engine)
	if err := receiver.Listen(streamAddr); err != nil {
		log.Fatalf("central: failed to start stream receiver on %s: %v", streamAddr, err)
	}
}
