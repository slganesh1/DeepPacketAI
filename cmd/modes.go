package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"DeepPacketAI/internal/capture"
	"DeepPacketAI/internal/stream"
)

// listInterfaces prints all available network interfaces and exits.
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

// AgentFlags holds all agent-mode configuration parsed from CLI flags.
type AgentFlags struct {
	Ifaces      string  // comma-separated interface list
	BPFFilter   string
	CentralAddr string
	AgentID     string
	Token       string
	UseTLS      bool
	TLSSkipVfy  bool
	TLSCA       string
	MaxMbps     float64
}

// runAgent starts one AgentStreamer per interface and streams all packets to
// a central DeepPacketAI node. Supports:
//   - Multiple interfaces (comma-separated --iface)
//   - TLS + token authentication
//   - Outbound bandwidth throttling
//   - BPF filter hot-swap (initiated by central)
//
// Usage:
//
//	deeppacketai --mode=agent --iface=eth0,eth1 --central=192.168.1.10:9090
//	deeppacketai --mode=agent --iface=eth0 --filter="port 5060" --token=secret --tls --central=host:9090
func runAgent(f AgentFlags) {
	if f.CentralAddr == "" {
		log.Fatal("agent mode: --central <host:port> is required")
	}
	if f.Ifaces == "" {
		log.Fatal("agent mode: --iface <interface[,interface...]> is required")
	}

	hostname, _ := os.Hostname()

	agentCfg := stream.AgentConfig{
		Token:         f.Token,
		UseTLS:        f.UseTLS,
		TLSSkipVerify: f.TLSSkipVfy,
		TLSCA:         f.TLSCA,
		MaxMbps:       f.MaxMbps,
	}

	capCfg := capture.DefaultCaptureConfig()
	factory := capture.NewSourceFactory(capCfg)
	normalizedFilter := capture.NormalizeBPFFilter(f.BPFFilter)

	// Split comma-separated interface list.
	ifaces := strings.Split(f.Ifaces, ",")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup
	for _, raw := range ifaces {
		iface := strings.TrimSpace(raw)
		if iface == "" {
			continue
		}
		resolved := capture.ResolveInterfaceName(iface)
		if resolved != iface {
			log.Printf("agent: resolved interface %q → %q", iface, resolved)
		}

		agentID := f.AgentID
		if agentID == "" {
			agentID = hostname + "-" + iface
		} else if len(ifaces) > 1 {
			agentID = agentID + "-" + iface // make ID unique per interface
		}

		info := stream.AgentInfo{
			ID:        agentID,
			Hostname:  hostname,
			Interface: resolved,
		}

		streamer := stream.NewAgentStreamer(info, factory, capCfg, normalizedFilter, f.CentralAddr, agentCfg)

		log.Printf("agent: id=%s iface=%s filter=%q central=%s tls=%v maxMbps=%.1f",
			agentID, resolved, normalizedFilter, f.CentralAddr, f.UseTLS, f.MaxMbps)

		wg.Add(1)
		go func() {
			defer wg.Done()
			streamer.Run(ctx)
		}()
	}

	wg.Wait()
	log.Println("agent: all interfaces stopped")
}

// startCentralReceiver starts the TCP listener that receives agent streams.
// Returns the AgentRegistry so the web server can expose it via /api/v1/agents.
func startCentralReceiver(ctx context.Context, streamAddr string, engine *capture.Engine, cfg stream.CentralConfig) *stream.AgentRegistry {
	receiver := stream.NewCentralReceiver(engine, cfg)
	if err := receiver.Listen(ctx, streamAddr); err != nil {
		log.Fatalf("central: failed to start stream receiver on %s: %v", streamAddr, err)
	}
	return receiver.Registry()
}
