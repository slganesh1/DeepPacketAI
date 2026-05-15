//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
)

const systemdUnit = `[Unit]
Description=DeepPacketAI Capture Agent
After=network.target

[Service]
Type=simple
ExecStart={{.ExecPath}} --mode=agent {{.Args}}
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=deeppacketai-agent

[Install]
WantedBy=multi-user.target
`

const unitName = "deeppacketai-agent.service"
const unitDir = "/etc/systemd/system"

func installAgentService() error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	execPath, err = filepath.Abs(execPath)
	if err != nil {
		return fmt.Errorf("abs path: %w", err)
	}

	unitPath := filepath.Join(unitDir, unitName)
	f, err := os.Create(unitPath)
	if err != nil {
		return fmt.Errorf("create unit file %s: %w (run as root?)", unitPath, err)
	}
	defer f.Close()

	tmpl := template.Must(template.New("unit").Parse(systemdUnit))
	if err := tmpl.Execute(f, struct{ ExecPath, Args string }{
		ExecPath: execPath,
		Args:     "--iface=eth0", // placeholder; edit unit file to customise
	}); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}

	for _, args := range [][]string{
		{"daemon-reload"},
		{"enable", unitName},
	} {
		if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %v: %v\n%s", args, err, out)
		}
	}

	fmt.Printf("Installed %s\n", unitPath)
	fmt.Printf("Edit %s to set --iface, --central, --filter, etc.\n", unitPath)
	fmt.Println("Then run: systemctl start deeppacketai-agent")
	return nil
}

func uninstallAgentService() error {
	// Stop if running (ignore errors — may already be stopped)
	_ = exec.Command("systemctl", "stop", unitName).Run()

	if out, err := exec.Command("systemctl", "disable", unitName).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl disable: %v\n%s", err, out)
	}

	unitPath := filepath.Join(unitDir, unitName)
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unit file: %w", err)
	}

	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %v\n%s", err, out)
	}

	fmt.Printf("Uninstalled %s\n", unitName)
	return nil
}
