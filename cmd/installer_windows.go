//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const serviceName = "DeepPacketAIAgent"
const serviceDisplay = "DeepPacketAI Capture Agent"
const serviceDesc = "Captures network traffic and streams it to a DeepPacketAI central node"

func installAgentService() error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	execPath, err = filepath.Abs(execPath)
	if err != nil {
		return fmt.Errorf("abs path: %w", err)
	}

	// binPath includes placeholder flags; the user should edit the service
	// via sc.exe or services.msc to add --iface, --central, etc.
	binPath := fmt.Sprintf(`"%s" --mode=agent --iface=Ethernet --central=127.0.0.1:9090`, execPath)

	args := []string{
		"create", serviceName,
		"binPath=", binPath,
		"start=", "auto",
		"DisplayName=", serviceDisplay,
	}
	if out, err := exec.Command("sc.exe", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("sc create: %v\n%s", err, out)
	}

	// Set description (separate sc call)
	descArgs := []string{"description", serviceName, serviceDesc}
	if out, err := exec.Command("sc.exe", descArgs...).CombinedOutput(); err != nil {
		// Non-fatal — description is cosmetic
		fmt.Printf("warning: sc description: %v\n%s\n", err, out)
	}

	fmt.Printf("Installed Windows service %q\n", serviceName)
	fmt.Println("Edit the service binary path via services.msc or sc.exe to set your flags.")
	fmt.Printf("Then run: sc.exe start %s\n", serviceName)
	return nil
}

func uninstallAgentService() error {
	// Stop if running
	_ = exec.Command("sc.exe", "stop", serviceName).Run()

	if out, err := exec.Command("sc.exe", "delete", serviceName).CombinedOutput(); err != nil {
		return fmt.Errorf("sc delete: %v\n%s", err, out)
	}

	fmt.Printf("Uninstalled Windows service %q\n", serviceName)
	return nil
}
