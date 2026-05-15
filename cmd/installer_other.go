//go:build !linux && !windows

package main

import "fmt"

func installAgentService() error {
	return fmt.Errorf("service installer is not supported on this platform (supported: linux, windows)")
}

func uninstallAgentService() error {
	return fmt.Errorf("service uninstaller is not supported on this platform (supported: linux, windows)")
}
