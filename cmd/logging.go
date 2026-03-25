package main

import (
	"log"
	"os"
	"path/filepath"
)

// setupLogging redirects the standard logger to a rolling log file in appDataDir.
// This is essential for windowsgui builds where there is no console attached.
func setupLogging(appDataDir string) {
	logPath := filepath.Join(appDataDir, "deeppacketai.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		// Can't open log file — fall back to stderr (works in console builds).
		return
	}
	log.SetOutput(f)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}
