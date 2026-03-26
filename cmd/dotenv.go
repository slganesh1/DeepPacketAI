package main

import (
	"log"
	"os"
	"strings"
)

// loadDotEnv reads a .env file and sets any keys that are not already present
// in the environment. It searches in the current working directory first, then
// in the directory of the executable.
//
// Format supported:
//
//	KEY=value
//	KEY = value       (spaces around = are trimmed)
//	# comment lines   (ignored)
//	                  (blank lines ignored)
//
// Values already set in the OS environment are never overwritten, so real
// environment variables always take precedence over .env.
func loadDotEnv() {
	candidates := []string{
		".env",
		envFileNextToExe(),
	}

	for _, path := range candidates {
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		loaded := applyEnv(string(data))
		if loaded > 0 {
			log.Printf("env: loaded %d variable(s) from %s", loaded, path)
		}
		return // stop after first successful file
	}
}

// envFileNextToExe returns the path to .env next to the running executable.
func envFileNextToExe() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	// exe is e.g. C:\path\to\deeppacketai.exe
	// Remove the filename, append .env
	idx := strings.LastIndexAny(exe, `/\`)
	if idx < 0 {
		return ".env"
	}
	return exe[:idx+1] + ".env"
}

// applyEnv parses dotenv-formatted text, sets missing env vars, and returns
// the count of variables that were actually applied.
func applyEnv(content string) int {
	applied := 0
	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimSpace(rawLine)

		// Skip blank lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue // no = sign → skip
		}

		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])

		// Strip optional surrounding quotes: KEY="value" or KEY='value'
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') ||
				(val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}

		if key == "" {
			continue
		}

		// Only set if not already in the environment
		if os.Getenv(key) == "" {
			_ = os.Setenv(key, val)
			applied++
		}
	}
	return applied
}
