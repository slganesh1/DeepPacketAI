.PHONY: all clean build build-ui build-release run installer

# ── Dev build (console window, fast) ──────────────────────────────────────────
all: build

build-ui:
	cd deeppacketai-ui && npm install && npm run build

build: build-ui
	go build -ldflags="-s -w" -o ./bin/deeppacketai.exe ./cmd/

run: build
	./bin/deeppacketai.exe

# ── Release build (no console window — opens browser silently) ────────────────
# Requires native Windows build environment with CGO (gcc via TDM-GCC or MSYS2).
build-release: build-ui
	go build -ldflags="-s -w -H windowsgui" -o ./installer/deeppacketai.exe ./cmd/

# ── Inno Setup installer ───────────────────────────────────────────────────────
# Prerequisites:
#   1. Run `make build-release` first.
#   2. Place the Npcap installer as installer/npcap-installer.exe
#      (download from https://npcap.com/#download).
#   3. Inno Setup must be installed (ISCC on PATH, or adjust the path below).
installer: build-release
	@echo "Building installer..."
	@if [ -f "installer/npcap-installer.exe" ]; then \
		ISCC installer/deeppacketai.iss; \
	else \
		echo "ERROR: installer/npcap-installer.exe not found."; \
		echo "       Download Npcap from https://npcap.com/#download and place it there."; \
		exit 1; \
	fi

clean:
	rm -rf ./bin ./installer/deeppacketai.exe ./installer/Output
