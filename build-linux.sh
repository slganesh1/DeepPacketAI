#!/usr/bin/env bash
# ============================================================================
# DeepPacketAI Linux Build Script
# Run this on Linux (or WSL2 / Docker).
#
# Usage:
#   ./build-linux.sh            -> produces bin/deeppacketai (binary)
#   ./build-linux.sh --appimage -> also wraps in an AppImage
#   ./build-linux.sh --deb      -> also builds a .deb package
# ============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="${VERSION:-1.0.0}"
ARCH="$(uname -m)"   # x86_64 or aarch64

BUILD_APPIMAGE=false
BUILD_DEB=false
for arg in "$@"; do
  case "$arg" in
    --appimage) BUILD_APPIMAGE=true ;;
    --deb)      BUILD_DEB=true      ;;
  esac
done

step() { echo ""; echo ">>> $1"; }

# ---- Check dependencies ---------------------------------------------------
step "Checking build dependencies"
command -v go      >/dev/null || { echo "ERROR: Go not found"; exit 1; }
command -v npm     >/dev/null || { echo "ERROR: npm not found"; exit 1; }
command -v gcc     >/dev/null || { echo "ERROR: gcc not found (needed for CGO)"; exit 1; }

# libpcap-dev needed for gopacket
if ! dpkg -s libpcap-dev &>/dev/null 2>&1 && ! rpm -q libpcap-devel &>/dev/null 2>&1; then
  echo "WARNING: libpcap-dev not found. Installing..."
  if command -v apt-get &>/dev/null; then
    sudo apt-get install -y libpcap-dev
  elif command -v dnf &>/dev/null; then
    sudo dnf install -y libpcap-devel
  elif command -v yum &>/dev/null; then
    sudo yum install -y libpcap-devel
  else
    echo "ERROR: Cannot install libpcap-dev automatically. Install it manually."
    exit 1
  fi
fi

# ---- Step 1: Build React UI -----------------------------------------------
step "Building React UI"
cd "$ROOT/deeppacketai-ui"
npm install
npm run build
cd "$ROOT"

# ---- Step 2: Build Go binary -----------------------------------------------
step "Building Go binary"
mkdir -p "$ROOT/bin"
CGO_ENABLED=1 go build \
  -ldflags="-s -w" \
  -o "$ROOT/bin/deeppacketai" \
  "$ROOT/cmd/"
echo "Binary: $ROOT/bin/deeppacketai"

# ---- Step 3: AppImage -------------------------------------------------------
if $BUILD_APPIMAGE; then
  step "Building AppImage"

  # Download appimagetool if not present
  APPIMAGETOOL="$ROOT/bin/appimagetool"
  if [ ! -f "$APPIMAGETOOL" ]; then
    echo "Downloading appimagetool..."
    curl -Lo "$APPIMAGETOOL" \
      "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage"
    chmod +x "$APPIMAGETOOL"
  fi

  # Build AppDir structure
  APPDIR="$ROOT/build/AppDir"
  rm -rf "$APPDIR"
  mkdir -p "$APPDIR/usr/bin"
  mkdir -p "$APPDIR/usr/share/applications"
  mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"

  cp "$ROOT/bin/deeppacketai" "$APPDIR/usr/bin/deeppacketai"

  # .desktop file
  cat > "$APPDIR/usr/share/applications/deeppacketai.desktop" <<EOF
[Desktop Entry]
Name=DeepPacketAI
Comment=Deep Packet Inspection and AI Analysis
Exec=deeppacketai
Icon=deeppacketai
Type=Application
Categories=Network;
Terminal=false
EOF

  # AppRun entrypoint
  cat > "$APPDIR/AppRun" <<'EOF'
#!/bin/bash
SELF=$(readlink -f "$0")
HERE="${SELF%/*}"
export PATH="$HERE/usr/bin:$PATH"
exec "$HERE/usr/bin/deeppacketai" "$@"
EOF
  chmod +x "$APPDIR/AppRun"

  # Symlinks required by AppImage spec
  ln -sf "usr/share/applications/deeppacketai.desktop" "$APPDIR/deeppacketai.desktop"

  # Build the AppImage
  mkdir -p "$ROOT/dist"
  ARCH="$ARCH" "$APPIMAGETOOL" "$APPDIR" \
    "$ROOT/dist/DeepPacketAI-$VERSION-$ARCH.AppImage"

  echo "AppImage: $ROOT/dist/DeepPacketAI-$VERSION-$ARCH.AppImage"
fi

# ---- Step 4: Debian .deb package -------------------------------------------
if $BUILD_DEB; then
  step "Building .deb package"

  DEB_ROOT="$ROOT/build/deb/deeppacketai_${VERSION}_amd64"
  rm -rf "$DEB_ROOT"
  mkdir -p "$DEB_ROOT/DEBIAN"
  mkdir -p "$DEB_ROOT/usr/bin"
  mkdir -p "$DEB_ROOT/usr/share/applications"
  mkdir -p "$DEB_ROOT/lib/systemd/system"

  cp "$ROOT/bin/deeppacketai" "$DEB_ROOT/usr/bin/deeppacketai"

  # DEBIAN/control
  cat > "$DEB_ROOT/DEBIAN/control" <<EOF
Package: deeppacketai
Version: $VERSION
Section: net
Priority: optional
Architecture: amd64
Depends: libpcap0.8
Maintainer: DeepPacketAI <support@deeppacketai.com>
Description: Deep Packet Inspection and AI Network Analysis
 DeepPacketAI captures and analyzes network traffic using AI.
 Supports SIP, RTP, GTP, DNS, HTTP, TLS and more.
EOF

  # Post-install script: ensure libpcap is available
  cat > "$DEB_ROOT/DEBIAN/postinst" <<'EOF'
#!/bin/bash
set -e
echo "DeepPacketAI installed. Run: deeppacketai"
echo "Data stored in: ~/.local/share/DeepPacketAI/"
EOF
  chmod 755 "$DEB_ROOT/DEBIAN/postinst"

  # .desktop file
  cat > "$DEB_ROOT/usr/share/applications/deeppacketai.desktop" <<EOF
[Desktop Entry]
Name=DeepPacketAI
Comment=Deep Packet Inspection and AI Analysis
Exec=/usr/bin/deeppacketai
Icon=deeppacketai
Type=Application
Categories=Network;
Terminal=false
EOF

  mkdir -p "$ROOT/dist"
  dpkg-deb --build "$DEB_ROOT" "$ROOT/dist/deeppacketai_${VERSION}_amd64.deb"
  echo ".deb: $ROOT/dist/deeppacketai_${VERSION}_amd64.deb"
fi

echo ""
echo "Build complete!"
