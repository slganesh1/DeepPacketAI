#!/usr/bin/env bash
# ============================================================================
# DeepPacketAI macOS Build Script
# Run this on a Mac (Intel or Apple Silicon).
#
# Usage:
#   ./build-mac.sh            -> produces bin/deeppacketai + .app bundle
#   ./build-mac.sh --dmg      -> also wraps .app in a distributable .dmg
#   ./build-mac.sh --sign     -> code-sign + notarize (needs Apple Developer account)
#
# Prerequisites:
#   brew install create-dmg   (for --dmg)
#   Xcode Command Line Tools  (for --sign)
# ============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="${VERSION:-1.0.0}"
APP_NAME="DeepPacketAI"
BUNDLE_ID="com.deeppacketai.app"

# Code signing (set these for --sign)
DEVELOPER_ID="${DEVELOPER_ID:-}"        # e.g. "Developer ID Application: Your Name (XXXXXXXXXX)"
NOTARIZE_TEAM="${NOTARIZE_TEAM:-}"      # Apple Team ID
NOTARIZE_USER="${NOTARIZE_USER:-}"      # Apple ID email
NOTARIZE_PASS="${NOTARIZE_PASS:-}"      # App-specific password

BUILD_DMG=false
DO_SIGN=false
for arg in "$@"; do
  case "$arg" in
    --dmg)  BUILD_DMG=true ;;
    --sign) DO_SIGN=true   ;;
  esac
done

step() { echo ""; echo ">>> $1"; }

# ---- Check dependencies ----------------------------------------------------
step "Checking build dependencies"
command -v go  >/dev/null || { echo "ERROR: Go not found"; exit 1; }
command -v npm >/dev/null || { echo "ERROR: npm not found"; exit 1; }

if $BUILD_DMG && ! command -v create-dmg &>/dev/null; then
  echo "ERROR: create-dmg not found. Install with: brew install create-dmg"
  exit 1
fi

# ---- Step 1: Build React UI -------------------------------------------------
step "Building React UI"
cd "$ROOT/deeppacketai-ui"
npm install
npm run build
cd "$ROOT"

# ---- Step 2: Build Go binary ------------------------------------------------
step "Building Go binary"
mkdir -p "$ROOT/bin"

# Detect architecture for universal binary support
GOARCH_FLAG=""
if [ "$(uname -m)" = "arm64" ]; then
  GOARCH_FLAG="arm64"
else
  GOARCH_FLAG="amd64"
fi

CGO_ENABLED=1 GOOS=darwin GOARCH="$GOARCH_FLAG" go build \
  -ldflags="-s -w" \
  -o "$ROOT/bin/deeppacketai" \
  "$ROOT/cmd/"

echo "Binary: $ROOT/bin/deeppacketai"

# ---- Step 3: Build .app bundle ----------------------------------------------
step "Building .app bundle"

APPDIR="$ROOT/dist/${APP_NAME}.app"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/Contents/MacOS"
mkdir -p "$APPDIR/Contents/Resources"

# Copy binary
cp "$ROOT/bin/deeppacketai" "$APPDIR/Contents/MacOS/deeppacketai"
chmod +x "$APPDIR/Contents/MacOS/deeppacketai"

# Info.plist
cat > "$APPDIR/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>${BUNDLE_ID}</string>
  <key>CFBundleName</key>
  <string>${APP_NAME}</string>
  <key>CFBundleDisplayName</key>
  <string>${APP_NAME}</string>
  <key>CFBundleVersion</key>
  <string>${VERSION}</string>
  <key>CFBundleShortVersionString</key>
  <string>${VERSION}</string>
  <key>CFBundleExecutable</key>
  <string>deeppacketai</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
  <key>LSMinimumSystemVersion</key>
  <string>12.0</string>
  <key>LSUIElement</key>
  <false/>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSRequiresAquaSystemAppearance</key>
  <false/>
</dict>
</plist>
EOF

echo ".app bundle: $APPDIR"

# ---- Step 4: Code sign (optional) ------------------------------------------
if $DO_SIGN; then
  step "Code signing"

  if [ -z "$DEVELOPER_ID" ]; then
    echo "ERROR: Set DEVELOPER_ID env var, e.g.:"
    echo "  export DEVELOPER_ID=\"Developer ID Application: Your Name (XXXXXXXXXX)\""
    exit 1
  fi

  # Sign the binary and bundle
  codesign --deep --force --verify --verbose \
    --sign "$DEVELOPER_ID" \
    --options runtime \
    --entitlements "$ROOT/installer/entitlements.plist" \
    "$APPDIR"

  echo "Signed: $APPDIR"

  # Notarize
  if [ -n "$NOTARIZE_USER" ] && [ -n "$NOTARIZE_PASS" ]; then
    step "Notarizing (this can take a few minutes)"
    ditto -c -k --keepParent "$APPDIR" "/tmp/${APP_NAME}.zip"
    xcrun notarytool submit "/tmp/${APP_NAME}.zip" \
      --apple-id "$NOTARIZE_USER" \
      --password "$NOTARIZE_PASS" \
      --team-id "$NOTARIZE_TEAM" \
      --wait
    xcrun stapler staple "$APPDIR"
    echo "Notarized and stapled."
  fi
fi

# ---- Step 5: DMG (optional) ------------------------------------------------
if $BUILD_DMG; then
  step "Building .dmg"

  mkdir -p "$ROOT/dist"
  DMG_OUT="$ROOT/dist/${APP_NAME}-${VERSION}.dmg"

  create-dmg \
    --volname "$APP_NAME $VERSION" \
    --window-pos 200 120 \
    --window-size 600 400 \
    --icon-size 100 \
    --icon "${APP_NAME}.app" 150 180 \
    --hide-extension "${APP_NAME}.app" \
    --app-drop-link 450 180 \
    "$DMG_OUT" \
    "$ROOT/dist/"

  echo "DMG: $DMG_OUT"
fi

echo ""
echo "Build complete!"
