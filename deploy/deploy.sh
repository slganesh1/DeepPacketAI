#!/bin/bash
# DeepPacketAI — Build & Deploy Script
# Run on the SERVER as root after copying source files.
# Usage: bash deploy.sh [SOURCE_DIR]
#
# SOURCE_DIR: where you copied the project (default: /root/DeepPacketAI)

set -e
export PATH=$PATH:/usr/local/go/bin

# ---- Find source directory --------------------------------------------------
SRC_DIR="${1:-}"

# Auto-detect if not provided
if [ -z "$SRC_DIR" ]; then
    for candidate in \
        /root/DeepPacketAI \
        /root/new-start/DeepPacketAI \
        /tmp/DeepPacketAI \
        /home/*/DeepPacketAI \
        /opt/deeppacketai-src; do
        if [ -f "$candidate/go.mod" ]; then
            SRC_DIR="$candidate"
            break
        fi
    done
fi

if [ -z "$SRC_DIR" ] || [ ! -f "$SRC_DIR/go.mod" ]; then
    echo "ERROR: Could not find project source directory."
    echo "Usage: bash deploy.sh /path/to/DeepPacketAI"
    echo ""
    echo "Common locations to check:"
    echo "  ls /root/"
    echo "  ls /tmp/"
    exit 1
fi

APP_DIR=/opt/deeppacketai
echo "=== DeepPacketAI Deploy ==="
echo "  Source: $SRC_DIR"
echo "  Target: $APP_DIR"
echo ""

# ---- 1. Verify dependencies -------------------------------------------------
echo "[1/5] Checking dependencies..."

if ! /usr/local/go/bin/go version &>/dev/null; then
    echo "ERROR: Go not found. Run setup.sh first."
    exit 1
fi
if ! command -v node &>/dev/null; then
    echo "ERROR: Node.js not found. Run setup.sh first."
    exit 1
fi
if ! command -v npm &>/dev/null; then
    echo "ERROR: npm not found. Run setup.sh first."
    exit 1
fi
echo "  Go:   $(/usr/local/go/bin/go version | awk '{print $3}')"
echo "  Node: $(node --version)"
echo "  npm:  $(npm --version)"

# ---- 2. Build React UI ------------------------------------------------------
echo ""
echo "[2/5] Building React UI..."
cd "$SRC_DIR/deeppacketai-ui"
npm ci --prefer-offline 2>/dev/null || npm install
npm run build
echo "  Built: $(du -sh dist | cut -f1) in dist/"

# ---- 3. Build Go binary -----------------------------------------------------
echo ""
echo "[3/5] Building Go binary..."
cd "$SRC_DIR"
CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w" \
    -o "$APP_DIR/deeppacketai" \
    ./cmd/
chown deeppacketai:deeppacketai "$APP_DIR/deeppacketai"
chmod 755 "$APP_DIR/deeppacketai"
echo "  Binary: $(du -sh $APP_DIR/deeppacketai | cut -f1)"

# ---- 4. Copy React UI to nginx root -----------------------------------------
echo ""
echo "[4/5] Copying UI files to $APP_DIR/ui/..."
rm -rf "$APP_DIR/ui"
cp -r "$SRC_DIR/deeppacketai-ui/dist" "$APP_DIR/ui"
chown -R www-data:www-data "$APP_DIR/ui"
echo "  UI: $(du -sh $APP_DIR/ui | cut -f1)"

# ---- 5. Create .env if it doesn't exist ------------------------------------
if [ ! -f "$APP_DIR/.env" ]; then
    echo ""
    echo "[5/5] Creating .env file..."
    cat > "$APP_DIR/.env" <<'EOF'
# DeepPacketAI Environment Variables
# Add your API key and restart: systemctl restart deeppacketai

ANTHROPIC_API_KEY=
# OPENAI_API_KEY=
# GEMINI_API_KEY=

# Uncomment to use PostgreSQL instead of SQLite:
# DATABASE_URL=postgres://user:password@localhost:5432/deeppacketai
EOF
    chown deeppacketai:deeppacketai "$APP_DIR/.env"
    chmod 600 "$APP_DIR/.env"
    echo "  Created $APP_DIR/.env"
    echo "  *** Edit it and add your AI API key! ***"
else
    echo "[5/5] .env already exists — keeping your API keys"
fi

# ---- Copy updated service file ----------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/deeppacketai.service" ]; then
    cp "$SCRIPT_DIR/deeppacketai.service" /etc/systemd/system/deeppacketai.service
    systemctl daemon-reload
fi

# ---- Restart services -------------------------------------------------------
echo ""
echo "Restarting services..."
systemctl restart deeppacketai
systemctl reload nginx 2>/dev/null || systemctl restart nginx

sleep 2

echo ""
echo "Service status:"
systemctl status deeppacketai --no-pager -l | head -20

echo ""
echo "========================================"
echo "  Deploy complete!"
echo ""
echo "  URL:    https://64.227.168.88"
echo "  Logs:   journalctl -u deeppacketai -f"
echo "  Status: systemctl status deeppacketai"
echo "  API key: nano $APP_DIR/.env"
echo "           systemctl restart deeppacketai"
echo "========================================"
