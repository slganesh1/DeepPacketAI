#!/bin/bash
# DeepPacketAI — First Deploy Script
# Run on the SERVER after setup.sh
# Usage: bash /tmp/deploy.sh

set -e
export PATH=$PATH:/usr/local/go/bin

SRC_DIR=/tmp/deeppacketai-src
APP_DIR=/opt/deeppacketai

echo "=== DeepPacketAI First Deploy ==="

# ── 1. Build Go backend ───────────────────────────────────────
echo "[1/4] Building Go backend (CGO + libpcap + sqlite3)..."
cd "$SRC_DIR"
CGO_ENABLED=1 GOOS=linux go build -o "$APP_DIR/deeppacketai" ./cmd/...
chown deeppacketai:deeppacketai "$APP_DIR/deeppacketai"
chmod 755 "$APP_DIR/deeppacketai"
echo "  Binary size: $(du -sh $APP_DIR/deeppacketai | cut -f1)"

# ── 2. Build React frontend ───────────────────────────────────
echo "[2/4] Building React frontend..."
cd "$SRC_DIR/deeppacketai-ui"
npm ci --silent
npm run build --silent
rm -rf "$APP_DIR/ui"
cp -r dist "$APP_DIR/ui"
chown -R www-data:www-data "$APP_DIR/ui"
echo "  UI size: $(du -sh $APP_DIR/ui | cut -f1)"

# ── 3. Create .env if it doesn't exist ───────────────────────
if [ ! -f "$APP_DIR/.env" ]; then
    echo "[3/4] Creating .env file..."
    cat > "$APP_DIR/.env" <<'EOF'
# DeepPacketAI Environment Variables
# Fill in your API key and restart: systemctl restart deeppacketai

ANTHROPIC_API_KEY=

# Optional alternative AI providers
# OPENAI_API_KEY=
# GEMINI_API_KEY=
EOF
    chown deeppacketai:deeppacketai "$APP_DIR/.env"
    chmod 600 "$APP_DIR/.env"
    echo "  Created $APP_DIR/.env"
    echo "  *** Add your ANTHROPIC_API_KEY then run: systemctl restart deeppacketai ***"
else
    echo "[3/4] .env already exists — skipping (your API keys are safe)"
fi

# ── 4. Start services ─────────────────────────────────────────
echo "[4/4] Starting services..."
systemctl daemon-reload
systemctl restart deeppacketai
systemctl reload nginx

sleep 2
echo ""
echo "========================================"
echo "  Deploy complete!"
echo "  URL:    https://64.227.168.88"
echo "  Logs:   journalctl -u deeppacketai -f"
echo "  Status: systemctl status deeppacketai"
echo "  DB:     sqlite3 $APP_DIR/deeppacketai.db"
echo "========================================"
