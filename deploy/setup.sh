#!/bin/bash
# DeepPacketAI — Server Setup Script
# Run as root on Ubuntu 22.04
# Usage: bash setup.sh

set -e
echo "=== DeepPacketAI Server Setup ==="

# ── 1. System update ──────────────────────────────────────────
echo "[1/9] Updating system packages..."
apt-get update -q && apt-get upgrade -y -q

# ── 2. Install all dependencies ───────────────────────────────
echo "[2/9] Installing system dependencies..."
apt-get install -y -q \
    nginx \
    ufw \
    curl \
    git \
    gcc \
    g++ \
    make \
    pkg-config \
    libpcap-dev \
    libpcap0.8 \
    sqlite3 \
    libsqlite3-dev \
    ca-certificates \
    openssl

# Explain what each critical library does:
# libpcap-dev      — compile-time: gopacket/pcap uses this (Wireshark uses same lib)
# libpcap0.8       — runtime:      live packet capture from network interfaces
# sqlite3          — CLI tool for inspecting/backing up the database
# libsqlite3-dev   — compile-time: mattn/go-sqlite3 (CGO) links against this
# gcc/g++/make     — required for CGO (go-sqlite3 compiles C code at build time)

# ── 3. Install Go 1.24 ────────────────────────────────────────
echo "[3/9] Installing Go 1.24..."
if ! /usr/local/go/bin/go version 2>/dev/null | grep -q "go1.24"; then
    curl -sL https://go.dev/dl/go1.24.0.linux-amd64.tar.gz -o /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
fi
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
echo "  Go: $(/usr/local/go/bin/go version)"

# ── 4. Install Node.js 20 LTS ─────────────────────────────────
echo "[4/9] Installing Node.js 20 LTS..."
if ! command -v node &>/dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - 2>/dev/null
    apt-get install -y -q nodejs
fi
echo "  Node: $(node --version)  npm: $(npm --version)"

# ── 5. Create app user ────────────────────────────────────────
echo "[5/9] Creating system user 'deeppacketai'..."
id deeppacketai &>/dev/null || \
    useradd --system --no-create-home --shell /usr/sbin/nologin deeppacketai
mkdir -p /opt/deeppacketai
chown deeppacketai:deeppacketai /opt/deeppacketai

# ── 6. Firewall ───────────────────────────────────────────────
echo "[6/9] Configuring UFW firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp  comment 'SSH'
ufw allow 80/tcp  comment 'HTTP → redirects to HTTPS'
ufw allow 443/tcp comment 'HTTPS'
# Port 8080 (Go backend) intentionally NOT opened — Nginx proxies it internally
ufw --force enable
echo "  Open ports:"
ufw status numbered

# ── 7. Self-signed SSL certificate ────────────────────────────
echo "[7/9] Generating self-signed SSL certificate (10 year)..."
mkdir -p /etc/ssl/deeppacketai
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/ssl/deeppacketai/server.key \
    -out    /etc/ssl/deeppacketai/server.crt \
    -subj   "/C=US/ST=State/L=City/O=Techtez/OU=DeepPacketAI/CN=64.227.168.88" \
    2>/dev/null
chmod 600 /etc/ssl/deeppacketai/server.key
chmod 644 /etc/ssl/deeppacketai/server.crt

# ── 8. Nginx configuration ────────────────────────────────────
echo "[8/9] Configuring Nginx..."
cp /tmp/deploy/nginx.conf /etc/nginx/sites-available/deeppacketai
ln -sf /etc/nginx/sites-available/deeppacketai /etc/nginx/sites-enabled/deeppacketai
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable nginx
systemctl restart nginx

# ── 9. SSH hardening ──────────────────────────────────────────
echo "[9/9] Hardening SSH..."
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/'  /etc/ssh/sshd_config
sed -i 's/^#*X11Forwarding.*/X11Forwarding no/'                    /etc/ssh/sshd_config
sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/'                       /etc/ssh/sshd_config
systemctl restart sshd

# ── Git bare repo + post-receive hook (for git push deploys) ──
echo "Setting up git bare repo for push-to-deploy..."
mkdir -p /opt/deeppacketai-repo.git
git init --bare /opt/deeppacketai-repo.git
chown -R root:root /opt/deeppacketai-repo.git

cat > /opt/deeppacketai-repo.git/hooks/post-receive <<'HOOK'
#!/bin/bash
# Runs on the server every time you do: git push production main
set -e
export PATH=$PATH:/usr/local/go/bin

DEPLOY_DIR=/tmp/deeppacketai-deploy-$$
APP_DIR=/opt/deeppacketai

echo "=== DeepPacketAI: post-receive deploy ==="

# Check out the pushed code to a temp dir
mkdir -p "$DEPLOY_DIR"
git --work-tree="$DEPLOY_DIR" --git-dir="/opt/deeppacketai-repo.git" checkout -f main

# Build Go backend
echo "[1/3] Building Go backend..."
cd "$DEPLOY_DIR"
CGO_ENABLED=1 GOOS=linux go build -o "$APP_DIR/deeppacketai" ./cmd/...
chown deeppacketai:deeppacketai "$APP_DIR/deeppacketai"
chmod 755 "$APP_DIR/deeppacketai"

# Build React frontend
echo "[2/3] Building React frontend..."
cd "$DEPLOY_DIR/deeppacketai-ui"
npm ci --silent
npm run build --silent
rm -rf "$APP_DIR/ui"
cp -r dist "$APP_DIR/ui"
chown -R www-data:www-data "$APP_DIR/ui"

# Restart services
echo "[3/3] Restarting services..."
systemctl restart deeppacketai
systemctl reload nginx

# Cleanup
rm -rf "$DEPLOY_DIR"

echo "=== Deploy complete: https://64.227.168.88 ==="
HOOK

chmod +x /opt/deeppacketai-repo.git/hooks/post-receive

# Install systemd service
cp /tmp/deploy/deeppacketai.service /etc/systemd/system/deeppacketai.service
systemctl daemon-reload
systemctl enable deeppacketai

echo ""
echo "========================================"
echo "  Setup complete!"
echo ""
echo "  NEXT STEPS:"
echo "  1. Run the first deploy:  bash /tmp/deploy.sh"
echo "  2. Add API key:           nano /opt/deeppacketai/.env"
echo ""
echo "  FUTURE DEPLOYS (from your Windows machine):"
echo "  git remote add production root@64.227.168.88:/opt/deeppacketai-repo.git"
echo "  git push production main"
echo "========================================"
