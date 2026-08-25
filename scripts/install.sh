#!/usr/bin/env bash
# Sub Manager VPN — one-shot installer.
# Writes all settings/keys into config.json, installs the binary as a systemd
# user service, and prints the admin + subscription URLs.
#
# Usage:
#   bash <(curl -fsSL https://raw.githubusercontent.com/HnDK0/Sub-Manager-VPN/main/scripts/install.sh)
#   bash install.sh                                 # build from a cloned repo
#   REPO=owner/repo BRANCH=main FORCE=1 bash install.sh
#
# Optional overrides (env): WEB_TOKEN WEB_SECRET SERVE_TOKEN WEB_ADDR SERVE_ADDR
#   INTERVAL TOPN CORPSE INSTALL_DIR
set -euo pipefail

# GitHub slug "owner/repo" the prebuilt binary is published to (the bin/ folder
# in the repo, updated automatically by CI). Override with REPO=/BRANCH= if needed.
REPO="${REPO:-HnDK0/Sub-Manager-VPN}"
BRANCH="${BRANCH:-main}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
BIN_NAME="vpn-sub-manager"
BIN_PATH="$INSTALL_DIR/$BIN_NAME"
CFG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/vpn-sub-manager"
CFG_PATH="$CFG_DIR/config.json"
UNIT_DIR="$HOME/.config/systemd/user"
UNIT_PATH="$UNIT_DIR/vpn-sub-manager.service"

WEB_ADDR="${WEB_ADDR:-127.0.0.1:8090}"
SERVE_ADDR="${SERVE_ADDR:-127.0.0.1:18080}"
WEB_TOKEN="${WEB_TOKEN:-}"
WEB_SECRET="${WEB_SECRET:-}"
SERVE_TOKEN="${SERVE_TOKEN:-}"
INTERVAL="${INTERVAL:-30m}"
TOPN="${TOPN:-5}"
CORPSE="${CORPSE:-5}"

gen_secret() {
  local n="$1"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 "$n" | tr -dc 'A-Za-z0-9' | head -c "$n"
  else
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$n"
  fi
  printf '\n'
}

echo "== Sub Manager VPN installer =="

# ── 1. Obtain the binary ────────────────────────────────────────────────
if [ -x "$BIN_PATH" ] && [ "${FORCE:-0}" != "1" ]; then
  echo "binary already present at $BIN_PATH (FORCE=1 to overwrite)"
else
  mkdir -p "$INSTALL_DIR"
  if [ -n "$REPO" ]; then
    url="https://raw.githubusercontent.com/$REPO/$BRANCH/bin/submanager-linux"
    echo "downloading $url"
    if command -v curl >/dev/null 2>&1; then
      curl -fL "$url" -o "$BIN_PATH"
    else
      wget -O "$BIN_PATH" "$url"
    fi
  elif [ -f go.mod ]; then
    echo "building from current directory (requires Go 1.25+)"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -trimpath -ldflags "-s -w" -o "$BIN_PATH" .
  else
    echo "error: set REPO=owner/repo to download, or run inside the cloned repo to build." >&2
    exit 1
  fi
  chmod +x "$BIN_PATH"
fi

# ── 2. Write config.json with randomized secrets ───────────────────────
mkdir -p "$CFG_DIR"
[ -z "$WEB_TOKEN" ]   && WEB_TOKEN=$(gen_secret 32)
[ -z "$WEB_SECRET" ]  && WEB_SECRET=$(gen_secret 32)
[ -z "$SERVE_TOKEN" ] && SERVE_TOKEN=$(gen_secret 24)

if [ -f "$CFG_PATH" ] && [ "${FORCE:-0}" != "1" ]; then
  echo "config already at $CFG_PATH (FORCE=1 to regenerate secrets)"
else
  cat > "$CFG_PATH" <<EOF
{
  "web_addr": "$WEB_ADDR",
  "web_token": "$WEB_TOKEN",
  "web_secret": "$WEB_SECRET",
  "serve_addr": "$SERVE_ADDR",
  "serve_token": "$SERVE_TOKEN",
  "interval": "$INTERVAL",
  "topn": $TOPN,
  "corpse_cycles": $CORPSE,
  "state_path": "$CFG_DIR/state.db",
  "sources_path": "$CFG_DIR/sources.txt",
  "assets_dir": "$CFG_DIR/assets",
  "out_dir": "$CFG_DIR/out",
  "cores_dir": "$CFG_DIR/cores"
}
EOF
  chmod 600 "$CFG_PATH"
  echo "wrote $CFG_PATH (secrets randomized, chmod 600)"
fi

# ── 3. Install systemd user service ────────────────────────────────────
mkdir -p "$UNIT_DIR"
cat > "$UNIT_PATH" <<EOF
[Unit]
Description=Sub Manager VPN (free VPN subscription manager)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN_PATH
Restart=always
RestartSec=5
MemoryMax=512M
Nice=10

[Install]
WantedBy=default.target
EOF

if command -v systemctl >/dev/null 2>&1; then
  systemctl --user daemon-reload
  systemctl --user enable --now vpn-sub-manager || \
    echo "note: could not auto-start (enable-linger may be required on headless hosts)"
  echo "for headless servers, run: loginctl enable-linger $USER"
fi

# ── 4. Report ──────────────────────────────────────────────────────────
echo
echo "== Done =="
echo "Admin UI:          http://$WEB_ADDR/$WEB_SECRET/"
echo "Web token:         $WEB_TOKEN"
echo "Subscriptions base: http://$SERVE_ADDR/s/$SERVE_TOKEN/"
echo "Config:            $CFG_PATH"
echo
echo "Open the admin UI in a browser and paste the web token to log in."

# ── 5. nginx hint (print only, no writes) ───────────────────────────────
if command -v nginx >/dev/null 2>&1; then
  NGINX_CONF=$(nginx -t 2>&1 | grep -oE '/[^ ]+nginx\.conf' | head -n1 || true)
  echo
  echo "nginx detected:      yes"
  [ -n "$NGINX_CONF" ] && echo "nginx config:        $NGINX_CONF"
  echo "vhost include dir:   /etc/nginx/sites-enabled/   (or /etc/nginx/conf.d/)"
  echo
  echo "# admin UI (SSE — keep proxy_buffering off):"
  cat <<EOF
location /$WEB_SECRET/ {
    proxy_pass http://$WEB_ADDR/$WEB_SECRET/;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_buffering off;
    proxy_cache off;
    proxy_read_timeout 1d;
}
EOF
  echo "# subscriptions:"
  cat <<EOF
location /s/$SERVE_TOKEN/ {
    proxy_pass http://$SERVE_ADDR/s/$SERVE_TOKEN/;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
}
EOF
fi
