#!/bin/bash
# install.sh — deploy sudo-server to a Linux system
# Run as root: sudo bash install.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash install.sh" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Creating sudo-agents group (if missing)"
groupadd -f sudo-agents

echo "==> Installing daemon and client"
install -o root -g root -m 0755 "$SCRIPT_DIR/sudo-server.py"  /usr/local/bin/sudo-server.py
install -o root -g root -m 0755 "$SCRIPT_DIR/sudoreq"         /usr/local/bin/sudoreq

echo "==> Creating config and log directories"
install -d -o root -g root -m 0755 /etc/sudo-server
install -d -o root -g root -m 0750 /var/log/sudo-server

if [[ ! -f /etc/sudo-server/config.json ]]; then
  install -o root -g root -m 0600 "$SCRIPT_DIR/config.json.example" /etc/sudo-server/config.json
  echo "    Created /etc/sudo-server/config.json — edit before starting!"
else
  echo "    /etc/sudo-server/config.json already exists, skipping."
fi

if [[ ! -f /etc/sudo-server/env ]]; then
  install -o root -g root -m 0600 "$SCRIPT_DIR/systemd/env.example" /etc/sudo-server/env
  echo "    Created /etc/sudo-server/env — set your Telegram credentials!"
else
  echo "    /etc/sudo-server/env already exists, skipping."
fi

echo "==> Installing systemd service"
install -o root -g root -m 0644 "$SCRIPT_DIR/systemd/sudo-server.service" \
  /etc/systemd/system/sudo-server.service

echo "==> Reloading systemd"
systemctl daemon-reload

echo ""
echo "Installation complete."
echo ""
echo "Next steps:"
echo "  1. Edit /etc/sudo-server/env        — set SUDO_SERVER_TG_TOKEN and SUDO_SERVER_TG_CHAT_ID"
echo "  2. Edit /etc/sudo-server/config.json — adjust allowlists and agent permissions"
echo "  3. Add each agent user to sudo-agents group:"
echo "       sudo usermod -aG sudo-agents agent1"
echo "  4. Start the service:"
echo "       sudo systemctl enable --now sudo-server"
echo "  5. Check logs:"
echo "       sudo journalctl -u sudo-server -f"
echo ""
echo "Test with your own user (add yourself to sudo-agents first):"
echo "  sudoreq -- echo hello from root"
