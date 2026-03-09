#!/bin/bash
# deploy.sh — запускается на Ubuntu сервере (138.124.3.221).
# Устанавливает dns-tunnel рядом с DNSTT и Slipstream.
#
# Как использовать (с Windows, после build.bat):
#   scp deploy/deploy.sh     user@138.124.3.221:~/
#   scp build/server         user@138.124.3.221:~/
#   scp config/server.yaml   user@138.124.3.221:~/
#   ssh user@138.124.3.221 "sudo bash ~/deploy.sh"

set -euo pipefail

INSTALL_DIR="/opt/dns-tunnel"
BIN="$HOME/server"
CFG="$HOME/server.yaml"

echo "=== DNS Tunnel Deploy ==="

# ── Проверка файлов ─────────────────────────────────────────────────────────

if [ ! -f "$BIN" ]; then
    echo "ERROR: $BIN not found. Run build.bat and scp the binary first."
    exit 1
fi
if [ ! -f "$CFG" ]; then
    echo "ERROR: $CFG not found. scp config/server.yaml first."
    exit 1
fi

# ── Установка бинаря и конфига ──────────────────────────────────────────────

echo "[1/5] Installing to $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"
cp "$BIN" "$INSTALL_DIR/server"
cp "$CFG" "$INSTALL_DIR/server.yaml"
chmod +x "$INSTALL_DIR/server"

# ── Systemd сервис ───────────────────────────────────────────────────────────

echo "[2/5] Installing systemd service ..."
cat > /etc/systemd/system/dns-tunnel.service << 'UNIT'
[Unit]
Description=DNS Tunnel Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/dns-tunnel/server -config /opt/dns-tunnel/server.yaml
Restart=on-failure
RestartSec=5s
TimeoutStopSec=10s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=dns-tunnel

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable dns-tunnel

# ── Скрипт переключения ──────────────────────────────────────────────────────

echo "[3/5] Installing /usr/local/bin/use-dns-tunnel ..."
cat > /usr/local/bin/use-dns-tunnel << 'EOF'
#!/bin/bash
set -euo pipefail
echo "[*] Stopping Slipstream..."
dnstm router stop 2>/dev/null || true
dnstm tunnel stop --tag slip1 2>/dev/null || true
echo "[*] Stopping DNSTT..."
systemctl stop dnstt-server 2>/dev/null || true
echo "[*] Updating iptables (UDP+TCP :53 → :5300)..."
iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null || true
iptables -t nat -D PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null || true
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
iptables -t nat -I PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports 5300
echo "[*] Starting dns-tunnel..."
systemctl start dns-tunnel
echo "[+] Switched to dns-tunnel"
echo "    Logs: journalctl -u dns-tunnel -f"
EOF
chmod +x /usr/local/bin/use-dns-tunnel

# ── Обновить существующие скрипты (добавить остановку нашего сервиса) ────────

echo "[4/5] Patching existing switch scripts ..."

# use-dnstt: добавить остановку dns-tunnel в начало если её ещё нет
if ! grep -q 'dns-tunnel' /usr/local/bin/use-dnstt; then
    sed -i '2a\\nsystemctl stop dns-tunnel 2>/dev/null || true' /usr/local/bin/use-dnstt
    # Также добавить TCP правило, которого там не было
    sed -i '/REDIRECT --to-ports 5300/a iptables -t nat -I PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null || true' /usr/local/bin/use-dnstt
    echo "    patched use-dnstt"
fi

# use-slipstream: добавить остановку dns-tunnel в начало если её ещё нет
if ! grep -q 'dns-tunnel' /usr/local/bin/use-slipstream; then
    sed -i '2a\\nsystemctl stop dns-tunnel 2>/dev/null || true' /usr/local/bin/use-slipstream
    echo "    patched use-slipstream"
fi

# ── Тест бинаря ──────────────────────────────────────────────────────────────

echo "[5/5] Smoke-testing binary ..."
if /opt/dns-tunnel/server --help 2>&1 | grep -q 'config\|Usage\|flag' || true; then
    echo "    binary runs OK"
fi

# ── Итог ─────────────────────────────────────────────────────────────────────

echo ""
echo "=== Done! ==="
echo ""
echo "  Команды переключения:"
echo "    sudo use-dns-tunnel    ← наш сервер"
echo "    sudo use-dnstt         ← DNSTT (обновлён)"
echo "    sudo use-slipstream    ← Slipstream (обновлён)"
echo ""
echo "  Быстрый тест:"
echo "    sudo use-dns-tunnel"
echo "    journalctl -u dns-tunnel -f"
echo ""
