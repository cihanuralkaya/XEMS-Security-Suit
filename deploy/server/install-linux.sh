#!/usr/bin/env bash
# XEMS C2 sunucu kurulumu (Linux, systemd).
# Yanında bulunması gerekenler: c2, gencerts (dist/linux-amd64/'den).
#
# Kullanım (root):
#   sudo ./install-linux.sh [SUNUCU_ADI]
# SUNUCU_ADI: sertifika SAN'ı (ajanların bağlanacağı ad; vars. xems-c2).
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "root olarak çalıştırın (sudo)." >&2; exit 1; }

SERVER_NAME="${1:-xems-c2}"
HERE="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/xems"
CONF_DIR="/etc/xems"
PKI_DIR="$CONF_DIR/pki"

command -v openssl >/dev/null 2>&1 || { echo "openssl gerekli." >&2; exit 1; }
[ -x "$HERE/c2" ] || { echo "c2 ikilisi bulunamadı ($HERE/c2)." >&2; exit 1; }
[ -x "$HERE/gencerts" ] || { echo "gencerts bulunamadı ($HERE/gencerts)." >&2; exit 1; }

mkdir -p "$INSTALL_DIR" "$PKI_DIR"
install -m 0755 "$HERE/c2" "$INSTALL_DIR/c2"

# Sertifikalar (yoksa üret; varsa dokunma).
if [ ! -f "$PKI_DIR/ca.crt" ]; then
  "$HERE/gencerts" -out "$PKI_DIR" -name "$SERVER_NAME"
  chmod 600 "$PKI_DIR"/*.key
  echo "PKI üretildi: $PKI_DIR"
else
  echo "Mevcut PKI korunuyor: $PKI_DIR"
fi

# Ana anahtar (yoksa üret).
ENV_FILE="$CONF_DIR/c2.env"
if [ ! -f "$ENV_FILE" ]; then
  MASTER_KEY="$(openssl rand -base64 32)"
  ADMIN_PASS="$(openssl rand -base64 12)"
  cat > "$ENV_FILE" <<EOF
XEMS_DATABASE_URL=
XEMS_DEMO=1
XEMS_MASTER_KEY=$MASTER_KEY
XEMS_CA_CERT=$PKI_DIR/ca.crt
XEMS_CA_KEY=$PKI_DIR/ca.key
XEMS_SERVER_CERT=$PKI_DIR/server.crt
XEMS_SERVER_KEY=$PKI_DIR/server.key
XEMS_LISTEN_AGENT=:8443
XEMS_LISTEN_ENROLL=:8444
XEMS_LISTEN_ADMIN=:8445
XEMS_DEMO_ADMIN_EMAIL=admin@local
XEMS_DEMO_ADMIN_PASSWORD=$ADMIN_PASS
XEMS_RETENTION_DAYS=90
EOF
  chmod 600 "$ENV_FILE"
  echo "Yapılandırma üretildi: $ENV_FILE"
  echo ">>> Konsol girişi: admin@local / $ADMIN_PASS  (DEMO/bellek-içi mod)"
  echo ">>> Üretim için: XEMS_DATABASE_URL ayarlayın ve tools/adminseed ile yönetici ekleyin."
else
  echo "Mevcut yapılandırma korunuyor: $ENV_FILE"
fi

cat > /etc/systemd/system/xems-c2.service <<UNITEOF
[Unit]
Description=XEMS C2 (Command & Control)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$ENV_FILE
ExecStart=$INSTALL_DIR/c2
Restart=always
RestartSec=5
# Sertleştirme (C2 ayrıcalıksız ağ hizmeti — agresif kum-havuzu; bkz. deploy/HARDENING.md).
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$CONF_DIR
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @obsolete
UMask=0077

[Install]
WantedBy=multi-user.target
UNITEOF

systemctl daemon-reload
systemctl enable --now xems-c2.service
echo "XEMS C2 kuruldu ve başlatıldı (systemctl status xems-c2)."
echo "Ajan istemci setup'ı üretmek için (aynı makinede):"
echo "  mkclient -os windows -server $SERVER_NAME -ca $PKI_DIR/ca.crt -agent agent.exe -token <TOKEN> -out setup.ps1"
