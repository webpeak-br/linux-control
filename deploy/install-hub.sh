#!/bin/sh
# Instala o Linux Control Hub num servidor Ubuntu/Debian limpo, com HTTPS via Caddy.
#
# Uso (como root):
#   sh deploy/install-hub.sh painel.seudominio.com            # certificado Let's Encrypt automático
#   sh deploy/install-hub.sh painel.seudominio.com --cloudflare
#        (domínio com proxy laranja da Cloudflare, SSL "Full": usa certificado interno na origem
#         e libera as portas 80/443 só para os IPs da Cloudflare)
#
# O que faz: Node.js 24 (binário oficial, verificado por SHA-256), Caddy, usuário de sistema,
# código em /opt/linux-control-hub, dados em /var/lib/linux-control, serviço systemd, firewall (ufw)
# e swap de 1 GB se o servidor não tiver. Pode ser rodado de novo para atualizar.
set -eu

DOMAIN="${1:-}"
MODE="${2:-}"
REPO="${LCTL_REPO:-https://github.com/webpeak-br/linux-control.git}"
APP=/opt/linux-control-hub
DATA=/var/lib/linux-control
ENVF=/etc/linux-control-hub.env

[ "$(id -u)" = 0 ] || { echo "Rode como root." >&2; exit 1; }
[ -n "$DOMAIN" ] || { echo "Uso: $0 <dominio> [--cloudflare]" >&2; exit 1; }
echo "$DOMAIN" | grep -Eq '^[A-Za-z0-9.-]+$' || { echo "Domínio inválido." >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
echo ">> Pacotes base"
apt-get update -qq
apt-get install -y -qq curl ca-certificates git xz-utils ufw caddy python3 >/dev/null

echo ">> Swap"
if [ "$(swapon --show | wc -l)" = 0 ] && [ ! -f /swapfile ]; then
  fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

echo ">> Node.js 24"
if ! command -v node >/dev/null || ! node -e 'process.exit(+process.versions.node.split(".")[0] >= 24 ? 0 : 1)'; then
  case "$(uname -m)" in x86_64) ARCH=x64 ;; aarch64) ARCH=arm64 ;; *) echo "Arquitetura não suportada" >&2; exit 1 ;; esac
  BASE=https://nodejs.org/dist/latest-v24.x
  TMP=$(mktemp -d)
  curl -fsSL "$BASE/SHASUMS256.txt" -o "$TMP/SHASUMS256.txt"
  FILE=$(grep "linux-$ARCH.tar.xz" "$TMP/SHASUMS256.txt" | awk '{print $2}')
  curl -fsSL "$BASE/$FILE" -o "$TMP/$FILE"
  (cd "$TMP" && grep " $FILE\$" SHASUMS256.txt | sha256sum -c -) >/dev/null
  rm -rf /opt/node && mkdir -p /opt/node && tar -xJf "$TMP/$FILE" -C /opt/node --strip-components=1
  ln -sf /opt/node/bin/node /usr/local/bin/node
  rm -rf "$TMP"
fi
node --version

echo ">> Código"
id linuxcontrol >/dev/null 2>&1 || useradd --system --home "$DATA" --shell /usr/sbin/nologin linuxcontrol
if [ -d "$APP/.git" ]; then git -C "$APP" pull -q --ff-only; else git clone -q --depth 1 "$REPO" "$APP"; fi
mkdir -p "$DATA" && chown linuxcontrol:linuxcontrol "$DATA" && chmod 700 "$DATA"

echo ">> Configuração"
if [ ! -f "$ENVF" ]; then
  PW=$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20)
  umask 077
  cat > "$ENVF" <<EOF
LCTL_ADMIN_PASSWORD=$PW
LCTL_PUBLIC_URL=https://$DOMAIN
LCTL_HOST=127.0.0.1
LCTL_PORT=7420
LCTL_DATA=$DATA
LCTL_TRUST_PROXY=1
EOF
  echo "$PW" > /root/linux-control-admin-password.txt
  chmod 600 "$ENVF" /root/linux-control-admin-password.txt
fi

cat > /etc/systemd/system/linux-control-hub.service <<EOF
[Unit]
Description=Linux Control Hub
After=network-online.target
Wants=network-online.target

[Service]
User=linuxcontrol
WorkingDirectory=$APP
EnvironmentFile=$ENVF
ExecStart=/usr/local/bin/node hub/server.js
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DATA

[Install]
WantedBy=multi-user.target
EOF

echo ">> Caddy (HTTPS)"
if [ "$MODE" = "--cloudflare" ]; then TLS="tls internal"; else TLS=""; fi
cat > /etc/caddy/Caddyfile <<EOF
$DOMAIN {
  $TLS
  encode gzip
  reverse_proxy 127.0.0.1:7420
  header -Server
}
EOF

echo ">> Firewall"
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow 22/tcp >/dev/null
if [ "$MODE" = "--cloudflare" ]; then
  for ip in $(curl -fsSL https://www.cloudflare.com/ips-v4) $(curl -fsSL https://www.cloudflare.com/ips-v6); do
    ufw allow proto tcp from "$ip" to any port 80,443 >/dev/null
  done
else
  ufw allow 80,443/tcp >/dev/null
fi
ufw --force enable >/dev/null

systemctl daemon-reload
systemctl enable --now linux-control-hub >/dev/null
systemctl restart linux-control-hub
systemctl enable caddy >/dev/null
systemctl restart caddy
sleep 2
curl -fsS http://127.0.0.1:7420/healthz && echo
echo
echo "Pronto: https://$DOMAIN"
echo "Senha inicial do admin: /root/linux-control-admin-password.txt (troque em $ENVF e reinicie o serviço)."
