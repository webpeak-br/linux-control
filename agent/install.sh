#!/bin/sh
# Instalador do Linux Control Agent. Normalmente servido pelo hub em /install.sh:
#   curl -fsSL https://SEU-HUB/install.sh | sudo sh -s -- <TOKEN>
# Opções (variáveis de ambiente):
#   LCTL_ACTIONS=all|readonly|none   quais ações o painel pode executar (padrão: all)
#   LCTL_INTERVAL=30                 segundos entre envios
#   LCTL_INSECURE_TLS=1              aceitar certificado autoassinado no hub
# Desinstalar:
#   curl -fsSL https://SEU-HUB/install.sh | sudo sh -s -- --uninstall
set -e

HUB_URL="${LCTL_HUB_URL:-__LCTL_HUB_URL__}"
AGENT_SHA256="__LCTL_AGENT_SHA256__"
TOKEN="$1"
BIN_DIR=/opt/linux-control
CONF_DIR=/etc/linux-control
UNIT=/etc/systemd/system/linux-control-agent.service

if [ "$(id -u)" != "0" ]; then
  echo "Execute como root (use sudo)." >&2; exit 1
fi

if [ "$TOKEN" = "--uninstall" ]; then
  systemctl disable --now linux-control-agent 2>/dev/null || true
  rm -f "$UNIT"; systemctl daemon-reload 2>/dev/null || true
  rm -rf "$BIN_DIR" "$CONF_DIR"
  echo "Linux Control Agent removido."; exit 0
fi

if [ -z "$TOKEN" ]; then
  echo "Uso: install.sh <TOKEN>  (copie o comando completo no painel do Linux Control)" >&2; exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 não encontrado. Instalando..."
  if command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y -qq python3
  elif command -v dnf >/dev/null; then dnf install -y -q python3
  elif command -v yum >/dev/null; then yum install -y -q python3
  elif command -v apk >/dev/null; then apk add --no-cache python3
  else echo "Instale o python3 manualmente e rode de novo." >&2; exit 1; fi
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemd não encontrado. Rode manualmente: python3 $BIN_DIR/linux-control-agent.py" >&2
fi

case "$HUB_URL" in
  https://*) ;;
  *) echo "AVISO: o hub não usa HTTPS ($HUB_URL). Use HTTPS em produção." >&2 ;;
esac

mkdir -p "$BIN_DIR" "$CONF_DIR"
CURL_OPT=""
[ "${LCTL_INSECURE_TLS:-0}" = "1" ] && CURL_OPT="-k"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL $CURL_OPT "$HUB_URL/agent/linux-control-agent.py" -o "$BIN_DIR/linux-control-agent.py"
else
  WGET_OPT=""; [ -n "$CURL_OPT" ] && WGET_OPT="--no-check-certificate"
  wget -q $WGET_OPT -O "$BIN_DIR/linux-control-agent.py" "$HUB_URL/agent/linux-control-agent.py"
fi
if command -v sha256sum >/dev/null 2>&1 && [ "${AGENT_SHA256#__}" = "$AGENT_SHA256" ]; then
  GOT=$(sha256sum "$BIN_DIR/linux-control-agent.py" | cut -d' ' -f1)
  if [ "$GOT" != "$AGENT_SHA256" ]; then
    echo "ERRO: o agente baixado não confere com o hash esperado. Instalação abortada." >&2
    rm -f "$BIN_DIR/linux-control-agent.py"; exit 1
  fi
fi
chmod 755 "$BIN_DIR/linux-control-agent.py"

umask 077
cat > "$CONF_DIR/agent.conf" <<EOF
# Linux Control Agent - configuração
HUB_URL=$HUB_URL
TOKEN=$TOKEN
INTERVAL=${LCTL_INTERVAL:-30}
ACTIONS=${LCTL_ACTIONS:-all}
INSECURE_TLS=${LCTL_INSECURE_TLS:-0}
EOF
chmod 600 "$CONF_DIR/agent.conf"

if command -v systemctl >/dev/null 2>&1; then
  cat > "$UNIT" <<EOF
[Unit]
Description=Linux Control Agent (monitoramento do servidor)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/env python3 $BIN_DIR/linux-control-agent.py
Restart=always
RestartSec=10
Nice=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now linux-control-agent >/dev/null
  systemctl restart linux-control-agent
fi

echo "Testando conexão com $HUB_URL ..."
if LCTL_CONF="$CONF_DIR/agent.conf" python3 "$BIN_DIR/linux-control-agent.py" --test; then
  echo "OK. Linux Control Agent instalado e enviando dados. Veja em $HUB_URL"
else
  echo "Instalado, mas o teste de envio falhou. Veja: journalctl -u linux-control-agent -f" >&2
fi
