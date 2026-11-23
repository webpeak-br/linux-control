#!/bin/sh
# Publica uma versão: atualiza a versão do hub e do agente, roda os testes, cria a tag e a release no GitHub.
# Uso: sh scripts/release.sh 0.3.0 "Resumo das novidades"
# Os painéis instalados veem a versão nova em até 12 h (Configurações > Atualizações) e os agentes se
# atualizam sozinhos quando o painel for atualizado.
set -eu
cd "$(dirname "$0")/.."

V="${1:-}"
NOTES="${2:-}"
echo "$V" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo "Uso: $0 X.Y.Z \"novidades\"" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "Há alterações não commitadas." >&2; exit 1; }

sed -i "s/\"version\": \"[0-9.]*\"/\"version\": \"$V\"/" hub/package.json
sed -i "s/^VERSION = \"[0-9.]*\"/VERSION = \"$V\"/" agent/linux-control-agent.py

(cd hub && npm test --silent)
python3 -m unittest discover -s test/agent

git add hub/package.json agent/linux-control-agent.py
git commit -q -m "chore: versão $V"
git tag -a "v$V" -m "v$V"
git push -q origin HEAD "v$V"
gh release create "v$V" --title "v$V" --notes "${NOTES:-Versão $V}"
echo "Publicada v$V"
