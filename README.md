# Linux Control

**Painel web open source para enxergar e cuidar de vários servidores Linux em um só lugar.**

O Linux é uma tela preta para a maioria das pessoas. O Linux Control mostra, em português e sem precisar abrir SSH:

- **Saúde**: CPU, memória, swap, disco (inclusive inodes), carga e rede, com histórico de até 7 dias.
- **Diagnóstico automático**: disco quase cheio, memória no limite, serviços com falha, reinício pendente, atualizações de segurança, firewall desligado, SSH com login de root, certificados vencendo, relógio fora de sincronia e mais.
- **O que roda dentro**: processos que mais consomem, serviços systemd, portas abertas (e se estão expostas para a internet), containers Docker, sites configurados no Nginx/Apache.
- **O que está instalado e onde**: software conhecido detectado com versão e caminho (Nginx, MySQL, PostgreSQL, Redis, Node, PHP, Docker…) e a lista completa de pacotes com as atualizações pendentes.
- **Segurança**: tentativas de invasão por SSH e IPs de origem, contas com shell, quem é admin, chaves SSH, firewall, fail2ban, certificados Let's Encrypt.
- **Agendamentos**: tarefas cron e timers do systemd.
- **Ações com um clique**: diagnóstico, limpeza (cache de pacotes, logs, /tmp, Docker), atualizações de segurança, reiniciar serviços e containers, reiniciar o servidor. Tudo registrado com a saída do comando.

## Como funciona

```
 ┌───────────────┐   HTTPS (saída)    ┌──────────────────────┐
 │ servidor A    │ ─────────────────▶ │                      │
 │ agente Python │ ◀─ ações na fila ─ │   Linux Control Hub  │ ◀── navegador
 └───────────────┘                    │   (Node + SQLite)    │
 ┌───────────────┐                    │                      │
 │ servidor B    │ ─────────────────▶ │                      │
 └───────────────┘                    └──────────────────────┘
```

- **Hub**: um único processo Node.js (sem dependências npm) com banco SQLite embutido. Serve o painel e recebe os dados.
- **Agente**: um único arquivo Python 3 (só biblioteca padrão) instalado como serviço systemd em cada servidor. Ele **só faz conexões de saída** para o hub, então funciona atrás de NAT e firewall sem abrir portas. A cada 30 s envia métricas; a cada 10 min, o inventário; a cada 6 h, a lista de pacotes. Na mesma resposta o hub devolve as ações pendentes.

### Segurança do modelo

- O hub **não guarda senha nem chave SSH** de nenhum servidor.
- O agente só executa ações de um **catálogo fixo definido no próprio agente**. Não existe execução de comando livre. Parâmetros (nome de serviço ou container) são validados no hub e no agente.
- Cada servidor tem um token próprio (guardado só como hash no hub). Trocar o token invalida o anterior na hora.
- Modo de ações por servidor: `all` (padrão), `readonly` (só diagnósticos, nada que altere o servidor) ou `none`.
- Ações perigosas (atualizar tudo, parar serviço, reiniciar servidor) exigem digitar o nome do servidor. Ações na fila expiram em 10 minutos, então nada roda horas depois se o servidor estava offline.
- Serviços só podem ser manipulados como unidades `.service` (não é possível acionar `reboot.target` e afins por esse caminho).
- Senhas e tokens que aparecem em linhas de comando de processos e no cron são mascarados pelo agente antes do envio.
- Painel com sessão `HttpOnly` + `SameSite=Strict`, proteção CSRF, CSP, limite de tentativas de login e trilha de auditoria.

## Instalação do hub

Requisitos: **Node.js 22.13+** (recomendado 24) ou Docker.

### Script automático (Ubuntu/Debian, com HTTPS)

Num servidor limpo, como root:

```bash
curl -fsSL https://raw.githubusercontent.com/webpeak-br/linux-control/main/deploy/install-hub.sh -o install-hub.sh
sh install-hub.sh painel.seudominio.com                 # Let's Encrypt automático
sh install-hub.sh painel.seudominio.com --cloudflare    # domínio com proxy da Cloudflare (SSL Full)
```

Instala Node.js 24, Caddy (HTTPS), serviço systemd, firewall e gera a senha do admin em `/root/linux-control-admin-password.txt`. Rodar de novo atualiza o código.

### Com Docker

```bash
git clone https://github.com/webpeak-br/linux-control.git
cd linux-control
LCTL_ADMIN_PASSWORD='troque-esta-senha' docker compose up -d
```

### Sem Docker

```bash
git clone https://github.com/webpeak-br/linux-control.git
cd linux-control
LCTL_ADMIN_PASSWORD='troque-esta-senha' node hub/server.js
```

Se não definir `LCTL_ADMIN_PASSWORD`, uma senha aleatória é gerada e exibida no log na primeira execução. Para trocar depois:

```bash
node hub/server.js --set-password 'nova-senha-forte'
```

Um exemplo de serviço systemd está em [`deploy/linux-control-hub.service`](deploy/linux-control-hub.service).

### HTTPS (obrigatório em produção)

O agente é instalado com `curl | sudo sh` e recebe ações do hub: sem HTTPS, alguém no meio do caminho poderia trocar o instalador. O instalador confere o hash SHA-256 do agente, mas isso só protege de verdade quando o próprio hub está em HTTPS. Coloque o hub atrás de um proxy com TLS (Nginx, Caddy, Traefik, Cloudflare Tunnel) e defina `LCTL_PUBLIC_URL` com o endereço público (os agentes usam esse endereço) e `LCTL_TRUST_PROXY=1`. Nesse caso, faça o hub escutar só em `127.0.0.1`. Exemplo para Caddy:

```
painel.seudominio.com {
  reverse_proxy 127.0.0.1:7420
}
```

### Variáveis de ambiente do hub

| Variável | Padrão | Descrição |
|---|---|---|
| `LCTL_PORT` | `7420` | Porta HTTP |
| `LCTL_HOST` | `0.0.0.0` | Interface de escuta (use `127.0.0.1` atrás de proxy) |
| `LCTL_DATA` | `./data` | Pasta do banco SQLite |
| `LCTL_PUBLIC_URL` | (detectado) | URL pública usada no comando de instalação dos agentes |
| `LCTL_ADMIN_PASSWORD` | (gerada) | Senha do administrador |
| `LCTL_RETENTION_DAYS` | `7` | Dias de histórico de métricas |
| `LCTL_SESSION_HOURS` | `12` | Duração da sessão no painel |
| `LCTL_TRUST_PROXY` | `0` | Use `1` **somente** se o hub estiver atrás de um proxy reverso (lê o IP real de `X-Forwarded-For`/`CF-Connecting-IP`) |

## Adicionando um servidor

1. No painel, clique em **Adicionar servidor** e dê um nome.
2. Copie o comando exibido e rode no servidor:

```bash
curl -fsSL https://painel.seudominio.com/install.sh | sudo sh -s -- lctl_SEU_TOKEN
```

Para instalar só com leitura (sem ações que alterem o servidor):

```bash
curl -fsSL https://painel.seudominio.com/install.sh | sudo LCTL_ACTIONS=readonly sh -s -- lctl_SEU_TOKEN
```

O agente fica em `/opt/linux-control`, a configuração em `/etc/linux-control/agent.conf` (permissão 600) e o serviço chama `linux-control-agent`. Para remover:

```bash
curl -fsSL https://painel.seudominio.com/install.sh | sudo sh -s -- --uninstall
```

Compatível com distribuições com systemd: Debian, Ubuntu, RHEL, Rocky, Alma, CentOS 7+, Fedora e Amazon Linux (Python 3.6+). Em sistemas sem systemd (ex.: Alpine com OpenRC) o agente funciona, mas o serviço precisa ser criado manualmente. O agente roda como root para conseguir ler firewall, SSH e executar as ações; sem root ele funciona com dados parciais.

## Desenvolvimento

```bash
# hub local
LCTL_ADMIN_PASSWORD=dev123456 LCTL_DATA=./data node hub/server.js

# ver tudo o que o agente coleta, sem enviar
python3 agent/linux-control-agent.py --once

# agente apontando para o hub local (sem instalar)
LCTL_CONF=/dev/null LCTL_HUB_URL=http://127.0.0.1:7420 LCTL_TOKEN=lctl_xxx python3 agent/linux-control-agent.py
```

Estrutura:

```
hub/server.js          API, sessão, fila de ações, arquivos estáticos
hub/db.js              esquema SQLite
hub/health.js          regras do diagnóstico automático
hub/public/            interface (HTML/CSS/JS puro, sem build)
agent/linux-control-agent.py   coletor + executor de ações
agent/install.sh       instalador servido pelo hub em /install.sh
```

Para adicionar uma ação nova, inclua no catálogo `ACTIONS` do agente: o painel passa a exibi-la automaticamente para os servidores que tiverem essa versão do agente.

## Roadmap

- Alertas por e-mail, webhook e chat
- Múltiplos usuários e perfis de acesso
- Atualização automática do agente
- Agrupamento por cliente/ambiente e visão de frota
- Histórico de inventário (o que mudou desde ontem)

Contribuições são bem-vindas: abra uma issue ou um pull request.

## Licença

[MIT](LICENSE)
