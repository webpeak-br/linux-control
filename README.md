# Linux Control

**Painel web open source para enxergar e cuidar de vários servidores Linux em um só lugar.**

O Linux é uma tela preta para a maioria das pessoas. O Linux Control mostra, em português e sem precisar abrir SSH:

- **Saúde**: CPU, memória, swap, disco (inclusive inodes), carga e rede, com histórico de até 7 dias.
- **Diagnóstico automático**: disco quase cheio, memória no limite, serviços com falha, reinício pendente, atualizações de segurança, firewall desligado, SSH com login de root, certificados vencendo, relógio fora de sincronia e mais.
- **Alertas por e-mail**: aviso quando um servidor fica crítico ou offline e quando volta ao normal, pelo SMTP da sua empresa.
- **O que roda dentro**: processos que mais consomem, serviços systemd, portas abertas (e se estão expostas para a internet), containers Docker, sites configurados no Nginx/Apache.
- **O que está instalado e onde**: software detectado com versão e caminho e a lista completa de pacotes com as atualizações pendentes.
- **Segurança**: tentativas de invasão por SSH e IPs de origem, contas com shell, quem é admin, chaves SSH, firewall, fail2ban, certificados Let's Encrypt.
- **Ações com um clique**: diagnóstico, limpeza (cache de pacotes, logs, /tmp, Docker), atualizações de segurança, reiniciar serviços e containers, reiniciar o servidor. Tudo registrado com a saída do comando.
- **Administração pelo navegador** (modo admin): criar e remover usuários, chaves SSH, permissão de administrador, agendamentos cron com montador visual, instaladores de um clique (Nginx, Docker, MariaDB, PostgreSQL, Redis, Node.js, PM2, PHP, Certbot, Fail2ban, UFW, atualizações automáticas e outros), portas do firewall e fuso horário.
- **Atualização simples**: o painel avisa quando há versão nova e se atualiza com um botão; os agentes se atualizam sozinhos.

## Como funciona

```
 ┌───────────────┐   HTTPS (saída)    ┌──────────────────────┐
 │ servidor A    │ ─────────────────▶ │                      │
 │ agente Python │ ◀─ ações na fila ─ │   Linux Control Hub  │ ◀── navegador
 └───────────────┘                    │   (Node + SQLite)    │
 ┌───────────────┐                    │                      │ ──▶ e-mail (SMTP)
 │ servidor B    │ ─────────────────▶ │                      │
 └───────────────┘                    └──────────────────────┘
```

- **Hub**: um único processo Node.js, sem dependências npm, com banco SQLite embutido. Serve o painel, recebe os dados e envia os alertas.
- **Agente**: um único arquivo Python 3 (só biblioteca padrão) instalado como serviço systemd em cada servidor. Ele **só faz conexões de saída** para o hub, então funciona atrás de NAT e firewall sem abrir portas. A cada 30 s envia métricas; a cada 10 min, o inventário; a cada 6 h, a lista de pacotes. Na mesma resposta o hub devolve as ações pendentes.

Detalhes de organização do código e o registro das decisões estão em [docs/ARQUITETURA.md](docs/ARQUITETURA.md).

### Segurança do modelo

- O hub **não guarda senha nem chave SSH** de nenhum servidor.
- O agente só executa ações de um **catálogo fixo definido no próprio agente**. Não existe execução de comando livre. Cada parâmetro é validado no hub e de novo no agente.
- Cada ação tem um nível, e o modo do agente decide o que vale naquele servidor:

| Modo do agente | O que o painel pode fazer |
|---|---|
| `readonly` | só diagnósticos, nada muda no servidor |
| `all` (padrão) | + limpeza, atualizações, reiniciar serviços e containers, reiniciar o servidor |
| `admin` | + usuários, chaves SSH, cron, instaladores, portas do firewall, fuso horário |
| `none` | só monitoramento |

- O modo `admin` equivale a dar root pelo painel (um cron roda qualquer comando). Por isso nunca vem ligado por padrão: precisa ser pedido na instalação do agente.
- Ações perigosas (atualizar tudo, parar serviço, remover usuário, reiniciar servidor) exigem digitar o nome do servidor. Ações na fila expiram em 10 minutos, então nada roda horas depois se o servidor estava offline.
- Contas de sistema e o root não são alterados pelo painel; agendamentos só são removidos se foram criados pelo painel.
- Senhas e tokens que aparecem em linhas de comando de processos e no cron são mascarados pelo agente antes do envio.
- Cada servidor tem um token próprio, guardado só como hash. A senha SMTP fica criptografada (AES-256-GCM) com uma chave separada do banco.
- Painel com sessão `HttpOnly` + `SameSite=Strict`, proteção CSRF, CSP, limite de tentativas de login e trilha de auditoria.

## Instalação do hub

Requisitos: **Node.js 22.13+** (recomendado 24) ou Docker. Use sempre HTTPS em produção: o agente é instalado com `curl | sudo sh` e recebe ações do hub.

### Script automático (Ubuntu/Debian, com HTTPS)

Num servidor limpo, como root:

```bash
curl -fsSL https://raw.githubusercontent.com/webpeak-br/linux-control/main/deploy/install-hub.sh -o install-hub.sh
sh install-hub.sh painel.seudominio.com                 # Let's Encrypt automático
sh install-hub.sh painel.seudominio.com --cloudflare    # domínio com proxy da Cloudflare (SSL Full)
```

Instala Node.js 24, Caddy (HTTPS), serviço systemd, firewall, swap e o vigia de atualização. A senha inicial do admin fica em `/root/linux-control-admin-password.txt`.

### Com Docker

```bash
git clone https://github.com/webpeak-br/linux-control.git
cd linux-control
docker compose up -d
```

### Sem Docker

```bash
git clone https://github.com/webpeak-br/linux-control.git
cd linux-control
node hub/server.js
```

### Primeiro acesso

Sem `LCTL_ADMIN_PASSWORD`, o painel abre a tela de **configuração inicial**: você informa o **código de configuração** que aparece no log do hub (`docker compose logs hub` ou `journalctl -u linux-control-hub`), cria a senha de administrador e registra a instalação (nome, e-mail e empresa) para receber a licença community gratuita. O código garante que só quem tem acesso ao servidor do painel consegue configurá-lo. Com a senha definida pelo ambiente, o registro é pedido logo após o primeiro login.

Para trocar a senha depois: **Configurações → Conta**, ou no servidor `node hub/server.js --set-password 'nova-senha-forte'`.

### HTTPS

Coloque o hub atrás de um proxy com TLS (Caddy, Nginx, Traefik, Cloudflare Tunnel), defina `LCTL_PUBLIC_URL` com o endereço público e `LCTL_TRUST_PROXY=1`, e faça o hub escutar só em `127.0.0.1`. O instalador automático já faz isso. Exemplo para Caddy:

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
| `LCTL_DATA` | `./data` | Pasta do banco SQLite e da chave de criptografia |
| `LCTL_PUBLIC_URL` | (detectado) | URL pública usada no comando de instalação dos agentes e nos e-mails |
| `LCTL_ADMIN_PASSWORD` | (tela inicial) | Senha do administrador definida pelo ambiente |
| `LCTL_RETENTION_DAYS` | `7` | Dias de histórico de métricas |
| `LCTL_SESSION_HOURS` | `12` | Duração da sessão no painel |
| `LCTL_TRUST_PROXY` | `0` | Use `1` **somente** atrás de proxy reverso (lê o IP real de `X-Forwarded-For`) |
| `LCTL_TRUST_CF` | `0` | Use `1` **somente** com a Cloudflare na frente e a origem aceitando apenas os IPs dela (lê `CF-Connecting-IP`) |
| `LCTL_TELEMETRY` | `1` | `0` não envia registro nem heartbeat ao servidor de licenças |
| `LCTL_LICENSE_URL` | (vazio) | Servidor de licenças que recebe o registro e o heartbeat; vazio mantém o registro só local |
| `LCTL_RELEASES_URL` | (GitHub) | Onde o painel procura versões novas; vazio desliga a verificação |
| `LCTL_GEOIP` | `1` | `0` não consulta a localização do IP público dos servidores (ipinfo.io) |
| `LCTL_GEOIP_URL` | `https://ipinfo.io/{ip}/json` | Outro serviço de localização no mesmo formato (`{ip}` é trocado pelo IP) |

## Adicionando um servidor

1. No painel, clique em **Adicionar servidor** e dê um nome.
2. Copie o comando exibido e rode no servidor:

```bash
curl -fsSL https://painel.seudominio.com/install.sh | sudo sh -s -- lctl_SEU_TOKEN
```

Variações (o próprio painel mostra os comandos prontos):

```bash
# somente leitura
curl -fsSL https://painel.seudominio.com/install.sh | sudo LCTL_ACTIONS=readonly sh -s -- lctl_SEU_TOKEN
# admin: libera usuários, cron e instaladores pelo navegador
curl -fsSL https://painel.seudominio.com/install.sh | sudo LCTL_ACTIONS=admin sh -s -- lctl_SEU_TOKEN
```

Para mudar o modo depois, edite `ACTIONS=` em `/etc/linux-control/agent.conf` e rode `systemctl restart linux-control-agent`.

O agente fica em `/opt/linux-control`, a configuração em `/etc/linux-control/agent.conf` (permissão 600) e o serviço chama `linux-control-agent`. Para remover:

```bash
curl -fsSL https://painel.seudominio.com/install.sh | sudo sh -s -- --uninstall
```

Compatível com distribuições com systemd: Debian, Ubuntu, RHEL, Rocky, Alma, CentOS 7+, Fedora e Amazon Linux (Python 3.6+). Em sistemas sem systemd o agente funciona, mas o serviço precisa ser criado manualmente.

## Alertas por e-mail

Em **Configurações → Alertas por e-mail**, informe o SMTP da sua empresa (servidor, porta, segurança, usuário, senha e remetente) e os destinatários. O botão **Enviar e-mail de teste** confirma a configuração. O painel avisa quando um servidor fica **crítico** ou **offline** por mais de 2 minutos e, se você quiser, quando fica em **atenção** e quando **volta ao normal**.

## Atualizações

- **Painel**: verifica as versões publicadas no GitHub a cada 12 h. Em **Configurações → Atualizações**, o botão **Atualizar o painel agora** aplica a versão nova (instalação pelo script). No Docker: `docker compose pull && docker compose up -d`. Manualmente: `sh /opt/linux-control-hub/deploy/install-hub.sh --update`.
- **Agentes**: quando o painel tem uma versão nova do agente, cada agente baixa o arquivo, confere o SHA-256 e reinicia sozinho. Dá para desligar a atualização automática no painel ou no agente (`AUTO_UPDATE=0` no `agent.conf`).

## Licença e privacidade

O código é [MIT](LICENSE). Cada instalação recebe uma licença community gratuita ao ser registrada. O registro envia nome, e-mail, empresa, um identificador aleatório da instalação, a versão e quantos servidores ela monitora, e uma vez por dia o painel envia um heartbeat com versão e quantidade de servidores. Dos servidores monitorados, só o IP público sai do painel, para o ipinfo.io, para mostrar cidade, país e operadora (desligue com `LCTL_GEOIP=0`). O datacenter é lido pelo agente no serviço de metadados do próprio provedor, sem terceiros. Com `LCTL_TELEMETRY=0`, nada é enviado ao servidor de licenças.

## Desenvolvimento

```bash
# hub local (abre a tela de configuração inicial)
LCTL_DATA=./data LCTL_HOST=127.0.0.1 node hub/server.js

# ver tudo o que o agente coleta, sem enviar
python3 agent/linux-control-agent.py --once

# agente apontando para o hub local (sem instalar)
LCTL_CONF=/dev/null LCTL_HUB_URL=http://127.0.0.1:7420 LCTL_TOKEN=lctl_xxx LCTL_ACTIONS=admin python3 agent/linux-control-agent.py

# testes
cd hub && npm test
python3 -m unittest discover -s test/agent
```

Para adicionar uma ação, inclua no catálogo `ACTIONS` do agente (nível, formulário e execução): o painel passa a exibi-la sozinho, com formulário, validação e confirmação. Publicar uma versão: `sh scripts/release.sh X.Y.Z "novidades"`.

## Roadmap

- Múltiplos usuários e perfis de acesso
- Alertas por webhook e chat
- Agrupamento por cliente/ambiente
- Histórico de inventário (o que mudou desde ontem)

Contribuições são bem-vindas: abra uma issue ou um pull request.
