# Arquitetura e registro de decisões

Este arquivo explica como o Linux Control é organizado e por quê. Ele serve para quem for contribuir, gente ou agente. A regra que guia a organização: **o que muda junto fica junto; o que muda por motivos diferentes não fica amarrado.**

## Visão geral

```
agent/linux-control-agent.py   fonte única do que um servidor sabe fazer (coleta + catálogo de ações)
hub/
  core/      config, versão, banco, HTTP, criptografia: muda pouco, ninguém daqui importa features
  features/  uma pasta por assunto; cada uma registra suas rotas e tarefas periódicas
    auth/       senha, sessões, limite de login, primeira configuração
    servers/    dados do servidor, histórico, diagnóstico (health) e níveis para a interface
    agents/     cadastro do agente (token e comandos de instalação), instalador e relatórios
    commands/   ciclo de vida das ações (fila, envio, resultado, expiração)
    alerts/     regras de alerta e envio de e-mail (SMTP próprio, sem dependências)
    license/    registro da instalação e heartbeat
    updates/    checagem de versão nova do hub e dos agentes
    audit/      trilha de auditoria
  public/    interface (módulos ES, sem build)
```

Dependências apontam sempre para o que muda menos: `features/*` importa `core/*`, nunca o contrário, e uma feature só importa outra pela função pública dela (o `index.js` da pasta).

## Registro de decisões (refatoração v0.2, skill untangle-codebase)

Cada correção aparece acima dos problemas que resolve.

- **O agente é a fonte única do catálogo de ações, com nível e formulário declarados.** O hub e a interface leem tudo do catálogo; nenhum outro lugar lista ids de ação.
  - `hub/server.js:202` mantinha `DANGER_ACTIONS` e `PARAM_RULES`, cópias do que o agente já declara (`danger`, `param`, `UNIT_RE`, `CONTAINER_RE`).
  - `hub/server.js:207` `paramKind()` deduzia o tipo de parâmetro pelo prefixo do id (`service.`, `docker.`).
  - `hub/public/app.js` `canAct(s, 'service.restart')`: a tabela de serviços conhecia ids de ação de cor.
  - `hub/public/app.js` `runAction`: escolhia a lista de sugestões por `a.param === 'service'`.
  - O nível de segurança era binário (`mut`) e não comportava o modo admin (usuários, cron, instaladores).
  - Formulários de ação só aceitavam um parâmetro de texto.
- **O hub calcula os níveis (ok, atenção, crítico) num único lugar e envia junto com os dados; a interface só pinta.**
  - `hub/health.js` usava 90/80 para disco; `hub/public/app.js` `lvl()` repetia 90/80 para colorir as barras.
  - `hub/server.js` `loadServer` calculava o disco mais cheio; `app.js` `tabOverview` recalculava.
- **O ciclo de vida de uma ação fica em `features/commands`: estados, prazos e transições num só arquivo.**
  - O prazo de 4000 s para "sem resposta" aparecia em duas consultas (`GET /commands` e `housekeeping`).
  - A expiração da fila aparecia em duas consultas (`handleAgentReport` e `housekeeping`).
  - Os nomes de estado estavam espalhados em literais SQL.
- **O hub é dividido por assunto em vez de um arquivo único; cada feature registra suas rotas num roteador.**
  - `hub/server.js` misturava HTTP, sessão, agentes, painel, arquivos estáticos e manutenção: toda feature nova cairia nele.
  - As rotas eram uma cadeia de `if`/regex misturada com regra de negócio.
- **A versão é declarada uma vez (`hub/package.json`). O agente tem a própria constante, e um teste garante que as duas batem.** O hub descobre a versão do agente que serve lendo o arquivo do agente, e é isso que move a atualização automática.
  - `VERSION` aparecia em `server.js`, no agente e no `package.json`, sem nada que mantivesse as três iguais.
- **A interface monta a estrutura da tela uma vez e só atualiza a área de dados.**
  - `app.js` `keepFocus()` existia só para devolver o foco ao campo de busca depois de redesenhar a página inteira a cada 10 s.
  - O intervalo de atualização tinha um caso especial para a aba Ações (3 s contra 10 s).
- **`app.js` é dividido em módulos por tela.**
  - Um arquivo de 600 linhas com API, gráficos, modais e as dez abas.
- **A senha é verificada por uma única função assíncrona.**
  - `checkPassword` e `checkPasswordAsync` duplicavam a mesma lógica.
- **Surplus removido.**
  - `seen_cmds` no agente: o hub nunca reenvia uma ação já enviada.
  - Rota `/api/audit` sem tela: agora aparece em Configurações → Auditoria.
  - Pasta `docs/` vazia.
- **Casos especiais do agente viram dados.**
  - `software()` tinha `if label == "Coolify"` e `if label == "cPanel"`: agora cada item declara como é detectado (binário ou pasta).
  - A contagem de logins SSH com falha existia em Python (coletor) e em shell (ação): agora é uma função usada pelos dois.

## Segurança: níveis de ação

| Nível | O que permite | Como liberar |
|---|---|---|
| `read` | diagnósticos, nada muda no servidor | sempre (modo `readonly`) |
| `change` | limpeza, atualizações, reiniciar serviços | modo `all` (padrão) |
| `danger` | atualizar tudo, parar serviço, reiniciar servidor | modo `all`, com o nome do servidor digitado para confirmar |
| `admin` | criar e remover usuários, cron, instalar programas | só com `LCTL_ACTIONS=admin` na instalação do agente |

O modo admin é equivalente a dar root pelo painel (um cron roda qualquer comando). Por isso ele nunca vem ligado por padrão e toda execução vai para a auditoria.

## Segunda rodada (verificação por revisores independentes)

- **O catálogo diz também onde e quando cada ação aparece.** Itens do inventário trazem `key` e `state`; a ação declara `target_field`, `when` (lista de estados) e `placement`. Campos declaram `suggest` e o tipo `cron` (montador visual). A interface não cita mais nenhum id de ação.
  - `views/tabs/users.js` e `schedules.js` citavam `users.create` e `cron.add`; o agendamento tinha um modal próprio.
  - `actions.js` tinha `TARGETS`, uma cópia de qual campo cada linha preenche e dos nomes de estado.
  - Sugestões eram escolhidas pelo nome do campo: o campo de usuário novo sugeria nomes de serviço.
  - A regra "UID ≥ 1000" estava no agente e na interface; agora é o estado `person`.
- **O hub manda os níveis e rótulos prontos**: status (`health.label`), certificados e flags de SSH (`levels`), eventos de auditoria (`label`), prazo do alerta, limite da auditoria, tamanho mínimo da senha, faixas do histórico, comandos de instalação, troca de modo e atualização manual.
- **Ação "sem resposta" usa o timeout que o agente publica** (gravado junto com a ação), em vez de 4000 s fixos.
- **O pedido de atualização de agente fica só em `updates`** (tabela própria, oferta, rota e limpeza).
- **Detecções do agente unificadas**: gerenciador de pacotes, lista de instalados, firewall, grupos de administrador e marcador do cron.
- **Segurança (revisão v0.2)**: chave SSH gravada sem seguir links simbólicos; remetente e destinatários SMTP sem quebra de linha; senha SMTP descartada quando o servidor muda; autenticação SMTP só com TLS; `CF-Connecting-IP` só com `LCTL_TRUST_CF=1`; catálogo do agente sanitizado no hub; CSP com `form-action` e `base-uri`; configuração inicial exige o código impresso no log; registro exige consentimento e HTTPS; autoatualização do agente só com TLS verificado, conferindo sintaxe e guardando `.bak`, e desligada por padrão em `readonly`/`none`; atualização do hub recusa downgrade e pedido via link simbólico; o painel não fecha a porta do SSH nem remove o último administrador.

### Mantido de propósito

- Rótulos dos estados de uma ação e as séries dos gráficos ficam na interface: são apresentação, mudam por motivo de tela.
- O cabeçalho `X-LCtl` aparece em `server.js` e em `api.js`: o navegador não importa código do servidor. Os testes usam a constante exportada.
- `health.js` usa 30 s quando o agente não informou o intervalo: é o fallback de dado ausente, não uma cópia de configuração.

## Resolver pelo diagnóstico

Cada problema do diagnóstico (`hub/features/servers/health.js`) tem um `code` e, quando existe, `see` (a aba com o detalhe). Uma ação do agente declara em `fixes` os códigos que resolve; a Visão geral mostra ao lado do problema um botão para cada ação do catálogo com aquele código. O hub e a interface não citam ids de ação, e um teste garante que todo código de `fixes` existe no diagnóstico.

- As ações que mudam o servidor aparecem primeiro como "Resolver: …"; as de leitura ajudam a investigar.
- Toda ação que não é de leitura pede uma recoleta do inventário, para o problema sumir do painel no ciclo seguinte.
- SSH: a opção é gravada em `/etc/ssh/sshd_config.d/00-linux-control.conf` (lido antes do `50-cloud-init.conf`; no sshd vale o primeiro valor) ou no topo do `sshd_config`. Antes de valer, passa por `sshd -t` e é desfeita se falhar. A ação recusa quando ninguém mais conseguiria entrar (nenhum administrador com chave).
- Firewall: liga o UFW (ou firewalld) mantendo abertas o SSH e todas as portas que já escutam fora do loopback.

## Protocolo agente ↔ hub

- `POST /api/agent/report` com `Authorization: Bearer <token>` e corpo `{ agent_version, interval, metrics, results: [{id, exit_code, output, duration}], inventory? }`. O inventário traz `actions` (catálogo) e, a cada 6 h, `packages`.
- Resposta: `{ commands: [{id, action, params}], agent_update: {version, sha256} | null, need_inventory }`.
- `GET /agent/linux-control-agent.py` serve o agente; `GET /install.sh` serve o instalador com o endereço do hub e o SHA-256 do agente embutidos.
