'use strict';
// Tudo que fala com o agente: cadastro (token + comandos de instalação), instalador, download e relatórios.
// Os caminhos e variáveis abaixo são o contrato com agent/install.sh.
const fs = require('node:fs');
const path = require('node:path');
const { sha256, randomToken } = require('../../core/crypto');
const { send } = require('../../core/http');

const REPORT_LIMIT = 4 * 1024 * 1024;
const AGENT_CONF = '/etc/linux-control/agent.conf';
const AGENT_SERVICE = 'linux-control-agent';
const MODES = ['readonly', 'all', 'admin'];

const WAIT_MS = 25_000;

function create({ config, net, features }) {
  const installScript = path.join(config.agentDir, 'install.sh');
  // Canal rápido: o agente deixa um GET /api/agent/wait aberto; quando há ação na fila ou terminal para abrir,
  // o hub responde na hora e o agente manda o relatório em seguida (em vez de esperar os 30 s do ciclo).
  const waiters = new Map();   // serverId -> res
  const pendingWake = new Set();
  function wake(serverId) {
    const res = waiters.get(serverId);
    if (res) { waiters.delete(serverId); send(res, 200, { wake: true }); } else pendingWake.add(serverId);
  }

  function commands(req, token) {
    const base = `curl -fsSL ${net.baseUrl(req)}/install.sh`;
    const install = Object.fromEntries(MODES.map(m => [m, `${base} | sudo ${m === 'all' ? '' : `LCTL_ACTIONS=${m} `}sh -s -- ${token}`]));
    return { install: install.all, install_modes: install };
  }

  function enroll(req) {
    const token = randomToken('lctl_');
    return { token, hash: sha256(token), ...commands(req, token) };
  }

  function agentFromRequest(req) {
    const auth = String(req.headers.authorization || '');
    const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
    return token ? features.servers.byTokenHash(sha256(token)) : null;
  }

  return {
    wake,
    // Autentica antes de ler o corpo, para que clientes anônimos não consigam forçar o hub a ler 4 MB.
    authenticate: agentFromRequest,
    routes(router) {
      router.add('POST /api/servers', ({ req, body, ip }) => {
        const e = enroll(req);
        const id = features.servers.insert(body.name, body.tags, e.hash);
        features.audit.record(ip, 'servidor_criado', String(body.name || ''));
        return { id, token: e.token, install: e.install, install_modes: e.install_modes, hub_url: net.baseUrl(req) };
      });
      router.add('POST /api/servers/:id/token', ({ req, params, ip }) => {
        const e = enroll(req);
        features.servers.setTokenHash(Number(params.id), e.hash);
        features.audit.record(ip, 'token_regenerado', params.id);
        return { token: e.token, install: e.install, install_modes: e.install_modes };
      });
      router.add('GET /api/agent/commands', ({ req }) => ({
        uninstall: `curl -fsSL ${net.baseUrl(req)}/install.sh | sudo sh -s -- --uninstall`,
        set_mode: Object.fromEntries(MODES.map(m => [m, `sudo sed -i 's/^ACTIONS=.*/ACTIONS=${m}/' ${AGENT_CONF} && sudo systemctl restart ${AGENT_SERVICE}`])),
      }));
      router.add('POST /api/agent/report', ({ body, ip, agent }) => {
        features.servers.ingest(agent.id, body, ip);
        return {
          ok: true,
          commands: features.commands.exchange(agent.id, body.results),
          agent_update: features.updates.offerFor(agent.id, String(body.agent_version || '')),
          need_inventory: !agent.has_inventory && !body.inventory,
          terminals: features.terminal.pendingFor(agent.id),
        };
      }, { auth: 'agent', bodyLimit: REPORT_LIMIT });
      router.add('GET /api/agent/wait', ({ agent, res }) => {
        if (pendingWake.delete(agent.id)) return { wake: true };
        const old = waiters.get(agent.id);
        if (old) send(old, 200, { wake: false });
        waiters.set(agent.id, res);
        const timer = setTimeout(() => { if (waiters.get(agent.id) === res) { waiters.delete(agent.id); send(res, 200, { wake: false }); } }, WAIT_MS);
        res.on('close', () => { clearTimeout(timer); if (waiters.get(agent.id) === res) waiters.delete(agent.id); });
      }, { auth: 'agent' });
      router.add('GET /install.sh', ({ req, res }) => {
        const pkg = features.updates.agentPackage();
        const script = fs.readFileSync(installScript, 'utf8')
          .replaceAll('__LCTL_HUB_URL__', net.baseUrl(req)).replaceAll('__LCTL_AGENT_SHA256__', pkg.sha256);
        send(res, 200, script, { 'Content-Type': 'text/x-shellscript; charset=utf-8' });
      }, { auth: 'public' });
      router.add('GET /agent/linux-control-agent.py', ({ res }) => {
        send(res, 200, features.updates.agentPackage().code, { 'Content-Type': 'text/x-python; charset=utf-8' });
      }, { auth: 'public' });
    },
  };
}

module.exports = { migrations: [], create };
