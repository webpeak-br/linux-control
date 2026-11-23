'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const config = require('../../hub/core/config');
const { build, CSRF_HEADER } = require('../../hub/server');

// Sobe um hub isolado (banco temporário, porta livre) e devolve um cliente HTTP simples.
async function startHub(overrides = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lctl-test-'));
  const cfg = { ...config, dataDir, host: '127.0.0.1', port: 0, adminPassword: '', licenseUrl: '', releasesUrl: '', geoipUrl: '', ...overrides };
  const app = build(cfg);
  await new Promise(r => app.server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${app.server.address().port}`;
  let cookie = '';
  async function call(method, url, { body, headers = {}, csrf = true } = {}) {
    const h = { 'Content-Type': 'application/json', ...headers };
    if (cookie) h.Cookie = cookie;
    if (csrf) h[CSRF_HEADER] = '1';
    const res = await fetch(base + url, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
    const set = res.headers.get('set-cookie');
    if (set) cookie = set.split(';')[0];
    const text = await res.text();
    let json; try { json = JSON.parse(text); } catch { json = text; }
    return { status: res.status, body: json };
  }
  const stop = () => { app.stop(); fs.rmSync(dataDir, { recursive: true, force: true }); };
  return { app, base, call, stop, dataDir, cfg, forgetCookie: () => { cookie = ''; } };
}

async function setupAdmin(hub) {
  const code = hub.app.features.auth.announceSetup();
  const r = await hub.call('POST', '/api/setup', { body: { code, password: 'senha-de-teste-1' }, csrf: false });
  if (r.status !== 200) throw new Error('setup falhou: ' + JSON.stringify(r.body));
}

function metrics({ disk = 40, mem = 30, cpu = 10 } = {}) {
  return {
    ts: Math.floor(Date.now() / 1000), cpu, ncpu: 2, load: [0.1, 0.1, 0.1],
    mem: { total: 1e9, used: mem * 1e7, available: 1e9 - mem * 1e7, pct: mem, swap_total: 0, swap_used: 0, swap_pct: 0 },
    disks: [{ mount: '/', device: '/dev/vda1', fs: 'ext4', total: 1e10, used: disk * 1e8, free: 1e10 - disk * 1e8, pct: disk, inode_pct: 5 }],
    net: { rx_bps: 100, tx_bps: 50 }, uptime: 1000, procs: { count: 10, top: [] },
  };
}

const ACTIONS = [
  { id: 'health.overview', group: 'Saúde', label: 'Diagnóstico', level: 'read' },
  { id: 'service.restart', group: 'Serviços', label: 'Reiniciar', level: 'change', target: 'service', target_field: 'name', when: ['running'], timeout: 120,
    fields: [{ name: 'name', label: 'Serviço', type: 'text', pattern: '^[a-z]+$', required: true }] },
  { id: 'system.reboot', group: 'Sistema', label: 'Reiniciar servidor', level: 'danger', confirm: true },
];

async function enrollServer(hub, name = 'srv-teste', { agentVersion = '0.0.1', actions = ACTIONS, m = metrics() } = {}) {
  const created = await hub.call('POST', '/api/servers', { body: { name } });
  const token = created.body.token;
  const report = body => hub.call('POST', '/api/agent/report', { body, headers: { Authorization: `Bearer ${token}` }, csrf: false });
  await report({ agent_version: agentVersion, interval: 30, metrics: m, results: [], inventory: { system: { hostname: name, is_root: true }, actions, actions_mode: 'all' } });
  return { id: created.body.id, token, report, install: created.body.install };
}

module.exports = { startHub, setupAdmin, enrollServer, metrics, ACTIONS };
