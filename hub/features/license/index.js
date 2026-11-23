'use strict';
// Registro da instalação (como no n8n): o dono informa nome, e-mail e empresa e recebe uma licença community gratuita.
// O registro vai ao servidor de licenças configurado em LCTL_LICENSE_URL; sem ele, ou com LCTL_TELEMETRY=0, fica só local.
const crypto = require('node:crypto');
const { HttpError } = require('../../core/http');
const { isEmail } = require('../../core/validate');

// Dados pessoais só saem por HTTPS (http fica liberado apenas para o próprio computador, em testes).
const SECURE_URL = /^(https:\/\/|http:\/\/(127\.0\.0\.1|localhost)[:/])/;
const HEARTBEAT_EVERY = 86400;
const RETRY_EVERY_MS = 30 * 60_000;

function create({ settings, config, now, features }) {
  const load = () => {
    const lic = settings.get('license', null) || { instance_id: crypto.randomUUID(), status: 'unregistered' };
    if (!settings.get('license')) settings.set('license', lic);
    return lic;
  };
  const save = lic => settings.set('license', lic);
  const remoteEnabled = () => config.telemetry && SECURE_URL.test(config.licenseUrl);

  async function post(route, payload) {
    const res = await fetch(config.licenseUrl + route, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'User-Agent': `linux-control-hub/${config.version}` },
      body: JSON.stringify(payload), signal: AbortSignal.timeout(15000),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.ok === false) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }

  async function sync() {
    const lic = load();
    if (!lic.owner || !remoteEnabled()) return lic;
    const servers = features.servers.count();
    try {
      if (!lic.key) {
        const r = await post('/register', { instance_id: lic.instance_id, ...lic.owner, version: config.version, servers });
        Object.assign(lic, { key: r.license_key, plan: r.plan || 'community', status: 'registered', registered_at: now(), error: null });
      } else if (now() - (lic.last_heartbeat || 0) >= HEARTBEAT_EVERY) {
        await post('/heartbeat', { instance_id: lic.instance_id, license_key: lic.key, version: config.version, servers });
        Object.assign(lic, { last_heartbeat: now(), error: null });
      }
    } catch (e) {
      lic.error = e.message;
      if (!lic.key) lic.status = 'pending';
    }
    save(lic);
    return lic;
  }

  function view(lic) {
    return {
      instance_id: lic.instance_id, owner: lic.owner || null, plan: lic.plan || 'community',
      status: lic.owner ? lic.status : 'unregistered', key: lic.key || null, registered_at: lic.registered_at || null,
      error: lic.error || null, registration_needed: !lic.owner, remote: remoteEnabled(),
    };
  }

  return {
    routes(router) {
      router.add('GET /api/license', () => view(load()));
      router.add('POST /api/license/register', async ({ body, ip }) => {
        const owner = {
          name: String(body.name || '').trim().slice(0, 120),
          email: String(body.email || '').trim().toLowerCase().slice(0, 200),
          company: String(body.company || '').trim().slice(0, 120),
        };
        if (!owner.name) throw new HttpError(400, 'Informe seu nome.');
        if (!isEmail(owner.email)) throw new HttpError(400, 'Informe um e-mail válido.');
        if (body.consent !== true) throw new HttpError(400, 'É preciso concordar com o registro da instalação.');
        const lic = load();
        Object.assign(lic, { owner, status: remoteEnabled() ? 'pending' : 'local', key: lic.owner && lic.owner.email === owner.email ? lic.key : null });
        save(lic);
        features.audit.record(ip, 'registro', owner.email);
        return view(await sync());
      });
    },
    jobs: [{ name: 'license-sync', everyMs: RETRY_EVERY_MS, runAtStart: true, run: sync }],
  };
}

module.exports = { migrations: [], create };
