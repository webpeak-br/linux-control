'use strict';
// Atualização do hub (versão publicada no GitHub) e dos agentes (versão servida por este hub).
// Contrato com deploy/install-hub.sh: o hub, sem privilégios, grava a tag pedida em <dados>/update-request;
// o vigia linux-control-hub-update.path (root) roda "install-hub.sh --update", que aplica e apaga o pedido.
// O instalador cria <dados>/self-update-enabled para indicar que o vigia existe.
const fs = require('node:fs');
const path = require('node:path');
const { sha256 } = require('../../core/crypto');
const { HttpError } = require('../../core/http');

const migrations = [{ name: 'updates:1', sql: 'CREATE TABLE IF NOT EXISTS agent_update_requests (server_id INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE, requested INTEGER)' }];

const CHECK_EVERY_MS = 12 * 3600_000;
const TAG_RE = /^v\d+\.\d+\.\d+$/;
const MANUAL_UPDATE = {
  script: 'sh /opt/linux-control-hub/deploy/install-hub.sh --update',
  docker: 'docker compose pull && docker compose up -d',
};

function compareVersions(a, b) {
  const pa = String(a || '0').replace(/^v/, '').split('.').map(Number);
  const pb = String(b || '0').replace(/^v/, '').split('.').map(Number);
  for (let i = 0; i < 3; i++) if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  return 0;
}

function create({ db, settings, config, now, features }) {
  const agentFile = path.join(config.agentDir, 'linux-control-agent.py');
  const requestFile = path.join(config.dataDir, 'update-request');
  const selfUpdateMarker = path.join(config.dataDir, 'self-update-enabled');

  let cached = { mtime: 0 };
  function agentPackage() {
    const st = fs.statSync(agentFile);
    if (st.mtimeMs !== cached.mtime) {
      const code = fs.readFileSync(agentFile);
      const m = code.toString('utf8').match(/^VERSION = "([^"]+)"/m);
      cached = { mtime: st.mtimeMs, code, version: m ? m[1] : '0.0.0', sha256: sha256(code) };
    }
    return cached;
  }

  const isRequested = id => !!db.prepare('SELECT 1 FROM agent_update_requests WHERE server_id=?').get(id);
  const agentOutdated = version => !!version && compareVersions(version, agentPackage().version) < 0;

  async function checkHub() {
    if (!config.releasesUrl) return;
    try {
      const res = await fetch(config.releasesUrl, { headers: { 'User-Agent': 'linux-control-hub', Accept: 'application/vnd.github+json' }, signal: AbortSignal.timeout(15000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const rel = await res.json();
      settings.set('updates.hub', { latest: rel.tag_name, url: rel.html_url, notes: String(rel.body || '').slice(0, 4000), checked_at: now(), error: null });
    } catch (e) {
      settings.set('updates.hub', { ...(settings.get('updates.hub') || {}), checked_at: now(), error: e.message });
    }
  }

  function status() {
    const hub = settings.get('updates.hub') || {};
    return {
      hub: {
        current: config.version,
        latest: hub.latest || null,
        available: !!hub.latest && compareVersions(hub.latest, config.version) > 0,
        url: hub.url || null, notes: hub.notes || '', checked_at: hub.checked_at || null, error: hub.error || null,
        can_self_update: fs.existsSync(selfUpdateMarker),
        requested: fs.existsSync(requestFile) ? fs.readFileSync(requestFile, 'utf8').trim() : null,
        manual: MANUAL_UPDATE,
      },
      agents: { version: agentPackage().version, auto: settings.get('updates.agents_auto', true) },
    };
  }

  return {
    agentPackage,
    // Resposta ao relatório do agente: oferta de atualização quando ele está atrás e isso é permitido.
    offerFor(serverId, version) {
      if (!agentOutdated(version)) {
        db.prepare('DELETE FROM agent_update_requests WHERE server_id=?').run(serverId);
        return null;
      }
      if (!settings.get('updates.agents_auto', true) && !isRequested(serverId)) return null;
      const pkg = agentPackage();
      return { version: pkg.version, sha256: pkg.sha256 };
    },
    routes(router) {
      router.add('GET /api/updates', () => status());
      router.add('POST /api/updates/check', async () => { await checkHub(); return status(); });
      router.add('PUT /api/updates/settings', ({ body }) => { settings.set('updates.agents_auto', body.agents_auto !== false); return status(); });
      router.add('POST /api/updates/hub', ({ ip }) => {
        const s = status();
        if (!s.hub.available) throw new HttpError(400, 'Não há versão nova do painel.');
        if (!s.hub.can_self_update) throw new HttpError(400, 'Atualização automática indisponível nesta instalação (Docker ou manual). Veja as instruções.');
        if (!TAG_RE.test(s.hub.latest)) throw new HttpError(400, 'Versão publicada inválida.');
        fs.writeFileSync(requestFile, s.hub.latest + '\n');
        features.audit.record(ip, 'atualizacao_hub', s.hub.latest);
        return { ok: true, version: s.hub.latest };
      });
      router.add('GET /api/servers/:id/agent', ({ params }) => {
        const srv = features.servers.get(Number(params.id));
        return { installed: srv.agent_version, available: agentPackage().version, outdated: agentOutdated(srv.agent_version), requested: isRequested(srv.id) };
      });
      router.add('POST /api/servers/:id/agent-update', ({ params, ip }) => {
        const srv = features.servers.get(Number(params.id));
        db.prepare('INSERT OR REPLACE INTO agent_update_requests(server_id, requested) VALUES(?,?)').run(srv.id, now());
        features.audit.record(ip, 'atualizacao_agente', srv.name);
        return { ok: true };
      });
    },
    jobs: [{ name: 'updates-check', everyMs: CHECK_EVERY_MS, runAtStart: true, run: checkHub }],
  };
}

module.exports = { migrations, create, compareVersions };
