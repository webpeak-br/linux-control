'use strict';
const { HttpError } = require('../../core/http');
const { evaluate, metricLevel, certLevel, sshLevel } = require('./health');
const geo = require('./geo');

const migrations = [
  { name: 'servers:1', sql: [
    `CREATE TABLE IF NOT EXISTS servers (
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, tags TEXT DEFAULT '', token_hash TEXT UNIQUE NOT NULL,
      created INTEGER, last_seen INTEGER, remote_ip TEXT, agent_version TEXT, interval INTEGER,
      metrics_json TEXT, inventory_json TEXT, inventory_at INTEGER, packages_json TEXT, packages_at INTEGER)`,
    `CREATE TABLE IF NOT EXISTS metrics (
      server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
      ts INTEGER NOT NULL, cpu REAL, mem REAL, swap REAL, disk REAL, load1 REAL, rx REAL, tx REAL)`,
    'CREATE INDEX IF NOT EXISTS metrics_srv_ts ON metrics(server_id, ts)',
  ] },
  ...geo.migrations,
];

// Séries gravadas a cada relatório e devolvidas pelo histórico.
const SERIES = ['cpu', 'mem', 'swap', 'disk', 'load1', 'rx', 'tx'];
const RANGES = { '1h': [3600, 30], '6h': [21600, 120], '24h': [86400, 300], '7d': [604800, 1800] };
const NAME_MAX = 80;

// O catálogo de ações chega do agente e vira HTML e formulário no painel: só passa o que tem formato conhecido.
const ACTION_ID = /^[a-z_]+\.[a-z0-9_]+$/;
const FIELD_NAME = /^[a-z_]{1,40}$/;
const FIELD_TYPES = new Set(['text', 'textarea', 'select', 'bool', 'cron']);
const TARGETS = new Set(['service', 'container', 'user', 'app', 'cron']);
const LEVELS = new Set(['read', 'change', 'danger', 'admin']);

const parseJSON = (s, d = null) => { try { return s ? JSON.parse(s) : d; } catch { return d; } };
const num = v => { const n = Number(v); return Number.isFinite(n) ? n : null; };
const cleanTags = t => String(t || '').split(',').map(x => x.trim()).filter(Boolean).slice(0, 10).join(',');
const cleanName = (n, fallback = '') => String(n || '').trim().slice(0, NAME_MAX) || fallback;

const ISSUE_CODE = /^[a-z_]{1,40}$/;

function cleanCatalog(actions) {
  return (Array.isArray(actions) ? actions : []).filter(a => a && ACTION_ID.test(a.id) && LEVELS.has(a.level)
    && (!a.target || TARGETS.has(a.target))
    && (a.fields || []).every(f => f && FIELD_NAME.test(f.name) && FIELD_TYPES.has(f.type)))
    .map(a => {
      const out = { ...a };
      if (a.fixes !== undefined) out.fixes = (Array.isArray(a.fixes) ? a.fixes : []).filter(c => typeof c === 'string' && ISSUE_CODE.test(c));
      if (a.done !== undefined) { out.done = a.done === true; out.done_label = String(a.done_label || 'já aplicado').slice(0, 120); }
      return out;
    });
}

function fromRow(row) {
  const srv = {
    id: row.id, name: row.name, tags: row.tags ? row.tags.split(',').filter(Boolean) : [],
    created: row.created, last_seen: row.last_seen, remote_ip: row.remote_ip,
    agent_version: row.agent_version, interval: row.interval,
    inventory_at: row.inventory_at, packages_at: row.packages_at,
    metrics: parseJSON(row.metrics_json), inventory: parseJSON(row.inventory_json), packages: parseJSON(row.packages_json),
  };
  srv.health = evaluate(srv);
  srv.levels = levelsOf(srv);
  srv.counts = countsOf(srv);
  return srv;
}

function levelsOf(srv) {
  const m = srv.metrics || {}, inv = srv.inventory || {};
  const worst = (m.disks || []).reduce((a, d) => (d.pct > a.pct ? d : a), { pct: 0, mount: '' });
  const ssh = (inv.security || {}).ssh || {};
  return {
    cpu: metricLevel('cpu', m.cpu), mem: metricLevel('mem', m.mem && m.mem.pct), swap: metricLevel('swap', m.mem && m.mem.swap_pct),
    disk: metricLevel('disk', worst.pct), disk_mount: worst.mount, disk_pct: worst.pct,
    disks: Object.fromEntries((m.disks || []).map(d => [d.mount, metricLevel('disk', d.pct)])),
    certificates: Object.fromEntries((inv.certificates || []).map(c => [c.name, certLevel(c)])),
    ssh: Object.fromEntries(Object.entries(ssh).map(([k, v]) => [k, sshLevel(k, v)])),
  };
}

function countsOf(srv) {
  const inv = srv.inventory || {}, pk = srv.packages || {};
  return {
    services_failed: ((inv.services || {}).units || []).filter(u => u.active === 'failed').length,
    containers: inv.docker && inv.docker.containers ? inv.docker.containers.filter(c => c.docker_state === 'running').length : null,
    security_updates: pk.updates ? pk.updates.filter(u => u.security).length : null,
  };
}

function summary(srv) {
  const inv = srv.inventory || {}, m = srv.metrics;
  return {
    id: srv.id, name: srv.name, tags: srv.tags, last_seen: srv.last_seen, remote_ip: srv.remote_ip,
    agent_version: srv.agent_version, health: srv.health, levels: srv.levels, counts: srv.counts, geo: srv.geo, cloud: inv.cloud || null,
    system: inv.system ? { hostname: inv.system.hostname, os: inv.system.os, ips: inv.system.ips } : null,
    metrics: m && m.ts ? { cpu: m.cpu, mem: m.mem && m.mem.pct, load: m.load, uptime: m.uptime } : null,
  };
}

function create({ db, now, config, features }) {
  const geoip = geo.createGeo({ db, now, config });
  function row(id) {
    const r = db.prepare('SELECT * FROM servers WHERE id=?').get(id);
    if (!r) throw new HttpError(404, 'Servidor não encontrado.');
    return r;
  }
  const withGeo = srv => { srv.geo = geoip.forServer(srv); return srv; };
  const get = id => withGeo(fromRow(row(id)));
  const all = () => db.prepare('SELECT * FROM servers ORDER BY name COLLATE NOCASE').all().map(r => withGeo(fromRow(r)));

  return {
    get,
    all,
    count: () => db.prepare('SELECT COUNT(*) n FROM servers').get().n,
    insert(name, tags, tokenHash) {
      const clean = cleanName(name);
      if (!clean) throw new HttpError(400, 'Informe um nome.');
      return Number(db.prepare('INSERT INTO servers(name,tags,token_hash,created) VALUES(?,?,?,?)').run(clean, cleanTags(tags), tokenHash, now()).lastInsertRowid);
    },
    setTokenHash(id, hash) { row(id); db.prepare('UPDATE servers SET token_hash=? WHERE id=?').run(hash, id); },
    byTokenHash: hash => db.prepare('SELECT id, name, inventory_json IS NOT NULL AS has_inventory FROM servers WHERE token_hash=?').get(hash),

    // Grava um relatório do agente (métricas sempre; inventário e pacotes quando vierem).
    ingest(id, report, ip) {
      const t = now();
      const m = report.metrics && typeof report.metrics === 'object' ? report.metrics : null;
      db.prepare('UPDATE servers SET last_seen=?, remote_ip=?, agent_version=?, interval=?, metrics_json=COALESCE(?, metrics_json) WHERE id=?')
        .run(t, ip, String(report.agent_version || '').slice(0, 20), parseInt(report.interval, 10) || null, m ? JSON.stringify(m) : null, id);
      if (m) {
        const point = { cpu: m.cpu, mem: m.mem && m.mem.pct, swap: m.mem && m.mem.swap_pct, disk: Math.max(0, ...(m.disks || []).map(d => d.pct || 0)),
          load1: m.load && m.load[0], rx: m.net && m.net.rx_bps, tx: m.net && m.net.tx_bps };
        db.prepare(`INSERT INTO metrics(server_id,ts,${SERIES.join(',')}) VALUES(?,?,${SERIES.map(() => '?').join(',')})`)
          .run(id, t, ...SERIES.map(k => num(point[k])));
      }
      if (report.inventory && typeof report.inventory === 'object') {
        const { packages, ...inv } = report.inventory;
        inv.actions = cleanCatalog(inv.actions);
        db.prepare('UPDATE servers SET inventory_json=?, inventory_at=? WHERE id=?').run(JSON.stringify(inv), t, id);
        if (packages) db.prepare('UPDATE servers SET packages_json=?, packages_at=? WHERE id=?').run(JSON.stringify(packages), t, id);
      }
    },

    routes(router) {
      router.add('GET /api/servers', () => ({ servers: all().map(summary), now: now() }));
      router.add('GET /api/servers/:id', ({ params }) => ({ server: get(Number(params.id)), now: now() }));
      router.add('PATCH /api/servers/:id', ({ params, body }) => {
        const r = row(Number(params.id));
        db.prepare('UPDATE servers SET name=?, tags=? WHERE id=?').run(cleanName(body.name, r.name), body.tags !== undefined ? cleanTags(body.tags) : r.tags, r.id);
        return { ok: true };
      });
      router.add('DELETE /api/servers/:id', ({ params, ip }) => {
        const r = row(Number(params.id));
        db.prepare('DELETE FROM servers WHERE id=?').run(r.id);
        features.audit.record(ip, 'servidor_removido', r.name);
        return { ok: true };
      });
      router.add('GET /api/servers/:id/history', ({ params, query }) => {
        const key = RANGES[query.get('range')] ? query.get('range') : '1h';
        const [range, bucket] = RANGES[key];
        const agg = SERIES.map(k => `${k === 'disk' ? 'max' : 'avg'}(${k}) ${k}`).join(', ');
        const points = db.prepare(`SELECT (ts/${bucket})*${bucket} AS t, ${agg} FROM metrics WHERE server_id=? AND ts>=? GROUP BY t ORDER BY t`)
          .all(Number(params.id), now() - range);
        return { range: key, ranges: Object.keys(RANGES), points };
      });
    },
    jobs: [{ name: 'geoip', everyMs: 120_000, runAtStart: true, run: () => geoip.refresh(all()) },
      { name: 'metrics-prune', everyMs: 3600_000, run: () => db.prepare('DELETE FROM metrics WHERE ts < ?').run(now() - config.retentionDays * 86400) }],
  };
}

module.exports = { migrations, create };
