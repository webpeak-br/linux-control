'use strict';
// Ciclo de vida de uma ação: queued -> sent -> done | failed, ou expired (ficou na fila), lost (o agente não respondeu
// dentro do tempo limite da própria ação) e canceled.
const { HttpError } = require('../../core/http');

const migrations = [
  { name: 'commands:1', sql: `CREATE TABLE IF NOT EXISTS commands (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
      action TEXT NOT NULL, param TEXT, label TEXT, status TEXT NOT NULL,
      created INTEGER, sent_at INTEGER, finished_at INTEGER,
      exit_code INTEGER, duration REAL, output TEXT, requested_by TEXT)` },
  { name: 'commands:2', tolerant: true, sql: [
    'ALTER TABLE commands ADD COLUMN params TEXT',
    'ALTER TABLE commands ADD COLUMN timeout INTEGER',
    'CREATE INDEX IF NOT EXISTS commands_srv ON commands(server_id, id)'] },
];

const S = { queued: 'queued', sent: 'sent', done: 'done', failed: 'failed', expired: 'expired', lost: 'lost', canceled: 'canceled' };
const QUEUE_TTL = 600;            // na fila por mais de 10 min: expira (evita um reboot horas depois)
const DEFAULT_TIMEOUT = 120;      // o mesmo padrão do agente quando a ação não declara timeout
const LOST_MARGIN = 300;          // folga para o agente devolver o resultado no ciclo seguinte
const OUTPUT_LIMIT = 70_000;      // o agente já corta a saída em 64 KB
const KEEP_DAYS = 90;
const MAX_PARAM = 8000;

function create({ db, now, features }) {
  function settle(serverId = null) {
    const t = now();
    const where = serverId ? ' AND server_id=?' : '';
    const args = serverId ? [serverId] : [];
    db.prepare(`UPDATE commands SET status='${S.expired}' WHERE status='${S.queued}' AND created < ?${where}`).run(t - QUEUE_TTL, ...args);
    db.prepare(`UPDATE commands SET status='${S.lost}' WHERE status='${S.sent}' AND sent_at + COALESCE(timeout, ${DEFAULT_TIMEOUT}) + ${LOST_MARGIN} < ?${where}`)
      .run(t, ...args);
  }

  // Confere os parâmetros contra o formulário que o próprio agente declarou. O agente revalida tudo antes de executar.
  function cleanParams(action, raw) {
    const input = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
    const out = {};
    for (const f of action.fields || []) {
      const v = input[f.name];
      if (f.type === 'bool') { out[f.name] = v === true; continue; }
      if (v === undefined || v === null || v === '') continue;
      if (typeof v !== 'string' || v.length > MAX_PARAM) throw new HttpError(400, `Valor inválido em ${f.label}.`);
      out[f.name] = v.trim();
    }
    return out;
  }

  function queue(server, actionId, rawParams, confirm, ip) {
    const action = ((server.inventory || {}).actions || []).find(a => a.id === actionId);
    if (!action) throw new HttpError(400, 'Ação não disponível neste servidor (verifique o modo de ações do agente).');
    if (action.confirm && confirm !== server.name) throw new HttpError(400, 'Confirme digitando o nome do servidor.');
    const params = cleanParams(action, rawParams);
    const summary = Object.values(params).filter(v => typeof v === 'string').join(' ').slice(0, 200) || null;
    const timeout = Number.isInteger(action.timeout) ? action.timeout : DEFAULT_TIMEOUT;
    const r = db.prepare(`INSERT INTO commands(server_id,action,params,param,label,status,timeout,created,requested_by) VALUES(?,?,?,?,?,?,?,?,?)`)
      .run(server.id, action.id, JSON.stringify(params), summary, String(action.label || action.id).slice(0, 120), S.queued, timeout, now(), ip);
    features.audit.record(ip, 'acao', `${server.name}: ${action.id}${summary ? ' ' + summary : ''}`);
    return Number(r.lastInsertRowid);
  }

  return {
    // Chamado a cada relatório do agente: grava resultados e devolve o que ainda falta executar.
    exchange(serverId, results) {
      const t = now();
      for (const r of Array.isArray(results) ? results : []) {
        const id = parseInt(r.id, 10);
        if (!id) continue;
        db.prepare(`UPDATE commands SET status=?, exit_code=?, output=?, duration=?, finished_at=? WHERE id=? AND server_id=? AND status IN ('${S.sent}','${S.lost}')`)
          .run(r.exit_code === 0 ? S.done : S.failed, parseInt(r.exit_code, 10), String(r.output || '').slice(0, OUTPUT_LIMIT), Number(r.duration) || null, t, id, serverId);
      }
      settle(serverId);
      const pending = db.prepare(`SELECT id, action, params FROM commands WHERE server_id=? AND status='${S.queued}' ORDER BY id LIMIT 10`).all(serverId);
      for (const c of pending) db.prepare(`UPDATE commands SET status='${S.sent}', sent_at=? WHERE id=?`).run(t, c.id);
      return pending.map(c => ({ id: c.id, action: c.action, params: JSON.parse(c.params || '{}') }));
    },
    routes(router) {
      router.add('GET /api/servers/:id/commands', ({ params }) => {
        settle(Number(params.id));
        return { commands: db.prepare(`SELECT id, action, param, label, status, created, sent_at, finished_at, exit_code, duration, output
          FROM commands WHERE server_id=? ORDER BY id DESC LIMIT 50`).all(Number(params.id)) };
      });
      router.add('POST /api/servers/:id/commands', ({ params, body, ip }) => {
        const server = features.servers.get(Number(params.id));
        return { id: queue(server, String(body.action || ''), body.params, body.confirm, ip) };
      });
      router.add('DELETE /api/commands/:id', ({ params }) => {
        db.prepare(`UPDATE commands SET status='${S.canceled}' WHERE id=? AND status='${S.queued}'`).run(Number(params.id));
        return { ok: true };
      });
    },
    jobs: [{ name: 'commands-settle', everyMs: 3600_000, run() {
      settle();
      db.prepare('DELETE FROM commands WHERE created < ?').run(now() - KEEP_DAYS * 86400);
    } }],
  };
}

module.exports = { migrations, create };
