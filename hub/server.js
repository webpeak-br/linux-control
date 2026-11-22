#!/usr/bin/env node
// Linux Control Hub - painel central que recebe dados dos agentes e serve a interface web.
// Zero dependências: node:http + node:sqlite (Node 22.13+).
'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { open } = require('./db');
const { evaluate } = require('./health');

const VERSION = '0.1.0';
const CFG = {
  port: parseInt(process.env.LCTL_PORT || '7420', 10),
  host: process.env.LCTL_HOST || '0.0.0.0',
  dataDir: process.env.LCTL_DATA || path.join(__dirname, '..', 'data'),
  publicUrl: (process.env.LCTL_PUBLIC_URL || '').replace(/\/+$/, ''),
  retentionDays: parseInt(process.env.LCTL_RETENTION_DAYS || '7', 10),
  sessionHours: parseInt(process.env.LCTL_SESSION_HOURS || '12', 10),
  trustProxy: process.env.LCTL_TRUST_PROXY === '1',
  commandTtl: 600, // ações na fila expiram em 10 min (evita reboot horas depois)
};
const PUBLIC_DIR = path.join(__dirname, 'public');
const AGENT_DIR = fs.existsSync(path.join(__dirname, 'agent')) ? path.join(__dirname, 'agent') : path.join(__dirname, '..', 'agent');

const db = open(CFG.dataDir);
const now = () => Math.floor(Date.now() / 1000);
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');

// ------------------------------------------------------------------ senha do admin
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(pw, salt, 64);
  return `scrypt$${salt.toString('hex')}$${key.toString('hex')}`;
}
function checkPassword(pw, stored) {
  if (!stored) return false;
  const [, saltHex, keyHex] = stored.split('$');
  const key = crypto.scryptSync(pw, Buffer.from(saltHex, 'hex'), 64);
  return crypto.timingSafeEqual(key, Buffer.from(keyHex, 'hex'));
}
function checkPasswordAsync(pw, stored) {
  return new Promise(resolve => {
    if (!stored) return resolve(false);
    const [, saltHex, keyHex] = stored.split('$');
    crypto.scrypt(String(pw).slice(0, 1024), Buffer.from(saltHex, 'hex'), 64, (err, key) =>
      resolve(!err && crypto.timingSafeEqual(key, Buffer.from(keyHex, 'hex'))));
  });
}
const getSetting = k => (db.prepare('SELECT value FROM settings WHERE key=?').get(k) || {}).value;
const setSetting = (k, v) => db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(k, v);

if (process.argv.includes('--set-password')) {
  const pw = process.argv[process.argv.indexOf('--set-password') + 1];
  if (!pw || pw.length < 10) { console.error('Informe uma senha com pelo menos 10 caracteres.'); process.exit(1); }
  setSetting('admin_password', hashPassword(pw));
  db.prepare('DELETE FROM sessions').run();
  console.log('Senha do admin atualizada. Sessões anteriores encerradas.');
  process.exit(0);
}
if (process.env.LCTL_ADMIN_PASSWORD) {
  const cur = getSetting('admin_password');
  if (!cur || !checkPassword(process.env.LCTL_ADMIN_PASSWORD, cur)) setSetting('admin_password', hashPassword(process.env.LCTL_ADMIN_PASSWORD));
} else if (!getSetting('admin_password')) {
  const pw = crypto.randomBytes(12).toString('base64url');
  setSetting('admin_password', hashPassword(pw));
  console.log('\n==============================================');
  console.log(' Linux Control: senha inicial do admin gerada:');
  console.log(`   ${pw}`);
  console.log(' Troque com: node hub/server.js --set-password "nova-senha"');
  console.log('==============================================\n');
}

// ------------------------------------------------------------------ utilidades HTTP
function clientIp(req) {
  if (CFG.trustProxy) {
    const cf = req.headers['cf-connecting-ip'];
    if (cf) return String(cf);
    const xf = req.headers['x-forwarded-for'];
    if (xf) return String(xf).split(',')[0].trim();
  }
  return req.socket.remoteAddress || '';
}
function isHttps(req) {
  return req.socket.encrypted || (CFG.trustProxy && req.headers['x-forwarded-proto'] === 'https');
}
function send(res, code, body, headers = {}) {
  const isObj = typeof body === 'object' && !Buffer.isBuffer(body);
  const data = isObj ? JSON.stringify(body) : body;
  res.writeHead(code, {
    'Content-Type': isObj ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(data);
}
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > limit) {
        if (!req._tooBig) { req._tooBig = true; reject(Object.assign(new Error('payload muito grande'), { status: 413 })); }
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (req._tooBig) return;
      if (!size) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(Object.assign(new Error('JSON inválido'), { status: 400 })); }
    });
    req.on('error', reject);
  });
}
function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) { try { out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } catch { /* cookie inválido */ } }
  }
  return out;
}
function audit(ip, event, detail = '') {
  db.prepare('INSERT INTO audit(ts,ip,event,detail) VALUES(?,?,?,?)').run(now(), ip, event, String(detail).slice(0, 500));
}
function baseUrl(req) {
  if (CFG.publicUrl) return CFG.publicUrl;
  const host = String((CFG.trustProxy && req.headers['x-forwarded-host']) || req.headers.host || `localhost:${CFG.port}`);
  if (!/^[A-Za-z0-9.\-:\[\]]+$/.test(host)) return `http://localhost:${CFG.port}`;
  return `${isHttps(req) ? 'https' : 'http'}://${host}`;
}

// ------------------------------------------------------------------ sessão
function currentSession(req) {
  const sid = parseCookies(req).lctl_sid;
  if (!sid) return null;
  const s = db.prepare('SELECT * FROM sessions WHERE id=?').get(sha256(sid));
  if (!s || s.expires < now()) return null;
  return s;
}
const loginAttempts = new Map(); // ip -> {count, until, last}
let globalFails = []; // timestamps de falhas (limite global contra IPs forjados/distribuídos)
function loginBlocked(ip) {
  const t = Date.now();
  globalFails = globalFails.filter(x => t - x < 60_000);
  if (globalFails.length >= 30) return true;
  const a = loginAttempts.get(ip);
  return !!(a && a.until > t);
}
function loginFailed(ip) {
  const t = Date.now();
  globalFails.push(t);
  const a = loginAttempts.get(ip) || { count: 0, until: 0, last: 0 };
  if (t - a.last > 3600_000) a.count = 0;
  a.count++; a.last = t;
  if (a.count >= 5) a.until = t + Math.min(15, a.count - 4) * 60_000;
  loginAttempts.set(ip, a);
  if (loginAttempts.size > 10_000) {
    for (const [k, v] of loginAttempts) if (t - v.last > 3600_000) loginAttempts.delete(k);
    if (loginAttempts.size > 10_000) loginAttempts.clear();
  }
}

// ------------------------------------------------------------------ servidores
function parseJSON(s, d = null) { try { return s ? JSON.parse(s) : d; } catch { return d; } }
function loadServer(row, full = false) {
  if (!row) return null;
  const srv = {
    id: row.id, name: row.name, tags: row.tags ? row.tags.split(',').filter(Boolean) : [],
    created: row.created, last_seen: row.last_seen, remote_ip: row.remote_ip,
    agent_version: row.agent_version, interval: row.interval,
    inventory_at: row.inventory_at, packages_at: row.packages_at,
    metrics: parseJSON(row.metrics_json, null),
    inventory: parseJSON(row.inventory_json, null),
    packages: parseJSON(row.packages_json, null),
  };
  srv.health = evaluate(srv);
  if (!full) {
    const inv = srv.inventory || {};
    const m = srv.metrics || {};
    const pk = srv.packages || {};
    return {
      id: srv.id, name: srv.name, tags: srv.tags, last_seen: srv.last_seen, remote_ip: srv.remote_ip,
      agent_version: srv.agent_version, health: srv.health,
      system: inv.system ? { hostname: inv.system.hostname, os: inv.system.os, ips: inv.system.ips, cores: inv.system.cores, virt: inv.system.virt } : null,
      metrics: m.ts ? { cpu: m.cpu, mem: m.mem && m.mem.pct, load: m.load, ncpu: m.ncpu, uptime: m.uptime, mem_total: m.mem && m.mem.total,
        disk: (m.disks || []).reduce((a, d) => (d.pct > a.pct ? d : a), { pct: 0, mount: '' }), net: m.net } : null,
      counts: {
        services_running: ((inv.services || {}).units || []).filter(u => u.sub === 'running').length,
        services_failed: ((inv.services || {}).units || []).filter(u => u.active === 'failed').length,
        containers: inv.docker && inv.docker.containers ? inv.docker.containers.filter(c => c.state === 'running').length : null,
        updates: pk.updates ? pk.updates.length : null,
        security_updates: pk.updates ? pk.updates.filter(u => u.security).length : null,
      },
    };
  }
  return srv;
}
// O hub não confia no catálogo enviado pelo agente para decidir o que é perigoso ou qual parâmetro aceitar.
const DANGER_ACTIONS = new Set(['security.apply_all', 'service.stop', 'system.reboot']);
const PARAM_RULES = {
  service: /^[A-Za-z0-9][A-Za-z0-9@_.:\\-]{0,199}$/,
  container: /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/,
};
function paramKind(id) {
  if (id.startsWith('service.')) return 'service';
  if (id.startsWith('docker.')) return 'container';
  return null;
}
function newToken() { return 'lctl_' + crypto.randomBytes(24).toString('base64url'); }
function installCommand(req, token) {
  const url = baseUrl(req);
  return `curl -fsSL ${url}/install.sh | sudo sh -s -- ${token}`;
}

// ------------------------------------------------------------------ API do agente
function agentFromRequest(req) {
  const auth = String(req.headers.authorization || '');
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  return token ? db.prepare('SELECT id, inventory_json FROM servers WHERE token_hash=?').get(sha256(token)) : null;
}
function handleAgentReport(req, res, body, row) {

  const ts = now();
  const m = body.metrics && typeof body.metrics === 'object' ? body.metrics : null;
  const ip = clientIp(req);
  db.exec('BEGIN');
  try {
    db.prepare('UPDATE servers SET last_seen=?, remote_ip=?, agent_version=?, interval=?, metrics_json=COALESCE(?, metrics_json) WHERE id=?')
      .run(ts, ip, String(body.agent_version || '').slice(0, 20), parseInt(body.interval, 10) || 30, m ? JSON.stringify(m) : null, row.id);
    if (m) {
      const disk = Math.max(0, ...(m.disks || []).map(d => d.pct || 0));
      db.prepare('INSERT INTO metrics(server_id,ts,cpu,mem,swap,disk,load1,rx,tx) VALUES(?,?,?,?,?,?,?,?,?)').run(
        row.id, ts, num(m.cpu), num(m.mem && m.mem.pct), num(m.mem && m.mem.swap_pct), disk,
        num(m.load && m.load[0]), num(m.net && m.net.rx_bps), num(m.net && m.net.tx_bps));
    }
    if (body.inventory && typeof body.inventory === 'object') {
      const inv = { ...body.inventory };
      const pk = inv.packages;
      delete inv.packages;
      db.prepare('UPDATE servers SET inventory_json=?, inventory_at=? WHERE id=?').run(JSON.stringify(inv), ts, row.id);
      if (pk) db.prepare('UPDATE servers SET packages_json=?, packages_at=? WHERE id=?').run(JSON.stringify(pk), ts, row.id);
    }
    for (const r of Array.isArray(body.results) ? body.results : []) {
      const id = parseInt(r.id, 10);
      if (!id) continue;
      db.prepare(`UPDATE commands SET status=?, exit_code=?, output=?, duration=?, finished_at=? WHERE id=? AND server_id=?`)
        .run(r.exit_code === 0 ? 'done' : 'failed', parseInt(r.exit_code, 10), String(r.output || '').slice(0, 70000), num(r.duration), ts, id, row.id);
    }
    db.prepare(`UPDATE commands SET status='expired' WHERE server_id=? AND status='queued' AND created < ?`).run(row.id, ts - CFG.commandTtl);
    const pending = db.prepare(`SELECT id, action, param FROM commands WHERE server_id=? AND status='queued' ORDER BY id LIMIT 10`).all(row.id);
    for (const c of pending) db.prepare(`UPDATE commands SET status='sent', sent_at=? WHERE id=?`).run(ts, c.id);
    db.exec('COMMIT');
    send(res, 200, { ok: true, commands: pending, need_inventory: !row.inventory_json && !body.inventory });
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}
function num(v) { const n = Number(v); return Number.isFinite(n) ? n : null; }

// ------------------------------------------------------------------ API do painel
async function handleApi(req, res, url) {
  const ip = clientIp(req);
  const p = url.pathname;

  if (p === '/api/login' && req.method === 'POST') {
    if (loginBlocked(ip)) return send(res, 429, { error: 'Muitas tentativas. Aguarde alguns minutos.' });
    const body = await readBody(req, 4096);
    if (!(await checkPasswordAsync(String(body.password || ''), getSetting('admin_password')))) {
      loginFailed(ip); audit(ip, 'login_falhou');
      return send(res, 401, { error: 'Senha incorreta.' });
    }
    loginAttempts.delete(ip);
    const sid = crypto.randomBytes(32).toString('base64url');
    const exp = now() + CFG.sessionHours * 3600;
    db.prepare('INSERT INTO sessions(id,created,expires,ip) VALUES(?,?,?,?)').run(sha256(sid), now(), exp, ip);
    audit(ip, 'login');
    const secure = isHttps(req) ? '; Secure' : '';
    return send(res, 200, { ok: true }, { 'Set-Cookie': `lctl_sid=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${CFG.sessionHours * 3600}${secure}` });
  }

  const session = currentSession(req);
  if (p === '/api/me') return send(res, 200, { authenticated: !!session, version: VERSION });
  if (!session) return send(res, 401, { error: 'não autenticado' });

  // Proteção CSRF: toda escrita exige o cabeçalho customizado (navegadores não enviam em cross-site sem CORS).
  if (req.method !== 'GET' && req.headers['x-lctl'] !== '1') return send(res, 403, { error: 'requisição recusada' });

  if (p === '/api/logout' && req.method === 'POST') {
    db.prepare('DELETE FROM sessions WHERE id=?').run(session.id);
    return send(res, 200, { ok: true }, { 'Set-Cookie': 'lctl_sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
  }

  if (p === '/api/servers' && req.method === 'GET') {
    const rows = db.prepare('SELECT * FROM servers ORDER BY name COLLATE NOCASE').all();
    return send(res, 200, { servers: rows.map(r => loadServer(r)), now: now() });
  }
  if (p === '/api/servers' && req.method === 'POST') {
    const body = await readBody(req, 4096);
    const name = String(body.name || '').trim().slice(0, 80);
    if (!name) return send(res, 400, { error: 'Informe um nome.' });
    const tags = String(body.tags || '').split(',').map(t => t.trim()).filter(Boolean).slice(0, 10).join(',');
    const token = newToken();
    const r = db.prepare('INSERT INTO servers(name,tags,token_hash,created) VALUES(?,?,?,?)').run(name, tags, sha256(token), now());
    audit(ip, 'servidor_criado', name);
    return send(res, 200, { id: Number(r.lastInsertRowid), token, install: installCommand(req, token), hub_url: baseUrl(req) });
  }

  let m = p.match(/^\/api\/servers\/(\d+)(\/[a-z-]+)?$/);
  if (m) {
    const id = parseInt(m[1], 10);
    const sub = m[2] || '';
    const row = db.prepare('SELECT * FROM servers WHERE id=?').get(id);
    if (!row) return send(res, 404, { error: 'servidor não encontrado' });

    if (!sub && req.method === 'GET') return send(res, 200, { server: loadServer(row, true), now: now() });
    if (!sub && req.method === 'PATCH') {
      const body = await readBody(req, 4096);
      const name = String(body.name || row.name).trim().slice(0, 80) || row.name;
      const tags = body.tags !== undefined ? String(body.tags).split(',').map(t => t.trim()).filter(Boolean).slice(0, 10).join(',') : row.tags;
      db.prepare('UPDATE servers SET name=?, tags=? WHERE id=?').run(name, tags, id);
      return send(res, 200, { ok: true });
    }
    if (!sub && req.method === 'DELETE') {
      db.prepare('DELETE FROM servers WHERE id=?').run(id);
      audit(ip, 'servidor_removido', row.name);
      return send(res, 200, { ok: true });
    }
    if (sub === '/token' && req.method === 'POST') {
      const token = newToken();
      db.prepare('UPDATE servers SET token_hash=? WHERE id=?').run(sha256(token), id);
      audit(ip, 'token_regenerado', row.name);
      return send(res, 200, { token, install: installCommand(req, token) });
    }
    if (sub === '/history' && req.method === 'GET') {
      const range = { '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800 }[url.searchParams.get('range')] || 3600;
      const bucket = range <= 3600 ? 30 : range <= 21600 ? 120 : range <= 86400 ? 300 : 1800;
      const rows = db.prepare(`SELECT (ts/${bucket})*${bucket} AS t, avg(cpu) cpu, avg(mem) mem, avg(swap) swap, max(disk) disk,
        avg(load1) load1, avg(rx) rx, avg(tx) tx FROM metrics WHERE server_id=? AND ts>=? GROUP BY t ORDER BY t`).all(id, now() - range);
      return send(res, 200, { range, bucket, points: rows });
    }
    if (sub === '/commands' && req.method === 'GET') {
      const rows = db.prepare(`SELECT id, action, param, label, status, created, sent_at, finished_at, exit_code, duration,
        substr(output,1,70000) output FROM commands WHERE server_id=? ORDER BY id DESC LIMIT 50`).all(id);
      const t = now();
      for (const r of rows) if (r.status === 'sent' && r.sent_at && t - r.sent_at > 4000) r.status = 'lost';
      return send(res, 200, { commands: rows });
    }
    if (sub === '/commands' && req.method === 'POST') {
      const body = await readBody(req, 4096);
      const inv = parseJSON(row.inventory_json, {}) || {};
      const action = (inv.actions || []).find(a => a.id === body.action);
      if (!action || typeof action.id !== 'string' || !/^[a-z_]+\.[a-z_]+$/.test(action.id)) return send(res, 400, { error: 'Ação não disponível neste servidor (verifique o modo de ações do agente).' });
      let param = null;
      const kind = paramKind(action.id);
      if (kind) {
        param = String(body.param || '').trim();
        if (!PARAM_RULES[kind].test(param)) return send(res, 400, { error: 'Parâmetro inválido.' });
      }
      if ((action.danger || DANGER_ACTIONS.has(action.id)) && body.confirm !== row.name) return send(res, 400, { error: 'Confirme digitando o nome do servidor.' });
      const r = db.prepare(`INSERT INTO commands(server_id,action,param,label,status,created,requested_by) VALUES(?,?,?,?, 'queued', ?, ?)`)
        .run(id, action.id, param, String(action.label || action.id).slice(0, 120), now(), ip);
      audit(ip, 'acao', `${row.name}: ${action.id}${param ? ' ' + param : ''}`);
      return send(res, 200, { id: Number(r.lastInsertRowid) });
    }
  }

  m = p.match(/^\/api\/commands\/(\d+)$/);
  if (m && req.method === 'DELETE') {
    db.prepare(`UPDATE commands SET status='canceled' WHERE id=? AND status='queued'`).run(parseInt(m[1], 10));
    return send(res, 200, { ok: true });
  }

  if (p === '/api/audit' && req.method === 'GET') {
    return send(res, 200, { events: db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT 200').all() });
  }
  return send(res, 404, { error: 'rota não encontrada' });
}

// ------------------------------------------------------------------ arquivos estáticos
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json' };
const SEC_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
};
function serveStatic(req, res, pathname) {
  let rel = pathname === '/' ? '/index.html' : pathname;
  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!file.startsWith(PUBLIC_DIR) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
    // SPA: qualquer outra rota cai no index
    return serveFile(res, path.join(PUBLIC_DIR, 'index.html'));
  }
  serveFile(res, file);
}
function serveFile(res, file) {
  res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache', ...SEC_HEADERS });
  fs.createReadStream(file).pipe(res);
}

// ------------------------------------------------------------------ servidor
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  try {
    if (url.pathname === '/api/agent/report' && req.method === 'POST') {
      const row = agentFromRequest(req);
      if (!row) { req.resume(); return send(res, 401, { error: 'token inválido' }); }
      const body = await readBody(req, 4 * 1024 * 1024);
      return handleAgentReport(req, res, body, row);
    }
    if (url.pathname === '/install.sh') {
      const agentSha = sha256(fs.readFileSync(path.join(AGENT_DIR, 'linux-control-agent.py')));
      const script = fs.readFileSync(path.join(AGENT_DIR, 'install.sh'), 'utf8').replaceAll('__LCTL_HUB_URL__', baseUrl(req)).replaceAll('__LCTL_AGENT_SHA256__', agentSha);
      return send(res, 200, script, { 'Content-Type': 'text/x-shellscript; charset=utf-8' });
    }
    if (url.pathname === '/agent/linux-control-agent.py') {
      return send(res, 200, fs.readFileSync(path.join(AGENT_DIR, 'linux-control-agent.py')), { 'Content-Type': 'text/x-python; charset=utf-8' });
    }
    if (url.pathname === '/healthz') return send(res, 200, { ok: true, version: VERSION });
    if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url);
    if (req.method === 'GET') return serveStatic(req, res, url.pathname);
    send(res, 405, { error: 'método não permitido' });
  } catch (e) {
    if (!e.status) console.error(e);
    if (!res.headersSent) send(res, e.status || 500, { error: e.status ? e.message : 'erro interno' });
  }
});

// Limpeza periódica: métricas antigas, sessões expiradas, comandos perdidos
function housekeeping() {
  const t = now();
  db.prepare('DELETE FROM metrics WHERE ts < ?').run(t - CFG.retentionDays * 86400);
  db.prepare('DELETE FROM sessions WHERE expires < ?').run(t);
  db.prepare(`UPDATE commands SET status='lost' WHERE status='sent' AND sent_at < ?`).run(t - 4000);
  db.prepare(`UPDATE commands SET status='expired' WHERE status='queued' AND created < ?`).run(t - CFG.commandTtl);
  db.prepare('DELETE FROM commands WHERE created < ?').run(t - 90 * 86400);
  db.prepare('DELETE FROM audit WHERE ts < ?').run(t - 180 * 86400);
}
setInterval(housekeeping, 3600_000).unref();
housekeeping();

if (CFG.publicUrl && !CFG.publicUrl.startsWith('https://')) {
  console.warn('AVISO: LCTL_PUBLIC_URL não usa HTTPS. Agentes instalados via curl|sh ficam expostos a interceptação. Use HTTPS em produção.');
}
server.listen(CFG.port, CFG.host, () => {
  console.log(`Linux Control Hub v${VERSION} ouvindo em http://${CFG.host}:${CFG.port} (dados em ${CFG.dataDir})`);
});
