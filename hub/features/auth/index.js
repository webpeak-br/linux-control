'use strict';
const crypto = require('node:crypto');
const { hashPassword, verifyPassword, sha256 } = require('../../core/crypto');
const { HttpError, parseCookies } = require('../../core/http');

const migrations = [
  { name: 'auth:1', sql: 'CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, created INTEGER, expires INTEGER, ip TEXT)' },
  // v0.1 guardava a senha em settings.admin_password (texto puro, não JSON).
  { name: 'auth:2', sql: "INSERT OR IGNORE INTO settings(key,value) SELECT 'auth.password', json_quote(value) FROM settings WHERE key='admin_password'" },
];

const COOKIE = 'lctl_sid';
const MIN_PASSWORD = 10;
const PER_IP_FREE_TRIES = 5;
const GLOBAL_FAILS_PER_MIN = 30;

// Limite de tentativas de login por IP e global (o global protege quando os IPs vêm de muitas origens).
function createLimiter() {
  const perIp = new Map();
  let recent = [];
  return {
    blocked(ip) {
      const t = Date.now();
      recent = recent.filter(x => t - x < 60_000);
      if (recent.length >= GLOBAL_FAILS_PER_MIN) return true;
      const a = perIp.get(ip);
      return !!(a && a.until > t);
    },
    failed(ip) {
      const t = Date.now();
      recent.push(t);
      const a = perIp.get(ip) || { count: 0, until: 0, last: 0 };
      if (t - a.last > 3600_000) a.count = 0;
      a.count++; a.last = t;
      if (a.count >= PER_IP_FREE_TRIES) a.until = t + Math.min(15, a.count - PER_IP_FREE_TRIES + 1) * 60_000;
      perIp.set(ip, a);
      if (perIp.size > 10_000) for (const [k, v] of perIp) if (t - v.last > 3600_000) perIp.delete(k);
    },
    succeeded(ip) { perIp.delete(ip); },
  };
}

function create({ db, settings, config, net, now, features }) {
  const limiter = createLimiter();
  const audit = () => features.audit;

  const hasPassword = () => !!settings.get('auth.password');

  // Enquanto não há senha, quem chega primeiro configura o painel. O código impresso no log do servidor
  // prova que a pessoa tem acesso à máquina onde o hub roda.
  let setupCode = null;
  function announceSetup() {
    if (hasPassword() || config.adminPassword) return;
    setupCode = crypto.randomBytes(4).toString('hex');
    console.log(`\nConfiguração inicial pendente. Código de configuração: ${setupCode}\n`);
    return setupCode;
  }

  async function setPassword(pw) {
    if (String(pw || '').length < MIN_PASSWORD) throw new HttpError(400, `A senha precisa de pelo menos ${MIN_PASSWORD} caracteres.`);
    settings.set('auth.password', await hashPassword(pw));
    db.prepare('DELETE FROM sessions').run();
  }

  function startSession(req, res, ip) {
    const sid = crypto.randomBytes(32).toString('base64url');
    const ttl = config.sessionHours * 3600;
    db.prepare('INSERT INTO sessions(id,created,expires,ip) VALUES(?,?,?,?)').run(sha256(sid), now(), now() + ttl, ip);
    const secure = net.isHttps(req) ? '; Secure' : '';
    res.setHeader('Set-Cookie', `${COOKIE}=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${ttl}${secure}`);
  }

  function session(req) {
    const sid = parseCookies(req)[COOKIE];
    if (!sid) return null;
    const s = db.prepare('SELECT * FROM sessions WHERE id=?').get(sha256(sid));
    return s && s.expires >= now() ? s : null;
  }

  return {
    session,
    setPassword,
    announceSetup,
    // Senha vinda do ambiente (instalador/Docker) tem prioridade e é aplicada a cada início.
    async applyEnvPassword() {
      if (!config.adminPassword) return;
      if (!(await verifyPassword(config.adminPassword, settings.get('auth.password')))) {
        settings.set('auth.password', await hashPassword(config.adminPassword));
      }
    },
    routes(router) {
      router.add('GET /api/me', ({ req }) => ({
        authenticated: !!session(req), setup_needed: !hasPassword(), version: config.version, min_password: MIN_PASSWORD,
      }), { auth: 'public' });

      router.add('POST /api/setup', async ({ req, res, body, ip }) => {
        if (hasPassword()) throw new HttpError(409, 'Este painel já foi configurado.');
        if (limiter.blocked(ip)) throw new HttpError(429, 'Muitas tentativas. Aguarde alguns minutos.');
        if (!setupCode || String(body.code || '').trim().toLowerCase() !== setupCode) {
          limiter.failed(ip);
          throw new HttpError(403, 'Código de configuração incorreto. Ele aparece no log do servidor do painel.');
        }
        if (String(body.password || '').length < MIN_PASSWORD) throw new HttpError(400, `A senha precisa de pelo menos ${MIN_PASSWORD} caracteres.`);
        const hash = await hashPassword(body.password);
        if (hasPassword()) throw new HttpError(409, 'Este painel já foi configurado.');
        settings.set('auth.password', hash);
        setupCode = null;
        audit().record(ip, 'configuracao_inicial');
        startSession(req, res, ip);
        return { ok: true };
      }, { auth: 'public' });

      router.add('POST /api/login', async ({ req, res, body, ip }) => {
        if (limiter.blocked(ip)) throw new HttpError(429, 'Muitas tentativas. Aguarde alguns minutos.');
        if (!(await verifyPassword(String(body.password || ''), settings.get('auth.password')))) {
          limiter.failed(ip);
          audit().record(ip, 'login_falhou');
          throw new HttpError(401, 'Senha incorreta.');
        }
        limiter.succeeded(ip);
        startSession(req, res, ip);
        audit().record(ip, 'login');
        return { ok: true };
      }, { auth: 'public' });

      router.add('POST /api/logout', ({ res, session: s }) => {
        db.prepare('DELETE FROM sessions WHERE id=?').run(s.id);
        res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
        return { ok: true };
      });

      router.add('POST /api/account/password', async ({ req, res, body, ip }) => {
        if (config.adminPassword) throw new HttpError(409, 'A senha é definida por LCTL_ADMIN_PASSWORD no servidor; altere lá.');
        if (!(await verifyPassword(String(body.current || ''), settings.get('auth.password')))) throw new HttpError(400, 'Senha atual incorreta.');
        await setPassword(body.password);
        audit().record(ip, 'senha_alterada');
        startSession(req, res, ip);
        return { ok: true };
      });
    },
    jobs: [{ name: 'sessions-prune', everyMs: 3600_000, run: () => db.prepare('DELETE FROM sessions WHERE expires < ?').run(now()) }],
  };
}

module.exports = { migrations, create };
