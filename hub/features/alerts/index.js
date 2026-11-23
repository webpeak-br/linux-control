'use strict';
// Alertas por e-mail quando um servidor muda de estado (crítico, offline, atenção) e quando volta ao normal.
const { HttpError } = require('../../core/http');
const { isEmail, isMailbox } = require('../../core/validate');
const { sendMail } = require('./smtp');

const migrations = [{ name: 'alerts:1', sql: `CREATE TABLE IF NOT EXISTS alert_state (
  server_id INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
  status TEXT, since INTEGER, notified TEXT, notified_at INTEGER)` }];

const CHECK_EVERY_MS = 60_000;
const STABLE_FOR = 120;  // o estado precisa durar 2 min antes de virar e-mail (evita alerta de oscilação)
const BAD = new Set(['crit', 'offline']);

const DEFAULTS = { enabled: false, recipients: '', notify_warn: false, notify_recovery: true,
  smtp: { host: '', port: 587, security: 'starttls', user: '', pass_sealed: '', from: '' } };

const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

function create({ db, settings, config, box, now, features }) {
  const load = () => { const s = settings.get('alerts', {}); return { ...DEFAULTS, ...s, smtp: { ...DEFAULTS.smtp, ...(s.smtp || {}) } }; };
  const recipients = cfg => cfg.recipients.split(/[,;\s]+/).filter(Boolean);
  const smtpOf = cfg => ({ ...cfg.smtp, pass: box.open(cfg.smtp.pass_sealed) });

  function publicView(cfg) {
    const { pass_sealed, ...smtp } = cfg.smtp;
    return { ...cfg, smtp: { ...smtp, has_pass: !!pass_sealed } };
  }

  function validate(input, current) {
    const smtp = input.smtp || {};
    const cur = current.smtp;
    const next = {
      enabled: input.enabled === true,
      recipients: String(input.recipients || '').trim().slice(0, 1000),
      notify_warn: input.notify_warn === true,
      notify_recovery: input.notify_recovery !== false,
      smtp: {
        host: String(smtp.host || '').trim().slice(0, 200),
        port: parseInt(smtp.port, 10) || 587,
        security: ['tls', 'starttls', 'none'].includes(smtp.security) ? smtp.security : 'starttls',
        user: String(smtp.user || '').trim().slice(0, 200),
        from: String(smtp.from || '').trim().slice(0, 200),
        pass_sealed: '',
      },
    };
    // A senha guardada só continua valendo para o mesmo servidor e usuário: assim ninguém a desvia para outro SMTP.
    const sameServer = ['host', 'port', 'security', 'user'].every(k => next.smtp[k] === cur[k]);
    if (smtp.pass) next.smtp.pass_sealed = box.seal(String(smtp.pass));
    else if (sameServer) next.smtp.pass_sealed = cur.pass_sealed;
    if (!/^[A-Za-z0-9.-]*$/.test(next.smtp.host)) throw new HttpError(400, 'Servidor SMTP inválido.');
    if (next.smtp.from && !isMailbox(next.smtp.from)) throw new HttpError(400, 'Remetente inválido. Use e-mail ou "Nome <e-mail>".');
    if (/[\r\n]/.test(next.smtp.user)) throw new HttpError(400, 'Usuário SMTP inválido.');
    for (const r of recipients(next)) if (!isEmail(r)) throw new HttpError(400, `E-mail inválido: ${r}`);
    if (next.enabled && (!next.smtp.host || !next.smtp.from || !recipients(next).length)) {
      throw new HttpError(400, 'Para ligar os alertas, preencha servidor SMTP, remetente e destinatários.');
    }
    return next;
  }

  function message(server, status, previous) {
    const recovered = !BAD.has(status) && BAD.has(previous);
    const subject = recovered ? `[Linux Control] ${server.name} voltou: ${server.health.label}` : `[Linux Control] ${server.name}: ${server.health.label}`;
    const issues = server.health.issues.filter(i => i.level !== 'info');
    const link = config.publicUrl ? `${config.publicUrl}/#/server/${server.id}` : '';
    const text = [subject, '', ...issues.map(i => `- ${i.text}`), '', link].join('\n');
    const html = `<div style="font-family:system-ui,sans-serif;max-width:560px">
      <h2 style="margin:0 0 8px">${esc(server.name)}: ${esc(server.health.label)}</h2>
      ${recovered ? '<p>O servidor voltou ao normal.</p>' : ''}
      <ul>${issues.map(i => `<li>${esc(i.text)}</li>`).join('') || '<li>Sem problemas pendentes.</li>'}</ul>
      ${link ? `<p><a href="${esc(link)}">Abrir no painel</a></p>` : ''}
      <p style="color:#888;font-size:12px">Linux Control · alerta automático</p></div>`;
    return { subject, text, html };
  }

  function shouldNotify(cfg, status, notified) {
    if (status === notified || status === 'pending') return false;
    if (BAD.has(status)) return true;
    if (status === 'warn') return cfg.notify_warn || (BAD.has(notified) && cfg.notify_recovery);
    return BAD.has(notified) ? cfg.notify_recovery : (notified === 'warn' && cfg.notify_warn);
  }

  async function check() {
    const cfg = load();
    const t = now();
    for (const server of features.servers.all()) {
      const status = server.health.status;
      let st = db.prepare('SELECT * FROM alert_state WHERE server_id=?').get(server.id);
      if (!st) {
        db.prepare('INSERT INTO alert_state(server_id,status,since,notified) VALUES(?,?,?,?)').run(server.id, status, t, status);
        continue;
      }
      if (st.status !== status) {
        db.prepare('UPDATE alert_state SET status=?, since=? WHERE server_id=?').run(status, t, server.id);
        st = { ...st, status, since: t };
      }
      if (t - st.since < STABLE_FOR || st.notified === status) continue;
      if (!cfg.enabled || !shouldNotify(cfg, status, st.notified)) {
        db.prepare('UPDATE alert_state SET notified=? WHERE server_id=?').run(status, server.id);
        continue;
      }
      try {
        await sendMail(smtpOf(cfg), { to: recipients(cfg), ...message(server, status, st.notified) });
        db.prepare('UPDATE alert_state SET notified=?, notified_at=? WHERE server_id=?').run(status, t, server.id);
      } catch (e) {
        console.error(`alerta de ${server.name} não enviado: ${e.message}`);
        settings.set('alerts.last_error', { at: t, message: e.message });
      }
    }
  }

  return {
    check,
    routes(router) {
      router.add('GET /api/settings/alerts', () => ({ ...publicView(load()), stable_minutes: STABLE_FOR / 60, last_error: settings.get('alerts.last_error') }));
      router.add('PUT /api/settings/alerts', ({ body, ip }) => {
        const next = validate(body, load());
        settings.set('alerts', next);
        features.audit.record(ip, 'alertas_configurados', next.enabled ? 'ligados' : 'desligados');
        return publicView(next);
      });
      router.add('POST /api/settings/alerts/test', async () => {
        const cfg = load();
        if (!cfg.smtp.host || !cfg.smtp.from || !recipients(cfg).length) throw new HttpError(400, 'Salve servidor SMTP, remetente e destinatários antes de testar.');
        try {
          await sendMail(smtpOf(cfg), { to: recipients(cfg), subject: '[Linux Control] Teste de alerta',
            text: 'Os alertas por e-mail do Linux Control estão funcionando.',
            html: '<p>Os alertas por e-mail do <b>Linux Control</b> estão funcionando.</p>' });
        } catch (e) {
          throw new HttpError(502, `Falha no envio: ${e.message}`);
        }
        return { ok: true };
      });
    },
    jobs: [{ name: 'alerts-check', everyMs: CHECK_EVERY_MS, run: check }],
  };
}

module.exports = { migrations, create };
