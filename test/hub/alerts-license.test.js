'use strict';
const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const http = require('node:http');
const { startHub, setupAdmin, enrollServer, metrics } = require('./helpers');

// Servidor SMTP falso: responde como um servidor real (EHLO multilinha, AUTH) e guarda o que recebeu.
function fakeSmtp() {
  const mails = [];
  const server = net.createServer(sock => {
    let data = false, buf = '', mail = { rcpt: [], body: '' };
    sock.write('220 fake ESMTP\r\n');
    sock.on('data', chunk => {
      buf += chunk.toString();
      let i;
      while ((i = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        if (data) {
          if (line === '.') { data = false; mails.push(mail); mail = { rcpt: [], body: '' }; sock.write('250 queued\r\n'); }
          else mail.body += line + '\n';
          continue;
        }
        if (/^EHLO/.test(line)) sock.write('250-fake\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n');
        else if (/^AUTH PLAIN/.test(line)) { mail.auth = Buffer.from(line.split(' ')[2], 'base64').toString(); sock.write('235 ok\r\n'); }
        else if (/^MAIL FROM/.test(line)) { mail.from = line; sock.write('250 ok\r\n'); }
        else if (/^RCPT TO/.test(line)) { mail.rcpt.push(line); sock.write('250 ok\r\n'); }
        else if (line === 'DATA') { data = true; sock.write('354 go\r\n'); }
        else if (line === 'QUIT') { sock.write('221 bye\r\n'); sock.end(); }
      }
    });
  });
  return new Promise(r => server.listen(0, '127.0.0.1', () => r({ server, mails, port: server.address().port })));
}

describe('alertas por e-mail', () => {
  let hub, smtp, srv;
  before(async () => {
    smtp = await fakeSmtp();
    hub = await startHub();
    await setupAdmin(hub);
    srv = await enrollServer(hub, 'web-01', { m: metrics({ disk: 95 }) });
  });
  after(() => { hub.stop(); smtp.server.close(); });

  const config = (extra = {}) => ({ enabled: true, recipients: 'ti@exemplo.com', notify_recovery: true,
    smtp: { host: '127.0.0.1', port: smtp.port, security: 'none', user: 'u', pass: 'segredo', from: 'Painel <alertas@exemplo.com>' }, ...extra });
  // security 'none' com autenticação só é aceito para o próprio computador (servidor SMTP de teste).

  test('ligar alertas sem SMTP completo é recusado', async () => {
    assert.equal((await hub.call('PUT', '/api/settings/alerts', { body: { enabled: true, recipients: 'a@b.com', smtp: {} } })).status, 400);
  });

  test('a senha SMTP nunca volta para o navegador', async () => {
    const r = await hub.call('PUT', '/api/settings/alerts', { body: config() });
    assert.equal(r.status, 200);
    assert.equal(r.body.smtp.has_pass, true);
    assert.ok(!JSON.stringify(r.body).includes('segredo'));
  });

  test('remetente com quebra de linha (injeção SMTP) é recusado', async () => {
    const r = await hub.call('PUT', '/api/settings/alerts', { body: config({ smtp: { ...config().smtp, from: 'a@b.com\r\nRCPT TO:<x@y.com>' } }) });
    assert.equal(r.status, 400);
  });

  test('trocar o servidor SMTP sem informar a senha apaga a senha guardada', async () => {
    await hub.call('PUT', '/api/settings/alerts', { body: config() });
    const moved = config({ smtp: { ...config().smtp, host: 'smtp.atacante.example', pass: '' } });
    assert.equal((await hub.call('PUT', '/api/settings/alerts', { body: moved })).body.smtp.has_pass, false);
    await hub.call('PUT', '/api/settings/alerts', { body: config() });
  });

  test('e-mail de teste chega autenticado, ao destinatário certo', async () => {
    assert.equal((await hub.call('POST', '/api/settings/alerts/test')).status, 200);
    const m = smtp.mails.at(-1);
    assert.equal(m.auth, '\0u\0segredo');
    assert.deepEqual(m.rcpt, ['RCPT TO:<ti@exemplo.com>']);
  });

  test('servidor crítico estável por 2 minutos gera um único alerta; a volta ao normal gera outro', async () => {
    const before = smtp.mails.length;
    const check = () => hub.app.features.alerts.check();
    const age = () => hub.app.db.prepare('UPDATE alert_state SET since = since - 300').run();
    await check();                                   // primeira observação vira linha de base
    hub.app.db.prepare("UPDATE alert_state SET notified='ok'").run();
    await check(); age(); await check(); await check();
    assert.equal(smtp.mails.length, before + 1);
    assert.match(smtp.mails.at(-1).body, /Subject: =\?UTF-8\?B\?/);
    await srv.report({ agent_version: '0.0.1', metrics: metrics({ disk: 40 }), results: [] });
    await check(); age(); await check();
    assert.equal(smtp.mails.length, before + 2);
  });
});

describe('licença', () => {
  test('registro envia o dono ao servidor de licenças e guarda a chave', async () => {
    const received = [];
    const lic = http.createServer((req, res) => {
      let b = ''; req.on('data', c => { b += c; });
      req.on('end', () => { received.push({ url: req.url, body: JSON.parse(b) }); res.end(JSON.stringify({ ok: true, license_key: 'LC1-AAAAA', plan: 'community' })); });
    });
    await new Promise(r => lic.listen(0, '127.0.0.1', r));
    const hub = await startHub({ licenseUrl: `http://127.0.0.1:${lic.address().port}`, telemetry: true });
    try {
      await setupAdmin(hub);
      assert.equal((await hub.call('GET', '/api/license')).body.registration_needed, true);
      assert.equal((await hub.call('POST', '/api/license/register', { body: { name: 'Ana', email: 'nao-e-email', consent: true } })).status, 400);
      assert.equal((await hub.call('POST', '/api/license/register', { body: { name: 'Ana', email: 'ana@exemplo.com' } })).status, 400);
      const r = await hub.call('POST', '/api/license/register', { body: { name: 'Ana', email: 'Ana@Exemplo.com', company: 'X', consent: true } });
      assert.equal(r.body.status, 'registered');
      assert.equal(r.body.key, 'LC1-AAAAA');
      assert.equal(received[0].url, '/register');
      assert.equal(received[0].body.email, 'ana@exemplo.com');
      assert.equal(received[0].body.instance_id, r.body.instance_id);
    } finally { hub.stop(); lic.close(); }
  });

  test('servidor de licenças sem HTTPS não recebe dados pessoais', async () => {
    const hub = await startHub({ licenseUrl: 'http://licencas.exemplo.com', telemetry: true });
    try {
      await setupAdmin(hub);
      const r = await hub.call('POST', '/api/license/register', { body: { name: 'Ana', email: 'ana@exemplo.com', consent: true } });
      assert.equal(r.body.remote, false);
      assert.equal(r.body.status, 'local');
    } finally { hub.stop(); }
  });

  test('com telemetria desligada nada sai do painel', async () => {
    const hub = await startHub({ licenseUrl: 'http://127.0.0.1:9', telemetry: false });
    try {
      await setupAdmin(hub);
      const r = await hub.call('POST', '/api/license/register', { body: { name: 'Ana', email: 'ana@exemplo.com', consent: true } });
      assert.equal(r.body.status, 'local');
      assert.equal(r.body.error, null);
    } finally { hub.stop(); }
  });
});
