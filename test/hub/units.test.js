'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { evaluate } = require('../../hub/features/servers/health');
const { compareVersions } = require('../../hub/features/updates');
const { buildMessage } = require('../../hub/features/alerts/smtp');

const now = 1_000_000;

test('servidor sem contato há mais de 3 intervalos fica offline', () => {
  assert.equal(evaluate({ last_seen: now - 200, interval: 30, metrics: {}, inventory: {} }, now).status, 'offline');
  assert.equal(evaluate({ last_seen: now - 30, interval: 30, metrics: {}, inventory: {} }, now).status, 'ok');
});

test('servidor que nunca falou fica aguardando', () => {
  assert.equal(evaluate({ last_seen: null }, now).status, 'pending');
});

test('limites de disco: 80% atenção, 90% crítico', () => {
  const at = pct => evaluate({ last_seen: now, metrics: { disks: [{ mount: '/', pct, inode_pct: 1 }] }, inventory: {} }, now).status;
  assert.equal(at(79), 'ok');
  assert.equal(at(80), 'warn');
  assert.equal(at(90), 'crit');
});

test('sem root, a falta de firewall não vira alerta (o agente não consegue ver)', () => {
  const inv = r => ({ system: { is_root: r }, security: { firewall: { active: false } } });
  assert.equal(evaluate({ last_seen: now, metrics: {}, inventory: inv(false) }, now).status, 'ok');
  assert.equal(evaluate({ last_seen: now, metrics: {}, inventory: inv(true) }, now).status, 'warn');
});

test('container que saiu com erro aparece no diagnóstico; o que saiu com 0, não', () => {
  const inv = containers => ({ docker: { containers } });
  const at = cs => evaluate({ last_seen: now, metrics: {}, inventory: inv(cs) }, now).issues.filter(i => i.area === 'docker').length;
  assert.equal(at([{ name: 'a', docker_state: 'exited', status: 'Exited (1) 2 hours ago', state: ['stopped'] }]), 1);
  assert.equal(at([{ name: 'b', docker_state: 'exited', status: 'Exited (0) 2 hours ago', state: ['stopped'] }]), 0);
});

test('comparação de versões é numérica, não alfabética', () => {
  assert.ok(compareVersions('v0.10.0', '0.9.9') > 0);
  assert.equal(compareVersions('v1.2.3', '1.2.3'), 0);
  assert.ok(compareVersions('0.2.0', '0.2.1') < 0);
});

test('mensagem de e-mail é MIME válido com assunto acentuado codificado', () => {
  const msg = buildMessage({ from: 'A <a@b.com>', to: ['c@d.com'], subject: 'Crítico', text: 'x', html: '<p>x</p>' });
  assert.match(msg, /^Subject: =\?UTF-8\?B\?/m);
  assert.match(msg, /^Content-Type: multipart\/alternative/m);
  assert.ok(!/\r\n\.\r\n/.test(msg));
});

test('a versão do agente acompanha a versão do projeto', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '../../hub/package.json'), 'utf8'));
  const agent = fs.readFileSync(path.join(__dirname, '../../agent/linux-control-agent.py'), 'utf8');
  assert.equal(agent.match(/^VERSION = "([^"]+)"/m)[1], pkg.version);
});

test('todo código em "fixes" do agente existe no diagnóstico do hub', () => {
  const agent = fs.readFileSync(path.join(__dirname, '../../agent/linux-control-agent.py'), 'utf8');
  const health = fs.readFileSync(path.join(__dirname, '../../hub/features/servers/health.js'), 'utf8');
  const codes = new Set([...agent.matchAll(/"fixes": \[([^\]]*)\]/g)].flatMap(m => [...m[1].matchAll(/"([a-z_]+)"/g)].map(x => x[1])));
  assert.ok(codes.size > 10);
  for (const c of codes) assert.ok(health.includes(`'${c}'`), `código sem problema correspondente: ${c}`);
});

test('problemas do diagnóstico trazem código e, quando há, a aba de detalhe', () => {
  const inv = { system: { is_root: true }, security: { ssh: { permitrootlogin: 'yes', passwordauthentication: 'yes' }, firewall: { active: false } } };
  const issues = evaluate({ last_seen: now, metrics: {}, inventory: inv }, now).issues;
  const byCode = Object.fromEntries(issues.map(i => [i.code, i]));
  assert.equal(byCode.ssh_root_password.see, 'security');
  assert.ok(byCode.ssh_password_auth && byCode.firewall_off);
  assert.ok(issues.every(i => /^[a-z_]+$/.test(i.code)));
});

test('ids de ação com número (fix.fail2ban) passam pelo filtro do catálogo', () => {
  const src = fs.readFileSync(path.join(__dirname, '../../hub/features/servers/index.js'), 'utf8');
  const re = new RegExp(src.match(/const ACTION_ID = \/(.+)\/;/)[1]);
  const agent = fs.readFileSync(path.join(__dirname, '../../agent/linux-control-agent.py'), 'utf8');
  for (const [, id] of agent.matchAll(/\{"id": "([a-z0-9_]+\.[a-z0-9_]+)"/g)) assert.ok(re.test(id), id);
});

test('localização: só IP público é consultado e a resposta é normalizada', () => {
  const { isPublic, publicIp, clean } = require('../../hub/features/servers/geo');
  for (const ip of ['10.0.0.1', '192.168.1.5', '172.20.0.1', '127.0.0.1', '100.64.1.1', '::1', 'fe80::1', 'fd00::1']) assert.equal(isPublic(ip), false, ip);
  assert.ok(isPublic('45.32.94.194'));
  assert.equal(publicIp({ remote_ip: '10.0.0.9', inventory: { system: { ips: [{ addr: '10.0.0.9/24' }, { addr: '203.0.113.7/24' }] } } }), '203.0.113.7');
  const g = clean({ city: 'Los Angeles', region: 'California', country: 'us', loc: '34.05,-118.24', org: 'AS20473 The Constant Company, LLC' });
  assert.deepEqual([g.country, g.asn, g.org, g.lat], ['US', 'AS20473', 'The Constant Company, LLC', 34.05]);
});
