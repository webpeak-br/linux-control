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

test('discos: setor ilegível é crítico, remapeado é atenção, erro no kernel é crítico', () => {
  const inv = dh => ({ disk_health: dh });
  const codes = dh => evaluate({ last_seen: now, metrics: {}, inventory: inv(dh) }, now).issues.map(i => `${i.level}:${i.code}`);
  assert.deepEqual(codes({ devices: [{ name: '/dev/sda', smart_passed: true, pending: 3, reallocated: 8 }] }), ['crit:disk_sectors', 'warn:disk_sectors']);
  assert.deepEqual(codes({ devices: [], io_errors_24h: 4 }), ['crit:disk_io_errors']);
  assert.deepEqual(codes({ devices: [], smartctl: false, virtual: false }), ['info:smart_missing']);
  assert.deepEqual(codes({ devices: [], smartctl: false, virtual: true }), []);
});

test('chaves SSH: só pública, privada é recusada com aviso', () => {
  const { parseKey, fingerprint } = require('../../hub/features/keys');
  const pub = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq0n7Xb9mWkq1f3mJ8l0j0tq3k2m0c8m7d1x2y3z4w5 ana@note';
  assert.equal(parseKey(`  ${pub}\n`), pub);
  assert.match(fingerprint(pub), /^SHA256:/);
  assert.throws(() => parseKey('-----BEGIN OPENSSH PRIVATE KEY-----\nabc'), /PRIVADA/);
  assert.throws(() => parseKey('ssh-ed25519 curta'), /inválida/);
});

test('tentativas de SSH com Fail2ban ativo viram informação, sem botão de instalar de novo', () => {
  const inv = f2b => ({ system: { is_root: true }, security: { failed_logins_24h: 2179, fail2ban_sshd: f2b, ssh: {}, firewall: { active: true } } });
  const at = f2b => evaluate({ last_seen: now, metrics: {}, inventory: inv(f2b) }, now).issues.find(i => /tentativas/.test(i.text));
  assert.equal(at(null).code, 'ssh_bruteforce');
  assert.equal(at(null).level, 'warn');
  const p = at({ active: true, banned_now: 3, banned_total: 40 });
  assert.equal(p.code, 'ssh_bruteforce_protected');
  assert.equal(p.level, 'info');
  assert.match(p.text, /3 IP\(s\) bloqueado/);
});
