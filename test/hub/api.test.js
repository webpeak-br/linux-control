'use strict';
const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startHub, setupAdmin, enrollServer, metrics } = require('./helpers');

describe('configuração inicial e login', () => {
  let hub;
  before(async () => { hub = await startHub(); });
  after(() => hub.stop());

  test('primeiro acesso exige o código impresso no log do servidor', async () => {
    assert.equal((await hub.call('GET', '/api/me')).body.setup_needed, true);
    const code = hub.app.features.auth.announceSetup();
    assert.equal((await hub.call('POST', '/api/setup', { body: { code: 'errado', password: 'senha-longa-ok' } })).status, 403);
    assert.equal((await hub.call('POST', '/api/setup', { body: { code, password: 'curta' } })).status, 400);
  });

  test('configuração só pode ser feita uma vez', async () => {
    await setupAdmin(hub);
    assert.equal((await hub.call('POST', '/api/setup', { body: { password: 'outra-senha-longa' } })).status, 409);
  });

  test('escrita sem o cabeçalho anti-CSRF é recusada', async () => {
    assert.equal((await hub.call('POST', '/api/servers', { body: { name: 'x' }, csrf: false })).status, 403);
  });

  test('tentativas erradas (login ou código de configuração) bloqueiam o IP, inclusive a senha certa', async () => {
    hub.forgetCookie();
    for (let i = 0; i < 5; i++) assert.ok([401, 429].includes((await hub.call('POST', '/api/login', { body: { password: 'errada' } })).status));
    assert.equal((await hub.call('POST', '/api/login', { body: { password: 'senha-de-teste-1' } })).status, 429);
  });

  test('X-Forwarded-For e CF-Connecting-IP não contornam o bloqueio sem proxy confiável', async () => {
    for (const h of [{ 'X-Forwarded-For': '9.9.9.9' }, { 'CF-Connecting-IP': '8.8.8.8' }]) {
      assert.equal((await hub.call('POST', '/api/login', { body: { password: 'senha-de-teste-1' }, headers: h })).status, 429);
    }
  });
});

describe('agente, servidores e ações', () => {
  let hub, srv;
  before(async () => { hub = await startHub(); await setupAdmin(hub); srv = await enrollServer(hub); });
  after(() => hub.stop());

  test('relatório sem token válido é recusado', async () => {
    const r = await hub.call('POST', '/api/agent/report', { body: {}, headers: { Authorization: 'Bearer lctl_x' }, csrf: false });
    assert.equal(r.status, 401);
  });

  test('o comando de instalação traz o token e o endereço do hub', () => {
    assert.match(srv.install, new RegExp(`^curl -fsSL ${hub.base}/install.sh \\| sudo sh -s -- lctl_`));
  });

  test('disco acima de 90% deixa o servidor crítico, com o nível já calculado para a interface', async () => {
    await srv.report({ agent_version: '0.0.1', interval: 30, metrics: metrics({ disk: 95 }), results: [] });
    const s = (await hub.call('GET', '/api/servers')).body.servers[0];
    assert.equal(s.health.status, 'crit');
    assert.equal(s.levels.disk, 'crit');
    assert.ok(s.health.issues.some(i => i.text.includes('95%')));
  });

  test('ação fora do catálogo do agente é recusada', async () => {
    assert.equal((await hub.call('POST', `/api/servers/${srv.id}/commands`, { body: { action: 'system.shell' } })).status, 400);
  });

  test('ação com confirmação exige o nome do servidor', async () => {
    const path = `/api/servers/${srv.id}/commands`;
    assert.equal((await hub.call('POST', path, { body: { action: 'system.reboot' } })).status, 400);
    assert.equal((await hub.call('POST', path, { body: { action: 'system.reboot', confirm: 'srv-teste' } })).status, 200);
  });

  test('ação vai ao agente uma única vez, só com os campos declarados, e o resultado volta', async () => {
    await hub.call('DELETE', '/api/commands/1');
    const q = await hub.call('POST', `/api/servers/${srv.id}/commands`, { body: { action: 'service.restart', params: { name: 'nginx', extra: 'rm -rf /' } } });
    const first = await srv.report({ agent_version: '0.0.1', metrics: metrics(), results: [] });
    const cmd = first.body.commands.find(c => c.id === q.body.id);
    assert.deepEqual(cmd.params, { name: 'nginx' });
    const second = await srv.report({ agent_version: '0.0.1', metrics: metrics(), results: [{ id: q.body.id, exit_code: 0, output: 'ok', duration: 1 }] });
    assert.ok(!second.body.commands.some(c => c.id === q.body.id));
    const list = (await hub.call('GET', `/api/servers/${srv.id}/commands`)).body.commands;
    assert.equal(list.find(c => c.id === q.body.id).status, 'done');
  });

  test('ação parada na fila por mais de 10 minutos expira e não é entregue', async () => {
    const q = await hub.call('POST', `/api/servers/${srv.id}/commands`, { body: { action: 'health.overview' } });
    hub.app.db.prepare('UPDATE commands SET created = created - 700 WHERE id=?').run(q.body.id);
    const r = await srv.report({ agent_version: '0.0.1', metrics: metrics(), results: [] });
    assert.ok(!r.body.commands.some(c => c.id === q.body.id));
    const list = (await hub.call('GET', `/api/servers/${srv.id}/commands`)).body.commands;
    assert.equal(list.find(c => c.id === q.body.id).status, 'expired');
  });

  test('catálogo vindo do agente com campo ou alvo desconhecido é descartado', async () => {
    const bad = [{ id: 'x.y', level: 'read', fields: [{ name: 'a" onmouseover="x', type: 'text' }] }, { id: 'x.z', level: 'read', target: 'disk' },
      { id: 'X.Y', level: 'read' }, { id: 'ok.ok', level: 'root' }];
    await srv.report({ agent_version: '0.0.1', metrics: metrics(), results: [], inventory: { actions: bad } });
    assert.deepEqual((await hub.call('GET', `/api/servers/${srv.id}`)).body.server.inventory.actions, []);
  });

  test('ação enviada e sem resposta vira "sem resposta" pelo timeout da própria ação', async () => {
    await srv.report({ agent_version: '0.0.1', metrics: metrics(), results: [], inventory: { actions: require('./helpers').ACTIONS } });
    const q = await hub.call('POST', `/api/servers/${srv.id}/commands`, { body: { action: 'service.restart', params: { name: 'nginx' } } });
    await srv.report({ agent_version: '0.0.1', metrics: metrics(), results: [] });
    hub.app.db.prepare('UPDATE commands SET sent_at = sent_at - 500 WHERE id=?').run(q.body.id);
    const list = (await hub.call('GET', `/api/servers/${srv.id}/commands`)).body.commands;
    assert.equal(list.find(c => c.id === q.body.id).status, 'lost');
  });

  test('instalador traz o hash do agente servido', async () => {
    const script = (await hub.call('GET', '/install.sh')).body;
    const pkg = hub.app.features.updates.agentPackage();
    assert.ok(script.includes(`AGENT_SHA256="${pkg.sha256}"`));
    assert.ok(script.includes(`HUB_URL="\${LCTL_HUB_URL:-${hub.base}}"`));
  });
});

describe('atualização dos agentes', () => {
  let hub, srv;
  before(async () => { hub = await startHub(); await setupAdmin(hub); srv = await enrollServer(hub); });
  after(() => hub.stop());

  test('agente desatualizado recebe a oferta com versão e hash', async () => {
    const r = await srv.report({ agent_version: '0.0.1', metrics: metrics(), results: [] });
    const pkg = hub.app.features.updates.agentPackage();
    assert.deepEqual(r.body.agent_update, { version: pkg.version, sha256: pkg.sha256 });
  });

  test('agente em dia não recebe oferta', async () => {
    const pkg = hub.app.features.updates.agentPackage();
    assert.equal((await srv.report({ agent_version: pkg.version, metrics: metrics(), results: [] })).body.agent_update, null);
  });

  test('com a atualização automática desligada, só o servidor pedido recebe', async () => {
    await hub.call('PUT', '/api/updates/settings', { body: { agents_auto: false } });
    assert.equal((await srv.report({ agent_version: '0.0.1', metrics: metrics(), results: [] })).body.agent_update, null);
    await hub.call('POST', `/api/servers/${srv.id}/agent-update`);
    assert.equal((await hub.call('GET', `/api/servers/${srv.id}/agent`)).body.requested, true);
    assert.ok((await srv.report({ agent_version: '0.0.1', metrics: metrics(), results: [] })).body.agent_update);
  });

  test('depois de atualizado, o pedido é apagado', async () => {
    const pkg = hub.app.features.updates.agentPackage();
    await srv.report({ agent_version: pkg.version, metrics: metrics(), results: [] });
    assert.equal((await hub.call('GET', `/api/servers/${srv.id}/agent`)).body.requested, false);
  });
});
