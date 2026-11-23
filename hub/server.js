#!/usr/bin/env node
'use strict';
// Linux Control Hub: liga as features ao HTTP e às tarefas periódicas. Regras de negócio ficam em features/.
const http = require('node:http');
const config = require('./core/config');
const { open } = require('./core/db');
const settingsStore = require('./core/settings');
const { secretBox } = require('./core/crypto');
const { HttpError, send, readBody, requestInfo, createRouter, serveStatic } = require('./core/http');

// Ordem importa só para as migrações (tabelas referenciadas vêm antes).
const FEATURES = ['audit', 'auth', 'servers', 'commands', 'updates', 'agents', 'alerts', 'license', 'keys'];
const CSRF_HEADER = 'x-lctl';

function build(cfg = config) {
  const modules = FEATURES.map(name => [name, require(`./features/${name}`)]);
  const db = open(cfg.dataDir, [...settingsStore.migrations, ...modules.flatMap(([, m]) => m.migrations)]);
  const now = () => Math.floor(Date.now() / 1000);
  const features = {};
  const ctx = { db, config: cfg, now, features, settings: settingsStore.create(db), net: requestInfo(cfg), box: secretBox(cfg.dataDir) };
  for (const [name, m] of modules) features[name] = m.create(ctx);

  const router = createRouter();
  for (const f of Object.values(features)) if (f.routes) f.routes(router);
  router.add('GET /healthz', () => ({ ok: true, version: cfg.version }), { auth: 'public' });

  async function handle(req, res) {
    const url = new URL(req.url, 'http://localhost');
    const match = router.match(req.method, url.pathname);
    if (!match) {
      if (req.method === 'GET' && !url.pathname.startsWith('/api/')) return serveStatic(res, cfg.publicDir, url.pathname, cfg.version);
      throw new HttpError(404, 'rota não encontrada');
    }
    const { route, params } = match;
    const input = { req, res, params, query: url.searchParams, ip: ctx.net.ip(req), body: {} };

    if (route.auth === 'agent') {
      input.agent = features.agents.authenticate(req);
      if (!input.agent) { req.resume(); throw new HttpError(401, 'token inválido'); }
    } else if (route.auth === 'session') {
      input.session = features.auth.session(req);
      if (!input.session) throw new HttpError(401, 'não autenticado');
      // CSRF: navegadores não enviam cabeçalho próprio em requisição cross-site sem CORS.
      if (req.method !== 'GET' && req.headers[CSRF_HEADER] !== '1') throw new HttpError(403, 'requisição recusada');
    }
    if (req.method !== 'GET') input.body = await readBody(req, route.bodyLimit);
    const out = await route.handler(input);
    if (!res.headersSent && out !== undefined) send(res, 200, out);
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch(e => {
      if (!(e instanceof HttpError)) console.error(e);
      if (!res.headersSent) send(res, e.status || 500, { error: e instanceof HttpError ? e.message : 'erro interno' });
    });
  });

  const timers = [];
  function startJobs() {
    for (const f of Object.values(features)) {
      for (const job of f.jobs || []) {
        const run = () => Promise.resolve().then(job.run).catch(e => console.error(`tarefa ${job.name}: ${e.message}`));
        if (job.runAtStart) run();
        timers.push(setInterval(run, job.everyMs).unref());
      }
    }
  }
  const stop = () => { timers.forEach(clearInterval); server.close(); db.close(); };
  return { server, features, db, startJobs, stop };
}

async function main() {
  const app = build();
  const arg = process.argv.indexOf('--set-password');
  if (arg > 0) {
    await app.features.auth.setPassword(process.argv[arg + 1]);
    console.log('Senha do admin atualizada. Sessões anteriores encerradas.');
    process.exit(0);
  }
  await app.features.auth.applyEnvPassword();
  app.features.auth.announceSetup();
  if (config.publicUrl && !config.publicUrl.startsWith('https://')) {
    console.warn('AVISO: LCTL_PUBLIC_URL não usa HTTPS. O comando de instalação dos agentes pode ser interceptado.');
  }
  app.startJobs();
  app.server.listen(config.port, config.host, () => {
    console.log(`Linux Control Hub v${config.version} em http://${config.host}:${config.port} (dados em ${config.dataDir})`);
  });
}

if (require.main === module) main().catch(e => { console.error(e.message); process.exit(1); });

module.exports = { build, CSRF_HEADER };
