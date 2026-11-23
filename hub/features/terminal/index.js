'use strict';
// Terminal no navegador. O agente só faz conexões de saída, então tudo passa pelo hub:
//   navegador --(SSE: saída)--> hub <--(long-poll: entrada / POST: saída)-- agente (PTY com bash como root)
// Segurança: só com o agente em modo admin, pede a senha do painel de novo, grava a saída inteira em
// data/terminal/<sessão>.log (90 dias; baixar pede a senha), registra abertura e fechamento na auditoria e fecha após 15 min sem uso.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { HttpError, send } = require('../../core/http');

const IDLE_SECONDS = 15 * 60;
const MAX_SECONDS = 4 * 3600;
const CONNECT_SECONDS = 60;           // prazo para o agente atender
const POLL_MS = 25_000;               // long-poll do agente
const HEARTBEAT_MS = 20_000;          // mantém o SSE vivo atrás de proxies (Cloudflare corta em 100 s)
const BACKLOG_BYTES = 64 * 1024;      // o que um navegador que reconecta recebe de volta
const RECORD_LIMIT = 20 * 1024 * 1024;
const MAX_PER_SERVER = 3;
const INPUT_LIMIT = 1024 * 1024;     // entrada pendente por sessão
const MAX_VIEWERS = 5;
const AGENT_LOST_SECONDS = 90;      // sem o agente buscar entrada por esse tempo, a sessão fecha
const KEEP_RECORDINGS_DAYS = 90;
const SID = /^[a-f0-9]{32}$/;

function create({ config, now, features }) {
  const dir = path.join(config.dataDir, 'terminal');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const sessions = new Map();

  function get(sid) {
    const s = SID.test(sid) && sessions.get(sid);
    if (!s) throw new HttpError(404, 'Sessão de terminal não encontrada ou encerrada.');
    return s;
  }

  function broadcast(s, event, data) {
    const line = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const res of s.viewers) res.write(line);
  }

  // Entrega ao agente o que estiver pendente (ou guarda até ele perguntar de novo).
  function flushToAgent(s) {
    if (!s.agentWaiter || (!s.input.length && !s.resize && !s.closing)) return;
    const res = s.agentWaiter;
    s.agentWaiter = null;
    clearTimeout(s.agentTimer);
    if (res.destroyed || res.writableEnded) return;   // conexão já caiu: a entrada fica para a próxima busca
    send(res, 200, { data: s.input.splice(0), resize: s.resize, close: s.closing });
    s.inputBytes = 0;
    s.resize = null;
  }

  function close(s, reason, ip = 'sistema') {
    if (s.closed) return;
    s.closed = true;
    s.closing = true;
    flushToAgent(s);
    broadcast(s, 'closed', { reason });
    for (const res of s.viewers) res.end();
    s.viewers.clear();
    fs.appendFileSync(s.file, `\r\n[Linux Control] sessão encerrada: ${reason}\r\n`);
    const secs = now() - s.created;
    features.audit.record(ip, 'terminal_fechado', `${s.serverName}: ${reason} (${Math.round(secs / 60)} min, ${Math.round(s.recorded / 1024)} KB gravados, sessão ${s.id})`);
    // Mantém o objeto alguns segundos para o agente receber o "close".
    setTimeout(() => sessions.delete(s.id), 30_000).unref();
  }

  return {
    // Sessões que o agente ainda precisa abrir (vão na resposta do relatório e do canal rápido).
    pendingFor(serverId) {
      return [...sessions.values()].filter(s => s.serverId === serverId && !s.agentConnected && !s.closed).map(s => ({ id: s.id }));
    },
    routes(router) {
      router.add('POST /api/servers/:id/terminal', async ({ params, body: raw, ip }) => {
        const body = raw || {};
        const server = features.servers.get(Number(params.id));
        if ((server.inventory || {}).actions_mode !== 'admin') {
          throw new HttpError(400, 'O terminal exige o agente no modo admin. No servidor: veja Configurações → Modo de ações.');
        }
        await features.auth.confirmPassword(body.password, ip);
        const open = [...sessions.values()].filter(s => s.serverId === server.id && !s.closed);
        if (open.length >= MAX_PER_SERVER) throw new HttpError(429, `Já há ${open.length} terminais abertos neste servidor.`);
        const id = crypto.randomBytes(16).toString('hex');
        const cols = Math.min(500, Math.max(20, parseInt(body.cols, 10) || 120));
        const rows = Math.min(200, Math.max(5, parseInt(body.rows, 10) || 32));
        const file = path.join(dir, `${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}-${server.id}-${id.slice(0, 8)}.log`);
        fs.writeFileSync(file, `[Linux Control] terminal em ${server.name}, aberto por ${ip} em ${new Date().toISOString()}\r\n`, { mode: 0o600 });
        sessions.set(id, {
          id, serverId: server.id, serverName: server.name, created: now(), lastInput: now(), file, recorded: 0,
          input: [], inputBytes: 0, lastAgent: 0, resize: { cols, rows }, closing: false, closed: false, agentConnected: false,
          agentWaiter: null, agentTimer: null, viewers: new Set(), backlog: [], backlogSize: 0,
        });
        features.audit.record(ip, 'terminal_aberto', `${server.name} (sessão ${id})`);
        features.agents.wake(server.id);
        return { id };
      });

      // Saída para o navegador (Server-Sent Events). GET não muda nada; a sessão é exigida pelo roteador.
      router.add('GET /api/terminal/:sid/stream', ({ params, req, res }) => {
        const s = get(params.sid);
        if (s.viewers.size >= MAX_VIEWERS) throw new HttpError(429, 'Muitas janelas abertas nesta sessão.');
        res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no', Connection: 'keep-alive' });
        if (s.closed) { res.end('event: closed\ndata: {"reason":"sessão encerrada"}\n\n'); return; }
        // "reset" antes do histórico: numa reconexão o navegador limpa a tela em vez de duplicar o conteúdo.
        res.write(`event: reset\ndata: {}\n\nevent: status\ndata: ${JSON.stringify({ connected: s.agentConnected })}\n\n`);
        for (const chunk of s.backlog) res.write(`event: out\ndata: ${JSON.stringify(chunk)}\n\n`);
        s.viewers.add(res);
        const beat = setInterval(() => res.write(': ping\n\n'), HEARTBEAT_MS);
        req.on('close', () => { clearInterval(beat); s.viewers.delete(res); });
      });

      router.add('POST /api/terminal/:sid/input', ({ params, body: raw }) => {
        const body = raw || {};
        const s = get(params.sid);
        if (s.closed) throw new HttpError(410, 'Sessão encerrada.');
        if (typeof body.data === 'string' && body.data) {
          const chunk = Buffer.from(body.data, 'utf8').toString('base64');
          if (s.inputBytes + chunk.length > INPUT_LIMIT) throw new HttpError(429, 'O servidor não está recebendo a entrada; aguarde.');
          s.input.push(chunk);
          s.inputBytes += chunk.length;
          s.lastInput = now();
        }
        if (body.resize) {
          s.resize = { cols: Math.min(500, Math.max(20, parseInt(body.resize.cols, 10) || 80)), rows: Math.min(200, Math.max(5, parseInt(body.resize.rows, 10) || 24)) };
        }
        flushToAgent(s);
        return { ok: true };
      }, { bodyLimit: 64 * 1024 });

      router.add('DELETE /api/terminal/:sid', ({ params, ip }) => {
        close(get(params.sid), 'fechado pelo usuário', ip);
        return { ok: true };
      });

      // Gravações: listagem e download (só quem está logado no painel).
      router.add('GET /api/terminal/recordings', () => ({
        recordings: fs.readdirSync(dir).filter(f => f.endsWith('.log')).sort().reverse().slice(0, 200)
          .map(f => ({ name: f, size: fs.statSync(path.join(dir, f)).size })),
      }));
      // Baixar uma gravação pede a senha de novo: ela pode conter segredos exibidos na tela.
      router.add('POST /api/terminal/recordings/:name', async ({ params, res, body, ip }) => {
        await features.auth.confirmPassword((body || {}).password, ip);
        const name = String(params.name);
        if (!/^[\w.-]+\.log$/.test(name)) throw new HttpError(400, 'Nome inválido.');
        const f = path.join(dir, name);
        if (!fs.existsSync(f)) throw new HttpError(404, 'Gravação não encontrada.');
        features.audit.record(ip, 'terminal_gravacao_baixada', name);
        send(res, 200, fs.readFileSync(f), { 'Content-Type': 'text/plain; charset=utf-8', 'Content-Disposition': `attachment; filename="${name}"` });
      });

      // Lado do agente: busca a entrada (long-poll) e envia a saída.
      router.add('GET /api/agent/terminal/:sid/in', ({ params, agent, res }) => {
        const s = get(params.sid);
        if (s.serverId !== agent.id) throw new HttpError(404, 'Sessão de outro servidor.');
        s.lastAgent = now();
        if (!s.agentConnected) { s.agentConnected = true; broadcast(s, 'status', { connected: true }); }
        if (s.agentWaiter) send(s.agentWaiter, 200, { data: [], resize: null, close: s.closing });
        s.agentWaiter = res;
        s.agentTimer = setTimeout(() => { if (s.agentWaiter === res) { s.agentWaiter = null; send(res, 200, { data: [], resize: null, close: s.closing }); } }, POLL_MS);
        res.on('close', () => { if (s.agentWaiter === res) s.agentWaiter = null; });
        flushToAgent(s);
      }, { auth: 'agent' });

      router.add('POST /api/agent/terminal/:sid/out', ({ params, agent, body }) => {
        const s = get(params.sid);
        if (s.serverId !== agent.id) throw new HttpError(404, 'Sessão de outro servidor.');
        s.lastAgent = now();
        for (const raw of Array.isArray(body.data) ? body.data : []) {
          const chunk = String(raw);
          const buf = Buffer.from(chunk, 'base64');
          if (buf.length) s.lastInput = now();   // saída também conta como uso (build longo, tail -f)
          if (s.recorded < RECORD_LIMIT) { fs.appendFileSync(s.file, buf); s.recorded += buf.length; }
          s.backlog.push(chunk); s.backlogSize += chunk.length;
          while (s.backlogSize > BACKLOG_BYTES && s.backlog.length > 1) s.backlogSize -= s.backlog.shift().length;
          broadcast(s, 'out', chunk);
        }
        if (body.exit !== undefined) close(s, `shell terminou (código ${parseInt(body.exit, 10)})`);
        return { ok: true, close: s.closing };
      }, { auth: 'agent', bodyLimit: 1024 * 1024 });
    },
    jobs: [{ name: 'terminal-recordings-prune', everyMs: 6 * 3600_000, runAtStart: true, run() {
      const limit = Date.now() - KEEP_RECORDINGS_DAYS * 86400_000;
      for (const f of fs.readdirSync(dir)) if (f.endsWith('.log') && fs.statSync(path.join(dir, f)).mtimeMs < limit) fs.unlinkSync(path.join(dir, f));
    } }, { name: 'terminal-timeouts', everyMs: 30_000, run() {
      const t = now();
      for (const s of sessions.values()) {
        if (s.closed) continue;
        if (!s.agentConnected && t - s.created > CONNECT_SECONDS) close(s, 'o agente não atendeu (está online e no modo admin?)');
        else if (s.agentConnected && t - s.lastAgent > AGENT_LOST_SECONDS) close(s, 'o agente parou de responder');
        else if (t - s.lastInput > IDLE_SECONDS) close(s, '15 minutos sem uso');
        else if (t - s.created > MAX_SECONDS) close(s, 'limite de 4 horas por sessão');
      }
    } }],
  };
}

module.exports = { migrations: [], create };
