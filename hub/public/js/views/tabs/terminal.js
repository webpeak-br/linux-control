// Terminal no navegador (xterm.js). A sessão sobrevive à troca de aba: o terminal fica guardado e volta
// a ser exibido quando a pessoa retorna. Fecha ao clicar em Encerrar, ao sair do shell ou após 15 min sem uso.
import { api } from '../../api.js';
import { esc } from '../../util.js';
import { mode, loadAgentCommands } from '../../actions.js';
import { toast } from '../../ui.js';

export const label = 'Terminal';
// O corpo é sempre o mesmo HTML: a atualização automática nunca recria o terminal.
let active = null;   // { serverId, id, term, fit, es, wrap, status }
let libs = null;

function loadXterm() {
  if (libs) return libs;
  const base = new URL('../../../vendor/xterm/', import.meta.url);
  const css = document.createElement('link');
  css.rel = 'stylesheet'; css.href = new URL('xterm.css', base);
  document.head.appendChild(css);
  const script = src => new Promise((ok, fail) => {
    const s = document.createElement('script');
    s.src = new URL(src, base); s.onload = ok; s.onerror = () => fail(new Error('não consegui carregar o terminal'));
    document.head.appendChild(s);
  });
  libs = script('xterm.js').then(() => script('addon-fit.js'));
  return libs;
}

export function body() {
  return '<div id="term-host"></div>';
}

export async function bind(el, s) {
  const host = el.querySelector('#term-host');
  if (active && active.serverId === s.id) { host.appendChild(active.wrap); active.fit.fit(); active.term.focus(); return; }
  if (active) host.innerHTML = `<div class="panel small muted">Há um terminal aberto em outro servidor. <button class="btn sm" id="term-other">Encerrar aquele</button></div>`;
  const admin = mode(s) === 'admin';
  let cmd = '';
  if (!admin) { try { cmd = (await loadAgentCommands()).set_mode.admin; } catch { cmd = ''; } }
  host.insertAdjacentHTML('beforeend', `<div class="panel narrow"><h3>Terminal de ${esc(s.name)}</h3>
    <p class="small muted">Abre um shell <b>root</b> no servidor. A sessão inteira fica gravada (Configurações → Auditoria) e fecha sozinha após 15 minutos sem uso.</p>
    ${admin ? `<form id="term-open"><label for="term-pw">Confirme a senha do painel</label>
      <input type="password" id="term-pw" autocomplete="current-password"><div class="err" id="term-err"></div>
      <button class="btn primary mt">Abrir terminal</button></form>`
    : `<p>O terminal exige o agente no modo <b>admin</b> (hoje: ${esc(mode(s))}).</p>${cmd ? `<p class="small">No servidor, rode:</p><code class="mono small">${esc(cmd)}</code>` : ''}`}</div>`);
  const other = host.querySelector('#term-other');
  if (other) other.onclick = () => { closeActive(); bind(el, s); };
  const form = host.querySelector('#term-open');
  if (form) form.onsubmit = async e => {
    e.preventDefault();
    const err = host.querySelector('#term-err');
    err.textContent = '';
    try {
      await loadXterm();
      const pw = host.querySelector('#term-pw').value;
      open(s, pw, host);
    } catch (x) { err.textContent = x.message; }
  };
}

async function open(s, password, host) {
  const err = host.querySelector('#term-err');
  const wrap = document.createElement('div');
  wrap.className = 'term-wrap';
  wrap.innerHTML = `<div class="term-bar"><span class="pill" id="term-status">conectando…</span><span class="grow small muted">${esc(s.name)} · root</span>
    <button class="btn sm danger" id="term-close">Encerrar</button></div><div class="term-screen"></div>`;
  const term = new window.Terminal({ cursorBlink: true, fontSize: 13, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
    theme: { background: '#0b0a0e' }, scrollback: 5000, convertEol: false });
  const fit = new window.FitAddon.FitAddon();
  term.loadAddon(fit);
  host.innerHTML = '';
  host.appendChild(wrap);
  term.open(wrap.querySelector('.term-screen'));
  fit.fit();
  let id;
  try {
    id = (await api(`/api/servers/${s.id}/terminal`, { method: 'POST', body: { password, cols: term.cols, rows: term.rows } })).id;
  } catch (x) {
    term.dispose(); host.innerHTML = ''; bindAgain(host, s, x.message);
    return;
  }
  const status = wrap.querySelector('#term-status');
  const setStatus = (txt, cls) => { status.textContent = txt; status.className = `pill ${cls}`; };
  setStatus('aguardando o servidor…', 'warn');
  const es = new EventSource(`/api/terminal/${id}/stream`);
  es.addEventListener('out', e => {
    const bin = atob(JSON.parse(e.data));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    term.write(bytes);
  });
  es.addEventListener('reset', () => term.reset());   // reconexão: o histórico chega de novo
  es.addEventListener('status', e => { if (JSON.parse(e.data).connected) setStatus('conectado', 'ok'); });
  es.addEventListener('closed', e => {
    setStatus('encerrado', '');
    term.write(`\r\n\x1b[33m[sessão encerrada: ${JSON.parse(e.data).reason}]\x1b[0m\r\n`);
    es.close();
    if (active && active.id === id) active.closed = true;
  });

  // Entrada: junta o que for digitado em ~15 ms para não fazer uma requisição por tecla.
  let pending = '', timer = null;
  const flush = () => {
    timer = null;
    const data = pending; pending = '';
    if (data) api(`/api/terminal/${id}/input`, { method: 'POST', body: { data } }).catch(x => toast(x.message));
  };
  term.onData(d => { if (active && active.closed) return; pending += d; if (!timer) timer = setTimeout(flush, 15); });
  const onResize = () => {
    fit.fit();
    api(`/api/terminal/${id}/input`, { method: 'POST', body: { resize: { cols: term.cols, rows: term.rows } } }).catch(() => {});
  };
  let rt = null;
  window.addEventListener('resize', () => { clearTimeout(rt); rt = setTimeout(onResize, 200); });
  wrap.querySelector('#term-close').onclick = () => { closeActive(); bindAgain(host, s); };
  active = { serverId: s.id, id, term, fit, es, wrap, closed: false };
  term.focus();
  if (err) err.textContent = '';
}

function bindAgain(host, s, message) {
  const el = host.parentElement;
  host.remove();
  el.insertAdjacentHTML('beforeend', '<div id="term-host"></div>');
  bind(el, s).then(() => { if (message) { const e = el.querySelector('#term-err'); if (e) e.textContent = message; } });
}

function closeActive() {
  if (!active) return;
  const a = active;
  active = null;
  if (!a.closed) api(`/api/terminal/${a.id}`, { method: 'DELETE' }).catch(() => {});
  a.es.close();
  a.term.dispose();
  a.wrap.remove();
}
