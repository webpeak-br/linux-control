/* Linux Control - interface web (vanilla JS, sem build) */
'use strict';

const $app = document.getElementById('app');
const S = {
  servers: [], filter: 'all', search: '', detail: null, tab: 'overview', range: '1h', history: null,
  commands: [], openCmds: new Set(), svcFilter: 'running', svcSearch: '', pkgSearch: '', pkgView: 'updates',
  timer: null, histTimer: null,
};

// ------------------------------------------------------------ utilidades
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function bytes(n, dec = 1) {
  if (n == null || isNaN(n)) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']; let i = 0; n = Number(n);
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? dec : 0)} ${u[i]}`;
}
const rate = n => (n == null ? '—' : bytes(n) + '/s');
function dur(s) {
  if (s == null) return '—';
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}min` : `${m}min`;
}
function ago(ts) {
  if (!ts) return 'nunca';
  const s = Date.now() / 1000 - ts;
  if (s < 60) return 'agora';
  if (s < 3600) return `há ${Math.floor(s / 60)} min`;
  if (s < 86400) return `há ${Math.floor(s / 3600)} h`;
  return `há ${Math.floor(s / 86400)} d`;
}
const dt = ts => (ts ? new Date(ts * 1000).toLocaleString('pt-BR') : '—');
const N = v => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
const lvl = p => (p >= 90 ? 'crit' : p >= 80 ? 'warn' : '');
const STATUS = { ok: 'Saudável', warn: 'Atenção', crit: 'Crítico', offline: 'Offline', pending: 'Aguardando' };
const LOGO = `<svg viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#5a44cd"/><path d="M13 9h6l1.5 16h-9z" fill="#f1f1f1"/><rect x="12.5" y="6" width="7" height="4" rx="1" fill="#e7f727"/><path d="M19.5 7.5 29 4v8z" fill="#e7f727" opacity=".55"/><rect x="9" y="25" width="14" height="2" rx="1" fill="#f1f1f1"/></svg>`;

async function api(path, opts = {}) {
  const res = await fetch(path, {
    method: opts.method || 'GET',
    headers: { 'Content-Type': 'application/json', 'X-LCtl': '1' },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    credentials: 'same-origin',
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && !path.endsWith('/login')) { stopTimers(); renderLogin(); throw new Error('não autenticado'); }
  if (!res.ok) throw new Error(data.error || `Erro ${res.status}`);
  return data;
}
function toast(msg) {
  const t = document.createElement('div'); t.className = 'toast'; t.textContent = msg;
  document.body.appendChild(t); setTimeout(() => t.remove(), 3200);
}
function stopTimers() { clearInterval(S.timer); clearInterval(S.histTimer); S.timer = S.histTimer = null; }
function keepFocus(fn) {
  const a = document.activeElement; const id = a && a.id; const pos = a && a.selectionStart;
  fn();
  if (id) { const el = document.getElementById(id); if (el) { el.focus(); try { el.setSelectionRange(pos, pos); } catch { /* */ } } }
}
function bar(p) { p = N(p); return `<div class="bar"><i class="${lvl(p)}" style="width:${Math.min(100, p || 0)}%"></i></div>`; }

// ------------------------------------------------------------ login
function renderLogin() {
  stopTimers();
  $app.innerHTML = `<div class="login"><form class="login-box" id="lf">
    <div class="logo">${LOGO} Linux Control</div>
    <h1>Entrar</h1><p>Painel de servidores Linux</p>
    <input type="password" id="pw" placeholder="Senha do administrador" autocomplete="current-password" autofocus>
    <button class="btn primary" type="submit">Entrar</button><div class="err" id="le"></div></form></div>`;
  document.getElementById('lf').onsubmit = async e => {
    e.preventDefault();
    try { await api('/api/login', { method: 'POST', body: { password: document.getElementById('pw').value } }); route(); }
    catch (err) { document.getElementById('le').textContent = err.message; }
  };
}

function shell(inner) {
  return `<header class="top"><a class="logo" href="#/">${LOGO} Linux Control</a><div class="spacer"></div>
    <button class="btn primary" data-act="add">+ Adicionar servidor</button>
    <button class="btn ghost" data-act="logout" title="Sair">Sair</button></header>
    <main class="wrap">${inner}</main>`;
}
function bindShell() {
  $app.querySelector('[data-act=add]').onclick = addServerModal;
  $app.querySelector('[data-act=logout]').onclick = async () => { await api('/api/logout', { method: 'POST' }).catch(() => {}); renderLogin(); };
}

// ------------------------------------------------------------ dashboard
async function loadDashboard() {
  const d = await api('/api/servers');
  S.servers = d.servers;
  keepFocus(renderDashboard);
}
function renderDashboard() {
  const sv = S.servers;
  const count = st => sv.filter(s => s.health.status === st).length;
  const q = S.search.toLowerCase();
  const list = sv.filter(s => (S.filter === 'all' || s.health.status === S.filter || (S.filter === 'offline' && s.health.status === 'pending'))
    && (!q || [s.name, s.tags.join(' '), s.system && s.system.hostname, s.system && s.system.os, s.remote_ip,
      ...(s.system && s.system.ips || []).map(i => i.addr)].join(' ').toLowerCase().includes(q)));
  const stat = (key, n, label, dot) => `<div class="stat ${S.filter === key ? 'active' : ''}" data-f="${key}"><div class="n">${n}</div><div class="l">${dot ? `<span class="dot ${dot}"></span>` : ''}${label}</div></div>`;
  let body;
  if (!sv.length) {
    body = `<div class="empty"><h3>Nenhum servidor ainda</h3><p>Adicione o primeiro servidor e rode um único comando nele para começar a monitorar.</p>
      <button class="btn primary" data-act="add2">+ Adicionar servidor</button></div>`;
  } else if (!list.length) {
    body = `<div class="empty">Nenhum servidor corresponde ao filtro.</div>`;
  } else {
    body = `<div class="grid">${list.map(card).join('')}</div>`;
  }
  $app.innerHTML = shell(`
    <div class="summary">
      ${stat('all', sv.length, 'Servidores')}
      ${stat('ok', count('ok'), 'Saudáveis', 'ok')}
      ${stat('warn', count('warn'), 'Atenção', 'warn')}
      ${stat('crit', count('crit'), 'Críticos', 'crit')}
      ${stat('offline', count('offline') + count('pending'), 'Offline', 'offline')}
    </div>
    <div class="toolbar"><h2>Servidores</h2><input type="search" id="q" placeholder="Buscar por nome, IP, tag, sistema…" value="${esc(S.search)}"></div>
    ${body}<div class="foot-note">Linux Control · código aberto · atualiza a cada 10 s</div>`);
  bindShell();
  const add2 = $app.querySelector('[data-act=add2]'); if (add2) add2.onclick = addServerModal;
  $app.querySelectorAll('.stat').forEach(el => el.onclick = () => { S.filter = el.dataset.f; renderDashboard(); });
  document.getElementById('q').oninput = e => { S.search = e.target.value; keepFocus(renderDashboard); };
}
function card(s) {
  const h = s.health, m = s.metrics;
  const sub = s.system ? `${s.system.hostname} · ${s.system.os}` : 'aguardando agente';
  const ip = (s.system && s.system.ips && s.system.ips[0] && s.system.ips[0].addr.split('/')[0]) || s.remote_ip || '';
  const bars = m ? `<div class="bars">
      <div class="bar-row">CPU ${bar(m.cpu)}<b>${N(m.cpu).toFixed(0)}%</b></div>
      <div class="bar-row">RAM ${bar(m.mem)}<b>${N(m.mem).toFixed(0)}%</b></div>
      <div class="bar-row" title="${esc(m.disk.mount)}">Disco ${bar(m.disk.pct)}<b>${N(m.disk.pct).toFixed(0)}%</b></div></div>` : '';
  const issues = h.issues.filter(i => i.level !== 'info').slice(0, 2)
    .map(i => `<div class="srv-issue"><span class="dot ${i.level}"></span>${esc(i.text)}</div>`).join('');
  const pills = [];
  if (m) pills.push(`<span class="pill">load ${m.load ? N(m.load[0]).toFixed(2) : '—'}</span>`, `<span class="pill">up ${dur(m.uptime)}</span>`);
  if (s.counts.containers != null) pills.push(`<span class="pill">${s.counts.containers} containers</span>`);
  if (s.counts.security_updates) pills.push(`<span class="pill warn">${s.counts.security_updates} atualiz. segurança</span>`);
  s.tags.forEach(t => pills.push(`<span class="pill brand">${esc(t)}</span>`));
  return `<a class="srv ${h.status}" href="#/server/${s.id}">
    <div class="srv-head"><span class="dot ${h.status}" title="${STATUS[h.status]}"></span>
      <div style="min-width:0;flex:1"><div class="srv-name">${esc(s.name)}</div><div class="srv-sub">${esc(sub)}</div></div>
      <span class="dim small">${esc(ip)}</span></div>
    ${bars}${issues}<div class="srv-foot">${pills.join('')}${h.status === 'offline' ? `<span class="pill crit">visto ${ago(s.last_seen)}</span>` : ''}</div></a>`;
}

// ------------------------------------------------------------ adicionar servidor
function modal(html, onMount) {
  const bg = document.createElement('div'); bg.className = 'modal-bg';
  bg.innerHTML = `<div class="modal">${html}</div>`;
  bg.onclick = e => { if (e.target === bg) close(); };
  const close = () => { bg.remove(); document.removeEventListener('keydown', onKey); };
  const onKey = e => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  document.body.appendChild(bg);
  if (onMount) onMount(bg, close);
  return close;
}
function copyBox(text) {
  return `<div class="copybox"><code>${esc(text)}</code><button class="btn sm" data-copy="${esc(text)}">Copiar</button></div>`;
}
function bindCopy(root) {
  root.querySelectorAll('[data-copy]').forEach(b => b.onclick = async () => {
    try { await navigator.clipboard.writeText(b.dataset.copy); b.textContent = 'Copiado'; }
    catch { const r = document.createRange(); r.selectNodeContents(b.previousElementSibling); getSelection().removeAllRanges(); getSelection().addRange(r); b.textContent = 'Selecionado, use Ctrl+C'; }
  });
}
function addServerModal() {
  modal(`<h2>Adicionar servidor</h2><p>Dê um nome. Em seguida você recebe o comando de instalação do agente.</p>
    <form id="af"><label>Nome</label><input type="text" id="an" placeholder="ex.: web-producao-01" required maxlength="80" autofocus>
    <label>Tags (opcional, separadas por vírgula)</label><input type="text" id="at" placeholder="ex.: produção, cliente-x">
    <div class="err" id="ae"></div>
    <div class="foot"><button type="button" class="btn ghost" data-x>Cancelar</button><button class="btn primary">Gerar comando</button></div></form>`,
  (root, close) => {
    root.querySelector('[data-x]').onclick = close;
    root.querySelector('#af').onsubmit = async e => {
      e.preventDefault();
      try {
        const r = await api('/api/servers', { method: 'POST', body: { name: root.querySelector('#an').value, tags: root.querySelector('#at').value } });
        showInstall(root.querySelector('.modal'), r, close);
      } catch (err) { root.querySelector('#ae').textContent = err.message; }
    };
  });
}
function showInstall(box, r, close) {
  box.innerHTML = `<h2>Instale o agente</h2>
    <p>Rode este comando no servidor (como root ou com sudo). Ele instala um agente leve em Python, sem dependências, como serviço systemd.</p>
    ${copyBox(r.install)}
    <p class="small" style="margin-top:12px">O token aparece só agora. Para instalar só com leitura (sem permitir ações), use
    <code>LCTL_ACTIONS=readonly</code> antes do <code>sh</code>: <code>… | sudo LCTL_ACTIONS=readonly sh -s -- TOKEN</code>.
    O servidor precisa alcançar <code>${esc(r.hub_url)}</code>.</p>
    ${/^https:/.test(r.hub_url) ? '' : '<p class="small" style="color:var(--warn)">Atenção: o painel não está em HTTPS. Em produção, coloque-o atrás de HTTPS e defina LCTL_PUBLIC_URL, senão o comando de instalação pode ser interceptado.</p>'}
    <div class="waiting" id="wt"><div class="spin"></div>Aguardando o primeiro contato do agente…</div>
    <div class="foot"><button class="btn" data-x>Fechar</button><a class="btn primary" href="#/server/${r.id}" data-go>Abrir servidor</a></div>`;
  bindCopy(box);
  box.querySelector('[data-x]').onclick = () => { close(); route(); };
  box.querySelector('[data-go]').onclick = () => close();
  const poll = setInterval(async () => {
    if (!document.body.contains(box)) return clearInterval(poll);
    try {
      const d = await api(`/api/servers/${r.id}`);
      if (d.server.last_seen) { clearInterval(poll); const w = box.querySelector('#wt'); if (w) w.innerHTML = '<span class="dot ok"></span> Agente conectado. Tudo certo!'; }
    } catch { /* */ }
  }, 3000);
}

// ------------------------------------------------------------ detalhe do servidor
const TABS = [
  ['overview', 'Visão geral'], ['processes', 'Processos'], ['services', 'Serviços'], ['network', 'Rede'],
  ['docker', 'Docker'], ['software', 'Software'], ['security', 'Segurança'], ['schedules', 'Agendamentos'],
  ['actions', 'Ações'], ['settings', 'Configurações'],
];
async function loadDetail(id) {
  const d = await api(`/api/servers/${id}`);
  S.detail = d.server;
  if (S.tab === 'actions') S.commands = (await api(`/api/servers/${id}/commands`)).commands;
  keepFocus(renderDetail);
}
async function loadHistory(id) {
  S.history = await api(`/api/servers/${id}/history?range=${S.range}`);
  const el = document.getElementById('charts'); if (el) { el.innerHTML = chartsHtml(); bindCharts(); }
}
function renderDetail() {
  const s = S.detail; if (!s) return;
  const inv = s.inventory || {}, sys = inv.system || {}, m = s.metrics || {};
  const failed = ((inv.services || {}).units || []).filter(u => u.active === 'failed').length;
  const cnt = { overview: s.health.issues.filter(i => i.level !== 'info').length, services: failed };
  const tabs = TABS.filter(([k]) => k !== 'docker' || inv.docker).map(([k, l]) => {
    const c = cnt[k] ? `<span class="cnt crit">${cnt[k]}</span>` : '';
    return `<a href="#/server/${s.id}/${k}" class="${S.tab === k ? 'on' : ''}">${l}${c}</a>`;
  }).join('');
  const ip = (sys.ips || []).map(i => i.addr.split('/')[0]).slice(0, 3).join(', ');
  $app.innerHTML = shell(`
    <div class="detail-head"><div style="flex:1;min-width:0">
      <a href="#/" class="small">← Servidores</a>
      <h1><span class="dot ${s.health.status}"></span>${esc(s.name)} <span class="pill ${s.health.status === 'offline' ? 'crit' : s.health.status}">${STATUS[s.health.status]}</span></h1>
      <div class="meta">${sys.os ? `<span>${esc(sys.os)}</span>` : ''}${sys.hostname ? `<span>${esc(sys.hostname)}</span>` : ''}
        ${ip ? `<span>${esc(ip)}</span>` : ''}${s.remote_ip ? `<span>IP de saída ${esc(s.remote_ip)}</span>` : ''}
        <span>atualizado ${ago(s.last_seen)}</span>${m.uptime ? `<span>ligado há ${dur(m.uptime)}</span>` : ''}</div>
    </div></div>
    <nav class="tabs">${tabs}</nav><div id="tab">${tabHtml(s)}</div>`);
  bindShell();
  bindTab(s);
}
function tabHtml(s) {
  if (!s.last_seen && S.tab !== 'settings') {
    return `<div class="empty"><h3>Aguardando o agente</h3><p>Ainda não recebemos dados deste servidor. Gere o comando de instalação em
      <a href="#/server/${s.id}/settings">Configurações</a> se precisar.</p></div>`;
  }
  const f = { overview: tabOverview, processes: tabProcesses, services: tabServices, network: tabNetwork, docker: tabDocker,
    software: tabSoftware, security: tabSecurity, schedules: tabSchedules, actions: tabActions, settings: tabSettings }[S.tab];
  return f ? f(s) : '';
}

// ---- visão geral
function tabOverview(s) {
  const m = s.metrics || {}, inv = s.inventory || {}, sys = inv.system || {};
  const mem = m.mem || {};
  const maxDisk = (m.disks || []).reduce((a, d) => (d.pct > a.pct ? d : a), { pct: 0 });
  const issues = s.health.issues.length
    ? s.health.issues.map(i => `<div class="issue"><span class="dot ${i.level}"></span><span>${esc(i.text)}</span><span class="area">${esc(i.area)}</span></div>`).join('')
    : `<div class="issue"><span class="dot ok"></span>Nenhum problema detectado.</div>`;
  const disks = (m.disks || []).map(d => `<tr><td>${esc(d.mount)}<div class="dim small">${esc(d.fs)} · ${bytes(d.free)} livres · inodes ${N(d.inode_pct)}%</div></td>
    <td style="width:35%">${bar(d.pct)}</td><td class="num">${N(d.pct)}%</td><td class="num">${bytes(d.used)} / ${bytes(d.total)}</td>
    </tr>`).join('');
  return `
    <div class="gauges">
      <div class="gauge"><div class="l">CPU</div><div class="v">${N(m.cpu).toFixed(0)}%</div>${bar(m.cpu)}<div class="s">${N(m.ncpu) || '?'} núcleos · load ${(m.load || []).map(x => N(x).toFixed(2)).join(' ')}</div></div>
      <div class="gauge"><div class="l">Memória</div><div class="v">${N(mem.pct).toFixed(0)}%</div>${bar(mem.pct)}<div class="s">${bytes(mem.used)} de ${bytes(mem.total)}${mem.swap_total ? ` · swap ${N(mem.swap_pct)}%` : ''}</div></div>
      <div class="gauge"><div class="l">Disco mais cheio</div><div class="v">${N(maxDisk.pct).toFixed(0)}%</div>${bar(maxDisk.pct)}<div class="s">${esc(maxDisk.mount || '—')} · ${bytes(maxDisk.free)} livres</div></div>
      <div class="gauge"><div class="l">Rede</div><div class="v small" style="font-size:16px;margin-bottom:6px">↓ ${rate(m.net && m.net.rx_bps)}<br>↑ ${rate(m.net && m.net.tx_bps)}</div><div class="s">${N((m.procs || {}).count)} processos</div></div>
    </div>
    <div class="panel"><h3>Diagnóstico</h3><div class="issues">${issues}</div></div>
    <div class="panel"><h3>Histórico <span class="r"><span class="seg" id="range">${['1h', '6h', '24h', '7d'].map(r => `<button data-r="${r}" class="${S.range === r ? 'on' : ''}">${r}</button>`).join('')}</span></span></h3>
      <div id="charts">${chartsHtml()}</div></div>
    <div class="cols">
      <div class="panel"><h3>Sistema</h3><dl class="kv">
        <dt>Hostname</dt><dd>${esc(sys.hostname)}</dd><dt>Sistema</dt><dd>${esc(sys.os)}</dd>
        <dt>Kernel</dt><dd>${esc(sys.kernel)} (${esc(sys.arch)})</dd><dt>CPU</dt><dd>${esc(sys.cpu_model)} · ${esc(sys.cores)} núcleos</dd>
        <dt>Memória</dt><dd>${bytes(mem.total)}</dd><dt>Virtualização</dt><dd>${esc(sys.virt)}</dd>
        <dt>Fuso horário</dt><dd>${esc(sys.timezone)} ${sys.ntp_synced === true ? '<span class="pill ok">NTP ok</span>' : sys.ntp_synced === false ? '<span class="pill warn">NTP fora</span>' : ''}</dd>
        <dt>Ligado desde</dt><dd>${dt(sys.boot_time)}</dd>
        <dt>IPs</dt><dd>${(sys.ips || []).map(i => `${esc(i.addr)} <span class="dim">(${esc(i.iface)})</span>`).join('<br>') || '—'}</dd>
        <dt>Agente</dt><dd>v${esc(s.agent_version)} · Python ${esc(sys.python)} · ${sys.is_root ? 'root' : '<span class="pill warn">sem root</span>'} · ações: ${esc(inv.actions_mode)}</dd>
        <dt>Inventário</dt><dd>${ago(s.inventory_at)}</dd></dl></div>
      <div class="panel"><h3>Discos</h3><div class="tbl-wrap"><table><tbody>${disks || '<tr><td class="muted">Sem dados</td></tr>'}</tbody></table></div></div>
    </div>`;
}
function chartsHtml() {
  const h = S.history;
  if (!h) return '<div class="muted small">Carregando…</div>';
  if (!h.points.length) return '<div class="muted small">Sem histórico ainda.</div>';
  return `<div class="charts">
    <div>${chartSvg('cpu', h.points, [{ k: 'cpu', c: '#b5bafe', n: 'CPU' }], 100, '%')}</div>
    <div>${chartSvg('mem', h.points, [{ k: 'mem', c: '#e7f727', n: 'Memória' }, { k: 'swap', c: '#f5b041', n: 'Swap' }], 100, '%')}</div>
    <div>${chartSvg('disk', h.points, [{ k: 'disk', c: '#3ecf8e', n: 'Disco mais cheio' }], 100, '%')}</div>
    <div>${chartSvg('net', h.points, [{ k: 'rx', c: '#7aa7ff', n: 'Download' }, { k: 'tx', c: '#ff8fb1', n: 'Upload' }], null, 'B/s')}</div></div>`;
}
function chartSvg(id, pts, series, fixedMax, unit) {
  const W = 600, H = 190, L = 38, R = 6, T = 8, B = 20;
  const t0 = pts[0].t, t1 = pts[pts.length - 1].t || t0 + 1;
  let max = fixedMax || Math.max(1, ...pts.flatMap(p => series.map(s => p[s.k] || 0))) * 1.15;
  const x = t => L + (W - L - R) * ((t - t0) / Math.max(1, t1 - t0));
  const y = v => T + (H - T - B) * (1 - Math.min(1, (v || 0) / max));
  const fmt = v => (unit === 'B/s' ? bytes(v, 0) : `${Math.round(v)}${unit}`);
  let g = '';
  for (let i = 0; i <= 4; i++) {
    const v = max * i / 4, yy = y(v);
    g += `<line class="grid-l" x1="${L}" x2="${W - R}" y1="${yy}" y2="${yy}"/><text class="axis" x="${L - 4}" y="${yy + 3}" text-anchor="end">${fmt(v)}</text>`;
  }
  const tf = t => new Date(t * 1000).toLocaleString('pt-BR', S.range === '7d' ? { day: '2-digit', month: '2-digit' } : { hour: '2-digit', minute: '2-digit' });
  g += `<text class="axis" x="${L}" y="${H - 4}">${tf(t0)}</text><text class="axis" x="${W - R}" y="${H - 4}" text-anchor="end">${tf(t1)}</text>`;
  const paths = series.map((s, i) => {
    const line = pts.map((p, j) => `${j ? 'L' : 'M'}${x(p.t).toFixed(1)},${y(p[s.k]).toFixed(1)}`).join('');
    const area = i === 0 ? `<path d="${line}L${x(t1)},${H - B}L${L},${H - B}Z" fill="${s.c}" opacity=".08"/>` : '';
    return `${area}<path d="${line}" fill="none" stroke="${s.c}" stroke-width="1.6" stroke-linejoin="round"/>`;
  }).join('');
  const legend = series.map(s => `<span><i style="background:${s.c}"></i>${s.n}</span>`).join('');
  return `<div class="legend" style="margin-bottom:4px">${legend}</div><div class="chart-wrap" data-chart="${id}">
    <svg class="chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet">${g}${paths}<line class="hover-l" x1="0" x2="0" y1="${T}" y2="${H - B}" style="display:none"/></svg>
    <div class="tip"></div></div>`;
}
const CHART_SERIES = { cpu: [['cpu', 'CPU', '%']], mem: [['mem', 'Memória', '%'], ['swap', 'Swap', '%']], disk: [['disk', 'Disco', '%']], net: [['rx', '↓', 'B/s'], ['tx', '↑', 'B/s']] };
function bindCharts() {
  document.querySelectorAll('[data-chart]').forEach(wrap => {
    const svg = wrap.querySelector('svg'), tip = wrap.querySelector('.tip'), hl = svg.querySelector('.hover-l');
    const pts = S.history.points; const ser = CHART_SERIES[wrap.dataset.chart];
    svg.onmousemove = e => {
      const r = svg.getBoundingClientRect(); const fx = (e.clientX - r.left) / r.width;
      const L = 38 / 600, R = 6 / 600; const rel = Math.min(1, Math.max(0, (fx - L) / (1 - L - R)));
      const p = pts[Math.round(rel * (pts.length - 1))]; if (!p) return;
      const xx = 38 + (600 - 44) * ((p.t - pts[0].t) / Math.max(1, pts[pts.length - 1].t - pts[0].t));
      hl.setAttribute('x1', xx); hl.setAttribute('x2', xx); hl.style.display = '';
      tip.style.display = 'block';
      tip.innerHTML = `${new Date(p.t * 1000).toLocaleString('pt-BR')}<br>` + ser.map(([k, n, u]) => `${n} <b>${u === 'B/s' ? rate(p[k]) : N(p[k]).toFixed(1) + u}</b>`).join(' · ');
      const left = Math.min(r.width - tip.offsetWidth - 4, Math.max(0, e.clientX - r.left + 12));
      tip.style.left = left + 'px';
    };
    svg.onmouseleave = () => { tip.style.display = 'none'; hl.style.display = 'none'; };
  });
}

// ---- processos
function tabProcesses(s) {
  const p = (s.metrics || {}).procs || { top: [] };
  const rows = [...p.top].sort((a, b) => b.cpu - a.cpu || b.rss - a.rss).map(x => `<tr><td class="num">${N(x.pid)}</td><td>${esc(x.user)}</td>
    <td>${esc(x.name)}</td><td class="num">${N(x.cpu).toFixed(1)}%</td><td class="num">${N(x.mem).toFixed(1)}%</td><td class="num">${bytes(x.rss)}</td>
    <td class="cmd" title="${esc(x.cmd)}">${esc(x.cmd)}</td></tr>`).join('');
  return `<div class="panel"><h3>Processos que mais consomem <span class="r dim small">${N(p.count)} processos no total${p.zombies ? ` · ${N(p.zombies)} zumbis` : ''} · CPU em % da máquina</span></h3>
    <div class="tbl-wrap"><table><thead><tr><th class="num">PID</th><th>Usuário</th><th>Nome</th><th class="num">CPU</th><th class="num">Mem</th><th class="num">RSS</th><th>Comando</th></tr></thead>
    <tbody>${rows}</tbody></table></div></div>`;
}

// ---- serviços
function canAct(s, id) { return ((s.inventory || {}).actions || []).some(a => a.id === id); }
function tabServices(s) {
  const sv = (s.inventory || {}).services || { units: [] };
  if (!sv.available) return `<div class="empty">systemd não encontrado neste servidor.</div>`;
  const q = S.svcSearch.toLowerCase();
  const all = sv.units;
  const list = all.filter(u => (S.svcFilter === 'all' || (S.svcFilter === 'running' && u.sub === 'running') || (S.svcFilter === 'failed' && u.active === 'failed')
    || (S.svcFilter === 'enabled' && u.enabled === 'enabled' && u.sub !== 'running')) && (!q || (u.name + ' ' + u.desc).toLowerCase().includes(q)));
  const st = u => u.active === 'failed' ? '<span class="pill crit">falhou</span>' : u.sub === 'running' ? '<span class="pill ok">rodando</span>' : `<span class="pill">${esc(u.sub)}</span>`;
  const btn = (id, u, label, cls = '') => canAct(s, id) ? `<button class="btn sm ${cls}" data-run="${id}" data-param="${esc(u.name)}">${label}</button>` : '';
  const rows = list.map(u => `<tr><td><b>${esc(u.name.replace(/\.service$/, ''))}</b><div class="dim small">${esc(u.desc)}</div></td><td>${st(u)}</td>
    <td class="small muted">${esc(u.enabled || '—')}</td><td class="acts">${btn('service.logs', u, 'Logs')} ${btn('service.status', u, 'Status')}
    ${u.sub === 'running' ? btn('service.restart', u, 'Reiniciar') : btn('service.start', u, 'Iniciar')}</td></tr>`).join('');
  const f = (k, l, n) => `<button data-sf="${k}" class="${S.svcFilter === k ? 'on' : ''}">${l} (${n})</button>`;
  return `<div class="toolbar"><span class="seg">${f('running', 'Rodando', all.filter(u => u.sub === 'running').length)}${f('failed', 'Com falha', all.filter(u => u.active === 'failed').length)}
    ${f('enabled', 'Habilitados parados', all.filter(u => u.enabled === 'enabled' && u.sub !== 'running').length)}${f('all', 'Todos', all.length)}</span>
    <input type="search" id="svcq" placeholder="Filtrar serviços…" value="${esc(S.svcSearch)}"></div>
    <div class="panel"><div class="tbl-wrap"><table><thead><tr><th>Serviço</th><th>Estado</th><th>Na inicialização</th><th></th></tr></thead>
    <tbody>${rows || '<tr><td class="muted" colspan="4">Nada aqui.</td></tr>'}</tbody></table></div></div>`;
}

// ---- rede
function tabNetwork(s) {
  const inv = s.inventory || {}, m = s.metrics || {};
  const pub = p => /^(0\.0\.0\.0|\*|\[::\]|::)$/.test(p.addr);
  const rows = (inv.ports || []).map(p => `<tr><td class="num"><b>${esc(p.port)}</b></td><td>${esc(p.proto)}</td>
    <td class="mono">${esc(p.addr)}</td><td>${pub(p) ? '<span class="pill warn">todas as interfaces</span>' : /^(127\.|\[::1\]|::1)/.test(p.addr) ? '<span class="pill ok">só local</span>' : '<span class="pill">interface específica</span>'}</td>
    <td>${esc(p.process) || '<span class="dim">—</span>'}${p.pid ? ` <span class="dim">(pid ${N(p.pid)})</span>` : ''}</td></tr>`).join('');
  const sites = (inv.websites || []).map(w => `<tr><td>${w.domains.map(esc).join('<br>') || '<span class="dim">(padrão)</span>'}</td><td>${esc(w.server)}</td>
    <td class="small">${esc(w.listen.join(', '))}</td><td class="small mono">${esc([...w.root, ...w.proxy].join('\n')).replace(/\n/g, '<br>')}</td><td class="small dim mono">${esc(w.file)}</td></tr>`).join('');
  return `<div class="gauges"><div class="gauge"><div class="l">Download agora</div><div class="v">${rate(m.net && m.net.rx_bps)}</div><div class="s">total ${bytes(m.net && m.net.rx_total)} desde o boot</div></div>
    <div class="gauge"><div class="l">Upload agora</div><div class="v">${rate(m.net && m.net.tx_bps)}</div><div class="s">total ${bytes(m.net && m.net.tx_total)} desde o boot</div></div></div>
    <div class="panel"><h3>Portas abertas <span class="r dim small">${(inv.ports || []).length} sockets escutando</span></h3>
      <div class="tbl-wrap"><table><thead><tr><th class="num">Porta</th><th>Protocolo</th><th>Endereço</th><th>Exposição</th><th>Processo</th></tr></thead><tbody>${rows}</tbody></table></div></div>
    ${sites ? `<div class="panel"><h3>Sites configurados (Nginx/Apache)</h3><div class="tbl-wrap"><table><thead><tr><th>Domínios</th><th>Servidor</th><th>Escuta</th><th>Destino</th><th>Arquivo</th></tr></thead><tbody>${sites}</tbody></table></div></div>` : ''}`;
}

// ---- docker
function tabDocker(s) {
  const d = (s.inventory || {}).docker;
  if (!d) return `<div class="empty">Docker não está instalado.</div>`;
  if (d.error) return `<div class="empty">${esc(d.error)}</div>`;
  const rows = d.containers.map(c => `<tr><td><b>${esc(c.name)}</b><div class="dim small mono">${esc(c.id)}</div></td><td class="small">${esc(c.image)}</td>
    <td>${c.state === 'running' ? '<span class="pill ok">rodando</span>' : `<span class="pill ${c.state === 'exited' ? '' : 'warn'}">${esc(c.state)}</span>`}<div class="dim small">${esc(c.status)}</div></td>
    <td class="num small">${c.stats ? `${esc(c.stats.cpu)}<br>${esc(c.stats.mem)}` : '—'}</td><td class="small mono">${esc(c.ports)}</td>
    <td class="acts">${canAct(s, 'docker.logs') ? `<button class="btn sm" data-run="docker.logs" data-param="${esc(c.name)}">Logs</button>` : ''}
      ${canAct(s, 'docker.restart') ? `<button class="btn sm" data-run="docker.restart" data-param="${esc(c.name)}">Reiniciar</button>` : ''}</td></tr>`).join('');
  return `<div class="panel"><h3>Containers <span class="r dim small">${d.containers.filter(c => c.state === 'running').length} rodando de ${d.containers.length}</span></h3>
    <div class="tbl-wrap"><table><thead><tr><th>Nome</th><th>Imagem</th><th>Estado</th><th class="num">CPU / Mem</th><th>Portas</th><th></th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}

// ---- software
function tabSoftware(s) {
  const inv = s.inventory || {}, pk = s.packages;
  const sw = (inv.software || []).map(x => `<tr><td><b>${esc(x.name)}</b></td><td class="small">${esc(x.version) || '<span class="dim">—</span>'}</td><td class="mono small muted">${esc(x.path)}</td></tr>`).join('');
  let pkHtml = '<div class="muted">Lista de pacotes ainda não coletada.</div>';
  if (pk) {
    const q = S.pkgSearch.toLowerCase();
    let rows;
    if (S.pkgView === 'updates') {
      rows = pk.updates.filter(u => !q || u.name.toLowerCase().includes(q)).slice(0, 500)
        .map(u => `<tr><td>${esc(u.name)}</td><td class="small muted">${esc(u.current)}</td><td class="small">${esc(u.new)}</td><td>${u.security ? '<span class="pill warn">segurança</span>' : ''}</td></tr>`).join('');
      rows = `<thead><tr><th>Pacote</th><th>Atual</th><th>Nova</th><th></th></tr></thead><tbody>${rows || '<tr><td class="muted" colspan="4">Tudo atualizado.</td></tr>'}</tbody>`;
    } else {
      const list = pk.installed.filter(([n]) => !q || n.toLowerCase().includes(q));
      rows = `<thead><tr><th>Pacote</th><th>Versão</th></tr></thead><tbody>${list.slice(0, 400).map(([n, v]) => `<tr><td>${esc(n)}</td><td class="small muted">${esc(v)}</td></tr>`).join('')}
        ${list.length > 400 ? `<tr><td class="dim" colspan="2">… e mais ${list.length - 400}. Refine a busca.</td></tr>` : ''}</tbody>`;
    }
    pkHtml = `<div class="toolbar"><span class="seg"><button data-pv="updates" class="${S.pkgView === 'updates' ? 'on' : ''}">Atualizações (${pk.updates.length})</button>
      <button data-pv="installed" class="${S.pkgView === 'installed' ? 'on' : ''}">Instalados (${pk.installed.length})</button></span>
      <input type="search" id="pkq" placeholder="Buscar pacote…" value="${esc(S.pkgSearch)}"><span class="dim small">${esc(pk.manager)} · coletado ${ago(pk.collected_at)}</span></div>
      <div class="tbl-wrap" style="max-height:520px"><table>${rows}</table></div>`;
  }
  return `<div class="panel"><h3>Software detectado</h3><div class="tbl-wrap"><table><thead><tr><th>Software</th><th>Versão</th><th>Onde está</th></tr></thead>
    <tbody>${sw || '<tr><td class="muted">Nada conhecido detectado.</td></tr>'}</tbody></table></div></div>
    <div class="panel"><h3>Pacotes</h3>${pkHtml}</div>`;
}

// ---- segurança
function tabSecurity(s) {
  const inv = s.inventory || {}, sec = inv.security || {}, ssh = sec.ssh || {}, fw = sec.firewall || {}, us = inv.users || {};
  const yes = (v, good) => v === undefined ? '<span class="dim">—</span>' : `<span class="pill ${v === good ? 'ok' : 'warn'}">${esc(v)}</span>`;
  const att = (sec.top_attackers || []).map(([ip, n]) => `<tr><td class="mono">${esc(ip)}</td><td class="num">${N(n)}</td></tr>`).join('');
  const users = (us.accounts || []).map(u => `<tr><td><b>${esc(u.name)}</b></td><td class="num">${N(u.uid)}</td><td>${u.sudo ? '<span class="pill warn">admin</span>' : ''}</td>
    <td class="num">${N(u.ssh_keys)}</td><td class="small mono muted">${esc(u.home)}</td><td class="small mono muted">${esc(u.shell)}</td></tr>`).join('');
  const certs = (inv.certificates || []).map(c => `<tr><td>${esc(c.name)}</td><td>${dt(c.expires)}</td>
    <td><span class="pill ${c.days_left < 0 ? 'crit' : c.days_left < 14 ? 'warn' : 'ok'}">${c.days_left < 0 ? 'expirado' : N(c.days_left) + ' dias'}</span></td></tr>`).join('');
  return `<div class="cols">
    <div class="panel"><h3>SSH</h3><dl class="kv"><dt>Porta</dt><dd>${esc(ssh.port || '—')}</dd>
      <dt>Login de root</dt><dd>${yes(ssh.permitrootlogin, 'no')}</dd><dt>Login por senha</dt><dd>${yes(ssh.passwordauthentication, 'no')}</dd>
      <dt>Login por chave</dt><dd>${yes(ssh.pubkeyauthentication, 'yes')}</dd>
      <dt>Falhas em 24h</dt><dd><b>${sec.failed_logins_24h == null ? '—' : N(sec.failed_logins_24h)}</b> tentativas</dd></dl>
      ${att ? `<h3 style="margin-top:16px">IPs que mais tentaram</h3><table><tbody>${att}</tbody></table>` : ''}</div>
    <div class="panel"><h3>Firewall e proteção</h3><dl class="kv">
      <dt>Firewall</dt><dd>${fw.active ? `<span class="pill ok">ativo</span> ${esc(fw.type)}` : '<span class="pill warn">não detectado</span>'}</dd>
      <dt>Atualizações automáticas</dt><dd>${sec.auto_updates === undefined ? '—' : sec.auto_updates ? '<span class="pill ok">ativas</span>' : '<span class="pill warn">desativadas</span>'}</dd>
      <dt>Reinício pendente</dt><dd>${sec.reboot_required ? `<span class="pill warn">sim</span> <span class="small muted">${esc((sec.reboot_pkgs || []).join(', '))}</span>` : 'não'}</dd>
      <dt>Fail2ban</dt><dd>${sec.fail2ban ? `<pre class="raw">${esc(sec.fail2ban)}</pre>` : '<span class="dim">não instalado</span>'}</dd></dl>
      ${fw.summary ? `<pre class="raw" style="margin-top:12px">${esc(fw.summary)}</pre>` : ''}</div></div>
    <div class="panel" style="margin-top:16px"><h3>Contas com acesso ao shell</h3><div class="tbl-wrap"><table><thead><tr><th>Usuário</th><th class="num">UID</th><th>Privilégio</th><th class="num">Chaves SSH</th><th>Home</th><th>Shell</th></tr></thead><tbody>${users}</tbody></table></div></div>
    ${certs ? `<div class="panel"><h3>Certificados SSL (Let's Encrypt)</h3><table><thead><tr><th>Domínio</th><th>Expira em</th><th></th></tr></thead><tbody>${certs}</tbody></table></div>` : ''}
    ${us.last_logins ? `<div class="panel"><h3>Últimos acessos</h3><pre class="raw">${esc(us.last_logins)}</pre></div>` : ''}`;
}

// ---- agendamentos
function tabSchedules(s) {
  const c = (s.inventory || {}).cron || {};
  const rows = (c.cron || []).map(j => `<tr><td class="mono small">${esc(j.line)}</td><td class="mono small dim">${esc(j.file)}</td></tr>`).join('');
  return `<div class="panel"><h3>Tarefas cron</h3><div class="tbl-wrap"><table><thead><tr><th>Linha</th><th>Arquivo</th></tr></thead>
    <tbody>${rows || '<tr><td class="muted">Nenhuma tarefa cron.</td></tr>'}</tbody></table></div></div>
    <div class="panel"><h3>Timers do systemd</h3><pre class="raw">${esc(c.timers || 'Sem dados.')}</pre></div>`;
}

// ---- ações
function tabActions(s) {
  const acts = (s.inventory || {}).actions || [];
  const groups = {};
  acts.forEach(a => { (groups[a.group] = groups[a.group] || []).push(a); });
  const g = Object.entries(groups).map(([name, list]) => `<div class="panel"><h3>${esc(name)}</h3>${list.map(a => `<div class="act"><div>
    <div class="t">${esc(a.label)} ${a.danger ? '<span class="pill crit">cuidado</span>' : a.mut ? '<span class="pill">altera o servidor</span>' : ''}</div>
    <div class="d">${esc(a.desc)}</div></div><button class="btn sm ${a.danger ? 'danger' : ''}" data-run="${esc(a.id)}">Executar</button></div>`).join('')}</div>`).join('');
  const cmds = S.commands.map(c => {
    const st = { queued: ['', 'na fila'], sent: ['info', 'executando'], done: ['ok', 'concluído'], failed: ['crit', `falhou (${N(c.exit_code)})`], lost: ['warn', 'sem resposta'], expired: ['', 'expirou na fila'], canceled: ['', 'cancelado'] }[c.status] || ['', c.status];
    const open = S.openCmds.has(c.id);
    return `<div class="cmd-item"><div class="cmd-row" data-cmd="${c.id}"><span class="pill ${st[0]}">${st[1]}</span><b>${esc(c.label || c.action)}</b>
      ${c.param ? `<span class="mono small muted">${esc(c.param)}</span>` : ''}${c.duration != null ? `<span class="dim small">${N(c.duration)}s</span>` : ''}
      ${c.status === 'queued' ? `<button class="btn sm ghost" data-cancel="${c.id}">Cancelar</button>` : ''}<span class="when">${dt(c.created)}</span></div>
      ${open && c.output != null ? `<pre class="out">${esc(c.output || '(sem saída)')}</pre>` : ''}</div>`;
  }).join('');
  const mode = (s.inventory || {}).actions_mode;
  return `${mode && mode !== 'all' ? `<div class="panel small muted">Este agente está no modo <b>${esc(mode)}</b>: só ações de leitura ficam disponíveis. Altere <code>ACTIONS=all</code> em <code>/etc/linux-control/agent.conf</code> para liberar as demais.</div>` : ''}
    <div class="act-groups">${g || '<div class="empty">Nenhuma ação disponível.</div>'}</div>
    <div class="panel"><h3>Histórico de execuções <span class="r dim small">clique para ver a saída</span></h3>${cmds || '<div class="muted">Nenhuma ação executada ainda.</div>'}</div>`;
}

// ---- configurações
function tabSettings(s) {
  return `<div class="cols"><div class="panel"><h3>Identificação</h3><form id="sf"><label class="small muted">Nome</label>
    <input type="text" id="sn" value="${esc(s.name)}" style="width:100%;margin:4px 0 12px" maxlength="80">
    <label class="small muted">Tags (separadas por vírgula)</label><input type="text" id="st" value="${esc(s.tags.join(', '))}" style="width:100%;margin:4px 0 12px">
    <button class="btn primary">Salvar</button></form></div>
    <div class="panel"><h3>Agente</h3><p class="muted small">Gere um novo token para (re)instalar o agente. O token anterior deixa de funcionar na hora.</p>
      <button class="btn" id="rt">Gerar novo comando de instalação</button><div id="rtout" style="margin-top:12px"></div>
      <p class="muted small" style="margin-top:16px">Para desinstalar, rode no servidor:</p>${copyBox(`curl -fsSL ${location.origin}/install.sh | sudo sh -s -- --uninstall`)}</div></div>
    <div class="panel" style="margin-top:16px"><h3>Remover servidor</h3><p class="muted small">Remove o servidor, o histórico e as execuções do painel. O agente instalado passa a ser recusado.</p>
      <button class="btn danger" id="rm">Remover do painel</button></div>`;
}

// ------------------------------------------------------------ eventos das abas
function bindTab(s) {
  const tab = document.getElementById('tab');
  bindCopy(tab);
  const rg = document.getElementById('range');
  if (rg) rg.querySelectorAll('button').forEach(b => b.onclick = () => { S.range = b.dataset.r; rg.querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b)); loadHistory(s.id); });
  if (S.tab === 'overview' && S.history) bindCharts();
  tab.querySelectorAll('[data-sf]').forEach(b => b.onclick = () => { S.svcFilter = b.dataset.sf; renderDetail(); });
  tab.querySelectorAll('[data-pv]').forEach(b => b.onclick = () => { S.pkgView = b.dataset.pv; renderDetail(); });
  const svcq = document.getElementById('svcq'); if (svcq) svcq.oninput = e => { S.svcSearch = e.target.value; keepFocus(renderDetail); };
  const pkq = document.getElementById('pkq'); if (pkq) pkq.oninput = e => { S.pkgSearch = e.target.value; keepFocus(renderDetail); };
  tab.querySelectorAll('[data-run]').forEach(b => b.onclick = () => runAction(s, b.dataset.run, b.dataset.param));
  tab.querySelectorAll('[data-cmd]').forEach(r => r.onclick = e => {
    if (e.target.closest('[data-cancel]')) return;
    const id = Number(r.dataset.cmd); S.openCmds.has(id) ? S.openCmds.delete(id) : S.openCmds.add(id); renderDetail();
  });
  tab.querySelectorAll('[data-cancel]').forEach(b => b.onclick = async () => { await api(`/api/commands/${b.dataset.cancel}`, { method: 'DELETE' }); loadDetail(s.id); });
  const sf = document.getElementById('sf');
  if (sf) sf.onsubmit = async e => { e.preventDefault(); await api(`/api/servers/${s.id}`, { method: 'PATCH', body: { name: document.getElementById('sn').value, tags: document.getElementById('st').value } }); toast('Salvo.'); loadDetail(s.id); };
  const rt = document.getElementById('rt');
  if (rt) rt.onclick = async () => {
    if (!confirm('Gerar um novo token? O agente atual vai parar de enviar dados até ser reinstalado.')) return;
    const r = await api(`/api/servers/${s.id}/token`, { method: 'POST' });
    document.getElementById('rtout').innerHTML = copyBox(r.install); bindCopy(document.getElementById('rtout'));
  };
  const rm = document.getElementById('rm');
  if (rm) rm.onclick = async () => {
    if (prompt(`Para remover, digite o nome do servidor: ${s.name}`) !== s.name) return;
    await api(`/api/servers/${s.id}`, { method: 'DELETE' }); location.hash = '#/';
  };
}

function runAction(s, id, param) {
  const a = ((s.inventory || {}).actions || []).find(x => x.id === id);
  if (!a) return;
  const services = ((s.inventory || {}).services || { units: [] }).units.map(u => u.name);
  const containers = (((s.inventory || {}).docker || {}).containers || []).map(c => c.name);
  const opts = a.param === 'service' ? services : containers;
  const paramField = a.param ? `<label>${a.param === 'service' ? 'Serviço' : 'Container'}</label>
    <input type="text" id="ap" list="apl" value="${esc(param || '')}" autocomplete="off" required><datalist id="apl">${opts.map(o => `<option value="${esc(o)}">`).join('')}</datalist>` : '';
  const confirmField = a.danger ? `<label>Digite <b>${esc(s.name)}</b> para confirmar</label><input type="text" id="ac" autocomplete="off" required>` : '';
  const needModal = a.param && !param || a.mut || a.danger;
  const exec = async (p, c) => {
    try {
      await api(`/api/servers/${s.id}/commands`, { method: 'POST', body: { action: id, param: p, confirm: c } });
      toast('Ação enviada. O resultado aparece em instantes.');
      location.hash = `#/server/${s.id}/actions`;
      S.tab = 'actions';
      const d = await api(`/api/servers/${s.id}/commands`); S.commands = d.commands;
      if (d.commands[0]) S.openCmds.add(d.commands[0].id);
      renderDetail();
    } catch (err) { toast(err.message); }
  };
  if (!needModal) return exec(param, undefined);
  modal(`<h2>${esc(a.label)}</h2><p>${esc(a.desc)}${a.mut ? ' Esta ação altera o servidor.' : ''}</p>
    <form id="axf">${paramField}${confirmField}<div class="foot"><button type="button" class="btn ghost" data-x>Cancelar</button>
    <button class="btn ${a.danger ? 'danger' : 'primary'}">Executar em ${esc(s.name)}</button></div></form>`, (root, close) => {
    root.querySelector('[data-x]').onclick = close;
    const first = root.querySelector('input'); if (first) first.focus();
    root.querySelector('#axf').onsubmit = e => {
      e.preventDefault();
      const p = a.param ? root.querySelector('#ap').value.trim() : undefined;
      const c = a.danger ? root.querySelector('#ac').value : undefined;
      close(); exec(p, c);
    };
  });
}

// ------------------------------------------------------------ roteamento
async function route() {
  stopTimers();
  const me = await api('/api/me').catch(() => ({}));
  if (!me.authenticated) return renderLogin();
  const parts = location.hash.replace(/^#\/?/, '').split('/');
  if (parts[0] === 'server' && parts[1]) {
    const id = parts[1];
    const changed = !S.detail || String(S.detail.id) !== id;
    S.tab = parts[2] || 'overview';
    if (changed) { S.detail = null; S.history = null; S.commands = []; S.openCmds.clear(); }
    $app.innerHTML = shell('<div class="muted">Carregando…</div>'); bindShell();
    try { await loadDetail(id); } catch (e) { $app.innerHTML = shell(`<div class="empty">${esc(e.message)} <a href="#/">Voltar</a></div>`); bindShell(); return; }
    if (S.tab === 'overview') loadHistory(id);
    S.timer = setInterval(() => loadDetail(id).catch(() => {}), S.tab === 'actions' ? 3000 : 10000);
    S.histTimer = setInterval(() => { if (S.tab === 'overview') loadHistory(id).catch(() => {}); }, 30000);
  } else {
    S.detail = null;
    await loadDashboard();
    S.timer = setInterval(() => loadDashboard().catch(() => {}), 10000);
  }
}
window.addEventListener('hashchange', route);
route();
