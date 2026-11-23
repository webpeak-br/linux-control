// Lista de servidores. Busca e filtro ficam fora da área atualizada, então o foco nunca se perde.
import { api } from '../api.js';
import { esc, N, bar, dur, ago, ipsOf, STATUS_GROUP, datacenter, ipPlace, flag } from '../util.js';
import { addServerModal } from './add-server.js';

const state = { filter: 'all', search: '' };
const REFRESH_MS = 10_000;

export function dashboardView(root) {
  let servers = [];
  root.innerHTML = `<div class="summary" id="sum"></div>
    <div class="toolbar"><h2>Servidores</h2><input type="search" id="q" placeholder="Buscar por nome, IP, tag, sistema…" value="${esc(state.search)}"></div>
    <div id="list"></div><div class="foot-note">Linux Control · código aberto · atualiza a cada ${REFRESH_MS / 1000} s</div>`;
  root.querySelector('#q').oninput = e => { state.search = e.target.value; render(); };

  function render() {
    const count = g => servers.filter(s => STATUS_GROUP[s.health.status] === g).length;
    const stat = (key, n, label, dot) => `<button class="stat ${state.filter === key ? 'active' : ''}" data-f="${key}"><div class="n">${n}</div>
      <div class="l">${dot ? `<span class="dot ${dot}"></span>` : ''}${label}</div></button>`;
    root.querySelector('#sum').innerHTML = stat('all', servers.length, 'Servidores') + stat('ok', count('ok'), 'Saudáveis', 'ok')
      + stat('warn', count('warn'), 'Atenção', 'warn') + stat('crit', count('crit'), 'Críticos', 'crit')
      + stat('offline', count('offline'), 'Offline', 'offline');
    root.querySelectorAll('[data-f]').forEach(b => { b.onclick = () => { state.filter = b.dataset.f; render(); }; });

    const q = state.search.toLowerCase();
    const list = servers.filter(s => (state.filter === 'all' || STATUS_GROUP[s.health.status] === state.filter)
      && (!q || [s.name, s.tags.join(' '), s.system && s.system.hostname, s.system && s.system.os, s.remote_ip, ...ipsOf(s.system)]
        .join(' ').toLowerCase().includes(q)));
    const el = root.querySelector('#list');
    if (!servers.length) {
      el.innerHTML = `<div class="empty"><h3>Nenhum servidor ainda</h3><p>Adicione o primeiro servidor e rode um único comando nele para começar.</p>
        <button class="btn primary" id="add2">+ Adicionar servidor</button></div>`;
      el.querySelector('#add2').onclick = () => addServerModal(load);
    } else {
      el.innerHTML = list.length ? `<div class="grid">${list.map(card).join('')}</div>` : '<div class="empty">Nenhum servidor corresponde ao filtro.</div>';
    }
  }

  async function load() {
    servers = (await api('/api/servers')).servers;
    render();
  }
  const quiet = () => { /* o aviso de "sem conexão" já aparece pelo api() */ };
  load().catch(quiet);
  const timer = setInterval(() => load().catch(quiet), REFRESH_MS);
  return { destroy: () => clearInterval(timer) };
}

function where(s) {
  const dc = datacenter(s), place = ipPlace(s);
  if (!dc && !place) return '';
  return `<div class="srv-where">${s.geo ? flag(s.geo.country) + ' ' : ''}${esc([place, dc].filter(Boolean).join(' — '))}</div>`;
}

function card(s) {
  const h = s.health, m = s.metrics, lv = s.levels || {};
  const sub = s.system ? `${s.system.hostname} · ${s.system.os}` : 'aguardando agente';
  const ip = ipsOf(s.system)[0] || s.remote_ip || '';
  const bars = m ? `<div class="bars">
      <div class="bar-row">CPU ${bar(m.cpu, lv.cpu)}<b>${N(m.cpu).toFixed(0)}%</b></div>
      <div class="bar-row">RAM ${bar(m.mem, lv.mem)}<b>${N(m.mem).toFixed(0)}%</b></div>
      <div class="bar-row" title="${esc(lv.disk_mount)}">Disco ${bar(lv.disk_pct, lv.disk)}<b>${N(lv.disk_pct).toFixed(0)}%</b></div></div>` : '';
  const issues = h.issues.filter(i => i.level !== 'info').slice(0, 2)
    .map(i => `<div class="srv-issue"><span class="dot ${i.level}"></span>${esc(i.text)}</div>`).join('');
  const pills = [];
  if (m) pills.push(`<span class="pill">load ${m.load ? N(m.load[0]).toFixed(2) : '—'}</span>`, `<span class="pill">up ${dur(m.uptime)}</span>`);
  if (s.counts.containers != null) pills.push(`<span class="pill">${N(s.counts.containers)} containers</span>`);
  if (s.counts.security_updates) pills.push(`<span class="pill warn">${N(s.counts.security_updates)} atualiz. segurança</span>`);
  s.tags.forEach(t => pills.push(`<span class="pill brand">${esc(t)}</span>`));
  if (h.status === 'offline') pills.push(`<span class="pill crit">visto ${ago(s.last_seen)}</span>`);
  return `<a class="srv ${h.status}" href="#/server/${Number(s.id)}">
    <div class="srv-head"><span class="dot ${h.status}" title="${esc(h.label)}"></span>
      <div class="grow"><div class="srv-name">${esc(s.name)}</div><div class="srv-sub">${esc(sub)}</div></div>
      <span class="dim small">${esc(ip)}</span></div>${where(s)}${bars}${issues}<div class="srv-foot">${pills.join('')}</div></a>`;
}
