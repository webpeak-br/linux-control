import { esc } from '../../util.js';
import { rowButtons } from '../../actions.js';

export const label = 'Serviços';
export const state = { filter: 'running', search: '' };

const FILTERS = {
  running: ['Rodando', u => u.sub === 'running'],
  failed: ['Com falha', u => u.active === 'failed'],
  stopped: ['Habilitados parados', u => u.enabled === 'enabled' && u.sub !== 'running'],
  all: ['Todos', () => true],
};
const units = s => ((s.inventory || {}).services || {}).units || [];

export function controls() {
  return `<div class="toolbar"><input type="search" id="svcq" placeholder="Filtrar serviços…" value="${esc(state.search)}"></div>`;
}
export function bindControls(el, s, ctx) {
  el.querySelector('#svcq').oninput = e => { state.search = e.target.value; ctx.rerender(); };
}

export function body(s) {
  const sv = (s.inventory || {}).services || {};
  if (!sv.available) return '<div class="empty">systemd não encontrado neste servidor.</div>';
  const q = state.search.toLowerCase();
  const list = units(s).filter(u => FILTERS[state.filter][1](u) && (!q || (u.name + ' ' + u.desc).toLowerCase().includes(q)));
  const st = u => (u.active === 'failed' ? '<span class="pill crit">falhou</span>' : u.sub === 'running' ? '<span class="pill ok">rodando</span>' : `<span class="pill">${esc(u.sub)}</span>`);
  const rows = list.map(u => `<tr><td><b>${esc(u.name.replace(/\.service$/, ''))}</b><div class="dim small">${esc(u.desc)}</div></td><td>${st(u)}</td>
    <td class="small muted">${esc(u.enabled || '—')}</td><td class="acts">${rowButtons(s, 'service', u)}</td></tr>`).join('');
  const seg = Object.entries(FILTERS).map(([k, [l, fn]]) =>
    `<button data-sf="${k}" class="${state.filter === k ? 'on' : ''}">${l} (${units(s).filter(fn).length})</button>`).join('');
  return `<div class="toolbar"><span class="seg">${seg}</span></div>
    <div class="panel"><div class="tbl-wrap"><table><thead><tr><th>Serviço</th><th>Estado</th><th>Na inicialização</th><th></th></tr></thead>
    <tbody>${rows || '<tr><td class="muted" colspan="4">Nada aqui.</td></tr>'}</tbody></table></div></div>`;
}

export function bind(el, s, ctx) {
  el.querySelectorAll('[data-sf]').forEach(b => { b.onclick = () => { state.filter = b.dataset.sf; ctx.rerender(); }; });
}
