import { esc, ago } from '../../util.js';
import { rowButtons, adminHint } from '../../actions.js';

export const label = 'Software';
export const state = { view: 'updates', search: '' };

export function body(s) {
  const inv = s.inventory || {};
  const apps = (inv.apps || []).filter(a => a.available);
  const installers = apps.map(a => `<div class="app-card"><div><b>${esc(a.label)}</b> ${a.installed ? '<span class="pill ok">instalado</span>' : ''}
    <div class="small muted">${esc(a.desc)}</div></div><div class="acts">${rowButtons(s, 'app', a)}</div></div>`).join('');
  const sw = (inv.software || []).map(x => `<tr><td><b>${esc(x.name)}</b></td><td class="small">${esc(x.version) || '<span class="dim">—</span>'}</td>
    <td class="mono small muted">${esc(x.path)}</td></tr>`).join('');
  return `<div class="panel"><h3>Instaladores</h3>${adminHint(s, 'Instalar programas')}
      ${installers ? `<div class="apps">${installers}</div>` : '<div class="muted small">Nenhum instalador disponível para este sistema.</div>'}</div>
    <div class="panel"><h3>Software detectado</h3><div class="tbl-wrap"><table><thead><tr><th>Software</th><th>Versão</th><th>Onde está</th></tr></thead>
      <tbody>${sw || '<tr><td class="muted">Nada conhecido detectado.</td></tr>'}</tbody></table></div></div>
    <div class="panel"><h3>Pacotes</h3>${packagesHtml(s.packages)}</div>`;
}

function packagesHtml(pk) {
  if (!pk) return '<div class="muted">Lista de pacotes ainda não coletada.</div>';
  return `<div class="toolbar"><span class="seg"><button data-pv="updates" class="${state.view === 'updates' ? 'on' : ''}">Atualizações (${pk.updates.length})</button>
    <button data-pv="installed" class="${state.view === 'installed' ? 'on' : ''}">Instalados (${pk.installed.length})</button></span>
    <input type="search" id="pkq" placeholder="Buscar pacote…" value="${esc(state.search)}"><span class="dim small">${esc(pk.manager)} · coletado ${ago(pk.collected_at)}</span></div>
    <div class="tbl-wrap tall"><table id="pkt">${packagesTable(pk)}</table></div>`;
}

function packagesTable(pk) {
  const q = state.search.toLowerCase();
  let table;
  if (state.view === 'updates') {
    const rows = pk.updates.filter(u => !q || u.name.toLowerCase().includes(q)).slice(0, 500)
      .map(u => `<tr><td>${esc(u.name)}</td><td class="small muted">${esc(u.current)}</td><td class="small">${esc(u.new)}</td><td>${u.security ? '<span class="pill warn">segurança</span>' : ''}</td></tr>`).join('');
    table = `<thead><tr><th>Pacote</th><th>Atual</th><th>Nova</th><th></th></tr></thead><tbody>${rows || '<tr><td class="muted" colspan="4">Tudo atualizado.</td></tr>'}</tbody>`;
  } else {
    const list = pk.installed.filter(([n]) => !q || n.toLowerCase().includes(q));
    table = `<thead><tr><th>Pacote</th><th>Versão</th></tr></thead><tbody>${list.slice(0, 400).map(([n, v]) => `<tr><td>${esc(n)}</td><td class="small muted">${esc(v)}</td></tr>`).join('')}
      ${list.length > 400 ? `<tr><td class="dim" colspan="2">… e mais ${list.length - 400}. Refine a busca.</td></tr>` : ''}</tbody>`;
  }
  return table;
}

export function bind(el, s, ctx) {
  el.querySelectorAll('[data-pv]').forEach(b => { b.onclick = () => { state.view = b.dataset.pv; ctx.rerender(); }; });
  const q = el.querySelector('#pkq');
  if (q) q.oninput = e => { state.search = e.target.value; el.querySelector('#pkt').innerHTML = packagesTable(s.packages); };
}
