import { esc } from '../../util.js';
import { rowButtons } from '../../actions.js';

export const label = 'Docker';
export const show = s => !!(s.inventory || {}).docker;

export function body(s) {
  const d = (s.inventory || {}).docker;
  if (d.error) return `<div class="empty">${esc(d.error)}</div>`;
  const rows = d.containers.map(c => `<tr><td><b>${esc(c.name)}</b><div class="dim small mono">${esc(c.id)}</div></td><td class="small">${esc(c.image)}</td>
    <td>${c.docker_state === 'running' ? '<span class="pill ok">rodando</span>' : `<span class="pill ${c.docker_state === 'exited' ? '' : 'warn'}">${esc(c.docker_state)}</span>`}<div class="dim small">${esc(c.status)}</div></td>
    <td class="num small">${c.stats ? `${esc(c.stats.cpu)}<br>${esc(c.stats.mem)}` : '—'}</td><td class="small mono">${esc(c.ports)}</td>
    <td class="acts">${rowButtons(s, 'container', c)}</td></tr>`).join('');
  return `<div class="panel"><h3>Containers <span class="r dim small">${d.containers.filter(c => c.docker_state === 'running').length} rodando de ${d.containers.length}</span></h3>
    <div class="tbl-wrap"><table><thead><tr><th>Nome</th><th>Imagem</th><th>Estado</th><th class="num">CPU / Mem</th><th>Portas</th><th></th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}
