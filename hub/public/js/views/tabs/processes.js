import { esc, N, bytes } from '../../util.js';

export const label = 'Processos';

export function body(s) {
  const p = (s.metrics || {}).procs || { top: [] };
  const rows = [...p.top].sort((a, b) => N(b.cpu) - N(a.cpu) || N(b.rss) - N(a.rss)).map(x => `<tr><td class="num">${N(x.pid)}</td><td>${esc(x.user)}</td>
    <td>${esc(x.name)}</td><td class="num">${N(x.cpu).toFixed(1)}%</td><td class="num">${N(x.mem).toFixed(1)}%</td><td class="num">${bytes(x.rss)}</td>
    <td class="cmd" title="${esc(x.cmd)}">${esc(x.cmd)}</td></tr>`).join('');
  return `<div class="panel"><h3>Processos que mais consomem <span class="r dim small">${N(p.count)} processos${p.zombies ? ` · ${N(p.zombies)} zumbis` : ''} · CPU em % da máquina</span></h3>
    <div class="tbl-wrap"><table><thead><tr><th class="num">PID</th><th>Usuário</th><th>Nome</th><th class="num">CPU</th><th class="num">Mem</th><th class="num">RSS</th><th>Comando</th></tr></thead>
    <tbody>${rows}</tbody></table></div></div>`;
}
