import { esc } from '../../util.js';
import { rowButtons, placementButtons, adminHint } from '../../actions.js';

export const label = 'Agendamentos';

export function body(s) {
  const c = (s.inventory || {}).cron || {};
  const rows = (c.cron || []).map(j => `<tr><td class="mono small">${esc(j.line)}</td><td class="mono small dim">${esc(j.file)}</td>
    <td class="acts">${rowButtons(s, 'cron', j)}</td></tr>`).join('');
  const add = placementButtons(s, 'schedules');
  return `${adminHint(s, 'Criar agendamentos')}
    <div class="panel"><h3>Tarefas cron ${add ? `<span class="r">${add}</span>` : ''}</h3>
    <div class="tbl-wrap"><table><thead><tr><th>Linha</th><th>Arquivo</th><th></th></tr></thead>
    <tbody>${rows || '<tr><td class="muted" colspan="3">Nenhuma tarefa cron.</td></tr>'}</tbody></table></div></div>
    <div class="panel"><h3>Timers do systemd</h3><pre class="raw">${esc(c.timers || 'Sem dados.')}</pre></div>`;
}
