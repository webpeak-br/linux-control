import { api } from '../../api.js';
import { esc, N, dt } from '../../util.js';
import { toast } from '../../ui.js';
import { catalog, actionRow, mode } from '../../actions.js';

export const label = 'Ações';
export const refreshMs = 3000;

const open = new Set();
let commands = [];
const STATUS = {
  queued: ['', 'na fila'], sent: ['info', 'executando'], done: ['ok', 'concluído'], failed: ['crit', 'falhou'],
  lost: ['warn', 'sem resposta'], canceled: ['', 'cancelado'], expired: ['', 'expirou na fila'],
};

// A rota #/server/:id/actions/:cmd abre a saída dessa execução.
export async function load(s, ctx) {
  if (ctx.arg) open.add(Number(ctx.arg));
  commands = (await api(`/api/servers/${s.id}/commands`)).commands;
}

export function body(s) {
  // Ações com alvo ou com lugar próprio aparecem nas outras abas; aqui ficam as gerais.
  const groups = {};
  catalog(s).filter(a => !a.target && !a.placement).forEach(a => { (groups[a.group] = groups[a.group] || []).push(a); });
  const g = Object.entries(groups).map(([name, list]) => `<div class="panel"><h3>${esc(name)}</h3>${list.map(a => actionRow(a, commands.find(c => c.action === a.id))).join('')}</div>`).join('');
  const cmds = commands.map(c => {
    const [cls, txt] = STATUS[c.status] || ['', c.status];
    return `<div class="cmd-item"><div class="cmd-row" data-cmd="${N(c.id)}"><span class="pill ${cls}">${txt}${c.status === 'failed' ? ` (${N(c.exit_code)})` : ''}</span>
      <b>${esc(c.label || c.action)}</b>${c.param ? `<span class="mono small muted">${esc(c.param)}</span>` : ''}
      ${c.duration != null ? `<span class="dim small">${N(c.duration)}s</span>` : ''}
      ${c.status === 'queued' ? `<button class="btn sm ghost" data-cancel="${N(c.id)}">Cancelar</button>` : ''}<span class="when">${dt(c.created)}</span></div>
      ${open.has(c.id) && c.output != null ? `<pre class="out">${esc(c.output || '(sem saída)')}</pre>` : ''}</div>`;
  }).join('');
  return `${mode(s) === 'readonly' ? '<div class="panel small muted">Agente em modo <b>somente leitura</b>: só diagnósticos ficam disponíveis.</div>' : ''}
    <div class="act-groups">${g || '<div class="empty">Nenhuma ação disponível.</div>'}</div>
    <div class="panel"><h3>Histórico de execuções <span class="r dim small">clique para ver a saída</span></h3>${cmds || '<div class="muted">Nenhuma ação executada ainda.</div>'}</div>`;
}

export function bind(el, s, ctx) {
  el.querySelectorAll('[data-cmd]').forEach(r => {
    r.onclick = e => {
      if (e.target.closest('[data-cancel]')) return;
      const id = Number(r.dataset.cmd);
      if (open.has(id)) open.delete(id); else open.add(id);
      ctx.rerender();
    };
  });
  el.querySelectorAll('[data-cancel]').forEach(b => {
    b.onclick = async () => {
      try { await api(`/api/commands/${b.dataset.cancel}`, { method: 'DELETE' }); ctx.reload(); } catch (e) { toast(e.message); }
    };
  });
}
