import { api } from '../../api.js';
import { esc } from '../../util.js';
import { copyBox, bindCopy, toast } from '../../ui.js';
import { loadAgentCommands, placementButtons } from '../../actions.js';

export const label = 'Configurações';
let agent = null, commands = null;

export async function load(s) {
  [agent, commands] = await Promise.all([api(`/api/servers/${s.id}/agent`), loadAgentCommands()]);
}

export function body(s) {
  const status = !agent.outdated ? '<span class="pill ok">em dia</span>'
    : agent.requested ? '<span class="pill info">atualização pedida</span>' : '<button class="btn sm" id="au">Atualizar agente</button>';
  return `<div class="cols"><div class="panel"><h3>Identificação</h3><form id="sf">
    <label class="small muted" for="sn">Nome</label><input type="text" id="sn" value="${esc(s.name)}" class="full" maxlength="80">
    <label class="small muted" for="st">Tags (separadas por vírgula)</label><input type="text" id="st" value="${esc(s.tags.join(', '))}" class="full">
    <button class="btn primary mt">Salvar</button></form></div>
    <div class="panel"><h3>Agente</h3>
      <p class="small">Versão instalada: <b>${esc(agent.installed || '—')}</b> · disponível no painel: <b>${esc(agent.available)}</b> ${status}</p>
      <p class="muted small">Gere um novo token para (re)instalar o agente. O token anterior deixa de funcionar na hora.</p>
      <button class="btn" id="rt">Gerar novo comando de instalação</button><div id="rtout" class="mt"></div>
      </div></div>
    <div class="panel mt"><h3>Desinstalação rápida do agente</h3>
      ${placementButtons(s, 'agent') ? `<p class="small">Pelo painel, com um clique (o servidor precisa estar online):</p><div class="fix">${placementButtons(s, 'agent')}</div>` : ''}
      <p class="small mt">Ou rode no servidor:</p>${copyBox(commands.uninstall)}
      <p class="muted small">Remove o serviço, os arquivos e a configuração do agente. Aplicativos instalados pelo painel continuam funcionando.
      Depois, use <b>Remover do painel</b> abaixo para apagar o histórico.</p></div>
    <div class="panel mt"><h3>Remover servidor</h3><p class="muted small">Remove o servidor, o histórico e as execuções do painel. O agente instalado passa a ser recusado.</p>
      <button class="btn danger" id="rm">Remover do painel</button></div>`;
}

export function bind(el, s, ctx) {
  const run = fn => async (...args) => { try { await fn(...args); } catch (e) { toast(e.message); } };
  el.querySelector('#sf').onsubmit = run(async e => {
    e.preventDefault();
    await api(`/api/servers/${s.id}`, { method: 'PATCH', body: { name: el.querySelector('#sn').value, tags: el.querySelector('#st').value } });
    toast('Salvo.'); ctx.reload();
  });
  const au = el.querySelector('#au');
  if (au) au.onclick = run(async () => { await api(`/api/servers/${s.id}/agent-update`, { method: 'POST' }); toast('O agente se atualiza no próximo contato.'); ctx.reload(); });
  el.querySelector('#rt').onclick = run(async () => {
    if (!confirm('Gerar um novo token? O agente atual vai parar de enviar dados até ser reinstalado.')) return;
    const r = await api(`/api/servers/${s.id}/token`, { method: 'POST' });
    const out = el.querySelector('#rtout');
    out.innerHTML = copyBox(r.install); bindCopy(out);
  });
  el.querySelector('#rm').onclick = run(async () => {
    if (prompt(`Para remover, digite o nome do servidor: ${s.name}`) !== s.name) return;
    await api(`/api/servers/${s.id}`, { method: 'DELETE' });
    location.hash = '#/';
  });
}
