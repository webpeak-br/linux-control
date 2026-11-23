// Tudo sobre ações vem do catálogo que o agente declara: botões de linha (target/when), botões de aba (placement),
// formulários, sugestões, confirmação e envio. Nenhum id de ação é citado fora daqui.
import { api } from './api.js';
import { esc } from './util.js';
import { modal, toast, formFields, bindFields, readForm } from './ui.js';

const LEVEL_PILL = { change: '<span class="pill">altera o servidor</span>', danger: '<span class="pill crit">cuidado</span>', admin: '<span class="pill brand">admin</span>' };

// Única exceção à regra de não citar ids: a biblioteca de chaves (Configurações) instala em vários servidores de uma vez.
export const AUTHORIZE_KEY_ACTION = 'ssh.authorize_key';

export const catalog = server => (server.inventory || {}).actions || [];
export const mode = server => (server.inventory || {}).actions_mode || 'readonly';
// Execuções recentes do servidor aberto: deixam o botão em "na fila/executando" e alimentam o painel de atividades.
export const COMMAND_STATUS = {
  queued: ['', 'na fila'], sent: ['info', 'executando'], done: ['ok', 'concluída'], failed: ['crit', 'falhou'],
  lost: ['warn', 'sem resposta'], canceled: ['', 'cancelada'], expired: ['', 'expirou na fila'],
};
let recent = [];
export function setRecentCommands(list) { recent = list || []; }
const ACTIVE = new Set(['queued', 'sent']);
const activeFor = (id, key) => recent.find(c => c.action === id && ACTIVE.has(c.status) && (!key || c.param === key));
const runningBtn = c => `<button class="btn sm" disabled title="Já enviada; acompanhe em Atividades">⏳ ${esc(COMMAND_STATUS[c.status][1])}</button>`;

const isDangerous = a => !!a.confirm || a.level === 'danger';
const actionById = (server, id) => catalog(server).find(a => a.id === id);
const btnClass = a => (isDangerous(a) ? 'danger' : '');

// Ações que aparecem na linha de um item do inventário (que traz "key" e "state").
export function rowButtons(server, target, item) {
  const states = item.state || [];
  return catalog(server)
    .filter(a => a.target === target && (a.when || []).every(w => states.includes(w)))
    .map(a => { const c = activeFor(a.id, item.key); return c ? runningBtn(c) : `<button class="btn sm ${btnClass(a)}" data-run="${esc(a.id)}" data-key="${esc(item.key)}">${esc(a.label)}</button>`; })
    .join(' ');
}

// Ações que o agente pede para mostrar no topo de uma aba (ex.: "Criar usuário" na aba Usuários).
export function placementButtons(server, place) {
  return catalog(server).filter(a => a.placement === place)
    .map(a => { const c = activeFor(a.id); return c ? runningBtn(c) : `<button class="btn sm primary" data-run="${esc(a.id)}">+ ${esc(a.label)}</button>`; }).join(' ');
}

// Botões ao lado de um problema do diagnóstico: as ações que declaram o código dele em "fixes".
// As que mudam o servidor vêm primeiro (resolvem); as de leitura depois (ajudam a investigar).
export function fixButtons(server, issue) {
  const order = a => (a.level === 'read' ? 1 : 0);
  return catalog(server).filter(a => (a.fixes || []).includes(issue.code) && !a.done)
    .sort((x, y) => order(x) - order(y))
    .map(a => activeFor(a.id) ? runningBtn(activeFor(a.id)) : `<button class="btn sm ${a.level === 'read' ? 'ghost' : isDangerous(a) ? 'danger' : 'primary'}" data-run="${esc(a.id)}"
      title="${esc(a.desc)}">${a.level === 'read' ? '' : 'Resolver: '}${esc(a.label)}</button>`).join('');
}

// Ação de estado já aplicada mostra o estado no lugar do botão (as de risco somem; as demais podem ser reaplicadas).
// "last" é a execução mais recente dessa ação, para lembrar quando ela rodou.
export function actionRow(a, last) {
  const ran = last ? `<div class="d dim">última vez: ${esc(new Date(last.created * 1000).toLocaleString('pt-BR'))} · ${esc(LAST_STATUS[last.status] || last.status)}</div>` : '';
  const done = a.done ? `<span class="pill ok">✓ ${esc(a.done_label)}</span>` : '';
  const busy = activeFor(a.id);
  const btn = busy ? runningBtn(busy) : a.done
    ? (isDangerous(a) ? '' : `<button class="btn sm ghost" data-run="${esc(a.id)}" title="Já aplicado; rodar de novo não faz mal">Reaplicar</button>`)
    : `<button class="btn sm ${btnClass(a)}" data-run="${esc(a.id)}">Executar</button>`;
  return `<div class="act${a.done ? ' done' : ''}"><div><div class="t">${esc(a.label)} ${a.done ? '' : LEVEL_PILL[a.level] || ''}</div><div class="d">${esc(a.desc)}</div>${ran}</div>
    <div class="act-side">${done}${btn}</div></div>`;
}
const LAST_STATUS = Object.fromEntries(Object.entries(COMMAND_STATUS).map(([k, v]) => [k, v[1]]));

// Painel flutuante com as execuções das últimas 2 horas: a pessoa continua onde está e acompanha daqui.
export function activityTray(serverId) {
  const since = Date.now() / 1000 - 7200;
  const list = recent.filter(c => c.created >= since || ACTIVE.has(c.status)).slice(0, 8);
  if (!list.length) return '';
  const running = list.filter(c => ACTIVE.has(c.status)).length;
  const rows = list.map(c => {
    const [cls, txt] = COMMAND_STATUS[c.status] || ['', c.status];
    return `<div class="tray-row"><span class="pill ${cls}">${esc(txt)}</span><span class="grow">${esc(c.label || c.action)}${c.param ? ` <span class="mono dim">${esc(c.param)}</span>` : ''}</span>
      <a href="#/server/${Number(serverId)}/actions/${Number(c.id)}">ver saída</a></div>`;
  }).join('');
  return `<details class="tray" ${running ? 'open' : ''}><summary>Atividades${running ? ` <span class="pill info">${running} em andamento</span>` : ''}</summary>${rows}</details>`;
}

export function bindRunButtons(root, server, onQueued) {
  root.querySelectorAll('[data-run]').forEach(b => {
    b.onclick = () => {
      const a = actionById(server, b.dataset.run);
      if (!a) return;
      runAction(server, a, a.target_field && b.dataset.key ? { [a.target_field]: b.dataset.key } : {}, onQueued);
    };
  });
}

async function queueAction(server, id, params, confirm, onQueued) {
  try {
    const r = await api(`/api/servers/${server.id}/commands`, { method: 'POST', body: { action: id, params, confirm } });
    toast(`Enviada: ${actionById(server, id) ? actionById(server, id).label : id}. Acompanhe em Atividades, no canto da tela.`);
    if (onQueued) onQueued(r.id);
  } catch (e) { toast(e.message); }
}

function suggestions(server) {
  const inv = server.inventory || {};
  return {
    services: ((inv.services || {}).units || []).map(u => u.key),
    containers: (((inv.docker || {}).containers) || []).map(c => c.key),
    users: ((inv.users || {}).accounts || []).map(u => u.key),
    ssh_keys: (keyLibrary || []).map(k => ({ label: k.name, value: k.key })),
  };
}

// Pede o que falta (campos e confirmação) e põe a ação na fila. Leitura com tudo preenchido roda direto.
function runAction(server, a, prefill, onQueued) {
  const fields = a.fields || [];
  const complete = fields.every(f => f.type === 'bool' || f.required === false || prefill[f.name]);
  if (complete && a.level === 'read' && !a.confirm) return queueAction(server, a.id, prefill, undefined, onQueued);

  const visible = fields.filter(f => !(f.name === a.target_field && prefill[f.name]));
  const subject = prefill[a.target_field] ? ` <span class="mono">${esc(prefill[a.target_field])}</span>` : '';
  modal(`<h2>${esc(a.label)}${subject}</h2><p>${esc(a.desc)}${a.level !== 'read' ? ' Esta ação altera o servidor.' : ''}</p>
    <form id="axf">${formFields(visible, prefill, suggestions(server))}
    ${a.confirm ? `<label for="ac">Digite <b>${esc(server.name)}</b> para confirmar</label><input type="text" id="ac" autocomplete="off">` : ''}
    <div class="err" id="axe"></div>
    <div class="foot"><button type="button" class="btn ghost" data-close>Cancelar</button>
    <button class="btn ${a.confirm ? 'danger' : 'primary'}">Executar em ${esc(server.name)}</button></div></form>`, (box, close) => {
    bindFields(box, visible);
    const first = box.querySelector('input,textarea,select');
    if (first) first.focus();
    box.querySelector('#axf').onsubmit = e => {
      e.preventDefault();
      try {
        const params = { ...prefill, ...readForm(box, visible) };
        const confirm = a.confirm ? box.querySelector('#ac').value : undefined;
        close();
        queueAction(server, a.id, params, confirm, onQueued);
      } catch (err) { box.querySelector('#axe').textContent = err.message; }
    };
  });
}

let agentCommands = null, keyLibrary = null;
export async function loadAgentCommands() {
  if (!agentCommands) agentCommands = await api('/api/agent/commands');
  keyLibrary = (await api('/api/ssh-keys').catch(() => ({ keys: [] }))).keys;  // chaves salvas viram opção nos formulários
  return agentCommands;
}

export function adminHint(server, what) {
  if (mode(server) === 'admin' || !agentCommands) return '';
  return `<div class="panel small muted">${esc(what)} pelo navegador exige o agente no modo <b>admin</b> (hoje: ${esc(mode(server))}).
    No servidor, rode: <code>${esc(agentCommands.set_mode.admin)}</code></div>`;
}
