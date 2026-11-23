// Detalhe de um servidor. Rota: #/server/:id/:aba[/:arg]. Cada aba é um módulo que exporta:
//   label                      nome na barra de abas
//   show?(server)              se a aba aparece (ex.: Docker só com Docker instalado)
//   load?(server, ctx)         busca dados extras antes de desenhar (ctx.arg traz o 4º pedaço da rota)
//   controls?(server, ctx)     HTML fixo acima do corpo (campos de busca); desenhado uma vez
//   bindControls?(el, server, ctx)
//   body(server, ctx)          HTML do corpo, redesenhado a cada atualização
//   bind?(el, server, ctx)     liga os eventos do corpo
//   refreshMs?                 intervalo de atualização (padrão 10 s)
// ctx oferece rerender() (redesenha com os dados atuais) e reload() (busca de novo).
import { api } from '../api.js';
import { esc, ago, dur, ipsOf, STATUS_PILL, datacenter, ipPlace, flag } from '../util.js';
import { bindRunButtons, loadAgentCommands } from '../actions.js';
import { bindCopy } from '../ui.js';
import * as overview from './tabs/overview.js';
import * as processes from './tabs/processes.js';
import * as services from './tabs/services.js';
import * as network from './tabs/network.js';
import * as docker from './tabs/docker.js';
import * as software from './tabs/software.js';
import * as security from './tabs/security.js';
import * as users from './tabs/users.js';
import * as schedules from './tabs/schedules.js';
import * as actions from './tabs/actions.js';
import * as settings from './tabs/settings.js';

const TABS = { overview, processes, services, network, docker, software, security, users, schedules, actions, settings };
const REFRESH_MS = 10_000;

export function serverView(root, id, tabName, arg) {
  const key = TABS[tabName] ? tabName : 'overview';
  const tab = TABS[key];
  const ctx = { id, arg, rerender: () => renderBody(), reload: () => load() };
  const goToCommand = cmdId => { location.hash = `#/server/${id}/actions/${cmdId}`; };
  let server = null, lastHtml = '';

  root.innerHTML = '<div class="muted">Carregando…</div>';

  const meta = () => {
    const sys = (server.inventory || {}).system || {}, m = server.metrics || {};
    const place = [server.geo && `${flag(server.geo.country)} ${ipPlace(server)}`, datacenter(server)].filter(Boolean).join(' — ');
    return [sys.os, sys.hostname, ipsOf(sys).slice(0, 3).join(', '), server.remote_ip && `IP de saída ${server.remote_ip}`, place,
      `atualizado ${ago(server.last_seen)}`, m.uptime && `ligado há ${dur(m.uptime)}`].filter(Boolean).map(x => `<span>${esc(x)}</span>`).join('');
  };

  function header() {
    const counts = { overview: server.health.issues.filter(i => i.level !== 'info').length, services: server.counts.services_failed };
    const tabs = Object.entries(TABS).filter(([, t]) => !t.show || t.show(server)).map(([k, t]) =>
      `<a href="#/server/${id}/${k}" class="${k === key ? 'on' : ''}">${t.label}${counts[k] ? `<span class="cnt crit">${counts[k]}</span>` : ''}</a>`).join('');
    const h = server.health;
    return `<div class="detail-head"><div class="grow"><a href="#/" class="small">← Servidores</a>
      <h1><span class="dot ${h.status}"></span>${esc(server.name)} <span class="pill ${STATUS_PILL[h.status]}">${esc(h.label)}</span></h1>
      <div class="meta" id="meta">${meta()}</div></div></div><nav class="tabs">${tabs}</nav>`;
  }

  // A atualização automática não substitui a área onde a pessoa está digitando.
  function renderBody(fromTimer = false) {
    const el = root.querySelector('#tabbody');
    if (!el) return;
    if (fromTimer && el.contains(document.activeElement) && /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) return;
    if (!server.last_seen && tab !== settings) {
      el.innerHTML = `<div class="empty"><h3>Aguardando o agente</h3><p>Ainda não recebemos dados deste servidor.
        Gere o comando de instalação em <a href="#/server/${id}/settings">Configurações</a>.</p></div>`;
      return;
    }
    const html = tab.body(server, ctx);
    // Sem mudança, não redesenha: trocar os botões no meio de um clique faz o clique se perder.
    if (fromTimer && html === lastHtml) return;
    lastHtml = html;
    el.innerHTML = html;
    bindCopy(el);
    bindRunButtons(el, server, goToCommand);
    if (tab.bind) tab.bind(el, server, ctx);
  }

  async function load(fromTimer = false) {
    const first = !server;
    server = (await api(`/api/servers/${id}`)).server;
    if (first) await loadAgentCommands();
    if (tab.load) await tab.load(server, ctx);
    if (first) {
      root.innerHTML = header() + '<div id="tabctl"></div><div id="tabbody"></div>';
      if (tab.controls && server.last_seen) {
        const ctl = root.querySelector('#tabctl');
        ctl.innerHTML = tab.controls(server, ctx);
        if (tab.bindControls) tab.bindControls(ctl, server, ctx);
      }
    } else {
      root.querySelector('#meta').innerHTML = meta();
    }
    renderBody(fromTimer);
  }

  load().catch(e => { root.innerHTML = `<div class="empty">${esc(e.message)} <a href="#/">Voltar</a></div>`; });
  const timer = setInterval(() => load(true).catch(() => { /* o aviso de "sem conexão" já aparece pelo api() */ }), tab.refreshMs || REFRESH_MS);
  return { destroy: () => clearInterval(timer) };
}
