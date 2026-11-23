// Ponto de entrada: monta o topo uma vez e troca só a área de conteúdo conforme a rota.
import { api, setUnauthorizedHandler } from './api.js';
import { LOGO } from './util.js';
import { loginView, setupView, registrationView } from './views/auth.js';
import { dashboardView } from './views/dashboard.js';
import { serverView } from './views/server.js';
import { settingsView } from './views/settings.js';
import { addServerModal } from './views/add-server.js';

const $app = document.getElementById('app');
let current = null;

function shell() {
  $app.innerHTML = `<header class="top"><a class="logo" href="#/">${LOGO} Linux Control</a>
    <nav class="topnav"><a href="#/" data-nav="servers">Servidores</a><a href="#/settings" data-nav="settings">Configurações<span class="badge" id="upd" hidden></span></a></nav>
    <div class="spacer"></div><button class="btn primary" id="add">+ Adicionar servidor</button>
    <button class="btn ghost" id="logout">Sair</button></header><main class="wrap" id="view"></main>`;
  document.getElementById('add').onclick = () => addServerModal(() => route());
  document.getElementById('logout').onclick = async () => { await api('/api/logout', { method: 'POST' }).catch(() => { /* a sessão expira de qualquer forma */ }); start(); };
  api('/api/updates').then(u => { if (u.hub.available) document.getElementById('upd').hidden = false; }).catch(() => { /* só o selo some */ });
}

function destroyCurrent() { if (current && current.destroy) current.destroy(); current = null; }

async function route() {
  destroyCurrent();
  if (!document.getElementById('view')) shell();
  const view = document.getElementById('view');
  const [page, id, tab, arg] = location.hash.replace(/^#\/?/, '').split('/');
  document.querySelectorAll('[data-nav]').forEach(a => a.classList.toggle('on', a.dataset.nav === (page === 'settings' ? 'settings' : 'servers')));
  if (page === 'server' && id) current = serverView(view, Number(id), tab || 'overview', arg);
  else if (page === 'settings') current = settingsView(view, id || 'account');
  else current = dashboardView(view);
}

async function start() {
  destroyCurrent();
  $app.innerHTML = '';
  const me = await api('/api/me', { quiet401: true }).catch(() => ({}));
  if (me.setup_needed) return setupView($app, start, me.min_password);
  if (!me.authenticated) return loginView($app, start);
  const lic = await api('/api/license').catch(() => ({ registration_needed: false }));
  if (lic.registration_needed) return registrationView($app, start);
  shell();
  route();
}

setUnauthorizedHandler(start);
window.addEventListener('hashchange', () => { if (document.getElementById('view')) route(); });
start();
