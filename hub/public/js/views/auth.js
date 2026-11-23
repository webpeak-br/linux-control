// Login, configuração inicial (primeiro acesso) e registro da instalação.
import { api } from '../api.js';
import { LOGO } from '../util.js';

const box = (title, sub, inner) => `<div class="login"><form class="login-box" id="af">
  <div class="logo">${LOGO} Linux Control</div><h1>${title}</h1><p>${sub}</p>${inner}<div class="err" id="ae"></div></form></div>`;

function bind(root, handler) {
  root.querySelector('#af').onsubmit = async e => {
    e.preventDefault();
    const btn = root.querySelector('button[type=submit]');
    btn.disabled = true;
    try { await handler(id => root.querySelector('#' + id).value.trim()); }
    catch (err) { root.querySelector('#ae').textContent = err.message; btn.disabled = false; }
  };
  const first = root.querySelector('input'); if (first) first.focus();
}

const ownerFields = `
  <label for="on">Seu nome</label><input type="text" id="on" autocomplete="name" required maxlength="120">
  <label for="oe">E-mail</label><input type="text" id="oe" autocomplete="email" required maxlength="200">
  <label for="oc">Empresa <span class="dim">(opcional)</span></label><input type="text" id="oc" autocomplete="organization" maxlength="120">`;
const consent = `<label class="check small"><input type="checkbox" id="ok"> Registrar esta instalação (licença community gratuita). O contato é usado
  para avisos de segurança e novidades do Linux Control.</label>`;
const owner = (v, root) => ({ name: v('on'), email: v('oe'), company: v('oc'), consent: root.querySelector('#ok').checked });

export function loginView(root, done) {
  root.innerHTML = box('Entrar', 'Painel de servidores Linux',
    `<input type="password" id="pw" placeholder="Senha do administrador" autocomplete="current-password">
     <button class="btn primary" type="submit">Entrar</button>`);
  bind(root, async v => { await api('/api/login', { method: 'POST', body: { password: v('pw') }, quiet401: true }); done(); });
}

export function setupView(root, done, minPassword) {
  root.innerHTML = box('Configuração inicial', 'Crie o acesso de administrador deste painel.',
    `<label for="sc">Código de configuração</label><input type="text" id="sc" autocomplete="off" placeholder="aparece no log do servidor do painel">
     ${ownerFields}
     <label for="p1">Senha (mínimo ${Number(minPassword) || 10} caracteres)</label><input type="password" id="p1" autocomplete="new-password" required>
     <label for="p2">Repita a senha</label><input type="password" id="p2" autocomplete="new-password" required>
     ${consent}<button class="btn primary" type="submit">Criar acesso</button>`);
  bind(root, async v => {
    if (v('p1') !== v('p2')) throw new Error('As senhas não conferem.');
    if (!v('on') || !v('oe')) throw new Error('Informe nome e e-mail.');
    await api('/api/setup', { method: 'POST', body: { code: v('sc'), password: v('p1') }, quiet401: true });
    await api('/api/license/register', { method: 'POST', body: owner(v, root) });
    done();
  });
}

export function registrationView(root, done) {
  root.innerHTML = box('Registre esta instalação', 'Leva 10 segundos e é gratuito.',
    `${ownerFields}${consent}<button class="btn primary" type="submit">Registrar e continuar</button>`);
  bind(root, async v => { await api('/api/license/register', { method: 'POST', body: owner(v, root) }); done(); });
}
