// Configurações do painel: conta, alertas por e-mail, licença, atualizações e auditoria.
import { api } from '../api.js';
import { esc, dt, ago } from '../util.js';
import { toast } from '../ui.js';

const SECTIONS = { account: 'Conta', alerts: 'Alertas por e-mail', license: 'Licença', updates: 'Atualizações', audit: 'Auditoria' };

export function settingsView(root, section) {
  const key = SECTIONS[section] ? section : 'account';
  root.innerHTML = `<div class="settings"><nav class="side">${Object.entries(SECTIONS).map(([k, l]) =>
    `<a href="#/settings/${k}" class="${k === key ? 'on' : ''}">${l}</a>`).join('')}</nav><section id="sec"><div class="muted">Carregando…</div></section></div>`;
  const el = root.querySelector('#sec');
  ({ account, alerts, license, updates, audit })[key](el).catch(e => { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; });
  return {};
}

const row = (id, label, input, hint = '') => `<div><label for="${id}">${label}</label>${input}${hint ? `<div class="hint">${hint}</div>` : ''}</div>`;
const text = (id, value, extra = '') => `<input type="text" id="${id}" value="${esc(value ?? '')}" ${extra}>`;
const check = (id, label, on) => `<label class="check"><input type="checkbox" id="${id}" ${on ? 'checked' : ''}> ${label}</label>`;

async function account(el) {
  const me = await api('/api/me');
  el.innerHTML = `<div class="panel narrow"><h3>Trocar senha do administrador</h3><form id="pf">
    ${row('pc', 'Senha atual', '<input type="password" id="pc" autocomplete="current-password">')}
    ${row('p1', `Nova senha (mínimo ${Number(me.min_password)} caracteres)`, '<input type="password" id="p1" autocomplete="new-password">')}
    ${row('p2', 'Repita a nova senha', '<input type="password" id="p2" autocomplete="new-password">')}
    <div class="err" id="pe"></div><button class="btn primary mt">Salvar senha</button></form></div>`;
  el.querySelector('#pf').onsubmit = async e => {
    e.preventDefault();
    const v = id => el.querySelector('#' + id).value;
    try {
      if (v('p1') !== v('p2')) throw new Error('As senhas não conferem.');
      await api('/api/account/password', { method: 'POST', body: { current: v('pc'), password: v('p1') } });
      toast('Senha alterada.'); el.querySelector('#pf').reset();
    } catch (err) { el.querySelector('#pe').textContent = err.message; }
  };
}

async function alerts(el) {
  const a = await api('/api/settings/alerts');
  const sec = a.smtp.security;
  el.innerHTML = `<div class="panel narrow"><h3>Alertas por e-mail</h3>
    <p class="small muted">O painel envia e-mail quando um servidor fica crítico ou offline por mais de ${Number(a.stable_minutes)} minutos e quando volta ao normal. Use o SMTP da sua empresa.</p>
    <form id="af">
    ${check('en', 'Alertas ligados', a.enabled)}
    ${row('rc', 'Destinatários', text('rc', a.recipients, 'placeholder="ti@empresa.com, plantao@empresa.com"'), 'separe por vírgula')}
    ${check('nw', 'Avisar também quando ficar em "Atenção"', a.notify_warn)}
    ${check('nr', 'Avisar quando o servidor voltar ao normal', a.notify_recovery)}
    <h3 class="mt">Servidor SMTP</h3>
    <div class="row-fields">${row('sh', 'Servidor', text('sh', a.smtp.host, 'placeholder="smtp.seudominio.com"'))}
      ${row('sp', 'Porta', `<input type="number" id="sp" value="${Number(a.smtp.port) || 587}">`)}
      ${row('ss', 'Segurança', `<select id="ss">${[['starttls', 'STARTTLS (587)'], ['tls', 'SSL/TLS (465)'], ['none', 'Nenhuma (25)']]
        .map(([v, l]) => `<option value="${v}" ${sec === v ? 'selected' : ''}>${l}</option>`).join('')}</select>`)}</div>
    ${row('su', 'Usuário', text('su', a.smtp.user, 'autocomplete="off"'))}
    ${row('sw', 'Senha', `<input type="password" id="sw" autocomplete="new-password" placeholder="${a.smtp.has_pass ? '•••••• (guardada; deixe em branco para manter)' : ''}">`, 'guardada criptografada no servidor do painel; ao trocar servidor, porta, segurança ou usuário, informe de novo')}
    ${row('sf', 'Remetente', text('sf', a.smtp.from, 'placeholder="Linux Control <alertas@empresa.com>"'))}
    ${a.last_error ? `<p class="small warn-text">Último erro de envio (${dt(a.last_error.at)}): ${esc(a.last_error.message)}</p>` : ''}
    <div class="err" id="ae"></div>
    <div class="foot left"><button class="btn primary">Salvar</button><button type="button" class="btn" id="test">Enviar e-mail de teste</button></div></form></div>`;
  const v = id => el.querySelector('#' + id);
  const payload = () => ({ enabled: v('en').checked, recipients: v('rc').value, notify_warn: v('nw').checked, notify_recovery: v('nr').checked,
    smtp: { host: v('sh').value, port: v('sp').value, security: v('ss').value, user: v('su').value, pass: v('sw').value, from: v('sf').value } });
  const save = async () => { await api('/api/settings/alerts', { method: 'PUT', body: payload() }); v('sw').value = ''; };
  v('af').onsubmit = async e => {
    e.preventDefault();
    try { await save(); toast('Alertas salvos.'); v('ae').textContent = ''; } catch (err) { v('ae').textContent = err.message; }
  };
  v('test').onclick = async () => {
    v('ae').textContent = '';
    try { await save(); await api('/api/settings/alerts/test', { method: 'POST' }); toast('E-mail de teste enviado.'); }
    catch (err) { v('ae').textContent = err.message; }
  };
}

async function license(el) {
  const l = await api('/api/license');
  const status = { registered: ['ok', 'registrada'], pending: ['warn', 'registro pendente (nova tentativa automática)'], local: ['', 'registrada só neste painel'],
    unregistered: ['warn', 'não registrada'] }[l.status] || ['', l.status];
  el.innerHTML = `<div class="panel narrow"><h3>Licença</h3><dl class="kv">
    <dt>Plano</dt><dd>${esc(l.plan)} (gratuito)</dd><dt>Situação</dt><dd><span class="pill ${status[0]}">${status[1]}</span></dd>
    <dt>Chave</dt><dd class="mono">${esc(l.key || '—')}</dd><dt>Instância</dt><dd class="mono small">${esc(l.instance_id)}</dd>
    <dt>Responsável</dt><dd>${l.owner ? `${esc(l.owner.name)} · ${esc(l.owner.email)}${l.owner.company ? ' · ' + esc(l.owner.company) : ''}` : '—'}</dd>
    ${l.registered_at ? `<dt>Registrada em</dt><dd>${dt(l.registered_at)}</dd>` : ''}
    ${l.error ? `<dt>Último erro</dt><dd class="small warn-text">${esc(l.error)}</dd>` : ''}</dl>
    <p class="small muted mt">${l.remote ? 'Uma vez por dia o painel informa ao servidor de licenças a versão e quantos servidores monitora. Para desligar, defina LCTL_TELEMETRY=0.'
      : 'Esta instalação não envia dados para fora (LCTL_TELEMETRY=0 ou servidor de licenças não configurado).'}</p></div>`;
}

async function updates(el) {
  const render = u => {
    const h = u.hub;
    let action;
    if (!h.available) action = `<p>Você está na versão mais recente (<b>${esc(h.current)}</b>).</p>`;
    else if (h.requested) action = `<p><span class="pill info">atualizando para ${esc(h.requested)}</span> O painel reinicia sozinho em instantes.</p>`;
    else if (h.can_self_update) action = `<p>Nova versão <b>${esc(h.latest)}</b> disponível (atual: ${esc(h.current)}).</p><button class="btn primary" id="uh">Atualizar o painel agora</button>`;
    else action = `<p>Nova versão <b>${esc(h.latest)}</b> disponível (atual: ${esc(h.current)}). Nesta instalação, atualize pelo servidor:</p>
      <p class="small muted">Docker:</p><pre class="raw">${esc(h.manual.docker)}</pre><p class="small muted">Instalação pelo script:</p><pre class="raw">${esc(h.manual.script)}</pre>`;
    el.innerHTML = `<div class="panel narrow"><h3>Painel</h3>${action}
      ${h.notes && h.available ? `<details class="mt"><summary>Novidades</summary><pre class="raw">${esc(h.notes)}</pre></details>` : ''}
      <p class="small muted mt">Última verificação: ${h.checked_at ? ago(h.checked_at) : 'nunca'}${h.error ? ` (erro: ${esc(h.error)})` : ''}
      · <a href="#" id="uc">verificar agora</a></p></div>
      <div class="panel narrow"><h3>Agentes</h3><p>Versão do agente distribuída por este painel: <b>${esc(u.agents.version)}</b>.</p>
      ${check('aa', 'Atualizar os agentes automaticamente quando o painel tiver versão nova', u.agents.auto)}
      <p class="small muted">O agente baixa a versão nova do painel, confere o hash SHA-256 e reinicia. Com a opção desligada, atualize cada servidor em Configurações do servidor.</p></div>`;
    const uh = el.querySelector('#uh');
    if (uh) uh.onclick = async () => {
      if (!confirm(`Atualizar o painel para ${h.latest}? Ele fica fora do ar por alguns segundos.`)) return;
      try { await api('/api/updates/hub', { method: 'POST' }); render(await api('/api/updates')); } catch (e) { toast(e.message); }
    };
    const safe = fn => async e => { try { await fn(e); } catch (err) { toast(err.message); } };
    el.querySelector('#uc').onclick = safe(async e => { e.preventDefault(); render(await api('/api/updates/check', { method: 'POST' })); });
    el.querySelector('#aa').onchange = safe(async e => { render(await api('/api/updates/settings', { method: 'PUT', body: { agents_auto: e.target.checked } })); });
  };
  render(await api('/api/updates'));
}

async function audit(el) {
  const { events, limit } = await api('/api/audit');
  el.innerHTML = `<div class="panel"><h3>Auditoria <span class="r dim small">últimos ${Number(limit)} eventos</span></h3><div class="tbl-wrap tall"><table>
    <thead><tr><th>Quando</th><th>Evento</th><th>Detalhe</th><th>IP</th></tr></thead><tbody>${events.map(e => `<tr><td class="small">${dt(e.ts)}</td>
    <td>${esc(e.label)}</td><td class="small">${esc(e.detail)}</td><td class="small mono muted">${esc(e.ip)}</td></tr>`).join('')
    || '<tr><td class="muted" colspan="4">Nada registrado.</td></tr>'}</tbody></table></div></div>`;
}
