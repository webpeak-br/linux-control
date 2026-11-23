// Aplicativos de 1 clique: os instalados no topo (com estado, endereço e botões) e a vitrine por categoria.
// A vitrine e o formulário vêm do agente (inventory.app_catalog); a instalação é a ação com placement "apps".
import { api } from '../../api.js';
import { esc, N } from '../../util.js';
import { catalog, rowButtons, adminHint } from '../../actions.js';
import { modal, toast } from '../../ui.js';

export const label = 'Aplicativos';
export const state = { category: '' };

const LICENSE = { 'grátis': ['ok', 'grátis'], pago: ['warn', 'pago'], freemium: ['', 'grátis + plano pago'] };
// Endereços vêm do agente: só viram link se forem http(s).
const safeUrl = u => (/^https?:\/\/[^\s"'<>]+$/.test(String(u || '')) ? String(u) : '');
const installAction = s => catalog(s).find(a => a.placement === 'apps');

export function body(s) {
  const inv = s.inventory || {};
  const apps = inv.app_catalog || [];
  const stacks = inv.stacks || [];
  const action = installAction(s);
  const installed = stacks.length ? `<div class="panel"><h3>Instalados</h3><div class="tbl-wrap"><table><tbody>${stacks.map(st => `<tr>
      <td><b>${esc(st.label || st.app)}</b><div class="dim small mono">${esc(st.name)}</div></td>
      <td>${safeUrl(st.url) ? `<a href="${esc(safeUrl(st.url))}" target="_blank" rel="noopener noreferrer">${esc(st.url)}</a>` : esc(st.url || '—')}</td>
      <td>${(st.state || []).includes('running') ? '<span class="pill ok">rodando</span>' : (st.state || []).includes('stopped') ? '<span class="pill warn">parado</span>' : '<span class="pill">no sistema</span>'}</td>
      <td class="acts">${rowButtons(s, 'stack', st)}</td></tr>`).join('')}</tbody></table></div></div>` : '';
  if (!apps.length) return installed + '<div class="empty">Atualize o agente deste servidor para ver o catálogo de aplicativos.</div>';
  const cats = [...new Set(apps.map(a => a.category))];
  const shown = apps.filter(a => !state.category || a.category === state.category);
  const cards = shown.map(a => {
    const [cls, txt] = LICENSE[a.license] || ['', a.license];
    return `<div class="app-card"><div class="app-head"><span class="app-icon">${esc(a.label.slice(0, 1))}</span>
      <div class="grow"><b>${esc(a.label)}</b><div class="dim small">${esc(a.category)}</div></div><span class="pill ${cls}">${esc(txt)}</span></div>
      <p class="small">${esc(a.desc)}</p>
      <div class="small dim">${a.kind === 'docker' ? 'Docker · HTTPS automático' : a.kind === 'script' ? 'Instalador oficial' : 'Instalação no sistema'}
        ${a.min_ram_mb ? ` · ${N(a.min_ram_mb) >= 1024 ? `${N(a.min_ram_mb) / 1024} GB` : `${N(a.min_ram_mb)} MB`} de RAM` : ''}${a.dedicated_server ? ' · <b>servidor dedicado</b>' : ''}</div>
      ${action ? `<button class="btn sm primary mt" data-install="${esc(a.id)}">Instalar</button>` : ''}</div>`;
  }).join('');
  return `${action ? '' : adminHint(s, 'Instalar aplicativos')}${installed}
    <div class="toolbar"><span class="seg"><button data-cat="" class="${state.category ? '' : 'on'}">Todos</button>${cats.map(c =>
      `<button data-cat="${esc(c)}" class="${state.category === c ? 'on' : ''}">${esc(c)}</button>`).join('')}</span></div>
    <div class="app-grid">${cards}</div>`;
}

function installForm(s, app) {
  const mem = ((s.metrics || {}).mem || {}).total;
  const ramMb = mem ? Math.round(mem / 1048576) : 0;
  const warns = [];
  if (app.dedicated_server) warns.push('Precisa de um servidor <b>dedicado e limpo</b>: ele assume as portas 80/443 e a configuração do sistema. Não instale onde já há sites ou outros aplicativos.');
  if (app.license === 'pago') warns.push(`Software <b>pago</b>. ${esc(app.license_note || '')}`);
  if (app.min_ram_mb && ramMb && ramMb < app.min_ram_mb) warns.push(`Este servidor tem ${ramMb} MB de RAM; ${esc(app.label)} pede ${N(app.min_ram_mb)} MB.`);
  if (app.risk_notes) warns.push(esc(app.risk_notes));
  const docker = app.kind === 'docker';
  const field = f => `<label for="af_${esc(f.name)}">${esc(f.label)}${f.required === false ? ' <span class="dim">(opcional)</span>' : ''}</label>
    <input type="${f.type === 'password' ? 'password' : 'text'}" id="af_${esc(f.name)}" data-field="${esc(f.name)}" autocomplete="off">`;
  return `<h2>Instalar ${esc(app.label)} em ${esc(s.name)}</h2><p class="small">${esc(app.desc)}</p>
    ${warns.length ? `<div class="warn-box small">${warns.map(w => `<p>${w}</p>`).join('')}</div>` : ''}
    <form id="appf">
      ${docker ? `<label for="af_domain">Domínio${app.needs_domain ? '' : ' <span class="dim">(opcional)</span>'}</label>
        <input type="text" id="af_domain" placeholder="app.suaempresa.com.br" autocomplete="off">
        <div class="hint">Aponte o DNS (registro A) do domínio para este servidor antes. Sem domínio, o app fica numa porta própria, sem HTTPS.</div>
        <label for="af_email">E-mail para o certificado HTTPS <span class="dim">(opcional)</span></label><input type="text" id="af_email" autocomplete="off">` : ''}
      ${(app.fields || []).map(field).join('')}
      ${app.dedicated_server || app.license === 'pago' ? `<label class="check"><input type="checkbox" id="af_ok"> Entendi os avisos acima</label>` : ''}
      <div class="err" id="af_err"></div>
      <div class="foot">${safeUrl(app.official_docs) ? `<a class="small" href="${esc(safeUrl(app.official_docs))}" target="_blank" rel="noopener noreferrer">documentação oficial</a>` : ''}
        <button type="button" class="btn ghost" data-close>Cancelar</button><button class="btn primary">Instalar</button></div>
    </form>`;
}

export function bind(el, s, ctx) {
  el.querySelectorAll('[data-cat]').forEach(b => { b.onclick = () => { state.category = b.dataset.cat; ctx.rerender(); }; });
  el.querySelectorAll('[data-install]').forEach(b => {
    b.onclick = () => {
      const app = (s.inventory.app_catalog || []).find(a => a.id === b.dataset.install);
      const action = installAction(s);
      if (!app || !action) return;
      modal(installForm(s, app), (box, close) => {
        box.querySelector('#appf').onsubmit = async e => {
          e.preventDefault();
          const err = box.querySelector('#af_err');
          const ok = box.querySelector('#af_ok');
          if (ok && !ok.checked) { err.textContent = 'Confirme que leu os avisos.'; return; }
          const val = id => { const i = box.querySelector(id); return i ? i.value.trim() : ''; };
          const domain = val('#af_domain').toLowerCase(), email = val('#af_email');
          if (app.kind === 'docker' && app.needs_domain && !domain && !confirm('Sem domínio o aplicativo fica sem HTTPS, numa porta do servidor. Continuar assim?')) return;
          const options = {};
          for (const i of box.querySelectorAll('[data-field]')) {
            const f = (app.fields || []).find(x => x.name === i.dataset.field);
            const v = i.value.trim();
            if (!v && f.required !== false) { err.textContent = `Preencha: ${f.label}`; return; }
            if (v) options[f.name] = v;
          }
          try {
            await api(`/api/servers/${s.id}/commands`, { method: 'POST', body: { action: action.id, params: { app: app.id, domain, email, options: JSON.stringify(options) } } });
            close();
            toast(`Instalação de ${app.label} enviada. Acompanhe em Atividades; pode levar alguns minutos.`);
            ctx.reload();
          } catch (x) { err.textContent = x.message; }
        };
      });
    };
  });
}
