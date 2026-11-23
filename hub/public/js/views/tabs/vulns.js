// Vulnerabilidades (CVE) dos pacotes instalados, pela base pública OSV.dev (avisos oficiais da distribuição).
import { api } from '../../api.js';
import { esc, N, ago } from '../../util.js';
import { fixButtons } from '../../actions.js';
import { toast } from '../../ui.js';

export const label = 'Vulnerabilidades';
export const show = s => !!(s.packages && s.packages.installed);
export const state = { filter: 'fixable', search: '' };
let data = null;

const SEV = {
  critical: ['crit', 'crítica'], high: ['crit', 'alta'], medium: ['warn', 'média'], low: ['', 'baixa'], negligible: ['', 'mínima'], unknown: ['', 'sem nota'],
};
const safeUrl = u => (/^https:\/\/[^\s"'<>]+$/.test(String(u || '')) ? String(u) : '');

export async function load(s) {
  data = await api(`/api/servers/${s.id}/vulns`);
}

export function controls() {
  return `<div class="toolbar"><input type="search" id="vq" placeholder="Filtrar por pacote ou CVE…" value="${esc(state.search)}"></div>`;
}
export function bindControls(el, s, ctx) {
  el.querySelector('#vq').oninput = e => { state.search = e.target.value; ctx.rerender(); };
}

export function body(s) {
  if (!data || !data.enabled) return '<div class="empty">A consulta de vulnerabilidades está desligada neste painel (LCTL_CVE=0).</div>';
  const r = data.result;
  const scanBtn = `<button class="btn sm" id="vscan" ${data.scanning ? 'disabled' : ''}>${data.scanning ? '⏳ analisando…' : 'Analisar agora'}</button>`;
  if (!r) return `<div class="panel"><h3>Vulnerabilidades <span class="r">${scanBtn}</span></h3><p class="muted">${data.scanning ? 'Analisando os pacotes deste servidor… (de 30 segundos a alguns minutos na primeira vez)' : 'Ainda não analisado. A análise roda sozinha quando o agente envia a lista de pacotes.'}</p></div>`;
  if (r.error) return `<div class="panel"><h3>Vulnerabilidades <span class="r">${scanBtn}</span></h3><p class="muted">${esc(r.error)}</p></div>`;
  const items = r.items || [];
  const fix = items.filter(i => i.fixed), nofix = items.filter(i => !i.fixed);
  const count = (list, sevs) => list.filter(i => sevs.includes(i.severity)).length;
  const card = (lbl, n, cls, sub) => `<div class="gauge"><div class="l">${lbl}</div><div class="v ${cls}">${N(n)}</div><div class="s">${sub}</div></div>`;
  const q = state.search.toLowerCase();
  const shown = (state.filter === 'fixable' ? fix : state.filter === 'nofix' ? nofix : items)
    .filter(i => !q || `${i.pkg} ${i.cve || ''} ${i.id} ${(i.binaries || []).join(' ')}`.toLowerCase().includes(q));
  const rows = shown.slice(0, 500).map(i => {
    const [cls, txt] = SEV[i.severity] || SEV.unknown;
    const link = safeUrl(i.url);
    return `<tr><td><span class="pill ${cls}">${esc(txt)}</span>${i.score != null ? `<div class="dim small">CVSS ${esc(i.score)}</div>` : ''}</td>
      <td>${link ? `<a href="${esc(link)}" target="_blank" rel="noopener noreferrer">${esc(i.cve || i.id)}</a>` : esc(i.cve || i.id)}
        ${i.published ? `<div class="dim small">${esc(i.published)}</div>` : ''}</td>
      <td><b>${esc(i.pkg)}</b>${(i.binaries || []).length > 1 || ((i.binaries || [])[0] && i.binaries[0] !== i.pkg) ? `<div class="dim small">${esc((i.binaries || []).slice(0, 4).join(', '))}</div>` : ''}</td>
      <td class="small mono">${esc(i.installed)}${i.fixed ? `<div class="ok-text">→ ${esc(i.fixed)}</div>` : '<div class="dim">sem correção ainda</div>'}</td>
      <td class="small">${esc(i.summary || '')}</td></tr>`;
  }).join('');
  const fixBtns = fixButtons(s, { code: 'cve_fixable' });
  return `<div class="gauges">
      ${card('Com correção disponível', fix.length, fix.length ? 'warn-text' : 'ok-text', `${count(fix, ['critical'])} crítica(s) · ${count(fix, ['high'])} alta(s)`)}
      ${card('Altas e críticas com correção', count(fix, ['critical', 'high']), count(fix, ['critical', 'high']) ? 'crit-text' : 'ok-text', 'priorize estas')}
      ${card('Sem correção da distribuição', nofix.length, '', `${count(nofix, ['critical', 'high'])} alta(s) ou crítica(s)`)}
      ${card('Pacotes analisados', r.packages, '', `${esc(r.ecosystem)} · ${esc(ago(r.scanned_at))}`)}
    </div>
    <div class="panel"><h3>Corrigir <span class="r">${scanBtn}</span></h3>
      <p class="small muted">As correções chegam pelas atualizações da própria distribuição. Depois de aplicar, a análise roda de novo sozinha quando o agente envia a nova lista de pacotes. Algumas correções só valem após reiniciar (kernel, bibliotecas em uso).</p>
      <div class="fix">${fixBtns || '<span class="small muted">As ações de atualização exigem o agente no modo "all" ou "admin".</span>'}</div>
      ${(r.old_kernels || []).length ? `<p class="small mt">Há ${r.old_kernels.length} kernel(s) antigo(s) instalado(s) (${esc(r.old_kernels.join(', '))}). Eles não estão em uso e ficaram fora da contagem; remova com <b>Limpar cache de pacotes</b> na aba Ações.</p>` : ''}</div>
    <div class="toolbar"><span class="seg">
      <button data-vf="fixable" class="${state.filter === 'fixable' ? 'on' : ''}">Com correção (${fix.length})</button>
      <button data-vf="nofix" class="${state.filter === 'nofix' ? 'on' : ''}">Sem correção (${nofix.length})</button>
      <button data-vf="all" class="${state.filter === 'all' ? 'on' : ''}">Todas (${items.length})</button></span></div>
    <div class="panel"><div class="tbl-wrap"><table><thead><tr><th>Gravidade</th><th>Vulnerabilidade</th><th>Pacote</th><th>Versão</th><th>Descrição</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="5" class="muted">Nada aqui.</td></tr>'}</tbody></table></div>
      ${shown.length > 500 ? `<p class="small muted">Mostrando 500 de ${shown.length}; use o filtro.</p>` : ''}
      <p class="small muted">Fonte: OSV.dev (avisos oficiais da distribuição). O painel envia só o nome e a versão dos pacotes.</p></div>`;
}

export function bind(el, s, ctx) {
  el.querySelectorAll('[data-vf]').forEach(b => { b.onclick = () => { state.filter = b.dataset.vf; ctx.rerender(); }; });
  const scan = el.querySelector('#vscan');
  if (scan) scan.onclick = async () => {
    try { await api(`/api/servers/${s.id}/vulns/scan`, { method: 'POST' }); toast('Análise iniciada; a página atualiza sozinha.'); ctx.reload(); }
    catch (e) { toast(e.message); }
  };
}
