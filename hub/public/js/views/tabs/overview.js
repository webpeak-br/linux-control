import { api } from '../../api.js';
import { esc, N, bar, bytes, rate, dt, ago } from '../../util.js';
import { chartsHtml, bindCharts } from '../../chart.js';
import { fixButtons } from '../../actions.js';

export const label = 'Visão geral';
export const state = { range: '1h' };
let history = null, historyAt = 0, historyFor = null;
const HISTORY_EVERY = 30_000;

export async function load(s) {
  if (historyFor !== s.id || Date.now() - historyAt > HISTORY_EVERY) await loadHistory(s.id);
}
async function loadHistory(id) {
  history = await api(`/api/servers/${id}/history?range=${state.range}`);
  historyAt = Date.now(); historyFor = id;
}

export function body(s) {
  const m = s.metrics || {}, inv = s.inventory || {}, sys = inv.system || {}, mem = m.mem || {}, lv = s.levels || {};
  const issues = s.health.issues.length
    ? s.health.issues.map(i => {
      const btns = fixButtons(s, i) + (i.see ? `<a class="btn sm ghost" href="#/server/${s.id}/${esc(i.see)}">Ver detalhes</a>` : '');
      return `<div class="issue"><span class="dot ${i.level}"></span><span class="txt">${esc(i.text)}</span><span class="area">${esc(i.area)}</span>
        ${btns ? `<div class="fix">${btns}</div>` : ''}</div>`;
    }).join('')
    : '<div class="issue"><span class="dot ok"></span>Nenhum problema detectado.</div>';
  const disks = (m.disks || []).map(d => `<tr><td>${esc(d.mount)}<div class="dim small">${esc(d.fs)} · ${bytes(d.free)} livres · inodes ${N(d.inode_pct)}%</div></td>
    <td class="w35">${bar(d.pct, (lv.disks || {})[d.mount])}</td><td class="num">${N(d.pct)}%</td><td class="num">${bytes(d.used)} / ${bytes(d.total)}</td></tr>`).join('');
  return `
    <div class="gauges">
      <div class="gauge"><div class="l">CPU</div><div class="v">${N(m.cpu).toFixed(0)}%</div>${bar(m.cpu, lv.cpu)}<div class="s">${N(m.ncpu) || '?'} núcleos · load ${(m.load || []).map(x => N(x).toFixed(2)).join(' ')}</div></div>
      <div class="gauge"><div class="l">Memória</div><div class="v">${N(mem.pct).toFixed(0)}%</div>${bar(mem.pct, lv.mem)}<div class="s">${bytes(mem.used)} de ${bytes(mem.total)}${mem.swap_total ? ` · swap ${N(mem.swap_pct)}%` : ''}</div></div>
      <div class="gauge"><div class="l">Disco mais cheio</div><div class="v">${N(lv.disk_pct).toFixed(0)}%</div>${bar(lv.disk_pct, lv.disk)}<div class="s">${esc(lv.disk_mount || '—')}</div></div>
      <div class="gauge"><div class="l">Rede</div><div class="v net">↓ ${rate(m.net && m.net.rx_bps)}<br>↑ ${rate(m.net && m.net.tx_bps)}</div><div class="s">${N((m.procs || {}).count)} processos</div></div>
    </div>
    <div class="panel"><h3>Diagnóstico</h3><div class="issues">${issues}</div></div>
    <div class="panel"><h3>Histórico <span class="r"><span class="seg" id="range">${((history && history.ranges) || []).map(r => `<button data-r="${esc(r)}" class="${state.range === r ? 'on' : ''}">${esc(r)}</button>`).join('')}</span></span></h3>
      <div id="charts">${chartsHtml(history, state.range)}</div></div>
    <div class="cols">
      <div class="panel"><h3>Sistema</h3><dl class="kv">
        <dt>Hostname</dt><dd>${esc(sys.hostname)}</dd><dt>Sistema</dt><dd>${esc(sys.os)}</dd>
        <dt>Kernel</dt><dd>${esc(sys.kernel)} (${esc(sys.arch)})</dd><dt>CPU</dt><dd>${esc(sys.cpu_model)} · ${N(sys.cores)} núcleos</dd>
        <dt>Memória</dt><dd>${bytes(mem.total)}</dd><dt>Virtualização</dt><dd>${esc(sys.virt)}</dd>
        <dt>Fuso horário</dt><dd>${esc(sys.timezone)} ${sys.ntp_synced === true ? '<span class="pill ok">NTP ok</span>' : sys.ntp_synced === false ? '<span class="pill warn">NTP fora</span>' : ''}</dd>
        <dt>Ligado desde</dt><dd>${dt(sys.boot_time)}</dd>
        <dt>IPs</dt><dd>${(sys.ips || []).map(i => `${esc(i.addr)} <span class="dim">(${esc(i.iface)})</span>`).join('<br>') || '—'}</dd>
        <dt>Agente</dt><dd>v${esc(s.agent_version)} · Python ${esc(sys.python)} · ${sys.is_root ? 'root' : '<span class="pill warn">sem root</span>'} · ações: ${esc(inv.actions_mode)}</dd>
        <dt>Inventário</dt><dd>${ago(s.inventory_at)}</dd></dl></div>
      <div class="panel"><h3>Discos</h3><div class="tbl-wrap"><table><tbody>${disks || '<tr><td class="muted">Sem dados</td></tr>'}</tbody></table></div></div>
    </div>`;
}

export function bind(el, s, ctx) {
  if (history) bindCharts(el, history);
  el.querySelectorAll('#range [data-r]').forEach(b => {
    b.onclick = async () => { state.range = b.dataset.r; await loadHistory(s.id); ctx.rerender(); };
  });
}
