import { esc, N, bytes, bar } from '../../util.js';
import { placementButtons } from '../../actions.js';

export const label = 'Discos';
export const show = s => !!(s.inventory || {}).disk_health;

const n = v => (v == null ? '—' : esc(v));
const pill = (cls, txt) => `<span class="pill ${cls}">${esc(txt)}</span>`;

function status(d) {
  const bad = (d.pending || 0) + (d.offline_uncorrectable || 0) + (d.reported_uncorrect || 0) + (d.media_errors || 0);
  if (d.smart_passed === false || bad > 0 || d.critical_warning || (d.last_test && d.last_test.passed === false)) return pill('crit', 'com defeito');
  if (d.reallocated > 0 || d.wear_pct >= 90) return pill('warn', 'atenção');
  return d.smart_passed ? pill('ok', 'saudável') : pill('', 'sem dados');
}

// Para HD/SSD SATA mostra os setores; para NVMe, erros de mídia e desgaste.
function sectors(d) {
  if (d.protocol === 'NVMe') return `erros de mídia ${n(d.media_errors)}<div class="dim small">reserva ${n(d.spare_pct)}%</div>`;
  return `remapeados ${n(d.reallocated)} · pendentes ${n(d.pending)}<div class="dim small">irrecuperáveis ${n(d.offline_uncorrectable)}</div>`;
}

export function body(s) {
  const dh = s.inventory.disk_health, lv = s.levels || {};
  const m = s.metrics || {};
  const top = placementButtons(s, 'disks');
  const rows = (dh.devices || []).map(d => `<tr><td><b>${esc(d.name)}</b><div class="dim small">${esc(d.model)} · ${d.protocol === 'NVMe' ? 'NVMe' : d.rotational ? 'HD' : 'SSD'}</div></td>
    <td class="num">${d.capacity ? bytes(d.capacity) : '—'}</td><td>${status(d)}</td><td class="small">${sectors(d)}</td>
    <td class="num">${d.wear_pct != null ? `${N(d.wear_pct)}%` : '—'}</td><td class="num">${d.temperature != null ? `${N(d.temperature)} °C` : '—'}</td>
    <td class="num">${d.power_on_hours != null ? `${Math.round(N(d.power_on_hours) / 24)} dias` : '—'}</td>
    <td class="small">${d.last_test ? `${esc(d.last_test.type)}<div class="dim small">${esc(d.last_test.status)}</div>` : '—'}</td></tr>`).join('');
  const why = !dh.smartctl ? (dh.virtual
    ? 'Máquina virtual: o disco físico pertence ao provedor e não expõe SMART. Os erros de leitura e gravação abaixo continuam valendo.'
    : 'O monitor de disco (smartmontools) não está instalado. Use o botão "Instalar monitor de disco" acima.')
    : 'Nenhum disco com SMART encontrado' + (dh.virtual ? ' (máquina virtual: o disco físico é do provedor).' : '.');
  const errs = dh.io_error_lines || [];
  const usage = (m.disks || []).map(d => `<tr><td>${esc(d.mount)}</td><td class="w35">${bar(d.pct, (lv.disks || {})[d.mount])}</td><td class="num">${N(d.pct)}%</td><td class="num">${bytes(d.free)} livres</td></tr>`).join('');
  return `<div class="panel"><h3>Saúde física ${top ? `<span class="r">${top}</span>` : ''}</h3>
      ${rows ? `<div class="tbl-wrap"><table><thead><tr><th>Disco</th><th class="num">Tamanho</th><th>Estado</th><th>Setores</th><th class="num">Desgaste</th>
        <th class="num">Temp.</th><th class="num">Ligado</th><th>Último teste</th></tr></thead><tbody>${rows}</tbody></table></div>`
        : `<div class="empty small">${esc(why)}</div>`}
      <p class="small muted">Setores pendentes ou irrecuperáveis indicam disco falhando: faça backup e planeje a troca. Remapeados mostram defeitos que o disco já contornou; se o número crescer, o disco está se deteriorando.</p></div>
    <div class="panel"><h3>Erros de leitura e gravação (últimas 24 h) <span class="r">${errs.length ? pill('crit', `${N(dh.io_errors_24h)} erros`) : pill('ok', 'nenhum')}</span></h3>
      ${errs.length ? `<pre class="out">${esc(errs.join('\n'))}</pre>` : '<div class="muted small">O kernel não registrou erros de disco nas últimas 24 horas.</div>'}</div>
    <div class="panel"><h3>Espaço</h3><div class="tbl-wrap"><table><tbody>${usage || '<tr><td class="muted">Sem dados</td></tr>'}</tbody></table></div></div>`;
}
