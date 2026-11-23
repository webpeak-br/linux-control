import { esc, N, bytes, rate } from '../../util.js';

export const label = 'Rede';

const exposure = addr => (/^(0\.0\.0\.0|\*|\[::\]|::)$/.test(addr) ? '<span class="pill warn">todas as interfaces</span>'
  : /^(127\.|\[::1\]|::1)/.test(addr) ? '<span class="pill ok">só local</span>' : '<span class="pill">interface específica</span>');

export function body(s) {
  const inv = s.inventory || {}, net = (s.metrics || {}).net || {};
  const rows = (inv.ports || []).map(p => `<tr><td class="num"><b>${esc(p.port)}</b></td><td>${esc(p.proto)}</td><td class="mono">${esc(p.addr)}</td>
    <td>${exposure(p.addr)}</td><td>${esc(p.process) || '<span class="dim">—</span>'}${p.pid ? ` <span class="dim">(pid ${N(p.pid)})</span>` : ''}</td></tr>`).join('');
  const sites = (inv.websites || []).map(w => `<tr><td>${(w.domains || []).map(esc).join('<br>') || '<span class="dim">(padrão)</span>'}</td><td>${esc(w.server)}</td>
    <td class="small">${esc((w.listen || []).join(', '))}</td><td class="small mono">${[...(w.root || []), ...(w.proxy || [])].map(esc).join('<br>')}</td>
    <td class="small dim mono">${esc(w.file)}</td></tr>`).join('');
  return `<div class="gauges"><div class="gauge"><div class="l">Download agora</div><div class="v">${rate(net.rx_bps)}</div><div class="s">total ${bytes(net.rx_total)} desde o boot</div></div>
    <div class="gauge"><div class="l">Upload agora</div><div class="v">${rate(net.tx_bps)}</div><div class="s">total ${bytes(net.tx_total)} desde o boot</div></div></div>
    <div class="panel"><h3>Portas abertas <span class="r dim small">${(inv.ports || []).length} sockets escutando</span></h3>
      <div class="tbl-wrap"><table><thead><tr><th class="num">Porta</th><th>Protocolo</th><th>Endereço</th><th>Exposição</th><th>Processo</th></tr></thead><tbody>${rows}</tbody></table></div></div>
    ${sites ? `<div class="panel"><h3>Sites configurados (Nginx/Apache)</h3><div class="tbl-wrap"><table><thead><tr><th>Domínios</th><th>Servidor</th><th>Escuta</th><th>Destino</th><th>Arquivo</th></tr></thead><tbody>${sites}</tbody></table></div></div>` : ''}`;
}
