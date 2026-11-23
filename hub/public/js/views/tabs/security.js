import { esc, N, dt } from '../../util.js';

export const label = 'Segurança';

const SSH_ROWS = [['port', 'Porta'], ['permitrootlogin', 'Login de root'], ['passwordauthentication', 'Login por senha'], ['pubkeyauthentication', 'Login por chave']];

export function body(s) {
  const inv = s.inventory || {}, sec = inv.security || {}, ssh = sec.ssh || {}, fw = sec.firewall || {}, us = inv.users || {};
  const lv = s.levels || {};
  const sshValue = k => (ssh[k] === undefined ? '<span class="dim">—</span>'
    : k === 'port' ? esc(ssh[k]) : `<span class="pill ${(lv.ssh || {})[k] || 'ok'}">${esc(ssh[k])}</span>`);
  const att = (sec.top_attackers || []).map(([ip, n]) => `<tr><td class="mono">${esc(ip)}</td><td class="num">${N(n)}</td></tr>`).join('');
  const certs = (inv.certificates || []).map(c => `<tr><td>${esc(c.name)}</td><td>${dt(c.expires)}</td>
    <td><span class="pill ${(lv.certificates || {})[c.name] || 'ok'}">${c.days_left < 0 ? 'expirado' : N(c.days_left) + ' dias'}</span></td></tr>`).join('');
  return `<div class="cols">
    <div class="panel"><h3>SSH</h3><dl class="kv">${SSH_ROWS.map(([k, l]) => `<dt>${l}</dt><dd>${sshValue(k)}</dd>`).join('')}
      <dt>Falhas em 24h</dt><dd><b>${sec.failed_logins_24h == null ? '—' : N(sec.failed_logins_24h)}</b> tentativas</dd></dl>
      ${att ? `<h3 class="mt">IPs que mais tentaram</h3><table><tbody>${att}</tbody></table>` : ''}</div>
    <div class="panel"><h3>Firewall e proteção</h3><dl class="kv">
      <dt>Firewall</dt><dd>${fw.active ? `<span class="pill ok">ativo</span> ${esc(fw.type)}` : '<span class="pill warn">não detectado</span>'}</dd>
      <dt>Atualizações automáticas</dt><dd>${sec.auto_updates === undefined ? '—' : sec.auto_updates ? '<span class="pill ok">ativas</span>' : '<span class="pill warn">desativadas</span>'}</dd>
      <dt>Reinício pendente</dt><dd>${sec.reboot_required ? `<span class="pill warn">sim</span> <span class="small muted">${esc((sec.reboot_pkgs || []).join(', '))}</span>` : 'não'}</dd>
      <dt>Fail2ban</dt><dd>${sec.fail2ban ? `<pre class="raw">${esc(sec.fail2ban)}</pre>` : '<span class="dim">não instalado</span>'}</dd></dl>
      ${fw.summary ? `<pre class="raw mt">${esc(fw.summary)}</pre>` : ''}</div></div>
    ${certs ? `<div class="panel mt"><h3>Certificados SSL (Let's Encrypt)</h3><table><thead><tr><th>Domínio</th><th>Expira em</th><th></th></tr></thead><tbody>${certs}</tbody></table></div>` : ''}
    ${us.last_logins ? `<div class="panel mt"><h3>Últimos acessos</h3><pre class="raw">${esc(us.last_logins)}</pre></div>` : ''}`;
}
