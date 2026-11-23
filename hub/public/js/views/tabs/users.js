import { esc, N } from '../../util.js';
import { rowButtons, placementButtons, adminHint } from '../../actions.js';

export const label = 'Usuários';

export function body(s) {
  const us = (s.inventory || {}).users || {};
  const rows = (us.accounts || []).map(u => `<tr><td><b>${esc(u.name)}</b>${u.locked ? ' <span class="pill warn">bloqueado</span>' : ''}</td>
    <td class="num">${N(u.uid)}</td><td>${u.sudo ? '<span class="pill warn">admin</span>' : ''}</td><td class="num">${N(u.ssh_keys)}</td>
    <td class="small mono muted">${esc(u.home)}</td><td class="small mono muted">${esc(u.shell)}</td>
    <td class="acts">${rowButtons(s, 'user', u)}</td></tr>`).join('');
  const add = placementButtons(s, 'users');
  return `${adminHint(s, 'Criar e gerenciar usuários')}
    <div class="panel"><h3>Contas com acesso ao shell ${add ? `<span class="r">${add}</span>` : ''}</h3>
    <div class="tbl-wrap"><table><thead><tr><th>Usuário</th><th class="num">UID</th><th>Privilégio</th><th class="num">Chaves SSH</th><th>Home</th><th>Shell</th><th></th></tr></thead>
    <tbody>${rows}</tbody></table></div></div>`;
}
