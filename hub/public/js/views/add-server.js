import { api } from '../api.js';
import { esc } from '../util.js';
import { modal, copyBox, bindCopy } from '../ui.js';

export function addServerModal(onDone) {
  modal(`<h2>Adicionar servidor</h2><p>Dê um nome. Em seguida você recebe o comando de instalação do agente.</p>
    <form id="sf"><label for="sn">Nome</label><input type="text" id="sn" placeholder="ex.: web-producao-01" maxlength="80">
    <label for="st">Tags <span class="dim">(opcional, separadas por vírgula)</span></label><input type="text" id="st" placeholder="ex.: produção, cliente-x">
    <div class="err" id="se"></div>
    <div class="foot"><button type="button" class="btn ghost" data-close>Cancelar</button><button class="btn primary">Gerar comando</button></div></form>`,
  (box, close) => {
    box.querySelector('#sn').focus();
    box.querySelector('#sf').onsubmit = async e => {
      e.preventDefault();
      try {
        const r = await api('/api/servers', { method: 'POST', body: { name: box.querySelector('#sn').value, tags: box.querySelector('#st').value } });
        showInstall(box, r, close, onDone);
      } catch (err) { box.querySelector('#se').textContent = err.message; }
    };
  });
}

function showInstall(box, r, close, onDone) {
  box.innerHTML = `<h2>Instale o agente</h2>
    <p>Rode no servidor (como root ou com sudo). Instala um agente leve em Python, sem dependências, como serviço systemd.</p>
    ${copyBox(r.install)}
    <details class="small" style="margin-top:12px"><summary>Outros modos de instalação</summary>
      <p class="muted">Somente leitura (nenhuma ação altera o servidor):</p>${copyBox(r.install_modes.readonly)}
      <p class="muted">Admin (libera criar usuários, cron e instaladores pelo painel):</p>${copyBox(r.install_modes.admin)}</details>
    ${/^https:/.test(r.hub_url) ? '' : '<p class="small warn-text">Atenção: o painel não está em HTTPS. Em produção use HTTPS e defina LCTL_PUBLIC_URL.</p>'}
    <p class="small muted">O token aparece só agora. O servidor precisa alcançar <code>${esc(r.hub_url)}</code>.</p>
    <div class="waiting" id="wt"><div class="spin"></div>Aguardando o primeiro contato do agente…</div>
    <div class="foot"><button class="btn" id="cl">Fechar</button><a class="btn primary" href="#/server/${Number(r.id)}" id="go">Abrir servidor</a></div>`;
  bindCopy(box);
  box.querySelector('#cl').onclick = () => { close(); onDone(); };
  box.querySelector('#go').onclick = () => close();
  const poll = setInterval(async () => {
    if (!document.body.contains(box)) return clearInterval(poll);
    const d = await api(`/api/servers/${r.id}`).catch(() => null);
    if (d && d.server.last_seen) {
      clearInterval(poll);
      box.querySelector('#wt').innerHTML = '<span class="dot ok"></span> Agente conectado. Tudo certo!';
    }
  }, 3000);
}
