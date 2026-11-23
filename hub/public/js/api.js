// Única porta de saída para o hub. 401 leva de volta ao login (menos quando o chamador trata, com quiet401).
// Falha de rede mostra um aviso fixo até a próxima resposta bem-sucedida.
let onUnauthorized = () => {};
export const setUnauthorizedHandler = fn => { onUnauthorized = fn; };

function offline(on) {
  let bar = document.getElementById('offline');
  if (on && !bar) {
    bar = document.createElement('div');
    bar.id = 'offline'; bar.className = 'offline-banner';
    bar.textContent = 'Sem conexão com o painel. Tentando de novo…';
    document.body.appendChild(bar);
  } else if (!on && bar) bar.remove();
}

export async function api(path, { method = 'GET', body, quiet401 = false } = {}) {
  let res;
  try {
    res = await fetch(path, {
      method,
      headers: { 'Content-Type': 'application/json', 'X-LCtl': '1' },
      body: body ? JSON.stringify(body) : undefined,
      credentials: 'same-origin',
    });
  } catch (e) {
    offline(true);
    throw new Error('Sem conexão com o painel.');
  }
  offline(false);
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && !quiet401) { onUnauthorized(); throw new Error('não autenticado'); }
  if (!res.ok) throw new Error(data.error || `Erro ${res.status}`);
  return data;
}
