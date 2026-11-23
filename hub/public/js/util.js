// Formatação e escape. Todo dado que vem do agente passa por esc() ou N() antes de ir para o HTML.
export const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export const N = v => { const n = Number(v); return Number.isFinite(n) ? n : 0; };

export function bytes(n, dec = 1) {
  if (n == null || isNaN(n)) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']; let i = 0; n = Number(n);
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? dec : 0)} ${u[i]}`;
}
export const rate = n => (n == null ? '—' : bytes(n) + '/s');
export function dur(s) {
  if (s == null) return '—';
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}min` : `${m}min`;
}
export function ago(ts) {
  if (!ts) return 'nunca';
  const s = Date.now() / 1000 - ts;
  if (s < 60) return 'agora';
  if (s < 3600) return `há ${Math.floor(s / 60)} min`;
  if (s < 86400) return `há ${Math.floor(s / 3600)} h`;
  return `há ${Math.floor(s / 86400)} d`;
}
export const dt = ts => (ts ? new Date(ts * 1000).toLocaleString('pt-BR') : '—');
export const ipsOf = sys => ((sys && sys.ips) || []).map(i => String(i.addr).split('/')[0]);

// Grupo do status para filtros e cor das pílulas: "aguardando" conta como offline; offline pinta como crítico.
export const STATUS_GROUP = { ok: 'ok', warn: 'warn', crit: 'crit', offline: 'offline', pending: 'offline' };
export const STATUS_PILL = { ok: 'ok', warn: 'warn', crit: 'crit', offline: 'crit', pending: '' };

// Barra de uso. O nível (ok/warn/crit/info) vem pronto do hub, que é quem conhece os limites.
export const bar = (pct, level = 'ok') => `<div class="bar"><i class="${level === 'ok' ? '' : esc(level)}" style="width:${Math.min(100, N(pct))}%"></i></div>`;

export const LOGO = `<svg viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="8" fill="#5a44cd"/><path d="M13 9h6l1.5 16h-9z" fill="#f1f1f1"/><rect x="12.5" y="6" width="7" height="4" rx="1" fill="#e7f727"/><path d="M19.5 7.5 29 4v8z" fill="#e7f727" opacity=".55"/><rect x="9" y="25" width="14" height="2" rx="1" fill="#f1f1f1"/></svg>`;
