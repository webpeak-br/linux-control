// Gráficos de linha em SVG. Cada série define onde está o valor, a cor e como formatar.
import { N, bytes, rate } from './util.js';

const W = 600, H = 190, L = 38, R = 6, T = 8, B = 20;

const CHARTS = [
  { id: 'cpu', max: 100, unit: '%', series: [{ k: 'cpu', c: '#b5bafe', n: 'CPU' }] },
  { id: 'mem', max: 100, unit: '%', series: [{ k: 'mem', c: '#e7f727', n: 'Memória' }, { k: 'swap', c: '#f5b041', n: 'Swap' }] },
  { id: 'disk', max: 100, unit: '%', series: [{ k: 'disk', c: '#3ecf8e', n: 'Disco mais cheio' }] },
  { id: 'net', max: null, unit: 'B/s', series: [{ k: 'rx', c: '#7aa7ff', n: 'Download' }, { k: 'tx', c: '#ff8fb1', n: 'Upload' }] },
];

const fmtValue = (v, unit) => (unit === 'B/s' ? rate(v) : `${N(v).toFixed(1)}${unit}`);

export function chartsHtml(history, range) {
  if (!history) return '<div class="muted small">Carregando…</div>';
  if (!history.points.length) return '<div class="muted small">Sem histórico ainda.</div>';
  return `<div class="charts">${CHARTS.map(c => chartSvg(c, history.points, range)).join('')}</div>`;
}

function chartSvg(chart, pts, range) {
  const t0 = pts[0].t, t1 = pts[pts.length - 1].t || t0 + 1;
  const max = chart.max || Math.max(1, ...pts.flatMap(p => chart.series.map(s => N(p[s.k])))) * 1.15;
  const x = t => L + (W - L - R) * ((t - t0) / Math.max(1, t1 - t0));
  const y = v => T + (H - T - B) * (1 - Math.min(1, N(v) / max));
  const label = v => (chart.unit === 'B/s' ? bytes(v, 0) : `${Math.round(v)}${chart.unit}`);
  const tf = t => new Date(t * 1000).toLocaleString('pt-BR', range === '7d' ? { day: '2-digit', month: '2-digit' } : { hour: '2-digit', minute: '2-digit' });
  let g = '';
  for (let i = 0; i <= 4; i++) {
    const yy = y(max * i / 4);
    g += `<line class="grid-l" x1="${L}" x2="${W - R}" y1="${yy}" y2="${yy}"/><text class="axis" x="${L - 4}" y="${yy + 3}" text-anchor="end">${label(max * i / 4)}</text>`;
  }
  g += `<text class="axis" x="${L}" y="${H - 4}">${tf(t0)}</text><text class="axis" x="${W - R}" y="${H - 4}" text-anchor="end">${tf(t1)}</text>`;
  const paths = chart.series.map((s, i) => {
    const line = pts.map((p, j) => `${j ? 'L' : 'M'}${x(p.t).toFixed(1)},${y(p[s.k]).toFixed(1)}`).join('');
    const area = i === 0 ? `<path d="${line}L${x(t1)},${H - B}L${L},${H - B}Z" fill="${s.c}" opacity=".08"/>` : '';
    return `${area}<path d="${line}" fill="none" stroke="${s.c}" stroke-width="1.6" stroke-linejoin="round"/>`;
  }).join('');
  return `<div><div class="legend">${chart.series.map(s => `<span><i style="background:${s.c}"></i>${s.n}</span>`).join('')}</div>
    <div class="chart-wrap" data-chart="${chart.id}"><svg class="chart" viewBox="0 0 ${W} ${H}">${g}${paths}
    <line class="hover-l" x1="0" x2="0" y1="${T}" y2="${H - B}" style="display:none"/></svg><div class="tip"></div></div></div>`;
}

export function bindCharts(root, history) {
  root.querySelectorAll('[data-chart]').forEach(wrap => {
    const chart = CHARTS.find(c => c.id === wrap.dataset.chart);
    const svg = wrap.querySelector('svg'), tip = wrap.querySelector('.tip'), hl = svg.querySelector('.hover-l');
    const pts = history.points;
    svg.onmousemove = e => {
      const r = svg.getBoundingClientRect();
      const rel = Math.min(1, Math.max(0, ((e.clientX - r.left) / r.width - L / W) / (1 - (L + R) / W)));
      const p = pts[Math.round(rel * (pts.length - 1))];
      if (!p) return;
      const xx = L + (W - L - R) * ((p.t - pts[0].t) / Math.max(1, pts[pts.length - 1].t - pts[0].t));
      hl.setAttribute('x1', xx); hl.setAttribute('x2', xx); hl.style.display = '';
      tip.style.display = 'block';
      tip.textContent = `${new Date(p.t * 1000).toLocaleString('pt-BR')} · ` + chart.series.map(s => `${s.n} ${fmtValue(p[s.k], chart.unit)}`).join(' · ');
      tip.style.left = Math.min(r.width - tip.offsetWidth - 4, Math.max(0, e.clientX - r.left + 12)) + 'px';
    };
    svg.onmouseleave = () => { tip.style.display = 'none'; hl.style.display = 'none'; };
  });
}
