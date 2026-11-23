import { esc } from './util.js';

export function toast(msg) {
  const t = document.createElement('div');
  t.className = 'toast'; t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

export function modal(html, onMount) {
  const bg = document.createElement('div');
  bg.className = 'modal-bg';
  bg.innerHTML = `<div class="modal" role="dialog" aria-modal="true">${html}</div>`;
  const close = () => { bg.remove(); document.removeEventListener('keydown', onKey); };
  const onKey = e => { if (e.key === 'Escape') close(); };
  bg.addEventListener('click', e => { if (e.target === bg) close(); });
  document.addEventListener('keydown', onKey);
  document.body.appendChild(bg);
  bg.querySelectorAll('[data-close]').forEach(b => { b.onclick = close; });
  if (onMount) onMount(bg.querySelector('.modal'), close);
  return close;
}

export const copyBox = text => `<div class="copybox"><code>${esc(text)}</code><button type="button" class="btn sm" data-copy="${esc(text)}">Copiar</button></div>`;

export function bindCopy(root) {
  root.querySelectorAll('[data-copy]').forEach(b => {
    b.onclick = async () => {
      try { await navigator.clipboard.writeText(b.dataset.copy); b.textContent = 'Copiado'; }
      catch {
        const r = document.createRange(); r.selectNodeContents(b.previousElementSibling);
        getSelection().removeAllRanges(); getSelection().addRange(r); b.textContent = 'Use Ctrl+C';
      }
    };
  });
}

// Montador visual de agendamento: cada opção vira a expressão cron que o agente valida e grava.
const WEEKDAYS = ['domingo', 'segunda', 'terça', 'quarta', 'quinta', 'sexta', 'sábado'];
const num = (id, label, min, max, val) => `<div><label for="${id}">${label}</label><input type="number" id="${id}" min="${min}" max="${max}" value="${val}"></div>`;
const CRON_PRESETS = [
  { id: 'min', label: 'A cada N minutos', parts: () => num('c_every', 'Intervalo (minutos)', 1, 59, 5), build: v => `*/${v.c_every} * * * *` },
  { id: 'hour', label: 'De hora em hora', parts: () => num('c_minute', 'No minuto', 0, 59, 0), build: v => `${v.c_minute} * * * *` },
  { id: 'day', label: 'Todo dia', parts: () => num('c_hour', 'Hora', 0, 23, 3) + num('c_minute', 'Minuto', 0, 59, 0), build: v => `${v.c_minute} ${v.c_hour} * * *` },
  { id: 'week', label: 'Toda semana',
    parts: () => `<div><label for="c_weekday">Dia</label><select id="c_weekday">${WEEKDAYS.map((d, i) => `<option value="${i}">${d}</option>`).join('')}</select></div>`
      + num('c_hour', 'Hora', 0, 23, 3) + num('c_minute', 'Minuto', 0, 59, 0),
    build: v => `${v.c_minute} ${v.c_hour} * * ${v.c_weekday}` },
  { id: 'month', label: 'Todo mês', parts: () => num('c_monthday', 'Dia do mês', 1, 28, 1) + num('c_hour', 'Hora', 0, 23, 3) + num('c_minute', 'Minuto', 0, 59, 0),
    build: v => `${v.c_minute} ${v.c_hour} ${v.c_monthday} * *` },
  { id: 'reboot', label: 'Ao ligar o servidor', parts: () => '', build: () => '@reboot' },
  { id: 'custom', label: 'Personalizado (expressão cron)', parts: () => '<div><label for="c_custom">Expressão</label><input type="text" id="c_custom" placeholder="*/15 8-18 * * 1-5"></div>',
    build: v => v.c_custom || '' },
];

function cronValue(root, id) {
  const preset = CRON_PRESETS.find(p => p.id === root.querySelector(`#${id}_p`).value);
  const values = Object.fromEntries([...root.querySelectorAll(`#${id}_parts input, #${id}_parts select`)].map(i => [i.id, i.value.trim()]));
  return preset.build(values);
}

function bindCron(root, id) {
  const update = () => { root.querySelector(`#${id}_x`).textContent = cronValue(root, id); };
  const show = () => {
    const parts = root.querySelector(`#${id}_parts`);
    parts.innerHTML = CRON_PRESETS.find(p => p.id === root.querySelector(`#${id}_p`).value).parts();
    parts.oninput = update; parts.onchange = update;
    update();
  };
  root.querySelector(`#${id}_p`).onchange = show;
  show();
}

const fieldId = f => `f_${String(f.name).replace(/[^a-z_]/g, '')}`;

// Campos no formato que o agente declara:
// { name, label, type: text|textarea|select|bool|cron, pattern, options, required, placeholder, help, suggest }
export function formFields(fields, values = {}, suggestions = {}) {
  return fields.map(f => {
    const id = fieldId(f);
    const v = values[f.name];
    const help = f.help ? `<div class="hint">${esc(f.help)}</div>` : '';
    if (f.type === 'bool') return `<label class="check"><input type="checkbox" id="${id}" ${v ? 'checked' : ''}> ${esc(f.label)}</label>${help}`;
    let input;
    if (f.type === 'cron') {
      input = `<select id="${id}_p">${CRON_PRESETS.map(p => `<option value="${p.id}">${p.label}</option>`).join('')}</select>
        <div id="${id}_parts" class="row-fields"></div><div class="preview">Expressão: <code id="${id}_x"></code></div>`;
      return `<label for="${id}_p">${esc(f.label)}</label>${input}${help}`;
    }
    if (f.type === 'select') {
      input = `<select id="${id}">${(f.options || []).map(o => `<option ${o === v ? 'selected' : ''}>${esc(o)}</option>`).join('')}</select>`;
    } else if (f.type === 'textarea') {
      // Sugestões com rótulo (ex.: chaves SSH salvas) viram um seletor que preenche o campo.
      const list = (suggestions[f.suggest] || []).filter(o => o && o.value);
      input = (list.length ? `<select data-fill="${id}"><option value="">Escolher uma chave cadastrada…</option>${list.map(o =>
        `<option value="${esc(o.value)}">${esc(o.label)}</option>`).join('')}</select>` : '')
        + `<textarea id="${id}" rows="3" placeholder="${esc(f.placeholder || '')}">${esc(v || '')}</textarea>`;
    } else {
      const list = suggestions[f.suggest];
      input = `<input type="text" id="${id}" value="${esc(v || '')}" placeholder="${esc(f.placeholder || '')}" autocomplete="off"${list ? ` list="${id}_l"` : ''}>`
        + (list ? `<datalist id="${id}_l">${list.map(o => `<option value="${esc(o)}">`).join('')}</datalist>` : '');
    }
    return `<label for="${id}">${esc(f.label)}${f.required === false ? ' <span class="dim">(opcional)</span>' : ''}</label>${input}${help}`;
  }).join('');
}

// Liga os campos que têm comportamento próprio (hoje, o montador de cron). Chamar depois de inserir formFields.
export function bindFields(root, fields) {
  for (const f of fields) if (f.type === 'cron') bindCron(root, fieldId(f));
  root.querySelectorAll('select[data-fill]').forEach(s => { s.onchange = () => { if (s.value) root.querySelector('#' + s.dataset.fill).value = s.value; }; });
}

export function readForm(root, fields) {
  const out = {};
  for (const f of fields) {
    const id = fieldId(f);
    if (f.type === 'bool') { out[f.name] = root.querySelector(`#${id}`).checked; continue; }
    const v = f.type === 'cron' ? cronValue(root, id) : root.querySelector(`#${id}`).value.trim();
    if (!v && f.required !== false) throw new Error(`Preencha: ${f.label}`);
    if (v && f.pattern) {
      let re = null;
      try { re = new RegExp(f.pattern); } catch { /* padrão no dialeto do Python: o agente valida */ }
      if (re && !re.test(v)) throw new Error(`Valor inválido em ${f.label}`);
    }
    if (v) out[f.name] = v;
  }
  return out;
}
