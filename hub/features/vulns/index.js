'use strict';
// Vulnerabilidades (CVE) dos pacotes instalados. O hub consulta a base pública OSV.dev (que agrega os avisos
// oficiais do Ubuntu, Debian, AlmaLinux, Rocky e Alpine) com nome e versão de cada pacote; nada mais sai do painel.
// Desligue com LCTL_CVE=0. Detalhes de cada aviso ficam em cache por 7 dias.
const { HttpError } = require('../../core/http');

const migrations = [{ name: 'vulns:1', sql: [
  'CREATE TABLE IF NOT EXISTS vuln_cache (id TEXT PRIMARY KEY, data TEXT, at INTEGER)',
  'CREATE TABLE IF NOT EXISTS server_vulns (server_id INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE, data TEXT, at INTEGER, packages_at INTEGER)',
] },
// v0.8.0 guardava o aviso inteiro no cache (pesado); o resumo do diagnóstico passa a ter coluna própria.
{ name: 'vulns:2', sql: ['DELETE FROM vuln_cache'] },
{ name: 'vulns:3', tolerant: true, sql: ['ALTER TABLE server_vulns ADD COLUMN summary TEXT'] },
// v0.8.2: kernels antigos fora da contagem; reanalisa tudo.
{ name: 'vulns:4', sql: ['UPDATE server_vulns SET packages_at = -1'] },
// v0.8.3: separa correção para instalar de correção que ainda não chegou ao servidor.
{ name: 'vulns:5', sql: ['UPDATE server_vulns SET packages_at = -1'] }];
const CACHE_SECONDS = 7 * 86400;
const BATCH = 1000;
const MAX_VULNS = 5000;
const PARALLEL = 4;
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'negligible', 'unknown'];

// Ecossistema OSV a partir do /etc/os-release que o agente envia.
function ecosystemOf(sys = {}) {
  const id = String(sys.os_id || '').toLowerCase();
  const v = String(sys.os_version_id || '');
  if (!v) return null;
  if (id === 'ubuntu') return `Ubuntu:${v}${/LTS/.test(sys.os || '') ? ':LTS' : ''}`;
  if (id === 'debian') return `Debian:${v.split('.')[0]}`;
  if (id === 'almalinux') return `AlmaLinux:${v.split('.')[0]}`;
  if (id === 'rocky') return `Rocky Linux:${v.split('.')[0]}`;
  if (id === 'alpine') return `Alpine:v${v.split('.').slice(0, 2).join('.')}`;
  return null;
}

// Nota base do CVSS 3.x a partir do vetor (especificação FIRST).
function cvss3Score(vector) {
  const m = Object.fromEntries(String(vector || '').split('/').slice(1).map(p => p.split(':')));
  const W = { AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }, AC: { L: 0.77, H: 0.44 }, UI: { N: 0.85, R: 0.62 }, CIA: { H: 0.56, L: 0.22, N: 0 } };
  if (!m.AV || !m.AC || !m.PR || !m.UI || !m.S || !m.C || !m.I || !m.A) return null;
  const changed = m.S === 'C';
  const pr = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR];
  const iss = 1 - (1 - W.CIA[m.C]) * (1 - W.CIA[m.I]) * (1 - W.CIA[m.A]);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const expl = 8.22 * W.AV[m.AV] * W.AC[m.AC] * pr * W.UI[m.UI];
  if (impact <= 0) return 0;
  const roundup = x => Math.ceil(x * 10 - 1e-9) / 10;
  return roundup(Math.min(changed ? 1.08 * (impact + expl) : impact + expl, 10));
}

const fromScore = s => (s == null ? 'unknown' : s >= 9 ? 'critical' : s >= 7 ? 'high' : s >= 4 ? 'medium' : s > 0 ? 'low' : 'negligible');

// Resume um aviso OSV para um pacote: CVE, gravidade (a da distribuição vale mais), versão que corrige e link.
function summarize(vuln, pkg, ecosystem) {
  const sev = vuln.severity || [];
  const cvss = sev.find(s => /^CVSS_V3/.test(s.type));
  const score = cvss ? cvss3Score(cvss.score) : null;
  const distro = sev.find(s => s.type === 'Ubuntu');
  let severity = distro && SEVERITIES.includes(String(distro.score).toLowerCase()) ? String(distro.score).toLowerCase() : fromScore(score);
  if (severity === 'unknown' && vuln.database_specific && vuln.database_specific.severity) severity = String(vuln.database_specific.severity).toLowerCase();
  if (!SEVERITIES.includes(severity)) severity = 'unknown';
  const aff = (vuln.affected || []).find(a => a.package && a.package.name === pkg.name && a.package.ecosystem === ecosystem);
  const fixed = aff ? ((aff.ranges || []).flatMap(r => r.events || []).map(e => e.fixed).filter(Boolean).pop() || null) : null;
  const cve = [vuln.id, ...(vuln.upstream || []), ...(vuln.aliases || [])].find(x => /^CVE-\d{4}-\d+$/.test(x)) || null;
  const url = cve && /^Ubuntu/.test(ecosystem) ? `https://ubuntu.com/security/${cve}`
    : cve && /^Debian/.test(ecosystem) ? `https://security-tracker.debian.org/tracker/${cve}` : `https://osv.dev/vulnerability/${encodeURIComponent(vuln.id)}`;
  const text = String(vuln.summary || vuln.details || '').replace(/\s+/g, ' ').replace(/^Issue summary:\s*/i, '').trim();
  return { id: vuln.id, cve, pkg: pkg.name, installed: pkg.version, binaries: pkg.binaries, fixed, severity, score, summary: text.slice(0, 240), url,
    published: vuln.published ? String(vuln.published).slice(0, 10) : null };
}

// Guarda do aviso só o que o painel usa: os registros da OSV listam versões de várias distribuições e podem
// ter centenas de KB; inteiros, estouram a memória de um hub pequeno.
const KNOWN_ECOSYSTEM = /^(Ubuntu|Debian|AlmaLinux|Rocky Linux|Alpine)/;
function slim(v) {
  return {
    id: v.id, upstream: v.upstream, aliases: (v.aliases || []).filter(a => /^CVE-/.test(a)), published: v.published,
    summary: String(v.summary || v.details || '').replace(/\s+/g, ' ').slice(0, 400),
    severity: (v.severity || []).filter(s => /^CVSS_V3/.test(s.type) || s.type === 'Ubuntu'),
    database_specific: v.database_specific && v.database_specific.severity ? { severity: v.database_specific.severity } : undefined,
    affected: (v.affected || []).filter(a => a.package && KNOWN_ECOSYSTEM.test(a.package.ecosystem || '')).map(a => ({
      package: { name: a.package.name, ecosystem: a.package.ecosystem },
      ranges: [{ events: (a.ranges || []).flatMap(r => r.events || []).filter(e => e.fixed) }],
    })),
  };
}

// Pacotes a consultar: no Debian/Ubuntu, o pacote-fonte (os avisos são por fonte), com os binários instalados dele.
function queriesFrom(installed, ecosystem) {
  const deb = /^(Ubuntu|Debian)/.test(ecosystem);
  const map = new Map();
  for (const row of installed || []) {
    const [name, version, src, srcVersion] = row;
    const qName = deb && src ? src : name, qVersion = deb && srcVersion ? srcVersion : version;
    const key = `${qName} ${qVersion}`;
    if (!map.has(key)) map.set(key, { name: qName, version: qVersion, binaries: [] });
    map.get(key).binaries.push(name);
  }
  // O Ubuntu/Debian guarda kernels anteriores para emergência. Eles não estão em uso e, contados, inflam o total
  // com centenas de CVEs já corrigidos no kernel novo: de cada pacote-fonte do kernel fica só a versão mais nova.
  const all = [...map.values()];
  const isKernel = q => /^linux/.test(q.name) && q.binaries.every(b => KERNEL_BIN.test(b));
  const newest = new Map();
  for (const q of all.filter(isKernel)) {
    const cur = newest.get(q.name);
    if (!cur || compareDebVersion(q.version, cur.version) > 0) newest.set(q.name, q);
  }
  const old = all.filter(q => isKernel(q) && newest.get(q.name) !== q);
  const out = all.filter(q => !isKernel(q) || newest.get(q.name) === q);
  out.oldKernels = old.map(q => q.version);
  return out;
}

// Marca em cada item se a correção já é oferecida pelo gerenciador de pacotes deste servidor. O kernel novo
// chega com nome de pacote novo, pelo metapacote (linux-generic, linux-image-generic…).
function markAvailable(items, updates) {
  const names = new Set(updates.map(u => u.name));
  const kernelMeta = updates.some(u => /^linux-(generic|image|headers|virtual|aws|azure|gcp|oracle|kvm|lowlatency|hwe|signed)/.test(u.name));
  for (const i of items) {
    if (!i.fixed) { i.available = false; continue; }
    const bins = i.binaries && i.binaries.length ? i.binaries : [i.pkg];
    i.available = bins.some(b => names.has(b)) || (bins.every(b => KERNEL_BIN.test(b)) && kernelMeta);
  }
  return items;
}

const KERNEL_BIN = /^linux-(image|modules|headers|tools|buildinfo|cloud-tools|objects|signatures|lib-rust)(-|$)/;

// Comparação aproximada de versões Debian (suficiente para escolher o kernel mais novo).
function compareDebVersion(a, b) {
  const pa = String(a).split(/[^0-9]+/).filter(Boolean).map(Number), pb = String(b).split(/[^0-9]+/).filter(Boolean).map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d;
  }
  return 0;
}

function create({ db, now, config, features }) {
  const scanning = new Set();
  // Fila: uma análise por vez, para não somar a memória de vários servidores.
  let chain = Promise.resolve();
  const enqueue = id => { if (scanning.has(id)) return chain; scanning.add(id); chain = chain.then(() => scanOne(id)).catch(e => console.error(`vulnerabilidades do servidor ${id}: ${e.message}`)).finally(() => scanning.delete(id)); return chain; };

  async function osv(path, body) {
    const res = await fetch(config.cveUrl + path, {
      method: body ? 'POST' : 'GET', headers: { 'Content-Type': 'application/json', 'User-Agent': `linux-control-hub/${config.version}` },
      body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(60_000),
    });
    if (!res.ok) throw new Error(`OSV respondeu HTTP ${res.status}`);
    return res.json();
  }

  async function details(ids) {
    const out = new Map();
    const missing = [];
    for (const id of ids) {
      const r = db.prepare('SELECT data, at FROM vuln_cache WHERE id=?').get(id);
      if (r && now() - r.at < CACHE_SECONDS) out.set(id, JSON.parse(r.data)); else missing.push(id);
    }
    let i = 0;
    const worker = async () => {
      while (i < missing.length) {
        const id = missing[i++];
        try {
          const v = slim(await osv(`/v1/vulns/${encodeURIComponent(id)}`));
          db.prepare('INSERT OR REPLACE INTO vuln_cache(id,data,at) VALUES(?,?,?)').run(id, JSON.stringify(v), now());
          out.set(id, v);
        } catch { /* um aviso que falhou não derruba a análise; entra na próxima */ }
      }
    };
    await Promise.all(Array.from({ length: PARALLEL }, worker));
    return out;
  }

  async function scanOne(serverId) {
    {
      const srv = features.servers.get(serverId);
      const eco = ecosystemOf((srv.inventory || {}).system);
      const installed = (srv.packages || {}).installed || [];
      if (!eco || !installed.length) {
        const reason = !eco ? 'Sistema sem base de vulnerabilidades suportada (Ubuntu, Debian, AlmaLinux, Rocky, Alpine).' : 'Lista de pacotes ainda não recebida do agente.';
        save(serverId, { error: reason, items: [] }, srv.packages_at);
        return;
      }
      const pkgs = queriesFrom(installed, eco);
      const hits = new Map();   // id -> [pkg]
      for (let i = 0; i < pkgs.length; i += BATCH) {
        const chunk = pkgs.slice(i, i + BATCH);
        const r = await osv('/v1/querybatch', { queries: chunk.map(p => ({ package: { name: p.name, ecosystem: eco }, version: p.version })) });
        (r.results || []).forEach((res, k) => {
          for (const v of res.vulns || []) { if (!hits.has(v.id)) hits.set(v.id, []); hits.get(v.id).push(chunk[k]); }
        });
      }
      const ids = [...hits.keys()].slice(0, MAX_VULNS);
      const info = await details(ids);
      const items = [];
      for (const id of ids) {
        const v = info.get(id);
        for (const p of hits.get(id)) items.push(v ? summarize(v, p, eco) : { id, pkg: p.name, installed: p.version, severity: 'unknown', fixed: null, url: `https://osv.dev/vulnerability/${encodeURIComponent(id)}` });
      }
      // A distribuição já ter corrigido não quer dizer que a correção chegou a este servidor (liberação gradual,
      // espelho atrasado, Ubuntu Pro). Só conta como "para instalar" o que o gerenciador de pacotes já oferece.
      markAvailable(items, (srv.packages || {}).updates || []);
      const order = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));
      items.sort((a, b) => (b.available ? 1 : 0) - (a.available ? 1 : 0) || (b.fixed ? 1 : 0) - (a.fixed ? 1 : 0) || order[a.severity] - order[b.severity] || (b.score || 0) - (a.score || 0));
      save(serverId, { ecosystem: eco, packages: pkgs.length, items, truncated: hits.size > MAX_VULNS, old_kernels: pkgs.oldKernels || [] }, srv.packages_at);
    }
  }

  function summarize_(items, error) {
    const has = (list, sev) => list.filter(i => !sev || sev.includes(i.severity)).length;
    const now_ = items.filter(i => i.available), waiting = items.filter(i => i.fixed && !i.available), none = items.filter(i => !i.fixed);
    return { error: error || null, old_kernels: (arguments[2] || []).length,
      fixable: has(now_), fixable_high: has(now_, ['critical', 'high']), fixable_critical: has(now_, ['critical']),
      waiting: has(waiting), waiting_high: has(waiting, ['critical', 'high']),
      unfixed: has(none), unfixed_high: has(none, ['critical', 'high']) };
  }
  function save(serverId, data, packagesAt) {
    db.prepare('INSERT OR REPLACE INTO server_vulns(server_id,data,at,packages_at,summary) VALUES(?,?,?,?,?)')
      .run(serverId, JSON.stringify(data), now(), packagesAt || 0, JSON.stringify(summarize_(data.items || [], data.error, data.old_kernels)));
  }

  function stored(serverId) {
    const r = db.prepare('SELECT data, at FROM server_vulns WHERE server_id=?').get(serverId);
    return r ? { ...JSON.parse(r.data), scanned_at: r.at } : null;
  }

  return {
    // Resumo que o diagnóstico usa (contagens por gravidade, com e sem correção).
    summary(serverId) {
      const r = db.prepare('SELECT summary, at FROM server_vulns WHERE server_id=?').get(serverId);
      return r && r.summary ? { at: r.at, ...JSON.parse(r.summary) } : null;
    },
    routes(router) {
      router.add('GET /api/servers/:id/vulns', ({ params }) => {
        const id = Number(params.id);
        features.servers.get(id);
        return { enabled: !!config.cveUrl, scanning: scanning.has(id), result: stored(id) };
      });
      router.add('POST /api/servers/:id/vulns/scan', ({ params }) => {
        const id = Number(params.id);
        features.servers.get(id);
        if (!config.cveUrl) throw new HttpError(400, 'A consulta de vulnerabilidades está desligada (LCTL_CVE=0).');
        enqueue(id);
        return { ok: true };
      });
    },
    jobs: [{ name: 'vulns-scan', everyMs: 10 * 60_000, runAtStart: true, async run() {
      if (!config.cveUrl) return;
      // Reanalisa quando o agente manda uma lista de pacotes nova (a cada 6 h ou depois de atualizar) ou a cada 24 h.
      for (const s of db.prepare('SELECT s.id, s.packages_at, v.packages_at AS done_at, v.at FROM servers s LEFT JOIN server_vulns v ON v.server_id = s.id WHERE s.packages_at IS NOT NULL').all()) {
        if (s.done_at !== s.packages_at || now() - (s.at || 0) > 86400) {
          await enqueue(s.id);
        }
      }
      db.prepare('DELETE FROM vuln_cache WHERE at < ?').run(now() - 4 * CACHE_SECONDS);
    } }],
  };
}

module.exports = { migrations, create, ecosystemOf, cvss3Score, summarize, queriesFrom, slim, compareDebVersion, markAvailable };
