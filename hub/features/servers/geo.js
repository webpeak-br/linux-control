// Localização do IP público de cada servidor (cidade, país, operadora), consultada num serviço de geolocalização
// e guardada por 7 dias. Desligue com LCTL_GEOIP=0: nesse caso nenhum IP sai do hub.
'use strict';

const migrations = [
  { name: 'geo:1', sql: ['CREATE TABLE IF NOT EXISTS ip_geo (ip TEXT PRIMARY KEY, data TEXT, at INTEGER)'] },
];
const FRESH = 7 * 86400;
const RETRY_FAILED = 3600;
const PER_RUN = 10;

// IPs que não dizem nada sobre o datacenter: privados, loopback, CGNAT, link-local, documentação.
const PRIVATE = [/^10\./, /^127\./, /^169\.254\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./, /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
  /^0\./, /^::1$/, /^f[cd]/i, /^fe80/i, /^::ffff:(10|127|192\.168)\./i];
const isPublic = ip => !!ip && /^[0-9a-f:.]+$/i.test(ip) && !PRIVATE.some(r => r.test(ip));

// IP que representa o servidor: o de saída visto pelo hub; se for privado (mesma rede do hub), o primeiro público da máquina.
function publicIp(srv) {
  if (isPublic(srv.remote_ip)) return srv.remote_ip;
  const ips = (((srv.inventory || {}).system || {}).ips || []).map(i => String(i.addr || '').split('/')[0]);
  return ips.find(isPublic) || null;
}

// ipinfo.io: { city, region, country, loc: "lat,lon", org: "AS20473 The Constant Company, LLC", timezone }
function clean(j) {
  const [lat, lon] = String(j.loc || '').split(',').map(Number);
  const org = String(j.org || '');
  return {
    city: String(j.city || '').slice(0, 80), region: String(j.region || '').slice(0, 80), country: String(j.country || '').slice(0, 2).toUpperCase(),
    asn: (org.match(/^AS\d+/) || [''])[0], org: org.replace(/^AS\d+\s*/, '').slice(0, 120),
    lat: Number.isFinite(lat) ? lat : null, lon: Number.isFinite(lon) ? lon : null, timezone: String(j.timezone || '').slice(0, 60),
  };
}

function createGeo({ db, now, config }) {
  const cached = ip => {
    const r = ip && db.prepare('SELECT data FROM ip_geo WHERE ip=?').get(ip);
    try { return r && r.data ? JSON.parse(r.data) : null; } catch { return null; }
  };

  async function lookup(ip) {
    try {
      const res = await fetch(config.geoipUrl.replace('{ip}', encodeURIComponent(ip)), { signal: AbortSignal.timeout(8000), headers: { Accept: 'application/json' } });
      const j = res.ok ? await res.json() : null;
      const data = j && !j.bogon && (j.city || j.country) ? JSON.stringify(clean(j)) : null;
      db.prepare('INSERT OR REPLACE INTO ip_geo(ip,data,at) VALUES(?,?,?)').run(ip, data, now());
    } catch {
      db.prepare('INSERT OR REPLACE INTO ip_geo(ip,data,at) VALUES(?,NULL,?)').run(ip, now());
    }
  }

  // Consulta os IPs sem localização (ou com mais de 7 dias), poucos por vez.
  async function refresh(servers) {
    if (!config.geoipUrl) return;
    const t = now();
    const due = [...new Set(servers.map(publicIp).filter(Boolean))].filter(ip => {
      const r = db.prepare('SELECT data, at FROM ip_geo WHERE ip=?').get(ip);
      return !r || t - r.at > (r.data ? FRESH : RETRY_FAILED);
    }).slice(0, PER_RUN);
    for (const ip of due) await lookup(ip);
  }

  return { forServer: srv => { const ip = publicIp(srv); const g = cached(ip); return g ? { ip, ...g } : null; }, refresh };
}

module.exports = { migrations, createGeo, publicIp, isPublic, clean };
