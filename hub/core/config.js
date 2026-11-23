'use strict';
const path = require('node:path');
const fs = require('node:fs');

const HUB_DIR = path.join(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(HUB_DIR, 'package.json'), 'utf8'));

// O agente fica em hub/agent dentro da imagem Docker e em ../agent no repositório.
const AGENT_DIR = fs.existsSync(path.join(HUB_DIR, 'agent')) ? path.join(HUB_DIR, 'agent') : path.join(HUB_DIR, '..', 'agent');

const env = process.env;
const config = {
  version: pkg.version,
  port: parseInt(env.LCTL_PORT || '7420', 10),
  host: env.LCTL_HOST || '0.0.0.0',
  dataDir: env.LCTL_DATA || path.join(HUB_DIR, '..', 'data'),
  publicUrl: (env.LCTL_PUBLIC_URL || '').replace(/\/+$/, ''),
  adminPassword: env.LCTL_ADMIN_PASSWORD || '',
  retentionDays: parseInt(env.LCTL_RETENTION_DAYS || '7', 10),
  sessionHours: parseInt(env.LCTL_SESSION_HOURS || '12', 10),
  trustProxy: env.LCTL_TRUST_PROXY === '1',
  // Só com a Cloudflare na frente (e a origem aceitando apenas os IPs dela) o CF-Connecting-IP é confiável.
  trustCloudflare: env.LCTL_TRUST_CF === '1',
  licenseUrl: (env.LCTL_LICENSE_URL ?? pkg.linuxControl.licenseUrl).replace(/\/+$/, ''),
  telemetry: env.LCTL_TELEMETRY !== '0',
  releasesUrl: env.LCTL_RELEASES_URL || pkg.linuxControl.releasesUrl,
  // Localização do IP dos servidores. LCTL_GEOIP=0 desliga ({ip} é trocado pelo IP consultado).
  geoipUrl: env.LCTL_GEOIP === '0' ? '' : (env.LCTL_GEOIP_URL || 'https://ipinfo.io/{ip}/json'),
  publicDir: path.join(HUB_DIR, 'public'),
  agentDir: AGENT_DIR,
};

module.exports = config;
