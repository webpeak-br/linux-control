'use strict';
const fs = require('node:fs');
const path = require('node:path');

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function send(res, code, body, headers = {}) {
  const isObj = typeof body === 'object' && !Buffer.isBuffer(body);
  res.writeHead(code, {
    'Content-Type': isObj ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(isObj ? JSON.stringify(body) : body);
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0, tooBig = false;
    const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > limit) { if (!tooBig) { tooBig = true; reject(new HttpError(413, 'payload muito grande')); } return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (tooBig) return;
      if (!size) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(new HttpError(400, 'JSON inválido')); }
    });
    req.on('error', reject);
  });
}

function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    try { out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } catch { /* cookie malformado */ }
  }
  return out;
}

// Contexto de rede de uma requisição, de acordo com a confiança no proxy reverso.
function requestInfo(config) {
  return {
    ip(req) {
      if (config.trustCloudflare && req.headers['cf-connecting-ip']) return String(req.headers['cf-connecting-ip']);
      if (config.trustProxy) {
        const xf = req.headers['x-forwarded-for'];
        if (xf) return String(xf).split(',')[0].trim();
      }
      return req.socket.remoteAddress || '';
    },
    isHttps(req) {
      return !!(req.socket.encrypted || (config.trustProxy && req.headers['x-forwarded-proto'] === 'https'));
    },
    baseUrl(req) {
      if (config.publicUrl) return config.publicUrl;
      const host = String((config.trustProxy && req.headers['x-forwarded-host']) || req.headers.host || `localhost:${config.port}`);
      if (!/^[A-Za-z0-9.\-:[\]]+$/.test(host)) return `http://localhost:${config.port}`;
      return `${this.isHttps(req) ? 'https' : 'http'}://${host}`;
    },
  };
}

// Roteador mínimo: rotas declaradas como 'GET /api/servers/:id/history'.
// opts.auth: 'public' | 'session' (padrão) | 'agent' — quem valida é o middleware registrado em server.js.
function createRouter() {
  const routes = [];
  return {
    add(spec, handler, opts = {}) {
      const [method, pattern] = spec.split(' ');
      const keys = [];
      const re = new RegExp('^' + pattern.replace(/:([a-z]+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '$');
      routes.push({ method, re, keys, handler, auth: opts.auth || 'session', bodyLimit: opts.bodyLimit || 64 * 1024 });
    },
    match(method, pathname) {
      for (const r of routes) {
        if (r.method !== method) continue;
        const m = pathname.match(r.re);
        if (m) return { route: r, params: Object.fromEntries(r.keys.map((k, i) => [k, decodeURIComponent(m[i + 1])])) };
      }
      return null;
    },
  };
}

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json' };
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
};

function serveStatic(res, publicDir, pathname) {
  const rel = pathname === '/' ? '/index.html' : pathname;
  let file = path.normalize(path.join(publicDir, rel));
  if (!file.startsWith(publicDir + path.sep) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
    file = path.join(publicDir, 'index.html');
  }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache', ...SECURITY_HEADERS });
  fs.createReadStream(file).pipe(res);
}

module.exports = { HttpError, send, readBody, parseCookies, requestInfo, createRouter, serveStatic };
