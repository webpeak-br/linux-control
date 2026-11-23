'use strict';
// Biblioteca de chaves SSH públicas da equipe: cadastradas uma vez, instaladas em qualquer servidor pela ação
// "Autorizar chave SSH" do agente. Só chaves públicas: chave privada é recusada e nunca é gravada.
const crypto = require('node:crypto');
const { HttpError } = require('../../core/http');

// Mesmo formato que o agente aceita (SSH_KEY_RE em agent/linux-control-agent.py).
const KEY_RE = /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/=]{40,8000}( [^\r\n]{0,200})?$/;
const MAX_KEYS = 100;

function fingerprint(key) {
  return 'SHA256:' + crypto.createHash('sha256').update(Buffer.from(key.split(' ')[1], 'base64')).digest('base64').replace(/=+$/, '');
}

function parseKey(raw) {
  const text = String(raw || '').trim();
  if (/PRIVATE KEY/.test(text)) throw new HttpError(400, 'Isso é uma chave PRIVADA. Envie só a pública (o arquivo que termina em .pub). Não compartilhe a privada.');
  const key = text.replace(/\s+/g, ' ');
  if (!KEY_RE.test(key)) throw new HttpError(400, 'Chave pública inválida. Ela começa com ssh-ed25519, ssh-rsa ou ecdsa-sha2- e fica numa linha só.');
  return key;
}

function create({ settings, now, features }) {
  const list = () => settings.get('ssh_keys', []);
  return {
    list,
    routes(router) {
      router.add('GET /api/ssh-keys', () => ({ keys: list().map(k => ({ ...k, fingerprint: fingerprint(k.key) })) }));
      router.add('POST /api/ssh-keys', ({ body, ip }) => {
        const key = parseKey(body.key);
        const keys = list();
        if (keys.some(k => k.key.split(' ').slice(0, 2).join(' ') === key.split(' ').slice(0, 2).join(' '))) throw new HttpError(409, 'Essa chave já está cadastrada.');
        if (keys.length >= MAX_KEYS) throw new HttpError(400, `Limite de ${MAX_KEYS} chaves.`);
        const name = String(body.name || key.split(' ')[2] || '').trim().slice(0, 80) || 'chave';
        const item = { id: crypto.randomUUID(), name, key, added: now() };
        settings.set('ssh_keys', [...keys, item]);
        features.audit.record(ip, 'chave_ssh_cadastrada', `${name} ${fingerprint(key)}`);
        return { ok: true, key: item };
      });
      router.add('DELETE /api/ssh-keys/:id', ({ params, ip }) => {
        const keys = list();
        const k = keys.find(x => x.id === params.id);
        if (!k) throw new HttpError(404, 'Chave não encontrada.');
        settings.set('ssh_keys', keys.filter(x => x.id !== params.id));
        features.audit.record(ip, 'chave_ssh_removida', `${k.name} ${fingerprint(k.key)}`);
        return { ok: true };
      });
    },
  };
}

module.exports = { create, parseKey, fingerprint };
module.exports.migrations = [];
