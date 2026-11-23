'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const sha256 = data => crypto.createHash('sha256').update(data).digest('hex');
const randomToken = (prefix, bytes = 24) => prefix + crypto.randomBytes(bytes).toString('base64url');

function scrypt(pw, salt) {
  return new Promise((resolve, reject) =>
    crypto.scrypt(String(pw).slice(0, 1024), salt, 64, (err, key) => (err ? reject(err) : resolve(key))));
}

async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  return `scrypt$${salt.toString('hex')}$${(await scrypt(pw, salt)).toString('hex')}`;
}

async function verifyPassword(pw, stored) {
  if (!stored) return false;
  const [, saltHex, keyHex] = String(stored).split('$');
  const key = await scrypt(pw, Buffer.from(saltHex, 'hex'));
  return crypto.timingSafeEqual(key, Buffer.from(keyHex, 'hex'));
}

// Cofre para segredos guardados no banco (ex.: senha SMTP). A chave fica num arquivo do diretório de
// dados, separado do banco, para que um backup só do .db não revele os segredos.
function secretBox(dataDir) {
  const keyFile = path.join(dataDir, 'secret.key');
  if (!fs.existsSync(keyFile)) fs.writeFileSync(keyFile, crypto.randomBytes(32), { mode: 0o600 });
  const key = fs.readFileSync(keyFile);
  return {
    seal(text) {
      const iv = crypto.randomBytes(12);
      const c = crypto.createCipheriv('aes-256-gcm', key, iv);
      const enc = Buffer.concat([c.update(String(text), 'utf8'), c.final()]);
      return [iv, c.getAuthTag(), enc].map(b => b.toString('base64')).join('.');
    },
    open(sealed) {
      if (!sealed) return '';
      const [iv, tag, enc] = String(sealed).split('.').map(s => Buffer.from(s, 'base64'));
      const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
      d.setAuthTag(tag);
      return Buffer.concat([d.update(enc), d.final()]).toString('utf8');
    },
  };
}

module.exports = { sha256, randomToken, hashPassword, verifyPassword, secretBox };
