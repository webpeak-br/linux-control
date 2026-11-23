'use strict';
// Cliente SMTP mínimo (sem dependências): TLS direto (465), STARTTLS (587) ou sem criptografia (25), AUTH PLAIN/LOGIN.
const net = require('node:net');
const tls = require('node:tls');
const os = require('node:os');
const crypto = require('node:crypto');

const TIMEOUT_MS = 20000;
const LOOPBACK = /^(localhost|127\.\d+\.\d+\.\d+|::1)$/;

// Tudo que vira linha de protocolo ou cabeçalho não pode ter quebra de linha.
function assertSingleLine(...values) {
  for (const v of values) if (/[\r\n]/.test(String(v))) throw new Error('quebra de linha não permitida em endereço ou assunto');
}

function addressOf(s) {
  const m = String(s).match(/<([^>]+)>/);
  return (m ? m[1] : String(s)).trim();
}

const encodeHeader = s => (/^[\x20-\x7e]*$/.test(s) ? s : `=?UTF-8?B?${Buffer.from(s, 'utf8').toString('base64')}?=`);
const b64lines = s => Buffer.from(s, 'utf8').toString('base64').replace(/.{1,76}/g, '$&\r\n');

function buildMessage({ from, to, subject, text, html }) {
  const boundary = 'lctl-' + crypto.randomBytes(12).toString('hex');
  const domain = addressOf(from).split('@')[1] || 'localhost';
  return [
    `From: ${from}`,
    `To: ${to.join(', ')}`,
    `Subject: ${encodeHeader(subject)}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${crypto.randomUUID()}@${domain}>`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    '',
    `--${boundary}`, 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: base64', '', b64lines(text),
    `--${boundary}`, 'Content-Type: text/html; charset=utf-8', 'Content-Transfer-Encoding: base64', '', b64lines(html),
    `--${boundary}--`, '',
  ].join('\r\n');
}

// Lê respostas SMTP (inclusive multilinha "250-...") de um socket que pode ser trocado por TLS no meio.
function replyReader() {
  let buf = '', waiting = null, lines = [];
  const pending = [];
  function feed(chunk) {
    buf += chunk.toString('utf8');
    let i;
    while ((i = buf.indexOf('\r\n')) >= 0) {
      const line = buf.slice(0, i); buf = buf.slice(i + 2);
      lines.push(line);
      if (/^\d{3} /.test(line) || /^\d{3}$/.test(line)) {
        const reply = { code: parseInt(line.slice(0, 3), 10), text: lines.join('\n') };
        lines = [];
        if (waiting) { const w = waiting; waiting = null; w(reply); } else pending.push(reply);
      }
    }
  }
  const next = () => (pending.length ? Promise.resolve(pending.shift()) : new Promise(r => { waiting = r; }));
  return { feed, next, reset() { buf = ''; lines = []; pending.length = 0; } };
}

async function sendMail(smtp, mail) {
  assertSingleLine(smtp.from, smtp.user, mail.subject, ...mail.to);
  if (smtp.user && smtp.security === 'none' && !LOOPBACK.test(smtp.host)) {
    throw new Error('autenticação SMTP sem criptografia recusada; use STARTTLS ou SSL/TLS');
  }
  const port = Number(smtp.port) || (smtp.security === 'tls' ? 465 : 587);
  const reader = replyReader();
  let socket = await new Promise((resolve, reject) => {
    const opts = { host: smtp.host, port, servername: smtp.host };
    const s = smtp.security === 'tls' ? tls.connect(opts, () => resolve(s)) : net.connect(opts, () => resolve(s));
    s.setTimeout(TIMEOUT_MS, () => s.destroy(new Error('tempo esgotado falando com o servidor SMTP')));
    s.once('error', reject);
  });
  let failure = null;
  const onError = e => { failure = e; };
  const attach = s => { s.on('data', reader.feed); s.on('error', onError); };
  attach(socket);

  const expect = async (codes, what) => {
    const r = await Promise.race([reader.next(), new Promise((_, rej) => setTimeout(() => rej(failure || new Error('sem resposta do SMTP')), TIMEOUT_MS))]);
    if (!codes.includes(r.code)) throw new Error(`SMTP recusou ${what}: ${r.text}`);
    return r;
  };
  const cmd = async (line, codes, what) => { socket.write(line + '\r\n'); return expect(codes, what || line.split(' ')[0]); };

  try {
    await expect([220], 'a conexão');
    let ehlo = await cmd(`EHLO ${os.hostname() || 'linux-control'}`, [250]);
    if (smtp.security === 'starttls') {
      await cmd('STARTTLS', [220]);
      socket.removeListener('data', reader.feed);
      reader.reset();
      socket = await new Promise((resolve, reject) => {
        const s = tls.connect({ socket, servername: smtp.host }, () => resolve(s));
        s.once('error', reject);
      });
      attach(socket);
      ehlo = await cmd(`EHLO ${os.hostname() || 'linux-control'}`, [250]);
    }
    if (smtp.user) {
      if (/AUTH[ =][^\n]*PLAIN/i.test(ehlo.text)) {
        await cmd('AUTH PLAIN ' + Buffer.from(`\0${smtp.user}\0${smtp.pass || ''}`).toString('base64'), [235], 'a autenticação');
      } else {
        await cmd('AUTH LOGIN', [334], 'a autenticação');
        await cmd(Buffer.from(smtp.user).toString('base64'), [334], 'o usuário');
        await cmd(Buffer.from(smtp.pass || '').toString('base64'), [235], 'a senha');
      }
    }
    await cmd(`MAIL FROM:<${addressOf(smtp.from)}>`, [250], 'o remetente');
    for (const to of mail.to) await cmd(`RCPT TO:<${addressOf(to)}>`, [250, 251], `o destinatário ${to}`);
    await cmd('DATA', [354]);
    const body = buildMessage({ from: smtp.from, ...mail }).replace(/^\./gm, '..');
    await cmd(body + '\r\n.', [250], 'a mensagem');
    socket.write('QUIT\r\n');
  } finally {
    socket.end();
  }
}

module.exports = { sendMail, buildMessage };
