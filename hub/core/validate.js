'use strict';
// Validações de texto que vão para protocolos de linha (SMTP, cabeçalhos): nada de quebra de linha.

const EMAIL_RE = /^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+$/;
const MAILBOX_RE = /^[^\r\n<>"]{0,100}<([^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+)>$/;

const isEmail = s => EMAIL_RE.test(String(s));
// Aceita "a@b.com" ou "Nome <a@b.com>".
const isMailbox = s => isEmail(s) || MAILBOX_RE.test(String(s).trim());

module.exports = { isEmail, isMailbox };
