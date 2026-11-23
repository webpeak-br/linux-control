'use strict';
// Configurações persistentes em chave/valor JSON. Cada feature usa o próprio prefixo de chave.

const migrations = [{ name: 'settings:1', sql: 'CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)' }];

function create(db) {
  return {
    get(key, fallback = null) {
      const row = db.prepare('SELECT value FROM settings WHERE key=?').get(key);
      if (!row) return fallback;
      try { return JSON.parse(row.value); } catch { return row.value; }
    },
    set(key, value) {
      db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value')
        .run(key, JSON.stringify(value));
    },
  };
}

module.exports = { migrations, create };
