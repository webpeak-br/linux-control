'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

// Cada feature declara as próprias migrações ({ name, sql }); elas rodam uma única vez, na ordem.
function open(dataDir, migrations) {
  fs.mkdirSync(dataDir, { recursive: true });
  const db = new DatabaseSync(path.join(dataDir, 'linux-control.db'));
  db.exec(`PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS migrations (name TEXT PRIMARY KEY, applied INTEGER);`);
  const done = new Set(db.prepare('SELECT name FROM migrations').all().map(r => r.name));
  for (const m of migrations) {
    if (done.has(m.name)) continue;
    db.exec('BEGIN');
    try {
      for (const stmt of [].concat(m.sql)) {
        try { db.exec(stmt); } catch (e) { if (!m.tolerant || !/duplicate column|already exists/i.test(e.message)) throw e; }
      }
      db.prepare('INSERT INTO migrations(name, applied) VALUES(?, ?)').run(m.name, Date.now());
      db.exec('COMMIT');
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }
  }
  return db;
}

module.exports = { open };
