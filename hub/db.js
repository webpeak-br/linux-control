// Banco SQLite embutido (node:sqlite) - sem dependências externas.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

function open(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true });
  const db = new DatabaseSync(path.join(dataDir, 'linux-control.db'));
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, created INTEGER, expires INTEGER, ip TEXT);
    CREATE TABLE IF NOT EXISTS servers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      tags TEXT DEFAULT '',
      token_hash TEXT UNIQUE NOT NULL,
      created INTEGER,
      last_seen INTEGER,
      remote_ip TEXT,
      agent_version TEXT,
      interval INTEGER,
      metrics_json TEXT,
      inventory_json TEXT,
      inventory_at INTEGER,
      packages_json TEXT,
      packages_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS metrics (
      server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
      ts INTEGER NOT NULL, cpu REAL, mem REAL, swap REAL, disk REAL, load1 REAL, rx REAL, tx REAL
    );
    CREATE INDEX IF NOT EXISTS metrics_srv_ts ON metrics(server_id, ts);
    CREATE TABLE IF NOT EXISTS commands (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
      action TEXT NOT NULL, param TEXT, label TEXT,
      status TEXT NOT NULL,
      created INTEGER, sent_at INTEGER, finished_at INTEGER,
      exit_code INTEGER, duration REAL, output TEXT, requested_by TEXT
    );
    CREATE INDEX IF NOT EXISTS commands_srv ON commands(server_id, id);
    CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, ip TEXT, event TEXT, detail TEXT
    );
  `);
  return db;
}

module.exports = { open };
