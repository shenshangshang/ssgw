// 数据层：SQLite（默认）或 PostgreSQL（SSGW_DB_URL）。统一同步接口 prepare().get/all/run/exec。
// PG 用 worker + SAB + Atomics 同步桥；SQL 方言自动转换（? → $n、AUTOINCREMENT、INSERT OR REPLACE）。
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { Worker } = require('node:worker_threads');
const { DatabaseSync } = require('node:sqlite');

const now = () => new Date().toISOString();

// 表定义（列名/约束通用，方言在 translate() 转换）
const TABLES = {
  meta: 'CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)',
  users: `CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY, username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'admin',
    user_group_id BIGINT NOT NULL DEFAULT 1, disabled INTEGER NOT NULL DEFAULT 0,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    failed_login_count INTEGER NOT NULL DEFAULT 0, locked_until TEXT,
    last_login_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
  user_groups: `CREATE TABLE IF NOT EXISTS user_groups (
    id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1, max_concurrency INTEGER NOT NULL DEFAULT 0,
    token_quota INTEGER NOT NULL DEFAULT 0, note TEXT NOT NULL DEFAULT '',
    queue_size INTEGER NOT NULL DEFAULT 0, queue_timeout_sec INTEGER NOT NULL DEFAULT 0,
    is_default INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
  user_group_model_groups: `CREATE TABLE IF NOT EXISTS user_group_model_groups (
    user_group_id BIGINT NOT NULL, model_group_id BIGINT NOT NULL,
    PRIMARY KEY (user_group_id, model_group_id))`,
  user_group_models: `CREATE TABLE IF NOT EXISTS user_group_models (
    user_group_id BIGINT NOT NULL, model_name TEXT NOT NULL,
    PRIMARY KEY (user_group_id, model_name))`,
  api_keys: `CREATE TABLE IF NOT EXISTS api_keys (
    id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL, name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE, prefix TEXT NOT NULL, mask TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, last_used_at TEXT)`,
  sessions: `CREATE TABLE IF NOT EXISTS sessions (
    id BIGSERIAL PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
    user_id BIGINT NOT NULL, csrf_hash TEXT NOT NULL,
    idle_expires_at TEXT NOT NULL, absolute_expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL, created_at TEXT NOT NULL)`,
  upstream_accounts: `CREATE TABLE IF NOT EXISTS upstream_accounts (
    id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL DEFAULT 'custom', protocol_type TEXT NOT NULL DEFAULT 'text',
    service_base_url TEXT NOT NULL, credential_envelope TEXT NOT NULL DEFAULT '{}',
    credential_mask TEXT NOT NULL DEFAULT '', validation_model TEXT NOT NULL DEFAULT '',
    priority INTEGER NOT NULL DEFAULT 0, max_concurrency INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1, health_status TEXT NOT NULL DEFAULT 'unknown',
    health_checked_at TEXT, cooldown_until TEXT, last_verified_at TEXT,
    note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
  upstream_account_protocols: `CREATE TABLE IF NOT EXISTS upstream_account_protocols (
    id BIGSERIAL PRIMARY KEY, account_id BIGINT NOT NULL,
    protocol TEXT NOT NULL, route TEXT NOT NULL DEFAULT '/v1',
    auth_mode TEXT NOT NULL DEFAULT 'bearer', sort INTEGER NOT NULL DEFAULT 0)`,
  upstream_account_models: `CREATE TABLE IF NOT EXISTS upstream_account_models (
    id BIGSERIAL PRIMARY KEY, account_id BIGINT NOT NULL,
    request_model_name TEXT NOT NULL, upstream_model_name TEXT NOT NULL,
    model_type TEXT NOT NULL DEFAULT '',
    UNIQUE (account_id, request_model_name))`,
  model_groups: `CREATE TABLE IF NOT EXISTS model_groups (
    id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE,
    protocol_type TEXT NOT NULL DEFAULT 'text', note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
  model_group_members: `CREATE TABLE IF NOT EXISTS model_group_members (
    id BIGSERIAL PRIMARY KEY, model_group_id BIGINT NOT NULL,
    request_model_name TEXT NOT NULL, sort INTEGER NOT NULL DEFAULT 0,
    UNIQUE (model_group_id, request_model_name))`,
  call_logs: `CREATE TABLE IF NOT EXISTS call_logs (
    id BIGSERIAL PRIMARY KEY, request_id TEXT NOT NULL UNIQUE,
    started_at_ms BIGINT NOT NULL, user_id BIGINT, api_key_id BIGINT,
    request_model TEXT, upstream_account_id BIGINT, upstream_model TEXT,
    result_kind INTEGER NOT NULL, upstream_status INTEGER, stream INTEGER NOT NULL DEFAULT 0,
    attempt_count INTEGER NOT NULL DEFAULT 1, duration_ms INTEGER NOT NULL DEFAULT 0,
    first_byte_ms BIGINT, error_code TEXT,
    input_tokens BIGINT, output_tokens BIGINT, total_tokens BIGINT, cached_tokens BIGINT)`,
  call_log_attempts: `CREATE TABLE IF NOT EXISTS call_log_attempts (
    id BIGSERIAL PRIMARY KEY, call_log_id BIGINT NOT NULL,
    sequence INTEGER NOT NULL, upstream_account_id BIGINT NOT NULL,
    upstream_model TEXT NOT NULL, upstream_status INTEGER, error_code TEXT,
    duration_ms INTEGER NOT NULL DEFAULT 0)`,
  settings: 'CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)',
  content_policy_groups: `CREATE TABLE IF NOT EXISTS content_policy_groups (
    id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE,
    action TEXT NOT NULL DEFAULT 'block', risk TEXT NOT NULL DEFAULT 'high',
    enabled INTEGER NOT NULL DEFAULT 1, description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
  content_sensitive_words: `CREATE TABLE IF NOT EXISTS content_sensitive_words (
    id BIGSERIAL PRIMARY KEY, policy_group_id BIGINT NOT NULL,
    word TEXT NOT NULL, normalized_word TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
    remark TEXT NOT NULL DEFAULT '')`,
  smart_route_samples: `CREATE TABLE IF NOT EXISTS smart_route_samples (
    id BIGSERIAL PRIMARY KEY, label TEXT NOT NULL,
    text TEXT NOT NULL, normalized_text TEXT NOT NULL,
    vector TEXT, vector_dim INTEGER NOT NULL DEFAULT 0,
    threshold REAL, remark TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
  smart_route_decision_logs: `CREATE TABLE IF NOT EXISTS smart_route_decision_logs (
    id BIGSERIAL PRIMARY KEY, request_id TEXT NOT NULL,
    request_model TEXT NOT NULL DEFAULT '',
    route_label TEXT NOT NULL, confidence REAL NOT NULL,
    selected_model TEXT NOT NULL, decision_source TEXT NOT NULL,
    created_at TEXT NOT NULL, created_at_ms BIGINT NOT NULL DEFAULT 0)`,
  body_audits: `CREATE TABLE IF NOT EXISTS body_audits (
    id BIGSERIAL PRIMARY KEY, occurred_at TEXT NOT NULL,
    request_id TEXT NOT NULL, direction TEXT NOT NULL, body TEXT NOT NULL)`,
};

const INDEXES = [
  'CREATE INDEX IF NOT EXISTS idx_call_logs_started ON call_logs(started_at_ms DESC)',
  'CREATE INDEX IF NOT EXISTS idx_call_logs_account ON call_logs(upstream_account_id, started_at_ms DESC)',
  'CREATE INDEX IF NOT EXISTS idx_call_logs_model ON call_logs(request_model, started_at_ms DESC)',
];

function initSchema(db) {
  for (const sql of Object.values(TABLES)) db.exec(sql);
  for (const sql of INDEXES) db.exec(sql);
  // 轻量迁移：已有表补列（失败=已存在，忽略）
  for (const [sql, params] of [
    ["ALTER TABLE upstream_account_models ADD COLUMN model_type TEXT NOT NULL DEFAULT ''", []],
    ["ALTER TABLE upstream_account_models ADD COLUMN priority INTEGER", []],
    ["ALTER TABLE smart_route_decision_logs ADD COLUMN request_model TEXT NOT NULL DEFAULT ''", []],
    ["ALTER TABLE smart_route_decision_logs ADD COLUMN created_at_ms BIGINT NOT NULL DEFAULT 0", []],
    ["ALTER TABLE api_keys ADD COLUMN max_concurrency INTEGER NOT NULL DEFAULT 0", []],
    ["ALTER TABLE user_groups ADD COLUMN queue_size INTEGER NOT NULL DEFAULT 0", []],
    ["ALTER TABLE user_groups ADD COLUMN queue_timeout_sec INTEGER NOT NULL DEFAULT 0", []],
  ]) {
    try { db.prepare(sql).run(...params); } catch {}
  }
}

// ---------------- SQLite ----------------
class SqliteDb {
  constructor(file) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    this.db = new DatabaseSync(file);
    this.db.exec('PRAGMA journal_mode = WAL');
    this.db.exec('PRAGMA busy_timeout = 5000');
    this.dialect = 'sqlite';
  }
  exec(sql) { this.db.exec(sql); }
  prepare(sql) {
    const stmt = this.db.prepare(sql);
    const clean = (a) => a.map(v => v === undefined ? null : v);
    return {
      get: (...a) => stmt.get(...clean(a)),
      all: (...a) => stmt.all(...clean(a)),
      run: (...a) => {
        const r = stmt.run(...clean(a));
        return { changes: r.changes, lastInsertRowid: r.lastInsertRowid };
      },
    };
  }
}

// ---------------- PostgreSQL 同步桥 ----------------
class PgSyncDb {
  constructor(url) {
    this.dialect = 'pg';
    this.sab = new SharedArrayBuffer(8);
    this.int32 = new Int32Array(this.sab);
    this.bufSAB = new SharedArrayBuffer(64 * 1024 * 1024);
    this.worker = new Worker(path.join(__dirname, 'pg-worker-sync.js'), {
      workerData: { url, sab: this.sab, buf: this.bufSAB },
    });
    this.buf = new Uint8Array(this.bufSAB);
    Atomics.wait(this.int32, 0, 0, 15000);
    const st = Atomics.load(this.int32, 0);
    if (st !== 2) throw new Error('pg worker init failed');
    Atomics.store(this.int32, 0, 0);
  }

  _sync(op, sql, params) {
    const req = JSON.stringify({ op, sql, params: (params || []).map(p => p === undefined ? null : p) });
    const bytes = Buffer.from(req, 'utf8');
    if (bytes.length > this.buf.length) throw new Error('request too large');
    this.buf.set(bytes, 0);
    Atomics.store(this.int32, 1, bytes.length);
    Atomics.store(this.int32, 0, 1);
    Atomics.notify(this.int32, 0);
    Atomics.wait(this.int32, 0, 1, 30000);
    const st = Atomics.load(this.int32, 0);
    const len = Atomics.load(this.int32, 1);
    if (st !== 2) { Atomics.store(this.int32, 0, 0); throw new Error('pg op timeout or failed'); }
    const result = JSON.parse(Buffer.from(this.buf.slice(0, len)).toString('utf8'));
    Atomics.store(this.int32, 0, 0);
    Atomics.notify(this.int32, 0); // 通知 worker 可以接受下个请求
    if (!result.ok) {
      const e = new Error('pg: ' + result.error + ' | sql: ' + sql.slice(0, 100));
      throw e;
    }
    return result;
  }

  exec(sql) { this._sync('exec', sql, []); }
  prepare(sql) {
    const pgSql = translate(sql);
    const self = this;
    return {
      get: (...a) => self._sync('get', pgSql, a).row ?? null,
      all: (...a) => self._sync('all', pgSql, a).rows ?? [],
      run: (...a) => {
        const r = self._sync('run', pgSql, a);
        return { changes: r.changes ?? 0, lastInsertRowid: r.lastInsertRowid ?? 0 };
      },
    };
  }
}

// SQL 方言转换（SQLite → PG）
function translate(sql) {
  let out = sql;
  let i = 0;
  out = out.replace(/\?/g, () => '$' + (++i));
  out = out.replace(/INTEGER PRIMARY KEY AUTOINCREMENT/g, 'BIGSERIAL PRIMARY KEY');
  // INSERT OR IGNORE → ON CONFLICT DO NOTHING（表名后到 VALUES 的列清单里没有嵌套括号，安全）
  out = out.replace(/INSERT OR IGNORE INTO (\w+)\s*(\([^)]*\))?\s*VALUES\s*\(([^)]*)\)/i,
    (m, tbl, cols, vals) => `INSERT INTO ${tbl} ${cols || ''} VALUES (${vals}) ON CONFLICT DO NOTHING`);
  // INSERT OR REPLACE → ON CONFLICT DO UPDATE（按唯一约束）
  out = out.replace(/INSERT OR REPLACE INTO (\w+) \(([^)]*)\) VALUES \(([^)]*)\)/i,
    (m, tbl, cols, vals) => {
      const colArr = cols.split(',').map(s => s.trim());
      const upd = colArr.filter(c => c !== 'id').map(c => `${c}=EXCLUDED.${c}`).join(', ');
      return `INSERT INTO ${tbl} (${cols}) VALUES (${vals}) ON CONFLICT DO UPDATE SET ${upd}`;
    });
  return out;
}

function openDb(dataDir) {
  const url = process.env.SSGW_DB_URL;
  if (url) {
    const db = new PgSyncDb(url);
    initSchema(db);
    return db;
  }
  const db = new SqliteDb(path.join(dataDir, 'ssgw.db'));
  initSchema(db);
  return db;
}

module.exports = { openDb, now, SqliteDb, PgSyncDb, translate };
