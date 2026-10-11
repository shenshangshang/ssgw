// 从 aigw SQLite 迁移配置到 ssgw：账号（凭据需明文重新提供）、模型组、智能路由、种子样本
// 用法：node migrate-from-aigw.js /path/to/ai-gateway.db
// 凭据不迁移（aigw 的 envelope 与本系统主密钥不同）；迁移后用管理 API 补录明文凭据。
'use strict';
const { DatabaseSync } = require('node:sqlite');
const { openDb, now } = require('./src/db');
const path = require('node:path');
const fs = require('node:fs');

const srcPath = process.argv[2];
if (!srcPath || !fs.existsSync(srcPath)) { console.error('usage: node migrate-from-aigw.js <ai-gateway.db>'); process.exit(1); }
const src = new DatabaseSync(srcPath, { readOnly: true });
const dataDir = process.env.SSGW_DATA_DIR || path.join(__dirname, 'data');
const db = openDb(dataDir);
const t = now();

// 上游账号（不含凭据）
const accounts = src.prepare('SELECT * FROM upstream_accounts').all();
for (const a of accounts) {
  if (a.name.includes('增强代理')) continue; // 仅展示用的伪账号
  db.prepare(`INSERT OR IGNORE INTO upstream_accounts (id,name,provider,protocol_type,service_base_url,credential_envelope,credential_mask,validation_model,priority,max_concurrency,enabled,health_status,note,created_at,updated_at)
    VALUES (?,?,?,?,?,'{}','',?,?,?,?,?,?,?,?)`)
    .run(a.id, a.name, a.provider, a.protocol_type, a.service_base_url, a.validation_model, a.priority, a.max_concurrency, a.enabled, 'unknown', a.note, t, t);
  const protos = src.prepare('SELECT * FROM upstream_account_protocols WHERE account_id=?').all(a.id);
  for (const [i, pr] of protos.entries()) {
    db.prepare('INSERT INTO upstream_account_protocols (account_id,protocol,route,auth_mode,sort) VALUES (?,?,?,?,?)').run(a.id, pr.protocol, pr.route, pr.auth_mode, i);
  }
  const models = src.prepare('SELECT * FROM upstream_account_models WHERE account_id=?').all(a.id);
  for (const m of models) db.prepare('INSERT OR IGNORE INTO upstream_account_models (account_id,request_model_name,upstream_model_name) VALUES (?,?,?)').run(a.id, m.request_model_name, m.upstream_model_name);
}

// 模型组
const groups = src.prepare('SELECT * FROM model_groups').all();
for (const g of groups) {
  db.prepare('INSERT OR IGNORE INTO model_groups (id,name,protocol_type,note,created_at,updated_at) VALUES (?,?,?,?,?,?)').run(g.id, g.name, g.protocol_type, g.note, t, t);
  const members = src.prepare('SELECT * FROM model_group_members WHERE model_group_id=? ORDER BY sort').all(g.id);
  for (const m of members) db.prepare('INSERT OR IGNORE INTO model_group_members (model_group_id,request_model_name,sort) VALUES (?,?,?)').run(g.id, m.request_model_name, m.sort);
}

// 用户组授权
const ug = src.prepare('SELECT * FROM user_group_model_groups').all();
for (const u of ug) db.prepare('INSERT OR IGNORE INTO user_group_model_groups (user_group_id,model_group_id) VALUES (?,?)').run(u.user_group_id, u.model_group_id);

// settings（不含凭据密钥）
const settings = src.prepare("SELECT key,value FROM settings WHERE key NOT LIKE '%credential%' AND key NOT LIKE '%envelope%'").all();
for (const s of settings) {
  if (s.key === 'smart_routing.policy') {
    const p = JSON.parse(s.value);
    db.prepare('INSERT OR IGNORE INTO settings (key,value) VALUES (?,?)').run('smart_routing', JSON.stringify(p));
    continue;
  }
  db.prepare('INSERT OR IGNORE INTO settings (key,value) VALUES (?,?)').run(s.key, s.value);
}

// 智能路由种子样本（aigw 存的是密文，无法迁移；写入基础种子由用户提供或留空）
console.log('migration done. accounts:', accounts.length, 'groups:', groups.length);
console.log('NOTE: credentials NOT migrated. Use admin API to set plaintext credentials per account.');
console.log('NOTE: smart_route_samples are encrypted in aigw; re-seed via admin UI.');
