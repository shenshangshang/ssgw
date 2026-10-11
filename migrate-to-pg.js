// SQLite → PG 数据迁移（按表逐行 COPY）
const { DatabaseSync } = require('node:sqlite');
const { PgSyncDb } = require('/app/src/db');
const src = new DatabaseSync('/app/data/ssgw.db', { readOnly: true });
const dst = new PgSyncDb(process.env.SSGW_DB_URL);
const tables = ['user_groups', 'users', 'user_group_model_groups', 'api_keys', 'sessions',
  'upstream_accounts', 'upstream_account_protocols', 'upstream_account_models',
  'model_groups', 'model_group_members', 'settings', 'content_policy_groups', 'content_sensitive_words', 'smart_route_samples'];
for (const t of tables) {
  const rows = src.prepare(`SELECT * FROM ${t}`).all();
  if (!rows.length) { console.log(t, 0); continue; }
  const cols = Object.keys(rows[0]);
  // 清空目标（幂等重跑）
  dst.exec(`DELETE FROM ${t}`);
  for (const r of rows) {
    const ph = cols.map(() => '?').join(',');
    const vals = cols.map(c => r[c] === undefined ? null : r[c]);
    try {
      dst.prepare(`INSERT INTO ${t} (${cols.join(',')}) VALUES (${ph})`).run(...vals);
    } catch (e) { console.log(t, 'ERR', e.message.slice(0, 120)); break; }
  }
  console.log(t, rows.length);
}
// 修正 PG 序列
for (const t of tables) {
  try { dst.exec(`SELECT setval(pg_get_serial_sequence('${t}','id'), GREATEST((SELECT COALESCE(MAX(id),1) FROM ${t}), 1))`); } catch {}
}
console.log('done');
process.exit(0);
