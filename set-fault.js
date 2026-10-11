const { openDb } = require('/app/src/db');
const db = openDb('/app/data');
// cooldown 设为过去 5 秒 → 立即进入半开探测窗口
const past = new Date(Date.now() - 5000).toISOString();
db.prepare("UPDATE upstream_accounts SET health_status='unavailable', cooldown_until=? WHERE id IN (6,8)").run(past);
console.log('accounts 6,8 set unavailable, cooldown expired');
process.exit(0);
