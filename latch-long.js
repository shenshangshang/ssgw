const { openDb } = require('/app/src/db');
const db = openDb('/app/data');
db.prepare("UPDATE upstream_accounts SET health_status='unavailable', cooldown_until=? WHERE id IN (6,8)").run(new Date(Date.now() + 25 * 60000).toISOString());
console.log('latched 25min');
process.exit(0);
