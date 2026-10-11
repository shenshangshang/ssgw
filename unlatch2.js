const { openDb } = require('/app/src/db');
const db = openDb('/app/data');
db.prepare("UPDATE upstream_accounts SET health_status='unavailable', cooldown_until=? WHERE id = 6").run(new Date(Date.now() - 5000).toISOString());
console.log('account 6 cooldown expired');
process.exit(0);
