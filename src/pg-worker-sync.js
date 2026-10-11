// PG 同步 worker：结果经 SharedArrayBuffer 回传，Atomics.notify 唤醒主线程
'use strict';
const { workerData } = require('node:worker_threads');
const { Client } = require('pg');

const client = new Client({ connectionString: workerData.url });
const int32 = new Int32Array(workerData.sab);
const buf = new Uint8Array(workerData.buf);

function reply(result) {
  if (result.error && JSON.stringify(result).length > buf.length) result = { ok: false, error: 'result too large' };
  const b = Buffer.from(JSON.stringify(result), 'utf8');
  buf.set(b, 0);
  Atomics.store(int32, 1, b.length);
  Atomics.store(int32, 0, 2);
  Atomics.notify(int32, 0);
}

async function main() {
  await client.connect();
  Atomics.store(int32, 1, 0);
  Atomics.store(int32, 0, 2);
  Atomics.notify(int32, 0);

  while (true) {
    // 主线程置 1 表示有请求；0 表示空闲
    Atomics.wait(int32, 0, 0);
    if (Atomics.load(int32, 0) !== 1) continue;
    const len = Atomics.load(int32, 1);
    const req = JSON.parse(Buffer.from(buf.slice(0, len)).toString('utf8'));
    let result;
    try {
      if (req.op === 'exec') {
        await client.query(req.sql);
        result = { ok: true };
      } else {
        const r = await client.query(req.sql, req.params);
        if (req.op === 'get') result = { ok: true, row: r.rows[0] || null };
        else if (req.op === 'all') result = { ok: true, rows: r.rows };
        else result = { ok: true, changes: r.rowCount, lastInsertRowid: r.rows?.[0] ? Object.values(r.rows[0])[0] : 0 };
      }
    } catch (e) {
      result = { ok: false, error: e.message };
    }
    reply(result);
    // 等主线程消费（0）
    while (Atomics.load(int32, 0) === 2) Atomics.wait(int32, 0, 2, 50);
  }
}

main().catch(e => {
  reply({ ok: false, error: 'connect: ' + e.message });
  setTimeout(() => process.exit(1), 100);
});
