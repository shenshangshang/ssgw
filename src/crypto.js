// 凭据加密 envelope：AES-256-GCM，格式 {v:1,k:'primary',n:<b64 iv>,c:<b64 ct>,t:<b64 tag>}
// 主密钥来自 settings.security_credential_key（与 aigw 兼容，base64 32 字节）或环境变量 SSGW_CREDENTIAL_KEY
'use strict';
const crypto = require('node:crypto');

function getKey(db, env) {
  if (env.SSGW_CREDENTIAL_KEY) {
    const raw = Buffer.from(env.SSGW_CREDENTIAL_KEY, 'base64');
    if (raw.length === 32) return raw;
  }
  let row = db.prepare("SELECT value FROM settings WHERE key='security.credential_key'").get();
  if (!row) {
    const key = crypto.randomBytes(32).toString('base64');
    db.prepare("INSERT INTO settings (key,value) VALUES ('security.credential_key',?)").run(key);
    return Buffer.from(key, 'base64');
  }
  return Buffer.from(row.value, 'base64');
}

function seal(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return JSON.stringify({ v: 1, k: 'primary', n: iv.toString('base64'), c: ct.toString('base64'), t: cipher.getAuthTag().toString('base64') });
}

function open(key, envelope) {
  try {
    const e = JSON.parse(envelope);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(e.n, 'base64'));
    decipher.setAuthTag(Buffer.from(e.t, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(e.c, 'base64')), decipher.final()]).toString('utf8');
  } catch { return null; }
}

function mask(credential) {
  const s = String(credential || '');
  if (s.length <= 8) return '****';
  return '****' + s.slice(-4);
}

function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

// 密码哈希：scrypt（带随机盐），格式 scrypt$<salt b64>$<hash b64>
// 旧格式（裸 sha256 hex，64 字符）仍可验证——登录成功后由调用方升级
function hashPassword(password, username) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password + ':' + username, salt, 32, { N: 16384, r: 8, p: 1 });
  return 'scrypt$' + salt.toString('base64') + '$' + hash.toString('base64');
}
function verifyPassword(password, username, stored) {
  const s = String(stored || '');
  if (s.startsWith('scrypt$')) {
    try {
      const [, saltB64, hashB64] = s.split('$');
      const hash = crypto.scryptSync(password + ':' + username, Buffer.from(saltB64, 'base64'), 32, { N: 16384, r: 8, p: 1 });
      return crypto.timingSafeEqual(hash, Buffer.from(hashB64, 'base64'));
    } catch { return false; }
  }
  // 旧 sha256 格式
  return sha256(password + ':' + username) === s;
}
function isLegacyPasswordHash(stored) { return !String(stored || '').startsWith('scrypt$'); }

module.exports = { getKey, seal, open, mask, sha256, hashPassword, verifyPassword, isLegacyPasswordHash };
