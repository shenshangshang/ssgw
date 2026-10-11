// 上游转发客户端：OpenAI 兼容 chat/completions(SSE)/embeddings/rerank/images，重试由 engine 层控制
'use strict';

const DEFAULT_TIMEOUT_MS = 1800000;   // 30 分钟，与 aigw gateway.request_timeout_seconds 一致
const STREAM_IDLE_MS = 600000;        // 流式空闲超时

function buildHeaders(account, credential, extra = {}) {
  const h = { 'Content-Type': 'application/json', ...extra };
  const authMode = (account.auth_mode || 'bearer');
  if (authMode === 'bearer') h['Authorization'] = 'Bearer ' + credential;
  else if (authMode === 'xApiKey') h['x-api-key'] = credential;
  else if (authMode === 'xGoogleApiKey') h['x-goog-api-key'] = credential;
  return h;
}

function joinUrl(base, route, suffix) {
  let u = base.replace(/\/+$/, '');
  if (route && route !== '/') u += route.replace(/\/+$/, '') || '';
  // suffix 如 /chat/completions
  if (suffix) u += suffix;
  return u;
}

// 非流式 POST，返回 {status, json, text, durationMs, firstByteMs}
async function postJson({ url, headers, body, timeoutMs = DEFAULT_TIMEOUT_MS }) {
  const t0 = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(new Error('upstream_timeout')), timeoutMs);
  try {
    const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body), signal: ctrl.signal });
    const firstByteMs = Date.now() - t0;
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { status: res.status, json, text, durationMs: Date.now() - t0, firstByteMs };
  } finally { clearTimeout(timer); }
}

// 流式 POST：返回 {status, res}，调用方读 res.body（按 SSE 转发）。空闲超时由调用方管。
async function postStream({ url, headers, body, timeoutMs = 60000 }) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(new Error('upstream_timeout')), timeoutMs);
  try {
    const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body), signal: ctrl.signal });
    return { status: res.status, res, abort: () => ctrl.abort() };
  } finally { clearTimeout(timer); }
}

module.exports = { buildHeaders, joinUrl, postJson, postStream, DEFAULT_TIMEOUT_MS, STREAM_IDLE_MS };
