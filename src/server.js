// ssgw 主服务：HTTP 服务器 + 业务端点 + 管理 API + Web UI
'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { openDb, now } = require('./db');
const cred = require('./crypto');
const { Config } = require('./config');
const { Engine } = require('./engine');
const { Api } = require('./api');
const { BodyAudit } = require('./audit');
const { responsesToChat, chatToResponses, ChatToResponsesStream } = require('./protocol');

const DATA_DIR = process.env.SSGW_DATA_DIR || path.join(__dirname, '..', 'data');
const PORT = Number(process.env.SSGW_PORT || 8080);
const LOG = (...a) => console.log(new Date().toISOString(), ...a);

const db = openDb(DATA_DIR);
const cfg = new Config(db);
const credKey = cred.getKey(db, process.env);

// ntfy 通知（可选；凭据走环境变量，不落库）
async function notify(title, body, priority = 'default', tags = 'robot') {
  try {
    const url = process.env.SSGW_NTFY_URL;
    if (!url) return;
    const auth = process.env.SSGW_NTFY_AUTH; // "user:pass" base64 格式或 user:pass
    const headers = { Title: Buffer.from(title).toString('base64'), Priority: priority, Tags: tags };
    if (auth) headers.Authorization = 'Basic ' + (auth.includes(':') && !auth.startsWith('Basic') ? Buffer.from(auth).toString('base64') : auth);
    await fetch(url, { method: 'POST', headers, body });
  } catch (e) { LOG('ntfy send failed:', e.message); }
}

const engine = new Engine(db, cred, { logger: LOG, notify, config: cfg });
engine.credKey = credKey;

// 正文审计（ES）——在 Api 之前创建以便注入
const audit = new BodyAudit(db, cfg, cred, { logger: LOG, credKey });
audit.applySettings();
const api = new Api(db, cred, engine, cfg, { logger: LOG, credKey, audit });
engine.audit = audit;

// 内部 embedder：默认走网关 embedding 账号；配置了独立向量服务时直连
async function embedderViaGateway(texts) {
  const model = cfg.get('embedding.model', 'Qwen/Qwen3-Embedding-8B');
  const arr = Array.isArray(texts) ? texts : [texts];
  const json = await engine.embeddings({ body: { model, input: arr } });
  const vecs = (json.data || []).sort((a, b) => a.index - b.index).map(d => d.embedding);
  return Array.isArray(texts) ? vecs : vecs[0];
}
let _directEmbedder = null;   // 独立向量服务（重新配置时刷新）
function applyVectorService() {
  const vs = cfg.get('vector_service', {}) || {};
  if (vs.mode === 'direct' && vs.base_url && vs.api_key && vs.model) {
    const base = String(vs.base_url).replace(/\/+$/, '');
    const url = base.endsWith('/embeddings') ? base : base + '/embeddings';
    _directEmbedder = async (texts) => {
      const arr = Array.isArray(texts) ? texts : [texts];
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + vs.api_key },
        body: JSON.stringify({ model: vs.model, input: arr, ...(vs.dimensions ? { dimensions: Number(vs.dimensions) } : {}) }),
        signal: AbortSignal.timeout(60000),
      });
      if (!res.ok) throw new Error('vector_service_http_' + res.status);
      const j = await res.json();
      const vecs = (j.data || []).sort((a, b) => a.index - b.index).map(d => d.embedding);
      return Array.isArray(texts) ? vecs : vecs[0];
    };
    LOG('vector service: direct ' + vs.model + ' @ ' + base);
  } else {
    _directEmbedder = null;
    LOG('vector service: via gateway embedding accounts');
  }
}
engine.applyVectorService = applyVectorService;
async function embedder(texts, isBatch = false) {
  if (_directEmbedder) {
    try { return await _directEmbedder(texts); }
    catch (e) { LOG('direct embedder fail, fallback to gateway: ' + e.message); }
  }
  return embedderViaGateway(texts);
}
engine.setEmbedder(embedder);

// 默认管理员
function ensureAdmin() {
  const adminUser = process.env.SSGW_ADMIN_USER || 'admin';
  const adminPass = process.env.SSGW_ADMIN_PASS || 'ssgw-admin';
  const has = db.prepare("SELECT id FROM users WHERE role='admin'").get();
  if (!has) {
    const t = now();
    db.prepare('INSERT INTO users (username,password_hash,role,user_group_id,created_at,updated_at) VALUES (?,?,?,?,?,?)')
      .run(adminUser, cred.hashPassword(adminPass, adminUser), 'admin', 1, t, t);
    db.prepare("INSERT OR IGNORE INTO user_groups (id,name,enabled,is_default,created_at,updated_at) VALUES (1,'Default',1,1,?,?)").run(t, t);
    LOG('created admin user:', adminUser);
  }
}
ensureAdmin();

const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };

function readBody(req, limitMb) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > (limitMb || 32) * 1024 * 1024) { reject(Object.assign(new Error('payload_too_large'), { statusCode: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      const buf = Buffer.concat(chunks);
      if (!buf.length) return resolve({});
      try { resolve(JSON.parse(buf.toString('utf8'))); } catch (e) { reject(Object.assign(new Error('invalid_json'), { statusCode: 400 })); }
    });
    req.on('error', reject);
  });
}

function sendJson(res, code, data) { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(typeof data === 'string' ? data : JSON.stringify(data)); }

// 上游 usage 字段名归一：OpenAI/Anthropic/vLLM 各自命名不同，统一成 input/output/total/cached
function normalizeUsage(u) {
  if (!u) return null;
  const input = u.input_tokens ?? u.prompt_tokens ?? u.promptTokens ?? null;
  const output = u.output_tokens ?? u.completion_tokens ?? u.completionTokens ?? null;
  const cached = u.cached_tokens ?? u.prompt_tokens_details?.cached_tokens ?? u.input_tokens_details?.cached_tokens ?? null;
  let total = u.total_tokens ?? null;
  if (total === null && (input !== null || output !== null)) total = (input || 0) + (output || 0);
  if (input === null && output === null && total === null && cached === null) return null;
  return { input, output, total, cached };
}

function logCall(entry) {
  const v = (x) => (x === undefined ? null : x);
  const u = normalizeUsage(entry.usage) || {};
  db.prepare(`INSERT OR IGNORE INTO call_logs (request_id,started_at_ms,user_id,api_key_id,request_model,upstream_account_id,upstream_model,result_kind,upstream_status,stream,attempt_count,duration_ms,first_byte_ms,error_code,input_tokens,output_tokens,total_tokens,cached_tokens)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(v(entry.requestId), v(entry.startedAtMs), v(entry.userId), v(entry.apiKeyId), v(entry.requestModel), v(entry.upstreamAccountId), v(entry.upstreamModel),
      v(entry.resultKind ?? 1), v(entry.upstreamStatus ?? 200), entry.stream ? 1 : 0, v(entry.attemptCount ?? 1), v(entry.durationMs ?? 0), v(entry.firstByteMs ?? null),
      v(entry.errorCode ?? null), v(u.input ?? null), v(u.output ?? null), v(u.total ?? null), v(u.cached ?? null));
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  try {
    // ---- 静态 UI ----
    if (req.method === 'GET' && !p.startsWith('/api/') && !p.startsWith('/v1/')) {
      let file = p === '/' ? '/index.html' : p;
      const fp = path.normalize(path.join(PUBLIC_DIR, file));
      if (fp.startsWith(PUBLIC_DIR) && fs.existsSync(fp) && fs.statSync(fp).isFile()) {
        res.writeHead(200, { 'Content-Type': MIME[path.extname(fp)] || 'application/octet-stream' });
        fs.createReadStream(fp).pipe(res);
        return;
      }
    }

    // ---- 认证端点 ----
    if (p === '/api/v1/auth/csrf' && req.method === 'GET') {
      // 先建匿名会话再发 CSRF（简化：CSRF 绑定登录后的会话；此处返回占位）
      return sendJson(res, 200, { token: crypto.randomBytes(16).toString('hex') });
    }
    if (p === '/api/v1/auth/login' && req.method === 'POST') {
      const body = await readBody(req, 1);
      const r = await api.login(body.username, body.password);
      if (!r) return sendJson(res, 401, { error: 'invalid_credentials' });
      if (r.locked) return sendJson(res, 423, { error: 'account_locked' });
      res.setHeader('Set-Cookie', `ssgw_session=${r.token}; Path=/; HttpOnly; SameSite=Lax`);
      return sendJson(res, 200, r);
    }
    if (p === '/api/v1/auth/logout' && req.method === 'POST') {
      const s = api.session(req); if (s) api.logout(s);
      return sendJson(res, 200, { ok: true });
    }
    if (p === '/api/v1/auth/current' && req.method === 'GET') {
      const s = api.session(req);
      if (!s) return sendJson(res, 200, { user: null });
      // 页面刷新会丢失内存中的 csrf：轮换一个新 csrf 随响应返回给前端
      const csrf = crypto.randomBytes(32).toString('hex');
      db.prepare('UPDATE sessions SET csrf_hash=? WHERE id=?').run(cred.sha256(csrf), s.id);
      return sendJson(res, 200, { user: { id: s.user_id, username: s.username, role: s.role }, csrf });
    }

    // ---- 管理端点 ----
    if (p.startsWith('/api/v1/admin/')) {
      const body = (req.method === 'GET' || req.method === 'DELETE') ? null : await readBody(req, 5);
      const handled = await api.handleAdmin(req, res, p, url, body);
      if (handled) return;
      return sendJson(res, 404, { error: 'not_found' });
    }

    // ---- 业务端点（API key 认证）----
    if (p.startsWith('/v1/')) {
      const keyRow = api.authKey(req);
      if (!keyRow) return sendJson(res, 401, { error: { message: 'invalid_api_key', type: 'invalid_request_error' } });
      const requestId = crypto.randomUUID();

      // 统一请求闸（所有 /v1/* 业务端点共用）：隐藏模型 404 → 用户组白名单 403 → 内容合规 400
      // 返回 null 表示放行；否则应直接 sendJson(res, g.code, g.body)
      const runGate = (model, text, clientProto, requestBodyRaw) => {
        if (new Set(cfg.get('routing', {}).hidden_models || []).has(String(model || ''))) {
          logCall({ requestId, startedAtMs: Date.now(), userId: keyRow.user_id, apiKeyId: keyRow.id, requestModel: model, resultKind: 4, upstreamStatus: 404, errorCode: 'model_hidden' });
          return { code: 404, body: { error: { message: 'model_not_found', type: 'invalid_request_error' } } };
        }
        const allowed = db.prepare('SELECT model_name FROM user_group_models WHERE user_group_id=?').all(keyRow.user_group_id).map(x => x.model_name);
        if (allowed.length && !allowed.includes(String(model || ''))) {
          logCall({ requestId, startedAtMs: Date.now(), userId: keyRow.user_id, apiKeyId: keyRow.id, requestModel: model, resultKind: 4, upstreamStatus: 403, errorCode: 'model_not_allowed' });
          return { code: 403, body: { error: { message: 'model_not_allowed_for_user_group', type: 'invalid_request_error' } } };
        }
        const auditCheck = api.checkContent(text);
        if (auditCheck && auditCheck.blocked) {
          logCall({ requestId, startedAtMs: Date.now(), userId: keyRow.user_id, apiKeyId: keyRow.id, requestModel: model, resultKind: 4, upstreamStatus: 400, errorCode: 'content_blocked' });
          if (audit.enabled) audit.capture({ requestId, userId: keyRow.user_id, apiKeyId: keyRow.id, requestModel: model, result: 'failed', statusCode: 400, stream: false, durationMs: 0, requestBody: requestBodyRaw, responseBody: { error: `content blocked by policy group ${auditCheck.groupName}` }, clientProtocol: clientProto });
          return { code: 400, body: { error: { message: `content blocked by policy group ${auditCheck.groupName}`, type: 'content_policy' } } };
        }
        return null;
      };

      if (p === '/v1/models' && req.method === 'GET') {
        const hidden = new Set(cfg.get('routing', {}).hidden_models || []);
        const members = db.prepare('SELECT DISTINCT request_model_name FROM model_group_members').all().map(x => x.request_model_name);
        const extra = db.prepare('SELECT DISTINCT request_model_name FROM upstream_account_models').all().map(x => x.request_model_name);
        const mrules = cfg.get('routing', {}).model_rules || {};
        const virtual = Object.entries(mrules).filter(([, v]) => v?.enabled).map(([k]) => k);
        let models = [...new Set([...members, ...extra, ...virtual])].filter(m => !hidden.has(m));
        // 用户组模型白名单
        const allowed = db.prepare('SELECT model_name FROM user_group_models WHERE user_group_id=?').all(keyRow.user_group_id).map(x => x.model_name);
        if (allowed.length) models = models.filter(m => allowed.includes(m));
        return sendJson(res, 200, { object: 'list', data: models.map(m => ({ id: m, object: 'model', owned_by: 'shenshang' })) });
      }
      if (p === '/v1/chat/completions' && req.method === 'POST') {
        const body = await readBody(req, cfg.get('gateway.max_body_mb', 32));
        const requestBodyRaw = audit.enabled ? JSON.stringify(body) : undefined;
        // 统一请求闸：隐藏模型 / 用户组白名单 / 内容合规
        const g = runGate(body.model, Engine.extractUserText(body), 'openaiChatCompletions', requestBodyRaw);
        if (g) return sendJson(res, g.code, g.body);
        const startedAtMs = Date.now();
        const t0 = Date.now();
        try {
          const r = await engine.chat({
            body, apiKey: keyRow, requestId,
            onLog: ({ account, upstreamModel, status, usage, decision }) => {
              logCall({ requestId, startedAtMs, userId: keyRow.user_id, apiKeyId: keyRow.id, requestModel: body.model,
                upstreamAccountId: account.id, upstreamModel, resultKind: 1, upstreamStatus: status,
                stream: !!body.stream, durationMs: Date.now() - t0, usage });
              if (decision) {
                const label = decision.label ?? '';
                const selModel = decision.model ?? decision.upstreamModel ?? body.model;
                db.prepare('INSERT INTO smart_route_decision_logs (request_id,request_model,route_label,confidence,selected_model,decision_source,created_at,created_at_ms) VALUES (?,?,?,?,?,?,?,?)')
                  .run(requestId, body.model, label, decision.confidence ?? 0, selModel, decision.source ?? '', now(), Date.now());
              }
            },
          });
          if (r.kind === 'json') {
            // 拒答重试的 usage 回填（首次调用的日志已写入 request_id；重试产生的 token 补记进去）
            if (r.usage) {
              const u = normalizeUsage(r.usage);
              if (u) db.prepare('UPDATE call_logs SET input_tokens=?, output_tokens=?, total_tokens=?, cached_tokens=? WHERE request_id=?')
                .run(u.input ?? null, u.output ?? null, u.total ?? null, u.cached ?? null, requestId);
            }
            // 非流式：一次调用写一条完整审计（请求+响应正文都在）
            if (audit.enabled) audit.capture({ requestId, userId: keyRow.user_id, apiKeyId: keyRow.id, userGroupId: keyRow.user_group_id, requestModel: body.model, upstreamModel: r.upstreamModel, upstreamAccountId: r.accountId ?? null, upstreamAccountName: r.accountName ?? null, result: 'success', statusCode: 200, stream: false, durationMs: Date.now() - t0, requestBody: requestBodyRaw, responseBody: r.json, clientProtocol: 'openaiChatCompletions' });
            return sendJson(res, 200, r.json);
          }
          // 流式：SSE 透传（Anthropic 协议时边转边发）
          res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            Connection: 'keep-alive',
            'X-Accel-Buffering': 'no',
          });
          const reader = r.res.body.getReader();
          const decoder = new TextDecoder();
          let idleTimer = setTimeout(() => { try { r.abort(); } catch {} }, 600000);
          // Anthropic SSE 解析缓冲（按事件块切分）
          let sseBuf = '';
          let streamUsage = null;
          let respText = '';
          let sawToolCall = false;   // 纯工具调用流：content/reasoning 为空是正常的，审计需区分
          let oaBuf = '';   // OpenAI 直通的行缓冲（SSE 行可能跨 chunk 分裂）
          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              clearTimeout(idleTimer); idleTimer = setTimeout(() => { try { r.abort(); } catch {} }, 600000);
              let chunkText = decoder.decode(value);
              if (r.converter) {
                // Anthropic → OpenAI 事件转换
                sseBuf += chunkText;
                const events = [];
                let idx;
                while ((idx = sseBuf.indexOf('\n\n')) >= 0) {
                  const block = sseBuf.slice(0, idx); sseBuf = sseBuf.slice(idx + 2);
                  const dataLines = block.split('\n').filter(l => l.startsWith('data:')).map(l => l.slice(5).trim());
                  if (!dataLines.length) continue;
                  try { events.push(JSON.parse(dataLines.join('\n'))); } catch {}
                }
                for (const ev of events) {
                  for (const oc of r.converter.convert(ev)) {
                    if (oc.choices?.[0]?.delta?.content) respText += oc.choices[0].delta.content;
                    if (oc.usage) streamUsage = oc.usage;
                    res.write('data: ' + JSON.stringify(oc) + '\n\n');
                  }
                }
              } else {
                // OpenAI 直通：累计正文（审计用）并抓取末尾 usage chunk
                oaBuf += chunkText;
                const cut = oaBuf.lastIndexOf('\n');
                const complete = cut >= 0 ? oaBuf.slice(0, cut) : '';
                oaBuf = cut >= 0 ? oaBuf.slice(cut + 1) : oaBuf;
                for (const line of complete.split('\n')) {
                  if (!line.startsWith('data: ') || line === 'data: [DONE]') continue;
                  try {
                    const j = JSON.parse(line.slice(6));
                    const c = j.choices?.[0]?.delta?.content || '';
                    if (c) respText += c;
                    if (!sawToolCall && Array.isArray(j.choices?.[0]?.delta?.tool_calls) && j.choices[0].delta.tool_calls.length) sawToolCall = true;
                    // 推理模型正文在 reasoning_content（content 可能为空）；计入审计文本避免整条丢失
                    const rc = j.choices?.[0]?.delta?.reasoning_content || j.choices?.[0]?.delta?.reasoning || '';
                    if (rc) respText += rc;
                    if (j.usage) streamUsage = j.usage;
                  } catch {}
                }
                res.write(chunkText);
              }
            }
            if (r.converter) res.write('data: [DONE]\n\n');
          } finally { clearTimeout(idleTimer); }
          // 空流（上游 200 但无任何 content/reasoning 文本）也写审计：否则 UI 显示
          // 「ES 中无正文记录」与"审计未开启"混淆，且空流成功本身是需要排查的异常
          if (audit.enabled) audit.capture({ requestId, userId: keyRow.user_id, apiKeyId: keyRow.id, requestModel: body.model, upstreamModel: r.upstreamModel, upstreamAccountName: null, result: 'success', statusCode: 200, stream: true, durationMs: Date.now() - t0, requestBody: requestBodyRaw, responseBody: respText ? { role: 'assistant', content: respText } : (sawToolCall ? { role: 'assistant', content: '', tool_calls: true } : { role: 'assistant', content: '', note: 'empty stream (no content/reasoning delta)' }), clientProtocol: 'openaiChatCompletions' });
          // 流式用量回填（上游返回 usage 才有；先按无用量落库，这里 UPDATE 覆盖）
          if (streamUsage) {
            const u = normalizeUsage(streamUsage);
            if (u) db.prepare('UPDATE call_logs SET input_tokens=?, output_tokens=?, total_tokens=?, cached_tokens=? WHERE request_id=?')
              .run(u.input ?? null, u.output ?? null, u.total ?? null, u.cached ?? null, requestId);
          }
          res.end();
          return;
        } catch (e) {
          // 流式出错必须留痕：历史上这里静默（头已发出 → 客户端只看到 200 空 SSE），排查代价极大
          LOG('stream failed', requestId, (e && e.stack ? String(e.stack).split('\n')[0] : String(e)));
          logCall({ requestId, startedAtMs, userId: keyRow.user_id, apiKeyId: keyRow.id, requestModel: body.model, resultKind: 4, upstreamStatus: e.statusCode || 502, errorCode: 'upstream_failed', durationMs: Date.now() - t0 });
          if (audit.enabled) audit.capture({ requestId, userId: keyRow.user_id, apiKeyId: keyRow.id, requestModel: body.model, result: 'failed', statusCode: e.statusCode || 502, stream: !!body.stream, durationMs: Date.now() - t0, requestBody: requestBodyRaw, responseBody: { error: e.message } });
          // 流式已发头后失败：不能再 sendJson（否则 "Cannot write headers after sent"）。
          // 用 SSE 错误事件收尾，让客户端拿到失败原因而不是空流。
          if (res.headersSent) {
            try { res.write('data: ' + JSON.stringify({ error: { message: e.message, type: 'upstream_error' } }) + '\n\ndata: [DONE]\n\n'); } catch {}
            res.end(); return;
          }
          return sendJson(res, e.statusCode || 502, { error: { message: e.message, type: 'upstream_error' } });
        }
      }

      // OpenAI Responses API：客户端用 Responses 格式，内部转 Chat 处理
      if (p === '/v1/responses' && req.method === 'POST') {
        const body = await readBody(req, cfg.get('gateway.max_body_mb', 32));
        const chatBody = responsesToChat(body);
        // 统一请求闸（与 chat 端点同规则）
        {
          const g = runGate(body.model, Engine.extractUserText(chatBody), 'openaiResponses', body);
          if (g) return sendJson(res, g.code, g.body);
        }
        const startedAtMs = Date.now();
        const t0 = Date.now();
        const stream = !!body.stream;
        try {
          const r = await engine.chat({
            body: chatBody, apiKey: keyRow, requestId,
            onLog: ({ account, upstreamModel, status }) => {
              logCall({ requestId, startedAtMs, userId: keyRow.user_id, apiKeyId: keyRow.id, requestModel: body.model,
                upstreamAccountId: account.id, upstreamModel, resultKind: 1, upstreamStatus: status,
                stream, durationMs: Date.now() - t0, clientProtocol: 'openaiResponses' });
              if (audit.enabled) audit.capture({ requestId, userId: keyRow.user_id, apiKeyId: keyRow.id, requestModel: body.model, upstreamModel, upstreamAccountId: account.id, upstreamAccountName: account.name, result: 'success', statusCode: status, stream, durationMs: Date.now() - t0, requestBody: body, clientProtocol: 'openaiResponses' });
            },
          });
          if (r.kind === 'json') {
            const resp = chatToResponses(r.json);
            if (audit.enabled) audit.capture({ requestId, userId: keyRow.user_id, apiKeyId: keyRow.id, requestModel: body.model, upstreamModel: r.upstreamModel, result: 'success', statusCode: 200, stream: false, durationMs: Date.now() - t0, responseBody: resp });
            return sendJson(res, 200, resp);
          }
          // 流式：Chat SSE → Responses SSE
          res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
          const reader = r.res.body.getReader();
          const decoder = new TextDecoder();
          const conv = new ChatToResponsesStream(body.model);
          let idleTimer = setTimeout(() => { try { r.abort(); } catch {} }, 600000);
          // SSE 事件缓冲解析（chunk 可能跨块分裂；兼容 data: 与 data: ）
          let rsBuf = '';
          const parseSSE = (text) => {
            rsBuf += text;
            const evs = [];
            let idx;
            while ((idx = rsBuf.indexOf('\n\n')) >= 0) {
              const block = rsBuf.slice(0, idx); rsBuf = rsBuf.slice(idx + 2);
              const dl = block.split('\n').filter(l => l.startsWith('data:')).map(l => l.slice(5).trim());
              if (!dl.length) continue;
              const raw = dl.join('\n');
              if (raw === '[DONE]') continue;
              try { evs.push(JSON.parse(raw)); } catch {}
            }
            return evs;
          };
          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              clearTimeout(idleTimer); idleTimer = setTimeout(() => { try { r.abort(); } catch {} }, 600000);
              const chunkText = decoder.decode(value);
              if (r.converter) {
                // 上游 Anthropic：先转 OpenAI chunk 再转 Responses
                for (const ev of parseSSE(chunkText)) {
                  for (const oc of r.converter.convert(ev)) {
                    for (const re of conv.convert(oc)) res.write('event: ' + re.type + '\ndata: ' + JSON.stringify(re) + '\n\n');
                  }
                }
              } else {
                for (const j of parseSSE(chunkText)) {
                  for (const re of conv.convert(j)) res.write('event: ' + re.type + '\ndata: ' + JSON.stringify(re) + '\n\n');
                }
              }
            }
          } finally { clearTimeout(idleTimer); }
          res.end();
          return;
        } catch (e) {
          logCall({ requestId, startedAtMs, userId: keyRow.user_id, apiKeyId: keyRow.id, requestModel: body.model, resultKind: 4, upstreamStatus: e.statusCode || 502, errorCode: 'upstream_failed', durationMs: Date.now() - t0 });
          return sendJson(res, e.statusCode || 502, { error: { message: e.message, type: 'upstream_error' } });
        }
      }

      if (p === '/v1/embeddings' && req.method === 'POST') {
        const body = await readBody(req, cfg.get('gateway.max_body_mb', 32));
        {
          const g = runGate(body.model, Array.isArray(body.input) ? body.input.filter(x => typeof x === 'string').join(' ') : String(body.input || ''), 'openaiEmbeddings', body);
          if (g) return sendJson(res, g.code, g.body);
        }
        const startedAtMs = Date.now();
        const t0 = Date.now();
        try {
          const json = await engine.embeddings({ body, onLog: ({ account, model, status }) => {
            logCall({ requestId, startedAtMs, userId: keyRow.user_id, apiKeyId: keyRow.id, requestModel: body.model, upstreamAccountId: account?.id, upstreamModel: account?.upstream_model_name, resultKind: 1, upstreamStatus: status, durationMs: Date.now() - t0 });
          } });
          return sendJson(res, 200, json);
        } catch (e) {
          logCall({ requestId, startedAtMs, userId: keyRow.user_id, apiKeyId: keyRow.id, requestModel: body.model, resultKind: 4, upstreamStatus: e.statusCode || 502, errorCode: 'upstream_failed', durationMs: Date.now() - t0 });
          return sendJson(res, e.statusCode || 502, { error: { message: e.message, type: 'upstream_error' } });
        }
      }

      if (p === '/v1/rerank' && req.method === 'POST') {
        const body = await readBody(req, cfg.get('gateway.max_body_mb', 32));
        {
          const g = runGate(body.model, String(body.query || ''), 'openaiRerank', body);
          if (g) return sendJson(res, g.code, g.body);
        }
        const startedAtMs = Date.now();
        const t0 = Date.now();
        try {
          const json = await engine.rerank({ body, onLog: ({ account, model, status }) => {
            logCall({ requestId, startedAtMs, userId: keyRow.user_id, apiKeyId: keyRow.id, requestModel: body.model, upstreamAccountId: account?.id, upstreamModel: account?.upstream_model_name, resultKind: 1, upstreamStatus: status, durationMs: Date.now() - t0 });
          } });
          return sendJson(res, 200, json);
        } catch (e) {
          logCall({ requestId, startedAtMs, userId: keyRow.user_id, apiKeyId: keyRow.id, requestModel: body.model, resultKind: 4, upstreamStatus: e.statusCode || 502, errorCode: 'upstream_failed', durationMs: Date.now() - t0 });
          return sendJson(res, e.statusCode || 502, { error: { message: e.message, type: 'upstream_error' } });
        }
      }

      if (p === '/v1/images/generations' && req.method === 'POST') {
        const body = await readBody(req, cfg.get('gateway.max_body_mb', 32));
        {
          const g = runGate(body.model, String(body.prompt || ''), 'openaiImages', body);
          if (g) return sendJson(res, g.code, g.body);
        }
        const startedAtMs = Date.now();
        const t0 = Date.now();
        try {
          const json = await engine.images({ body, onLog: ({ account, model, status }) => {
            logCall({ requestId, startedAtMs, userId: keyRow.user_id, apiKeyId: keyRow.id, requestModel: body.model, upstreamAccountId: account?.id, upstreamModel: account?.upstream_model_name, resultKind: 1, upstreamStatus: status, durationMs: Date.now() - t0 });
          } });
          return sendJson(res, 200, json);
        } catch (e) {
          logCall({ requestId, startedAtMs, userId: keyRow.user_id, apiKeyId: keyRow.id, requestModel: body.model, resultKind: 4, upstreamStatus: e.statusCode || 502, errorCode: 'upstream_failed', durationMs: Date.now() - t0 });
          return sendJson(res, e.statusCode || 502, { error: { message: e.message, type: 'upstream_error' } });
        }
      }

      return sendJson(res, 404, { error: { message: 'unknown_endpoint', type: 'invalid_request_error' } });
    }

    sendJson(res, 404, { error: 'not_found' });
  } catch (e) {
    LOG('request error', p, e.message);
    if (!res.headersSent) sendJson(res, e.statusCode || 500, { error: { message: e.message, type: 'internal_error' } });
    else res.end();
  }
});

// 日志清理
function cleanup() {
  const days = cfg.get('log.call_retention_days', 30);
  const cutoff = Date.now() - days * 86400000;
  db.prepare('DELETE FROM call_logs WHERE started_at_ms < ?').run(cutoff);
  db.prepare('DELETE FROM smart_route_decision_logs WHERE created_at_ms < ?').run(cutoff);
  db.prepare("DELETE FROM sessions WHERE absolute_expires_at < ?").run(new Date().toISOString());
}
setInterval(cleanup, 3600 * 1000).unref?.();
cleanup();

// 启动时向量化样本（若向量服务可用）
engine.vectorizeSamples().catch(e => LOG('startup vectorize:', e.message));

server.listen(PORT, () => LOG(`神殇AI网关 listening on :${PORT} (data: ${DATA_DIR})`));

process.on('SIGTERM', () => { engine.close(); server.close(() => process.exit(0)); });
