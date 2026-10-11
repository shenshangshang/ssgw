// 路由引擎：账号选择、健康熔断/半开恢复、降级链、智能分流、视觉改写、拒答重试
'use strict';
const crypto = require('node:crypto');
const { postJson, postStream, buildHeaders, joinUrl } = require('./upstream');
const { openaiToAnthropic, anthropicToOpenai, AnthropicStreamConverter } = require('./protocol');

const BUSY_MARKERS = ['rate limit', 'rate_limit', 'too many requests', 'overloaded', 'busy', 'capacity', '429', '503'];
const QUOTA_MARKERS = ['insufficient_balance', '余额不足', 'quota', 'exceeded', 'billing', '402'];
const REFUSAL_KEYWORDS = ['cannot assist', "can't assist", "can't help", 'cannot help', "i'm sorry", 'i am sorry', 'sorry, but', 'cannot provide', "can't provide", 'not able to', 'as an ai', "i won't", 'i will not', "i'm not able", 'cannot generate', 'i cannot generate', 'not something i', 'unable to provide', 'against my', "i can't write", "can't write", "i can't create", "won't write", "won't generate", "can't generate", 'not appropriate for me', "i'm unable", '对不起，我不能', '很抱歉，我无法', '无法协助', '我不能提供', '我无法', '不会生成', '不能创建', '不能写', '无法生成', '无法提供', '内容安全', '安全准则', '违反法律法规', '不适宜内容', '不合适的内容', '设计原则', '使用规范'];

function isBusyError(status, text) {
  if (status === 429 || status === 503) return true;
  if (status === 402) return false;
  const t = (text || '').toLowerCase();
  return BUSY_MARKERS.some(m => t.includes(m));
}
function isQuotaError(status, text) {
  if (status === 402) return true;
  const t = (text || '').toLowerCase();
  return QUOTA_MARKERS.some(m => t.includes(m));
}
// 追问/征集信息豁免：模型要求用户补充资料（如"无法撰写，请提供介绍对象"）不是拒答，
// 这类文本常同时含"无法/不能"字样，只看关键词会误伤并触发不必要的拒答重试链
const CLARIFY_PHRASES = ['请补充', '请提供', '请您提供', '请您补充', '期待您的补充', '期待您补充', '请补充以下信息', '请提供以下信息', 'please provide', 'please specify', 'please share more'];
function looksLikeRefusal(content, refusalField) {
  if (refusalField && refusalField.trim()) return true;
  const t = (content || '').toLowerCase();
  if (!t) return false;
  if (CLARIFY_PHRASES.some(k => t.includes(k))) return false;
  return REFUSAL_KEYWORDS.some(k => t.includes(k));
}

class Engine {
  constructor(db, cred, opts) {
    this.db = db;
    this.cred = cred;               // {getKey, seal, open, mask, sha256}
    this.log = opts.logger || (() => {});
    this.notify = opts.notify || (() => {});   // async (title, body, prio, tags) => {}
    this.cfg = opts.config;         // config 模块
    // 运行时状态（内存，定期刷库）
    this.accountState = new Map();  // id -> {inflight, health, lastFailureAt, cooldownUntil, consecutiveFails, halfOpen}
    this.inflight = 0;              // 网关级并发（供概览展示）
    this.streaming = 0;             // 当前流式请求数
    this.groupInflight = new Map(); // user_group_id -> 当前并发（组限额闸）
    this.keyInflight = new Map();   // api_key_id -> 当前并发（单 Key 限额闸）
    this._loadAccountState();
    // 半开探测：每 60s 检查一次熔断账号
    this._probeTimer = setInterval(() => this._halfOpenSweep().catch(e => this.log('probe err ' + e.message)), 60000);
    this._probeTimer.unref?.();
    // 通知去重：accountId -> date
    this._notified = new Map();
  }

  _loadAccountState() {
    const rows = this.db.prepare('SELECT id, health_status, cooldown_until FROM upstream_accounts').all();
    for (const r of rows) {
      this.accountState.set(r.id, {
        inflight: 0,
        health: r.health_status || 'unknown',
        cooldownUntil: r.cooldown_until ? Date.parse(r.cooldown_until) : null,
        consecutiveFails: 0,
      });
    }
  }

  accountsForModel(modelName) {
    return this.db.prepare(`
      SELECT a.*, m.upstream_model_name FROM upstream_accounts a
      JOIN upstream_account_models m ON m.account_id = a.id
      WHERE m.request_model_name = ? AND a.enabled = 1
      ORDER BY COALESCE(m.priority, a.priority) DESC, a.id`).all(modelName);
  }

  _state(id) {
    if (!this.accountState.has(id)) this.accountState.set(id, { inflight: 0, health: 'unknown', cooldownUntil: null, consecutiveFails: 0 });
    return this.accountState.get(id);
  }

  // 等待账号并发槽位：轮询至超时；返回 true=等到槽位，false=超时放弃
  _waitAccountSlot(st, max, waitMs) {
    return new Promise(resolve => {
      const t0 = Date.now();
      const timer = setInterval(() => {
        if (st.inflight < max) { clearInterval(timer); resolve(true); }
        else if (Date.now() - t0 >= waitMs) { clearInterval(timer); resolve(false); }
      }, 100);
      timer.unref?.();
    });
  }

  // 账号级请求频率闸：闲鱼等上游有 nginx 层 rate limit（实测 60 req/min），并发控制管不住
  // 短时间请求次数。用最小请求间隔平滑限速，避免 429 → busy 熔断 → 全量秒败的连锁。
  // minIntervalMs = 60000 / 上游每分钟限额；0 = 不限制。
  async _rateLimitGate(st, waitMs) {
    const interval = Number(this.cfg.get('performance', {}).account_min_interval_ms ?? 1100);
    if (interval <= 0) return;
    const now = Date.now();
    const earliest = (st.lastSentAt || 0) + interval;
    if (now >= earliest) { st.lastSentAt = now; return; }
    const delay = Math.min(earliest - now, waitMs);
    st.lastSentAt = now + delay;   // 先占号，并发等待者不会同时放行
    await new Promise(r => setTimeout(r, delay));
  }

  _available(st, account) {
    if (account.max_concurrency > 0 && st.inflight >= account.max_concurrency) return false;
    if (st.health === 'unavailable') {
      if (st.cooldownUntil && Date.now() >= st.cooldownUntil) return true; // 半开：冷却到期允许试探
      return st.cooldownUntil === null ? false : false;
    }
    if (st.health === 'cooldown' && st.cooldownUntil && Date.now() < st.cooldownUntil) return false;
    return true;
  }

  markFailure(account, kind /* 'busy' | 'quota' | 'error' */) {
    const st = this._state(account.id);
    st.lastFailureAt = Date.now();
    st.consecutiveFails++;
    const policy = this.cfg.get('health_policy', { cooldownBaseSec: 60, quotaLatchSec: 0 });
    if (kind === 'quota') {
      // 配额错误：长闩锁（默认 30 分钟），靠半开探测恢复——修复 aigw 无自愈的缺陷
      const latchMs = (policy.quotaLatchSec ?? 1800) * 1000;
      st.health = 'unavailable'; st.cooldownUntil = Date.now() + latchMs;
      this._persistHealth(account.id, st);
      this._notifyQuota(account);
    } else if (kind === 'busy') {
      const backoff = Math.min((policy.cooldownBaseSec ?? 60) * Math.pow(2, Math.min(st.consecutiveFails - 1, 5)), 3600);
      st.health = 'cooldown'; st.cooldownUntil = Date.now() + backoff * 1000;
      this._persistHealth(account.id, st);
    } else if (st.consecutiveFails >= (policy.errorFails ?? 3)) {
      st.health = 'unavailable'; st.cooldownUntil = Date.now() + (policy.cooldownBaseSec ?? 60) * 1000;
      this._persistHealth(account.id, st);
    }
  }

  markSuccess(account) {
    const st = this._state(account.id);
    st.consecutiveFails = 0; st.health = 'available'; st.cooldownUntil = null;
    this.db.prepare("UPDATE upstream_accounts SET health_status='available', health_checked_at=?, cooldown_until=NULL, last_verified_at=? WHERE id=?")
      .run(new Date().toISOString(), new Date().toISOString(), account.id);
    // 恢复通知（同一账号同一天只发一次异常通知，恢复也提示）
    if (this._notified.has(account.id)) {
      this._notified.delete(account.id);
      this.notify(`ssgw：上游账号 ${account.name} 已恢复`, `健康探测通过，恢复路由。`, 'default', 'white_check_mark');
    }
  }

  _persistHealth(id, st) {
    this.db.prepare('UPDATE upstream_accounts SET health_status=?, health_checked_at=?, cooldown_until=? WHERE id=?')
      .run(st.health, new Date().toISOString(), st.cooldownUntil ? new Date(st.cooldownUntil).toISOString() : null, id);
  }

  async _notifyQuota(account) {
    const today = new Date().toISOString().slice(0, 10);
    if (this._notified.get(account.id) === today) return;
    this._notified.set(account.id, today);
    await this.notify(`ssgw：上游账号 ${account.name} 配额/余额异常`, `账号已被熔断，进入半开探测队列；若上游确已欠费需要人工充值。`, 'high', 'warning,robot');
  }

  // 半开探测：冷却到期的 unavailable 账号用接近真实体积的请求试探。
  // 关键：某些上游（闲鱼）小请求 200 而大请求 402，tiny 探测会假阳性"恢复"，
  // 探测正文必须撑到真实负载量级（~30KB）。
  static PROBE_TEXT = 'quantum computing post-quantum cryptography analysis. '.repeat(600) + '请总结上述内容。';

  async _halfOpenSweep() {
    const rows = this.db.prepare("SELECT * FROM upstream_accounts WHERE enabled=1").all();
    for (const account of rows) {
      const st = this._state(account.id);
      if (st.health !== 'unavailable' && st.health !== 'unknown') continue;
      // unknown（从未请求过/重启后）也探测，探测成功即 available；unavailable 需冷却到期
      if (st.health === 'unavailable' && (!st.cooldownUntil || Date.now() < st.cooldownUntil)) continue;
      const key = this.cred.open(this.credKey, account.credential_envelope);
      if (!key) continue;
      const model = account.validation_model || this.db.prepare('SELECT request_model_name FROM upstream_account_models WHERE account_id=?').get(account.id)?.request_model_name;
      if (!model) continue;
      // 探测必须走账号的模型映射（request→upstream 名），否则上游按原始名计费/判定（如闲鱼 glm-5.2 大请求 402 而 glm-5.3 可用）
      const mapping = this.db.prepare('SELECT upstream_model_name FROM upstream_account_models WHERE account_id=? AND request_model_name=?').get(account.id, model);
      const upstreamModel = mapping?.upstream_model_name || model;
      try {
        const url = joinUrl(account.service_base_url, this._route(account), '/chat/completions');
        const r = await postJson({
          url, headers: buildHeaders(account, key),
          body: { model: upstreamModel, messages: [{ role: 'user', content: Engine.PROBE_TEXT }], max_tokens: 4 },
          timeoutMs: 60000,
        });
        if (r.status === 200) { this.markSuccess(account); this.log(`半开探测成功（真实体积） ${account.name}`); }
        else { this.markFailure(account, isQuotaError(r.status, r.text) ? 'quota' : 'error'); this.log(`半开探测失败 ${account.name} ${r.status}`); }
      } catch (e) {
        this.markFailure(account, 'error');
        this.log(`半开探测异常 ${account.name} ${e.message}`);
      }
    }
  }

  _route(account) {
    const row = this.db.prepare('SELECT route FROM upstream_account_protocols WHERE account_id=? ORDER BY sort LIMIT 1').get(account.id);
    return row?.route || '/';
  }

  // 账号上游协议（默认 openai；anthropic = /v1/messages Anthropic Messages 格式）
  _upstreamProtocol(account) {
    const row = this.db.prepare('SELECT protocol FROM upstream_account_protocols WHERE account_id=? ORDER BY sort LIMIT 1').get(account.id);
    return row?.protocol || 'openaiChatCompletions';
  }

  // 按协议把统一 Chat body 转成上游请求体（返回 {path, body, authMode, protocol}）
  _upstreamRequest(account, body, upstreamModel) {
    const proto = this._upstreamProtocol(account);
    if (proto === 'anthropicMessages') {
      return { path: '/messages', body: openaiToAnthropic({ ...body, model: upstreamModel }), authMode: 'xApiKey', protocol: proto };
    }
    const out = { ...body, model: upstreamModel };
    // 流式请求显式索取 usage（OpenAI 兼容上游默认不在流里返回用量）
    if (out.stream && !out.stream_options) out.stream_options = { include_usage: true };
    return { path: '/chat/completions', body: out, authMode: 'bearer', protocol: 'openaiChatCompletions' };
  }

  // ---- 主请求路径 ----
  // 处理 chat 请求：选择账号 → 转发（流式/非流式）→ 忙降级重试 → 拒答检测（非流式）
  // 等待队列：组/Key 并发满时挂起等待槽位释放（默认 30s 超时→429）
  // 组并发/队列配置内存缓存（30s TTL）：_waitSlot 每 200ms 轮询，不缓存会打满同步 DB 桥
  _groupCfg(gid) {
    const nowT = Date.now();
    const c = this._groupLimitCache?.get(gid);
    if (c && nowT - c.t < 30000) return c.v;
    const g = this.db.prepare('SELECT max_concurrency, queue_size, queue_timeout_sec FROM user_groups WHERE id=?').get(gid);
    const v = { conc: g?.max_concurrency || 0, queueSize: g?.queue_size || 0, queueTimeoutSec: g?.queue_timeout_sec || 0 };
    if (!this._groupLimitCache) this._groupLimitCache = new Map();
    this._groupLimitCache.set(gid, { v, t: nowT });
    return v;
  }
  _groupLimit(gid) { return this._groupCfg(gid).conc; }

  // 等待队列：组/Key 并发满时挂起等待槽位释放。
  // 组级队列深度 queue_size（0=不限）：排队人数超限直接 429 不排队；
  // 组级 queue_timeout_sec（0=用全局 performance.queue_timeout_sec）覆盖等待超时。
  async _waitSlot(gid, keyId, keyMax) {
    const perf = this.cfg.get('performance', {});
    const gcfg = gid ? this._groupCfg(gid) : { queueSize: 0, queueTimeoutSec: 0 };
    const timeoutMs = Math.max(0, (gcfg.queueTimeoutSec || perf.queue_timeout_sec || 30)) * 1000;
    if (!this.groupQueuing) this.groupQueuing = new Map();   // gid -> 当前排队数
    if (gcfg.queueSize > 0 && (this.groupQueuing.get(gid) || 0) >= gcfg.queueSize) {
      const e = new Error('user_group_queue_full');
      e.statusCode = 429;
      throw e;
    }
    this.groupQueuing.set(gid, (this.groupQueuing.get(gid) || 0) + 1);
    const t0 = Date.now();
    const groupAt = () => gid ? (this.groupInflight.get(gid) || 0) : 0;
    const keyAt = () => keyId ? (this.keyInflight.get(keyId) || 0) : 0;
    try {
      while (Date.now() - t0 < timeoutMs) {
        const groupMax = gid ? this._groupLimit(gid) : 0;
        const groupLimited = groupMax > 0 && groupAt() >= groupMax;
        const keyLimited = keyMax > 0 && keyAt() >= keyMax;
        if (!groupLimited && !keyLimited) return true;
        await new Promise(r => setTimeout(r, 200));
      }
      return false;
    } finally {
      this.groupQueuing.set(gid, Math.max(0, (this.groupQueuing.get(gid) || 1) - 1));
    }
  }

  async chat({ body, apiKey, requestId, onLog }) {
    // 两级并发闸（组 + 单 Key）：满时先排队等待，超时 429
    let gid = apiKey?.user_group_id || null;
    const keyId = apiKey?.id || null;
    let keyMax = 0;
    if (keyId) {
      const k = this.db.prepare('SELECT max_concurrency FROM api_keys WHERE id=?').get(keyId);
      keyMax = k?.max_concurrency || 0;
    }
    const groupMax0 = gid ? this._groupLimit(gid) : 0;
    const groupFull = groupMax0 > 0 && (this.groupInflight.get(gid) || 0) >= groupMax0;
    const keyFull = keyMax > 0 && (this.keyInflight.get(keyId) || 0) >= keyMax;
    if (groupFull || keyFull) {
      const got = await this._waitSlot(gid, keyId, keyMax);
      if (!got) {
        const e = new Error(groupFull ? 'user_group_concurrency_limit' : 'api_key_concurrency_limit');
        e.statusCode = 429; throw e;
      }
    }
    this.inflight++;
    this.queued = Math.max(0, (this.queued || 0));
    if (gid) this.groupInflight.set(gid, (this.groupInflight.get(gid) || 0) + 1);
    if (keyId) this.keyInflight.set(keyId, (this.keyInflight.get(keyId) || 0) + 1);
    try { return await this._chat({ body, apiKey, requestId, onLog }); }
    finally {
      this.inflight--;
      if (gid) this.groupInflight.set(gid, Math.max(0, (this.groupInflight.get(gid) || 1) - 1));
      if (keyId) this.keyInflight.set(keyId, Math.max(0, (this.keyInflight.get(keyId) || 1) - 1));
    }
  }

  async _chat({ body, apiKey, requestId, onLog }) {
    const origModel = body.model;
    const stream = !!body.stream;
    await this._extractFileParts(body);

    // 1. 模型解析（优先级从高到低）：
    //    ① 规则命中（含图/简单/复杂/关键词/长上下文…）→ 规则目标模型
    //    ② 全部未命中 → 该模型的 default_model
    //    ③ 未配 default_model → 按该模型自身上游账号优先级降级
    //    ④ 目标模型全链失败（429/熔断）→ 失败分流：按 simple/complex 分类改走 fallback_simple/fallback_complex
    //    所有模型（含 auto）统一走模型级规则集；拒答链（设置页全局默认 + 模型级覆盖）在响应阶段处理
    let targetModel = origModel;
    let decision = null;
    if (this._modelSmartRouteOn(origModel)) {
      const hit = await this._evalRouteRules(body, origModel);
      if (hit) { targetModel = hit.model; decision = { label: hit.label, confidence: hit.confidence ?? 0, source: 'rule:' + hit.rule, model: hit.model, smart: true }; }
      else {
        // 规则未命中的默认模型（该模型独享）：配置了则改走之，否则按该模型自身账号优先级降级
        const defModel = (this._modelRules()[origModel] || {}).default_model;
        if (defModel) { targetModel = defModel; decision = { label: 'default', confidence: 1, source: 'rule:default', model: defModel, smart: true }; }
      }
    }
    const hasImg = Engine.hasImage(body);
    if (hasImg) {
      // 视觉模型（routing.vision_model）：当前输入带图且目标模型不吃图时改走它
      const vision = this.cfg.get('routing', {}).vision_model;
      const accounts = this.accountsForModel(targetModel);
      const supportsVision = accounts.some(a => a.upstream_model_name);
      if (vision && (accounts.length === 0 || !this._modelSupportsVision(targetModel))) {
        targetModel = vision;
        decision = decision || {};
        decision.visionRewrite = true;
      }
    } else if (Engine.historyHasImage(body) && !this._modelSupportsVision(targetModel)) {
      // 历史消息带图 + 当前纯文字 + 目标模型不吃图：用同一视觉模型把图片转成文字描述再发（aigw 逻辑）
      const vision = this.cfg.get('routing', {}).vision_model;
      if (vision && this.accountsForModel(vision).length) {
        this.log(`历史图片 → ${vision} 转文字描述后走 ${targetModel}`);
        // 深拷贝再改写：原始 body 保持带图（拒答重试给本地多模态模型时还能看到原图）
        const converted = JSON.parse(JSON.stringify(body));
        await this.describeHistoryImages(converted, vision);
        body.messages = converted.messages;
        decision = decision || {};
        decision.imageDescribed = true;
      }
    }

    // 2. 候选账号链：目标模型账号（+ 失败分流，仅配置了 fallback_simple/complex 的模型）
    // 返回：成功 = { ok: true, result }（结果对象含 stream/json）；全失败 = { ok: false, err }
    const tryChain = async (chain, decisionExtra) => {
      let le = null;
      for (const model of chain) {
        let accounts = this.accountsForModel(model);
        // 原生协议（OpenAI Chat）始终优先；协议转换开启时 Anthropic 账号作为兜底，关闭时只用原生账号
        {
          const convOn = this.cfg.get('routing', {}).protocol_conversion !== false;
          const nat = [], conv = [];
          for (const a of accounts) (this._upstreamProtocol(a) === 'openaiChatCompletions' ? nat : conv).push(a);
          accounts = convOn ? [...nat, ...conv] : nat;
        }
        for (const account of accounts) {
        const st = this._state(account.id);
        // 账号并发满：先等槽位（performance.account_concurrency_wait_ms，默认 30s，0=不等待），
        // 而不是立即跳过导致 no_available_upstream 秒败——闲鱼上限 2，ZCode 并行工具调用常 3+。
        // 必须放在 _available 之前：_available 对并发满返回 false，先查会直接 continue 跳过本账号
        if (account.max_concurrency > 0 && st.inflight >= account.max_concurrency) {
          const waitMs = Number(this.cfg.get('performance', {}).account_concurrency_wait_ms ?? 30000);
          if (waitMs > 0) await this._waitAccountSlot(st, account.max_concurrency, waitMs);
        }
        if (!this._available(st, account)) continue;
        const credential = this.cred.open(this.credKey, account.credential_envelope);
        if (!credential) { this.markFailure(account, 'error'); continue; }
        // 频率闸：按最小间隔放行，超上游 rate limit 的请求在网关内排队而非撞 429 熔断
        await this._rateLimitGate(st, Number(this.cfg.get('performance', {}).account_concurrency_wait_ms ?? 30000));
        st.inflight++;
        try {
          const { path: upPath, body: upstreamBody, authMode, protocol } = this._upstreamRequest(account, body, account.upstream_model_name || model);
          const url = joinUrl(account.service_base_url, this._route(account), upPath);
          const headers = buildHeaders({ ...account, auth_mode: authMode }, credential);
          if (stream) {
            // 首字节超时可配（performance.stream_first_byte_timeout_sec，默认 180）：
            // 闲鱼 glm-5.3 大上下文流式 prefill 实测 26-60s+，写死 60s 会误杀并连锁熔断账号
            const ttfbSec = Number(this.cfg.get('performance', {}).stream_first_byte_timeout_sec) || 180;
            const r = await postStream({ url, headers, body: upstreamBody, timeoutMs: ttfbSec * 1000 });
            if (r.status === 200) {
              // Anthropic SSE → OpenAI SSE 边转边发（转换器挂在返回对象上，由 server 层驱动）
              const converter = protocol === 'anthropicMessages' ? new AnthropicStreamConverter(body.model) : null;
              // smartStream：拒答检测覆盖流式（aigw v3.7 对齐）。
              // 先缓冲 SSE 累积 content：超 500 字立即透传（拒答必短）；阈值内读完则做拒答检测，
              // 命中即按拒答链非流式重试并合成 SSE 返回，否则把缓冲整体放出。
              // 成功记账放到缓冲之后：空响应不能记成功（否则 call_logs 记 result_kind=1、用量为空）
              if (this.cfg.get('routing', {}).refusal_retry) {
                const smart = await this._smartStream(r, body, upstreamBody, account, headers, url, origModel, converter);
                if (!smart) continue;   // 空响应/上游流异常：不记成功，交给下一账号或失败分流
                this.markSuccess(account);
                onLog && onLog({ account, model, upstreamModel: account.upstream_model_name, status: 200, decision: { ...decision, ...decisionExtra } });
                return smart;
              }
              this.markSuccess(account);
              onLog && onLog({ account, model, upstreamModel: account.upstream_model_name, status: 200, decision: { ...decision, ...decisionExtra } });
              return { ok: true, result: { kind: 'stream', res: r.res, abort: r.abort, upstreamModel: account.upstream_model_name, protocol, converter } };
            }
            const errText = await r.res.text().catch(() => '');
            r.abort?.();
            le = { status: r.status, text: errText };
            if (isQuotaError(r.status, errText)) { this.markFailure(account, 'quota'); continue; }
            if (isBusyError(r.status, errText)) { this.markFailure(account, 'busy'); continue; }
            if (r.status >= 500) this.markFailure(account, 'error');
            continue; // 4xx 客户端类错误：跳过该账号但不熔断（模型能力/请求问题，非上游故障）
          } else {
            const r = await postJson({ url, headers, body: upstreamBody });
            if (r.status === 200) {
              // Anthropic 非流式响应 → OpenAI 格式
              const json = protocol === 'anthropicMessages' ? anthropicToOpenai(r.json, body.model) : r.json;
              const choice = json?.choices?.[0];
              const content = choice?.message?.content || '';
              // 空响应（200 但无正文/无工具调用/无推理/无用量）不是有效结果：不记成功，按该账号失败继续
              const msg = choice?.message || {};
              const hasBody = String(content).trim() || (Array.isArray(msg.tool_calls) && msg.tool_calls.length) ||
                msg.reasoning_content || msg.reasoning;
              if (!hasBody && !json?.usage) {
                this.log(`上游非流式空响应（${account.upstream_model_name || model}）→ 按失败处理`);
                le = { status: 502, text: 'upstream_empty_completion' };
                continue;
              }
              this.markSuccess(account);
              onLog && onLog({ account, model, upstreamModel: account.upstream_model_name, status: 200, durationMs: r.durationMs, decision: { ...decision, ...decisionExtra }, usage: json?.usage });
              // 拒答检测与本地重试
              if (this.cfg.get('routing', {}).refusal_retry && looksLikeRefusal(content, choice?.message?.refusal)) {
                const retried = await this.refusalRetry({ body, upstreamBody, account, headers, url, r, json, origModel });
                if (retried) return { ok: true, result: retried };
              }
              return { ok: true, result: { kind: 'json', json, upstreamModel: account.upstream_model_name, accountId: account.id, accountName: account.name } };
            }
            le = { status: r.status, text: r.text };
            if (isQuotaError(r.status, r.text)) { this.markFailure(account, 'quota'); continue; }
            if (isBusyError(r.status, r.text)) { this.markFailure(account, 'busy'); continue; }
            if (r.status >= 500) this.markFailure(account, 'error');
            continue; // 4xx 客户端错误：跳过但不熔断
          }
        } catch (e) {
          le = { status: 0, text: e.message };
          this.markFailure(account, 'error');
        } finally { st.inflight--; }
      }
      }
      return { ok: false, err: le };   // 该链全失败，返回最后的错误供调用方决定是否走失败分流
    };

    const first = await tryChain([targetModel]);
    if (first.ok) return first.result;
    let lastErr = first.err;

    // 失败分流：仅配置了 fallback_simple/complex 的模型（如 auto）全链失败时，
    // 按请求分类改走简单/复杂分流模型（如 auto 全挂：简单→DeepSeek-V3.2，复杂→deepseek-v4-flash）。
    // 无全局降级链：显式指定的模型（glm-5.3、DeepSeek-V3.2…）全链失败直接报错，不偷偷换模型
    if (lastErr) {
      const mr = this._modelRules()[origModel] || {};
      if (mr.fallback_simple || mr.fallback_complex) {
        let label = 'complex';
        try { label = (await this.classifyRequest(Engine.extractUserText(body))).label; } catch {}
        const fbModel = label === 'simple' ? mr.fallback_simple : mr.fallback_complex;
        const fbTarget = fbModel && this.accountsForModel(fbModel).length ? fbModel : (mr.fallback_simple || mr.fallback_complex);
        if (fbTarget && this.accountsForModel(fbTarget).length) {
          this.log(`模型 ${origModel} 全链失败（${lastErr.status}），失败分流[${label}] → ${fbTarget}`);
          const fbDecision = { label: 'fallback_' + label, confidence: 1, source: 'failure:' + lastErr.status, model: fbTarget, smart: true };
          const r = await tryChain([fbTarget], { fallback: fbDecision });
          if (r.ok) return r.result;   // 分流链成功
          lastErr = r.err;
        }
      }
    }
    if (lastErr) {
      const err = new Error(lastErr ? `upstream_unavailable (${lastErr.status}) ${String(lastErr.text || '').slice(0, 300)}` : 'no_available_upstream');
      err.statusCode = 502;
      throw err;
    }
    throw new Error('no_available_upstream');
  }

  // 模型级智能路由开关（settings.routing.model_rules：{ "<请求模型>": { enabled } }）
  _modelRules() { return this.cfg.get('routing', {}).model_rules || {}; }
  _modelSmartRouteOn(modelName) {
    const r = this._modelRules()[modelName];
    return !!(r && r.enabled);
  }

  // 规则引擎（settings.routing.rules，按序匹配，模块化——参考原版 auto 的分流逻辑）
  // 每条规则：{ name, type, value, target, enabled }
  //   type=has_image  请求含图片          → target
  //   type=simple     分类为简单          → target
  //   type=complex    分类为复杂          → target
  //   type=keyword    正文含关键词 value  → target
  //   type=min_chars  正文长度 ≥ value    → target
  //   type=long_ctx   估算输入 token ≥ value → target（重量级请求）
  // 上下文（分类结果）只算一次，逐条规则短路返回第一个命中的 target
  // JEV 分类（1Panel ai-gateway 1.3 对齐，laya-provider 模式）：
  // 把用户请求发给 laya-server /v1/systemone，对每个自定义 target（name/appliesTo/notFor/examples）
  // 做概率分类，选概率最高且能服务的 target；置信度边缘低于 minimumMargin 时落 fallbackModel。
  // 返回 {model, rule, label, confidence, probabilities, targetName} 或 null（禁用/失败/无可用目标）。
  async _classifyJev(text) {
    const jev = this.cfg.get('routing', {}).jev || {};
    if (!jev.enabled || !Array.isArray(jev.targets) || !jev.targets.length) return null;
    const usable = jev.targets.filter(t => t && t.name && this.accountsForModel(t.model).length);
    if (!usable.length) { this.log('JEV: 无可用 target（模型无账号映射）'); return null; }
    const endpoint = (jev.endpoint || '').replace(/\/+$/, '');
    if (!endpoint) return null;
    // 凭据：laya 账号信封里的 API key
    const acct = this.db.prepare("SELECT credential_envelope FROM upstream_accounts WHERE name='laya-server' AND enabled=1").get();
    let apiKey = '';
    if (acct) {
      const c = this.cred.open(this.credKey, acct.credential_envelope);
      apiKey = typeof c === 'string' ? c : (c?.api_key || '');
    }
    // 单一多选问题：全部 target 名作为 criteria，一次分类得到互斥概率分布。
    // （此前"每类别独立问属于/不属于"失败：laya 对什么都答"属于"，概率全高且边缘恒为 0）
    const questions = {};
    let instr = '把用户请求归入最合适的一个类别。';
    for (const t of usable) {
      instr += `\n【${t.name}】= ${t.appliesTo || '（无描述）'}`;
      if (t.notFor) instr += `（不含: ${t.notFor}）`;
    }
    instr += '\n只输出一个类别名。';
    questions.route = { type: 'choice', criteria: usable.map(t => t.name), instructions: instr.slice(0, 2000) };
    const payload = { state: { message: String(text || '').slice(0, 8000) }, questions };
    if (jev.model) payload.model = jev.model === 'auto' ? 'auto' : jev.model;
    const t0 = Date.now();
    try {
      const r = await postJson({
        url: endpoint + '/v1/systemone',
        headers: apiKey ? { Authorization: 'Bearer ' + apiKey, 'Content-Type': 'application/json' } : { 'Content-Type': 'application/json' },
        body: payload,
        timeoutMs: 15000,
      });
      if (r.status !== 200 || !r.json?.answers) {
        this.log(`JEV 分类失败: HTTP ${r.status} ${String(r.text || '').slice(0, 120)}`);
        return null;
      }
      const dur = Date.now() - t0;
      // 单问题多选：answers.route.probabilities 的 key 是各 target 名（互斥分布）
      const a = r.json.answers.route;
      const prob = {};
      for (const t of usable) prob[t.name] = a?.probabilities?.[t.name] ?? (a?.choice === t.name ? 1 : 0);
      // 归一化（多 target 概率非互斥时仍可比）
      const ranked = [...usable].sort((a, b) => (prob[b.name] || 0) - (prob[a.name] || 0));
      const best = ranked[0];
      const second = ranked[1];
      const confidence = prob[best.name] || 0;
      const margin = second ? confidence - (prob[second.name] || 0) : confidence;
      this.log(`JEV 分类 ${dur}ms → ${best.name} p=${confidence.toFixed(2)} margin=${margin.toFixed(2)}（${usable.map(t => t.name + ':' + (prob[t.name] || 0).toFixed(2)).join(' ')}）`);
      // 置信度边缘不足 → 优先 fallback 模型；fallback 未配置或全部账号不健康时，
      // 直接走最高概率 target（p 很高时它本来就能用），绝不让请求在 fallback 挂掉后直接报错
      if (margin < (Number(jev.minimumMargin) || 0)) {
        const fb = jev.fallbackModel;
        const fbHealthy = fb && this.accountsForModel(fb).some(a => {
          const st = this._state(a.id);
          return this._available(st, a);
        });
        if (fb && this.accountsForModel(fb).length) {
          if (fbHealthy) {
            this.log(`JEV 边缘不足 → fallback ${fb}`);
            return { model: fb, rule: 'jev_fallback', label: best.name, confidence, probabilities: prob, targetName: best.name, fallback: true };
          }
          this.log(`JEV 边缘不足且 fallback ${fb} 不可用 → 按最高概率走 ${best.name}（p=${confidence.toFixed(2)}）`);
          return { model: best.model, rule: 'jev:' + best.name, label: best.name, confidence, probabilities: prob, targetName: best.name, fallbackUsed: true };
        }
        return null;
      }
      return { model: best.model, rule: 'jev:' + best.name, label: best.name, confidence, probabilities: prob, targetName: best.name };
    } catch (e) {
      this.log(`JEV 分类异常: ${e.message}`);
      return null;
    }
  }

  async _evalRouteRules(body, scopeModel) {
    const routing = this.cfg.get('routing', {});
    // 每个开启智能路由的模型有独立规则集；auto 未开智能路由时用全局规则
    let rules;
    if (scopeModel === 'auto' && !this._modelSmartRouteOn('auto')) {
      rules = (routing.rules || []).filter(r => r && r.enabled !== false && r.target);
    } else if (scopeModel) {
      const mr = (routing.model_rules || {})[scopeModel];
      rules = (mr?.rules || []).filter(r => r && r.enabled !== false && r.target);
    } else {
      rules = (routing.rules || []).filter(r => r && r.enabled !== false && r.target);
    }
    if (!rules.length) return null;
    const text = Engine.extractUserText(body);
    // JEV 分类优先于通用规则（1.3 对齐：routingMode=jev 时替代本地向量分类作为主力路由）
    const jev = await this._classifyJev(text);
    if (jev) return { model: jev.model, rule: jev.rule, label: jev.label, confidence: jev.confidence, probabilities: jev.probabilities, jevTarget: jev.targetName };
    let cls = null;   // 懒分类
    const getClass = async () => cls || (cls = await this.classifyRequest(text));
    let hasImage = null;
    const getImg = () => hasImage === null ? (hasImage = Engine.hasImage(body)) : hasImage;
    for (const r of rules) {
      let hit = false, label = r.name || r.type;
      try {
        if (r.type === 'has_image') { hit = getImg(); }
        else if (r.type === 'simple' || r.type === 'complex') {
          const c = await getClass();
          hit = c.label === r.type;
          label = r.type + '(' + c.source + ',' + c.confidence.toFixed(2) + ')';
        }
        else if (r.type === 'keyword') { hit = !!text && text.toLowerCase().includes(String(r.value || '').toLowerCase()); }
        else if (r.type === 'min_chars') { hit = text.length >= Number(r.value || 0); }
        else if (r.type === 'long_ctx') {
          const est = Math.ceil((JSON.stringify(body.messages || []).length) / 4);
          hit = est >= Number(r.value || 0);
        }
      } catch { hit = false; }
      // 命中后必须存在能服务 target 的账号，否则继续尝试下一条（软匹配）
      if (hit && this.accountsForModel(r.target).length) {
        // has_image 规则的目标还必须真的能吃图（是 VLM），否则上游会 400 拒收
        if (r.type === 'has_image' && !this._modelSupportsVision(r.target)) {
          this.log(`规则 ${label} 命中但目标 ${r.target} 非视觉模型，跳过`);
          continue;
        }
        return { model: r.target, rule: label, label: r.type, confidence: cls?.confidence ?? 1 };
      }
    }
    return null;
  }

  _modelSupportsVision(model) {
    const v = (this.cfg.get('routing', {}).vision_models || []);
    return v.some(m => model.toLowerCase().includes(m.toLowerCase()));
  }

  // 当前真实输入是否带图：只查最后一条 user 消息（aigw 语义——历史图片不该把会话钉死在 vision 模型）
  static hasImage(body) {
    const msgs = body.messages || [];
    for (let i = msgs.length - 1; i >= 0; i--) {
      if (msgs[i].role === 'user') {
        const c = msgs[i].content;
        if (Array.isArray(c)) return c.some(p => p?.type === 'image_url' || p?.type === 'image');
        return false;
      }
    }
    return false;
  }

  // 历史消息中是否有图片（最后一条 user 之前的消息）
  static historyHasImage(body) {
    const msgs = body.messages || [];
    let lastUserIdx = -1;
    for (let i = msgs.length - 1; i >= 0; i--) if (msgs[i].role === 'user') { lastUserIdx = i; break; }
    for (let i = 0; i < (lastUserIdx < 0 ? msgs.length : lastUserIdx); i++) {
      const c = msgs[i].content;
      if (Array.isArray(c) && c.some(p => p?.type === 'image_url' || p?.type === 'image')) return true;
    }
    return false;
  }

  // PDF → 文本。两层：①pdftotext 提文字层；②文字层为空（扫描版）→ pdftoppm 转图 →
  // 视觉模型（routing.vision_model）逐页识别。结果按文件 sha256 缓存。
  async _pdfToText(buf, name) {
    const { execFile } = require('node:child_process');
    const fs = require('node:fs');
    const crypto = require('node:crypto');
    const tmp = '/tmp/ssgw-pdf-' + crypto.randomBytes(6).toString('hex') + '.pdf';
    fs.writeFileSync(tmp, buf);
    try {
      const text = await new Promise((resolve, reject) => {
        execFile('pdftotext', ['-layout', tmp, '-'], { maxBuffer: 32 * 1024 * 1024, timeout: 30000 }, (e, stdout) => e ? reject(e) : resolve(stdout));
      }).catch(() => '');
      const content = (text || '').trim();
      if (content.length >= 30) {
        this.log(`附件提取: ${name} → ${content.length} 字文本（文字层）`);
        return `[PDF 文件「${name}」的全文内容]:\n${content.slice(0, 200000)}\n[/PDF]`;
      }
      // 扫描版：pdftoppm 逐页转 png → 视觉模型识别（最多 8 页，防失控费用）
      const pages = await new Promise((resolve, reject) => {
        execFile('pdftoppm', ['-png', '-r', '110', '-l', '8', tmp, tmp.replace('.pdf', '')], { timeout: 60000 }, (e) => e ? reject(e) : resolve(fs.readdirSync('/tmp').filter(f => f.startsWith(tmp.slice(5).replace('.pdf', '')) && f.endsWith('.png'))));
      }).catch(() => []);
      if (!pages.length) { this.log(`PDF 无文字层且转图失败（${name}）`); return null; }
      const vision = this.cfg.get('routing', {}).vision_model;
      const accounts = vision ? this.accountsForModel(vision) : [];
      if (!accounts.length) { this.log(`PDF 扫描版无视觉模型可用（${name}）`); return null; }
      const prefix = tmp.slice(5).replace('.pdf', '');
      let ocr = '';
      for (const pg of pages.sort()) {
        const b64 = fs.readFileSync('/tmp/' + pg).toString('base64');
        for (const a of accounts) {
          const c = this.cred.open(this.credKey, a.credential_envelope);
          if (!c) continue;
          const key = (() => { try { return JSON.parse(c).api_key; } catch { return c; } })();
          try {
            const r = await postJson({
              url: joinUrl(a.service_base_url, this._route(a), '/chat/completions'),
              headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' },
              body: {
                model: a.upstream_model_name || vision,
                messages: [{ role: 'user', content: [
                  { type: 'text', text: '识别并转录这一页 PDF 中的全部文字内容（包括表格数据），保持原始结构与顺序，只输出转录文本。' },
                  { type: 'image_url', image_url: { url: 'data:image/png;base64,' + b64 } },
                ] }],
              },
              timeoutMs: 120000,
            });
            const t = r.json?.choices?.[0]?.message?.content;
            if (r.status === 200 && t && t.trim()) { ocr += `\n[第 ${pg.match(/(\d+)\.png$/)?.[1] || '?'} 页]\n${t.trim()}\n`; break; }
          } catch (e) { this.log(`PDF 页识别失败（${name} ${pg}）: ${e.message}`); }
        }
        try { fs.unlinkSync('/tmp/' + pg); } catch {}
      }
      try { fs.unlinkSync(tmp); } catch {}
      if (!ocr.trim()) { this.log(`PDF 扫描版识别无结果（${name}）`); return null; }
      this.log(`附件提取: ${name} → ${ocr.length} 字（视觉识别 ${pages.length} 页）`);
      return `[PDF 文件「${name}」（扫描版，视觉识别转录，共处理 ${pages.length} 页）]:\n${ocr.slice(0, 200000)}\n[/PDF]`;
    } catch (e) {
      this.log(`PDF 提取失败（${name}）: ${e.message}`);
      try { fs.unlinkSync(tmp); } catch {}
      return null;
    }
  }

  // 附件（file part）→ 文本提取：上游（闲鱼/硅基流动/DeepSeek chat）都不支持 type:file，
  // ZCode 发 PDF 时整条链 500。PDF 用容器内 pdftotext 提取文本替换为文本 part；
  // 其他类型文件替换为占位说明，保证请求不中断。
  async _extractFileParts(body) {
    const msgs = body.messages || [];
    let hasFile = false;
    for (const m of msgs) {
      if (!Array.isArray(m.content)) continue;
      if (m.content.some(p => p && p.type === 'file')) { hasFile = true; break; }
    }
    if (!hasFile) return;
    const { execFile } = require('node:child_process');
    const crypto = require('node:crypto');
    for (const m of msgs) {
      if (!Array.isArray(m.content)) continue;
      m.content = await Promise.all(m.content.map(async p => {
        if (!p || p.type !== 'file') return p;
        const f = p.file || {};
        const name = f.filename || '附件';
        const dataUrl = String(f.file_data || '');
        const mMatch = dataUrl.match(/^data:([^;]+);base64,(.*)$/s);
        const mime = mMatch ? mMatch[1] : 'application/octet-stream';
        if (mMatch && mime === 'application/pdf') {
          const hash = crypto.createHash('sha256').update(mMatch[2]).digest('hex');
          if (!this._pdfCache) this._pdfCache = new Map();
          if (this._pdfCache.has(hash)) return { type: 'text', text: this._pdfCache.get(hash) };
          const result = await this._pdfToText(Buffer.from(mMatch[2], 'base64'), name);
          if (result) {
            if (this._pdfCache.size > 100) this._pdfCache.delete(this._pdfCache.keys().next().value);
            this._pdfCache.set(hash, result);
            return { type: 'text', text: result };
          }
        }
        return { type: 'text', text: `[附件: ${name} (${mime}, ${(dataUrl.length / 1024 / 1.37 | 0)}KB)——当前上游不支持读取该附件内容]` };
      }));
      // content 变成全文本后收拢为纯字符串（部分上游对混合数组仍有兼容问题）
      const allText = m.content.every(p => p.type === 'text');
      if (allText) m.content = m.content.map(p => p.text).join('\n');
    }
  }

  // 历史图片 → 文字描述（aigw describeHistoryImages 对齐）：
  // 目标模型不吃图时，用 vision 模型把历史图片识别成 [图片内容: …] 文本替换，让 glm 等纯文本模型拿到完整图片信息继续对话。
  // 描述按图片 sha256 缓存，同一张图只识别一次；识别失败兜底 "[图片内容暂不可用]"。
  async describeHistoryImages(body, visionModel) {
    const crypto = require('crypto');
    const msgs = body.messages || [];
    let lastUserIdx = -1;
    for (let i = msgs.length - 1; i >= 0; i--) if (msgs[i].role === 'user') { lastUserIdx = i; break; }
    if (!this._imageDescCache) this._imageDescCache = new Map();
    const cache = this._imageDescCache;
    const describe = async (imgUrl) => {
      const data = String(imgUrl);
      const hash = crypto.createHash('sha256').update(data).digest('hex');
      if (cache.has(hash)) return cache.get(hash);
      let desc = null;
      try {
        const accounts = this.accountsForModel(visionModel);
        for (const a of accounts) {
          const cred = this.cred.open(this.credKey, a.credential_envelope);
          if (!cred) continue;
          const key = (() => { try { return JSON.parse(cred).api_key; } catch { return cred; } })();
          const r = await postJson({
            url: joinUrl(a.service_base_url, this._route(a), '/chat/completions'),
            headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' },
            body: {
              model: a.upstream_model_name || visionModel,
              messages: [{ role: 'user', content: [
                { type: 'text', text: '详细描述这张图片的主要内容物、颜色外观、图内文字、空间布局和场景特征，600字内。' },
                { type: 'image_url', image_url: { url: data } },
              ] }],
            },
            timeoutMs: 60000,
          });
          if (r.status === 200 && r.json?.choices?.[0]?.message?.content) {
            desc = '[图片内容: ' + r.json.choices[0].message.content.trim() + ']';
            break;
          }
          this.log(`图片描述失败（${a.upstream_model_name || visionModel}: status=${r.status}${r.status === 200 ? ' 空内容' : ''}）`);
        }
      } catch (e) { this.log('图片描述失败: ' + e.message); }
      // 只缓存成功结果：识别失败/超时不落缓存，下次请求还会重试，避免一张图被占位文本永久钉死
      if (!desc) return '[图片内容暂不可用]';
      cache.set(hash, desc);
      if (cache.size > 500) { // 简单防膨胀
        const first = cache.keys().next().value;
        cache.delete(first);
      }
      return desc;
    };
    for (let i = 0; i < (lastUserIdx < 0 ? msgs.length : lastUserIdx); i++) {
      const c = msgs[i].content;
      if (!Array.isArray(c)) continue;
      if (!c.some(p => p?.type === 'image_url' || p?.type === 'image')) continue;
      const converted = [];
      for (const p of c) {
        if (p?.type === 'image_url' || p?.type === 'image') {
          const url = p.image_url?.url || p.url || p.source?.data;
          if (url) converted.push({ type: 'text', text: await describe(url) });
        } else converted.push(p);
      }
      msgs[i].content = converted;
    }
  }

  // 智能分流：embedding 分类 simple/complex
  // 请求分类（simple/complex），供 auto 与模型级智能路由共用
  async classifyRequest(text) {
    const routing = this.cfg.get('routing', {});
    text = (text || '').slice(0, 2000);
    let label = routing.default_label || 'complex', confidence = 0.5, source = 'default';
    if (text && this.embedder) {
      try {
        const vec = await this.embedder(text);
        const samples = this.db.prepare('SELECT label, vector FROM smart_route_samples WHERE vector IS NOT NULL').all();
        if (samples.length) {
          // 各标签取最高相似度（任意标签集：simple/complex/refusal/…）
          const scores = {};
          for (const s of samples) {
            const sv = JSON.parse(s.vector);
            const sim = cosine(vec, sv);
            if (!scores[s.label] || sim > scores[s.label].sim) scores[s.label] = { sim, label: s.label };
          }
          const keys = Object.keys(scores);
          if (keys.length) {
            // 只在 simple/complex 都存在时维持原二分类语义；否则取全标签最高分
            if (scores.simple && scores.complex && keys.length === 2) {
              const total = scores.simple.sim + scores.complex.sim;
              confidence = Math.abs(scores.simple.sim - scores.complex.sim) / total;
              label = scores.simple.sim > scores.complex.sim ? 'simple' : 'complex';
            } else {
              const best = keys.reduce((a, b) => scores[a].sim >= scores[b].sim ? a : b);
              const sorted = keys.map(k => scores[k].sim).sort((a, b) => b - a);
              confidence = sorted.length > 1 ? (sorted[0] - sorted[1]) / (sorted[0] + sorted[1] || 1) : 1;
              label = best;
            }
            source = 'embedding';
          }
        }
      } catch (e) { this.log('classify embed err: ' + e.message); source = 'embed_failed'; }
    }
    const threshold = routing.route_threshold ?? 0.15;
    if (source === 'embedding' && confidence < threshold) { label = routing.default_label || 'complex'; source = 'low_confidence'; }
    return { label, confidence, source };
  }

  // 拒答样本分类：对响应文本判定 refusal 与否（与 simple/complex 同一套样本机制）
  async classifyRefusal(answer) {
    const samples = this.db.prepare("SELECT COUNT(*) c FROM smart_route_samples WHERE label='refusal' AND vector IS NOT NULL").get().c;
    if (!samples || !this.embedder) return null;   // 无 refusal 样本，交回调用方走原链路
    const c = await this.classifyRequest(answer);
    if (c.label === 'refusal') return { refusal: true, confidence: c.confidence, source: c.source };
    // 非拒答判断只在置信度足够高（≥0.75）时才否决初筛；否则交回 LLM 确认链，
    // 避免拒答话术与 simple 样本相似导致的误放行
    return c.confidence >= 0.75 ? { refusal: false, confidence: c.confidence, source: c.source }
      : { refusal: null, confidence: c.confidence, source: c.source + ',low_conf' };
  }

  // auto 入口：全局默认（简单→simple_model / 复杂→complex_model）
  static extractUserText(body) {
    let text = '';
    for (const m of body.messages || []) {
      if (m.role === 'user') {
        if (typeof m.content === 'string') text += m.content + '\n';
        else if (Array.isArray(m.content)) for (const p of m.content) if (p.type === 'text') text += p.text + '\n';
      }
    }
    return text.trim();
  }

  // smartStream：流式拒答检测（aigw v3.7 对齐）
  // 缓冲上游 SSE 累积 content；>500 字（拒答必短）立即放弃检测改透传；阈值内读完做拒答检测，
  // 命中拒答链则用目标模型非流式重发并合成单条 SSE 返回。
  // 返回 { ok:true, result }（stream 或合成的 json 包装）；null 表示上游流中断（调用方按失败继续）。
  async _smartStream(r, body, upstreamBody, account, headers, url, origModel, converter) {
    const FLUSH_THRESHOLD = 500;
    const reader = r.res.body.getReader();
    const decoder = new TextDecoder();
    let content = '';
    let usage = null;
    let sawToolCall = false, sawReasoning = false, readErr = null;
    const chunks = [];
    let buf = '';
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const text = decoder.decode(value, { stream: true });
        chunks.push(text);
        // 解析 OpenAI 直通 SSE 行（Anthropic 先经 converter；此处只处理 OpenAI 格式主路径）
        if (!converter) {
          buf += text;
          const cut = buf.lastIndexOf('\n');
          if (cut >= 0) {
            const complete = buf.slice(0, cut); buf = buf.slice(cut + 1);
            for (const line of complete.split('\n')) {
              if (!line.startsWith('data: ') || line === 'data: [DONE]') continue;
              try {
                const j = JSON.parse(line.slice(6));
                const d = j.choices?.[0]?.delta || {};
                const c = d.content || '';
                if (c) content += c;
                // 判空要算上工具调用与推理字段：只回 tool_calls 或只回 reasoning 同样是有效结果
                if (!sawToolCall && Array.isArray(d.tool_calls) && d.tool_calls.length) sawToolCall = true;
                if (!sawReasoning && (d.reasoning_content || d.reasoning)) sawReasoning = true;
                if (j.usage) usage = j.usage;
                if (content.length > FLUSH_THRESHOLD) break;
              } catch {}
            }
          }
        }
        if (content.length > FLUSH_THRESHOLD) break;
      }
    } catch (e) { readErr = (e && e.message) || String(e); }
    // 透传模式（内容长/非拒答）：reader 已被本方法锁定，包装成新流 —— 先放已缓冲内容，再泵余量
    const passthrough = () => {
      // chunks 已含未完成的半行（buf 只是从中切出来的解析残留），不能再拼一次，否则重放数据重复损坏 SSE
      const replay = chunks.join('');
      const enc = new TextEncoder();
      const body = new ReadableStream({
        async start(controller) {
          if (replay) controller.enqueue(enc.encode(replay));
          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              controller.enqueue(value);
              // 背压：客户端消费慢（desiredSize <= 0）时等待，避免上游持续推导致内存堆积
              while (controller.desiredSize !== null && controller.desiredSize <= 0) {
                await new Promise(res => setTimeout(res, 20));
              }
            }
          } catch { /* 上游中断 */ }
          try { controller.close(); } catch {}
        },
      });
      return { ok: true, result: { kind: 'stream', res: { body, status: 200 }, abort: r.abort, upstreamModel: account.upstream_model_name, protocol: 'openaiChatCompletions', converter } };
    };
    // 空响应：上游 200 但整条流里没有正文、没有工具调用、没有推理、也没有用量。
    // 原样透传会让客户端收到「200 空流」（ZCode 侧即 empty_model_response，且网关记成成功），
    // 这里按该账号失败处理，交给调用方继续下一账号 / 失败分流。
    if (!converter && !content && !sawToolCall && !sawReasoning && !usage) {
      this.log(`上游流式空响应（chunks=${chunks.length}, bytes=${chunks.join('').length}, readErr=${readErr || '-'}）→ 按失败处理`);
      r.abort?.();
      return null;
    }
    if (content.length > FLUSH_THRESHOLD) {
      return passthrough();
    }
    // 阈值内读完：拒答检测
    if (!looksLikeRefusal(content)) {
      return passthrough();
    }
    r.abort?.();
    this.log(`流式疑似拒答（${content.length} 字），进入确认与重试`);
    const retried = await this.refusalRetry({ body, upstreamBody, account, headers, url, json: { choices: [{ message: { content } }] }, origModel });
    if (retried) {
      // 合成单条 SSE（客户端按流式接收）
      const j = retried.kind === 'json' ? retried.json : retried;
      const payload = { id: 'chatcmpl-' + require('node:crypto').randomUUID().slice(0, 12), object: 'chat.completion.chunk', created: Math.floor(Date.now() / 1000), model: body.model, choices: [{ index: 0, delta: { role: 'assistant', content: j?.choices?.[0]?.message?.content || '' }, finish_reason: 'stop' }], usage: usage || j?.usage || undefined };
      const text = 'data: ' + JSON.stringify(payload) + '\n\ndata: [DONE]\n\n';
      const stream = new ReadableStream({
        start(controller) { controller.enqueue(new TextEncoder().encode(text)); controller.close(); },
      });
      return { ok: true, result: { kind: 'stream', res: { body: stream, status: 200 }, abort: () => {}, upstreamModel: retried.upstreamModel || account.upstream_model_name, protocol: 'openaiChatCompletions', converter: null, refusalRetry: true } };
    }
    // 重试失败：无法回放已消费的流（客户端还没收到任何字节），报错让调用方走下一账号/分流
    return null;
  }

  // 拒答确认 + 重试。优先级：模型级/全局 refusal 规则目标模型 > local_retry_model
  async refusalRetry({ body, upstreamBody, account, headers, url, r, json, origModel }) {
    const routing = this.cfg.get('routing', {});
    const answer = json?.choices?.[0]?.message?.content || '';
    // 第一步：refusal 样本向量分类（与 simple/complex 同机制；无样本则跳过）
    try {
      const cls = await this.classifyRefusal(answer);
      if (cls && cls.refusal === false) return null;   // 样本判非拒答，原样返回
    } catch { /* 样本分类失败继续走 LLM 确认 */ }
    // 第二步：LLM 结构化确认（cheap model）
    try {
      const confirmModel = routing.confirm_model;
      if (confirmModel) {
        const confirm = await this._llmJSON(confirmModel, [
          { role: 'system', content: '判断以下 AI 回复是否为拒答/回避不回答。只输出 JSON: {"refusal": true|false}' },
          { role: 'user', content: answer.slice(0, 2000) },
        ]);
        if (confirm && confirm.refusal === false) return null;
      }
    } catch { /* 确认失败按疑似拒答处理 */ }
    // 第二步：refusal 规则目标模型（模型级优先，其次全局）
    const rulesOf = (m) => (this._modelRules()[m] || this._modelRules()[m.toUpperCase()] || {}).rules || [];
    const refusalRule = (origModel && rulesOf(origModel).find(x => x.type === 'refusal' && x.enabled !== false && x.target))
      || (routing.rules || []).find(x => x.type === 'refusal' && x.enabled !== false && x.target);
    if (refusalRule) {
      this.log(`拒答改走规则目标 ${refusalRule.target}`);
      return await this._retryWithModel(body, refusalRule.target, 'refusal_rule');
    }
    // 第三步：本地无审查模型重试
    const localModel = routing.local_retry_model;
    if (!localModel) return null;
    const localAccounts = this.accountsForModel(localModel);
    for (const la of localAccounts) {
      const cred = this.cred.open(this.credKey, la.credential_envelope);
      if (!cred) continue;
      try {
        const lr = await postJson({
          url: joinUrl(la.service_base_url, this._route(la), '/chat/completions'),
          headers: buildHeaders(la, cred),
          body: { ...body, model: la.upstream_model_name || localModel, stream: false, stream_options: undefined, max_tokens: undefined },
        });
        if (lr.status === 200 && lr.json?.choices?.[0]?.message?.content) {
          this.log('拒答本地重试成功');
          return { kind: 'json', json: lr.json, upstreamModel: la.upstream_model_name, accountId: la.id, accountName: la.name, usage: lr.json?.usage, refusalRetry: true };
        }
      } catch (e) { this.log('本地重试失败 ' + e.message); }
    }
    return null;
  }

  // 用指定模型重发当前请求（拒答规则/本地重试共用）
  async _retryWithModel(body, model, tag) {
    const accounts = this.accountsForModel(model);
    for (const la of accounts) {
      const st = this._state(la.id);
      if (!this._available(st, la)) continue;
      const cred = this.cred.open(this.credKey, la.credential_envelope);
      if (!cred) continue;
      try {
        const lr = await postJson({
          url: joinUrl(la.service_base_url, this._route(la), '/chat/completions'),
          headers: buildHeaders(la, cred),
          body: { ...body, model: la.upstream_model_name || model, stream: false, stream_options: undefined, max_tokens: undefined },
        });
        if (lr.status === 200 && lr.json?.choices) {
          this.log(`${tag} 重试成功（${model} @ ${la.name}）`);
          return { kind: 'json', json: lr.json, upstreamModel: la.upstream_model_name, accountId: la.id, accountName: la.name, usage: lr.json?.usage, refusalRetry: true };
        }
      } catch (e) { this.log(`${tag} 重试失败 ` + e.message); }
    }
    return null;
  }

  async _llmJSON(model, messages) {
    const accounts = this.accountsForModel(model);
    for (const a of accounts) {
      const cred = this.cred.open(this.credKey, a.credential_envelope);
      if (!cred) continue;
      const r = await postJson({
        url: joinUrl(a.service_base_url, this._route(a), '/chat/completions'),
        headers: buildHeaders(a, cred),
        body: { model: a.upstream_model_name || model, messages, max_tokens: 512, temperature: 0 },
        timeoutMs: 30000,
      });
      if (r.status === 200) {
        const t = r.json?.choices?.[0]?.message?.content || '';
        const m = t.match(/\{[\s\S]*\}/);
        if (m) { try { return JSON.parse(m[0]); } catch {} }
      }
    }
    return null;
  }

  // 类别名归一（chat/text 同义）
  static normalizeKind(k) { return k === 'text' ? 'chat' : (k || ''); }

  // 显式 model_type 查询缓存（account_id+model -> kind；无类型时回退模型名推断）
  _modelType(accountId, modelName) {
    const row = this.db.prepare('SELECT model_type FROM upstream_account_models WHERE account_id=? AND request_model_name=?').get(accountId, modelName);
    return Engine.normalizeKind(row?.model_type) || null;
  }

  // 模型类别判定：优先账号映射里显式指定的 model_type，否则由模型名推断端点类型（一个账号可同时服务多类别）
  static modelKind(modelName) {
    const m = String(modelName || '').toLowerCase();
    if (/(rerank|bge-reranker)/.test(m)) return 'rerank';
    if (/(embed|bge-m3|gte-|e5-|jina-embed|minlm)/.test(m)) return 'embedding';
    if (/(image|flux|sd3|stable-diffusion|cogview|dall-e|wanx|seedream)/.test(m)) return 'image';
    return 'chat';
  }

  // embeddings 转发：按模型类别找到能服务该模型的账号（类别由模型名判定，不再依赖账号 protocol_type）
  async embeddings({ body, onLog }) {
    const model = body.model;
    const accounts = this.accountsForModel(model);
    for (const account of accounts) {
      const st = this._state(account.id);
      if (!this._available(st, account)) continue;
      const credential = this.cred.open(this.credKey, account.credential_envelope);
      if (!credential) continue;
      st.inflight++;
      try {
        const r = await postJson({
          url: joinUrl(account.service_base_url, this._route(account), '/embeddings'),
          headers: buildHeaders(account, credential),
          body: { ...body, model: account.upstream_model_name || model },
        });
        if (r.status === 200) { this.markSuccess(account); onLog?.({ account, model, status: 200 }); return r.json; }
        if (isQuotaError(r.status, r.text)) { this.markFailure(account, 'quota'); continue; }
        if (isBusyError(r.status, r.text)) { this.markFailure(account, 'busy'); continue; }
        if (r.status >= 500) this.markFailure(account, 'error');
      } catch { this.markFailure(account, 'error'); }
      finally { st.inflight--; }
    }
    const err = new Error('no_available_upstream (embeddings)'); err.statusCode = 502; throw err;
  }

  // 图像生成转发
  async images({ body, onLog }) {
    const model = body.model;
    const accounts = this.accountsForModel(model);
    for (const account of accounts) {
      const st = this._state(account.id);
      if (!this._available(st, account)) continue;
      const credential = this.cred.open(this.credKey, account.credential_envelope);
      if (!credential) continue;
      st.inflight++;
      try {
        const r = await postJson({
          url: joinUrl(account.service_base_url, this._route(account), '/images/generations'),
          headers: buildHeaders(account, credential),
          body: { ...body, model: account.upstream_model_name || model },
          timeoutMs: 300000,
        });
        if (r.status === 200) { this.markSuccess(account); onLog?.({ account, model, status: 200 }); return r.json; }
        if (isQuotaError(r.status, r.text)) { this.markFailure(account, 'quota'); continue; }
        if (isBusyError(r.status, r.text)) { this.markFailure(account, 'busy'); continue; }
        if (r.status >= 500) this.markFailure(account, 'error');
      } catch { this.markFailure(account, 'error'); }
      finally { st.inflight--; }
    }
    const err = new Error('no_available_upstream (images)'); err.statusCode = 502; throw err;
  }

  // rerank：模型走账号体系原生 /rerank 转发；无可用 reranker 模型时用 embedding 余弦重排兜底
  async rerank({ body, onLog }) {
    const model = body.model;
    const query = body.query || '';
    const docs = body.documents || [];
    // 1) 原生 rerank：按请求模型（或默认 rerank 模型）找账号转发
    const target = model || this.cfg.get('routing', {}).rerank_model;
    const accounts0 = target ? this.accountsForModel(target) : [];
    const explicitKind = accounts0.length ? (this._modelType(accounts0[0].id, target) || Engine.modelKind(target)) : null;
    if (target && explicitKind === 'rerank') {
      const accounts = this.accountsForModel(target);
      for (const account of accounts) {
        const st = this._state(account.id);
        if (!this._available(st, account)) continue;
        const credential = this.cred.open(this.credKey, account.credential_envelope);
        if (!credential) continue;
        st.inflight++;
        try {
          const r = await postJson({
            url: joinUrl(account.service_base_url, this._route(account), '/rerank'),
            headers: buildHeaders(account, credential),
            body: { ...body, model: account.upstream_model_name || target },
            timeoutMs: 60000,
          });
          if (r.status === 200) { this.markSuccess(account); onLog?.({ account, model: target, status: 200, kind: 'native' }); return r.json; }
          if (isQuotaError(r.status, r.text)) { this.markFailure(account, 'quota'); continue; }
          if (isBusyError(r.status, r.text)) { this.markFailure(account, 'busy'); continue; }
          if (r.status >= 500) this.markFailure(account, 'error');
        } catch { this.markFailure(account, 'error'); }
        finally { st.inflight--; }
      }
      this.log('native rerank no available account, falling back to embedding');
    }
    // 2) embedding 余弦重排兜底
    if (!this.embedder) { const err = new Error('rerank_unavailable'); err.statusCode = 501; throw err; }
    const qv = await this.embedder(query);
    const dvs = await this.embedder(docs, true);
    const results = docs.map((d, i) => ({ index: i, relevance_score: cosine(qv, dvs[i]) }))
      .sort((a, b) => b.relevance_score - a.relevance_score)
      .slice(0, body.top_n || docs.length);
    onLog?.({ kind: 'embedding' });
    return { results };
  }

  // 内部 embedding 通道（智能路由/重排用），指向向量账号
  setEmbedder(fn) { this.embedder = fn; }

  // 批量向量化待处理样本（智能路由分类用）
  async vectorizeSamples() {
    if (!this.embedder) return { vectorized: 0, note: 'no_embedder' };
    const rows = this.db.prepare('SELECT id, text FROM smart_route_samples WHERE vector IS NULL').all();
    let done = 0, failed = 0;
    for (const r of rows) {
      try {
        const v = await this.embedder(r.text);
        this.db.prepare('UPDATE smart_route_samples SET vector=?, vector_dim=? WHERE id=?').run(JSON.stringify(v), v.length, r.id);
        done++;
      } catch (e) { failed++; if (failed > 10) break; }
    }
    if (rows.length) this.log(`向量化样本 ${done}/${rows.length}（失败 ${failed}）`);
    return { vectorized: done, failed, total: rows.length };
  }

  close() { clearInterval(this._probeTimer); }
}

function cosine(a, b) {
  if (!a || !b || a.length !== b.length) return 0;
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) { dot += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i]; }
  if (!na || !nb) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

module.exports = { Engine, cosine, looksLikeRefusal, isBusyError, isQuotaError };
