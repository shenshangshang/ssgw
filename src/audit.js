// ES 正文审计：请求/响应正文捕获 → 内存队列 → 异步 _bulk 写入 Elasticsearch
// 字段与 1Panel ai-gateway 的 ai-gateway-audit 数据流对齐，可共用同一 ES 检索
'use strict';
const crypto = require('node:crypto');

class BodyAudit {
  constructor(db, cfg, cred, opts = {}) {
    this.db = db;
    this.cfg = cfg;
    this.cred = cred;              // {seal, open, sha256}
    this.credKey = opts.credKey;   // 主密钥（与账号凭据同一体系）
    this.log = opts.logger || (() => {});
    this.queue = [];               // 待写入文档
    this.flushing = false;
    this.failStreak = 0;
    this.enabled = false;          // 由 applySettings 刷新
    this.es = null;                // {endpoint, username, password}
    // 定时 flush（即使失败也按周期重试，指数退避上限 60s 由 failStreak 控制）
    this.timer = setInterval(() => this.flush().catch(e => this.log('audit flush err ' + e.message)), 5000);
    this.timer.unref?.();
  }

  // 启动/设置变更时调用：读 settings.log.body_audit + elasticsearch 凭据
  applySettings() {
    const s = this.cfg.get('log.body_audit', {});
    this.settings = {
      enabled: !!s.enabled,
      requestMaxKiB: s.requestMaxKiB ?? 1024,
      responseMaxKiB: s.responseMaxKiB ?? 1024,
      retentionDays: s.retentionDays ?? 30,
    };
    const es = s.elasticsearch || {};
    let password = '';
    if (es.credentialEnvelope) {
      try { password = this.cred.open(this.credKey, es.credentialEnvelope); } catch { password = ''; }
    }
    this.es = (es.endpoint && password) ? { endpoint: es.endpoint.replace(/\/+$/, ''), username: es.username || 'elastic', password } : null;
    this.enabled = this.settings.enabled && !!this.es;
    return this.enabled;
  }

  // 设置端点用：加密存凭据
  sealPassword(password) {
    return this.cred.seal(this.credKey, password);
  }

  // 捕获一条调用（chat/embeddings/rerank/images 通用入口，fire-and-forget）
  capture(entry) {
    if (!this.enabled || !this.es) return;
    const s = this.settings;
    const doc = {
      '@timestamp': new Date().toISOString(),
      request_id: String(entry.requestId || '').replace(/-/g, '').slice(0, 32), // mapping ignore_above:32，UUID 去横线截断
      user_id: entry.userId ?? null,
      api_key_id: entry.apiKeyId ?? null,
      user_group_id: entry.userGroupId ?? null,
      provider: entry.provider || 'shenshang',
      request_model: entry.requestModel || '',
      upstream_model: entry.upstreamModel || '',
      client_protocol: entry.clientProtocol || 'openaiChatCompletions',
      upstream_protocol: entry.upstreamProtocol || 'openaiChatCompletions',
      upstream_account_id: entry.upstreamAccountId ?? null,
      result: entry.result || 'success',
      status_code: entry.statusCode ?? 200,
      stream: !!entry.stream,
    };
    // 请求正文
    const req = this._truncate(entry.requestBody, s.requestMaxKiB);
    if (req) {
      doc.request_present = true;
      doc.request_original_bytes = req.originalBytes;
      doc.request_stored_bytes = req.storedBytes;
      doc.request_truncated = req.truncated;
      doc.request_content_type = 'application/json';
      doc.request_sha256 = req.sha256;
      doc.request_body_raw = req.text;
    } else {
      doc.request_present = false;
    }
    // 响应正文
    const res = this._truncate(entry.responseBody, s.responseMaxKiB);
    if (res) {
      doc.response_present = true;
      doc.response_original_bytes = res.originalBytes;
      doc.response_stored_bytes = res.storedBytes;
      doc.response_truncated = res.truncated;
      doc.response_content_type = 'application/json';
      doc.response_sha256 = res.sha256;
      doc.response_body_raw = res.text;
    } else {
      doc.response_present = false;
    }
    this.queue.push(doc);
    // 队列上限（防 ES 长期不可用时内存膨胀）
    if (this.queue.length > 2000) this.queue.splice(0, this.queue.length - 2000);
  }

  _truncate(obj, maxKiB) {
    if (obj === undefined || obj === null) return null;
    const text = typeof obj === 'string' ? obj : JSON.stringify(obj);
    if (!text) return null;
    const buf = Buffer.from(text, 'utf8');
    const max = maxKiB * 1024;
    return {
      originalBytes: buf.length,
      storedBytes: Math.min(buf.length, max),
      truncated: buf.length > max,
      sha256: crypto.createHash('sha256').update(buf.subarray(0, max)).digest('hex'),
      text: buf.length > max ? buf.subarray(0, max).toString('utf8') : text,
    };
  }

  // 批量写入 ES（datastream 用 _bulk + create op，自动 rollover）
  async flush() {
    if (this.flushing || !this.queue.length || !this.es) return;
    this.flushing = true;
    const batch = this.queue.splice(0, 100);
    try {
      const lines = [];
      for (const doc of batch) {
        lines.push(JSON.stringify({ create: { _index: 'ai-gateway-audit' } }));
        lines.push(JSON.stringify(doc));
      }
      const res = await fetch(this.es.endpoint + '/_bulk', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-ndjson',
          Authorization: 'Basic ' + Buffer.from(this.es.username + ':' + this.es.password).toString('base64'),
        },
        body: lines.join('\n') + '\n',
        signal: AbortSignal.timeout(15000),
      });
      if (!res.ok) throw new Error('bulk HTTP ' + res.status);
      const j = await res.json().catch(() => ({}));
      if (j.errors) {
        // 数据流未初始化等错误：取第一条错误信息便于诊断
        const err = j.items?.[0]?.create?.error;
        if (err) throw new Error(err.type + ': ' + (err.reason || ''));
      }
      this.failStreak = 0;
    } catch (e) {
      this.failStreak++;
      // 失败放回队首（保留最近 2000 条的丢弃策略已在 capture 控制）
      this.queue.unshift(...batch);
      if (this.failStreak === 1 || this.failStreak % 20 === 0) this.log('ES audit flush 失败 x' + this.failStreak + ': ' + e.message);
    } finally { this.flushing = false; }
  }

  // 检索（管理 UI 用）：match_phrase 全文 + 时间范围
  async search({ keyword, model, result, requestId, days = 7, size = 20 }) {
    if (!this.es) throw Object.assign(new Error('elasticsearch_not_configured'), { statusCode: 400 });
    // aigw 的 mapping 对正文 index:false，全文不可检索；与 aigw 同能力——
    // 按结构化字段过滤（request_id/model/result），正文在命中后取回
    const filter = [{ range: { '@timestamp': { gte: `now-${days}d` } } }];
    if (requestId) filter.push({ term: { request_id: requestId } });
    if (model) filter.push({ term: { request_model: model } });
    if (result) filter.push({ term: { result } });
    const body = {
      query: { bool: { filter } },
      sort: [{ '@timestamp': 'desc' }],
      _source: ['@timestamp', 'request_id', 'request_model', 'upstream_model', 'result', 'status_code', 'stream', 'request_present', 'response_present', 'request_stored_bytes', 'response_stored_bytes'],
      size: Math.min(size, 50),
    };
    const res = await fetch(this.es.endpoint + '/ai-gateway-audit/_search', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Basic ' + Buffer.from(this.es.username + ':' + this.es.password).toString('base64'),
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) throw Object.assign(new Error('ES search HTTP ' + res.status), { statusCode: 502 });
    const j = await res.json();
    return {
      total: j.hits?.total?.value ?? 0,
      hits: (j.hits?.hits || []).map(h => ({ id: h._id, index: h._index, ...h._source })),
    };
  }

  // 取单条正文（详情用）
  async get(id, index) {
    if (!this.es) throw Object.assign(new Error('elasticsearch_not_configured'), { statusCode: 400 });
    const idx = index ? '/' + encodeURIComponent(index) : '/ai-gateway-audit';
    const res = await fetch(this.es.endpoint + idx + '/_doc/' + encodeURIComponent(id), {
      headers: { Authorization: 'Basic ' + Buffer.from(this.es.username + ':' + this.es.password).toString('base64') },
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) throw Object.assign(new Error('ES get HTTP ' + res.status), { statusCode: 404 });
    const j = await res.json();
    return j._source;
  }

  async healthCheck() {
    if (!this.es) return { ok: false, error: 'not_configured' };
    try {
      const res = await fetch(this.es.endpoint + '/', {
        headers: { Authorization: 'Basic ' + Buffer.from(this.es.username + ':' + this.es.password).toString('base64') },
        signal: AbortSignal.timeout(8000),
      });
      const j = res.ok ? await res.json() : null;
      return { ok: res.ok, version: j?.version?.number, cluster: j?.cluster_name };
    } catch (e) { return { ok: false, error: e.message }; }
  }

  stats() {
    return { enabled: this.enabled, queued: this.queue.length, failStreak: this.failStreak, endpoint: this.es?.endpoint || null };
  }
}

module.exports = { BodyAudit };
