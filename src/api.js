// 管理 API（扩展版）：账号/模型组/用户/用户组/Key/日志/用量/智能路由/合规/设置
'use strict';
const crypto = require('node:crypto');
const { Engine } = require('./engine');

const SESSION_IDLE_MS = 24 * 3600 * 1000;
const SESSION_ABS_MS = 7 * 24 * 3600 * 1000;

class Api {
  constructor(db, cred, engine, cfg, opts) {
    this.db = db; this.cred = cred; this.engine = engine; this.cfg = cfg;
    this.credKey = opts.credKey;
    this.logger = opts.logger || (() => {});
    this.audit = opts.audit || null;  // BodyAudit 实例（server.js 注入）
  }

  // ---------- 认证 ----------
  authKey(req) {
    const auth = req.headers['authorization'] || '';
    const m = auth.match(/^Bearer\s+(sk-\S+)$/);
    if (!m) return null;
    const hash = this.cred.sha256(m[1]);
    const row = this.db.prepare('SELECT k.*, u.disabled AS user_disabled, u.user_group_id FROM api_keys k JOIN users u ON u.id=k.user_id WHERE k.key_hash=?').get(hash);
    if (!row || row.disabled || row.user_disabled) return null;
    this.db.prepare('UPDATE api_keys SET last_used_at=? WHERE id=?').run(new Date().toISOString(), row.id);
    return row;
  }

  async login(username, password) {
    const user = this.db.prepare('SELECT * FROM users WHERE username=?').get(username);
    if (!user || user.disabled) return null;
    if (user.locked_until && Date.now() < Date.parse(user.locked_until)) return { locked: true };
    const ok = this.cred.verifyPassword(password, user.username, user.password_hash);
    if (ok && this.cred.isLegacyPasswordHash?.(user.password_hash)) {
      // 旧 sha256 哈希升级为 scrypt（用户名不变，密码刚验证过）
      this.db.prepare('UPDATE users SET password_hash=?, updated_at=? WHERE id=?').run(this.cred.hashPassword(password, user.username), new Date().toISOString(), user.id);
    }
    if (!ok) {
      const fails = (user.failed_login_count || 0) + 1;
      this.db.prepare('UPDATE users SET failed_login_count=?, locked_until=? WHERE id=?')
        .run(fails, fails >= 5 ? new Date(Date.now() + 15 * 60000).toISOString() : null, user.id);
      return null;
    }
    this.db.prepare('UPDATE users SET failed_login_count=0, locked_until=NULL, last_login_at=? WHERE id=?').run(new Date().toISOString(), user.id);
    const token = crypto.randomBytes(32).toString('hex');
    const csrf = crypto.randomBytes(32).toString('hex');
    const t = new Date().toISOString();
    this.db.prepare('INSERT INTO sessions (token_hash,user_id,csrf_hash,idle_expires_at,absolute_expires_at,last_seen_at,created_at) VALUES (?,?,?,?,?,?,?)')
      .run(this.cred.sha256(token), user.id, this.cred.sha256(csrf),
        new Date(Date.now() + SESSION_IDLE_MS).toISOString(), new Date(Date.now() + SESSION_ABS_MS).toISOString(), t, t);
    return { token, csrf, user: { id: user.id, username: user.username, role: user.role } };
  }

  session(req) {
    const token = parseCookies(req.headers.cookie || '').ssgw_session;
    if (!token) return null;
    const row = this.db.prepare('SELECT s.*, u.username, u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?').get(this.cred.sha256(token));
    if (!row) return null;
    if (Date.now() > Date.parse(row.absolute_expires_at) || Date.now() > Date.parse(row.idle_expires_at)) {
      this.db.prepare('DELETE FROM sessions WHERE id=?').run(row.id);
      return null;
    }
    this.db.prepare('UPDATE sessions SET last_seen_at=?, idle_expires_at=? WHERE id=?')
      .run(new Date().toISOString(), new Date(Date.now() + SESSION_IDLE_MS).toISOString(), row.id);
    return row;
  }

  checkCsrf(req, session) {
    const h = req.headers['x-csrf-token'];
    return !!h && this.cred.sha256(h) === session.csrf_hash;
  }

  logout(session) { this.db.prepare('DELETE FROM sessions WHERE id=?').run(session.id); }

  changePassword(userId, oldPw, newPw) {
    const user = this.db.prepare('SELECT * FROM users WHERE id=?').get(userId);
    if (!user) return false;
    if (!this.cred.verifyPassword(oldPw, user.username, user.password_hash)) return false;
    this.db.prepare('UPDATE users SET password_hash=?, must_change_password=0, updated_at=? WHERE id=?')
      .run(this.cred.hashPassword(newPw, user.username), new Date().toISOString(), userId);
    return true;
  }

  // ---------- 路由 ----------
  async handleAdmin(req, res, path, url, body) {
    const session = this.session(req);
    const json = (code, data) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(data)); return true; };
    if (!session) return json(401, { error: 'unauthorized' });
    if (req.method !== 'GET' && !this.checkCsrf(req, session)) return json(403, { error: 'csrf_invalid' });
    // 权限墙：非 admin 只能访问用户中心所需的白名单端点
    if (session.role !== 'admin') {
      const allowGet = path === '/api/v1/admin/users' || path === '/api/v1/admin/api-keys' || path === '/api/v1/admin/models';
      const allowPost = path === '/api/v1/admin/api-keys' && req.method === 'POST';
      if (!(allowGet || allowPost)) return json(403, { error: 'forbidden' });
      req._scopedUser = session;   // handler 据此把数据范围限制到本人
    }

    let m;
    const M = (re) => path.match(re);
    if ((m = M(/^\/api\/v1\/admin\/upstream-accounts(?:\/(\d+))?(?:\/(enable|disable|test-model|balance))?$/))) return this.accounts(req, res, m, body, json);
    if ((m = M(/^\/api\/v1\/admin\/upstream-accounts\/(\d+)\/models\/([^/]+)$/))) return this.accountModelItem(req, res, m, json);
    if ((m = M(/^\/api\/v1\/admin\/model-groups(?:\/(\d+))?$/))) return this.modelGroups(req, res, m, body, json);
    if ((m = M(/^\/api\/v1\/admin\/users(?:\/(\d+))?$/))) return this.users(req, res, m, body, json);
    if ((m = M(/^\/api\/v1\/admin\/user-groups(?:\/(\d+))?$/))) return this.userGroups(req, res, m, body, json);
    if ((m = M(/^\/api\/v1\/admin\/api-keys(?:\/(\d+))?$/))) return this.apiKeys(req, res, m, body, json);
    if ((m = M(/^\/api\/v1\/admin\/smart-routing\/samples(?:\/(\d+))?$/))) return this.samples(req, res, m, body, url, json);
    if ((m = M(/^\/api\/v1\/admin\/smart-routing\/vectorize$/))) return this.vectorize(req, res, body, json);
    // 向量服务独立配置：GET 不回明文 key；PUT 保存（key 信封加密）；test 直连验证
    if (path === '/api/v1/admin/vector-service' && req.method === 'GET') {
      const vs = this.cfg.get('vector_service', {}) || {};
      return json(200, { mode: vs.mode || 'gateway', base_url: vs.base_url || '', model: vs.model || '', dimensions: vs.dimensions || 0, hasKey: !!vs.api_key_envelope });
    }
    if (path === '/api/v1/admin/vector-service' && req.method === 'PUT') {
      const vs = { ...(this.cfg.get('vector_service', {}) || {}) };
      vs.mode = body.mode === 'direct' ? 'direct' : 'gateway';
      if (body.base_url !== undefined) vs.base_url = String(body.base_url || '').trim();
      if (body.model !== undefined) vs.model = String(body.model || '').trim();
      if (body.dimensions !== undefined) vs.dimensions = Math.max(0, Number(body.dimensions) || 0);
      if (body.api_key) vs.api_key_envelope = this.cred.seal(this.credKey, String(body.api_key));
      if (body.clearKey) delete vs.api_key_envelope;
      this.cfg.set('vector_service', vs);
      this.engine.applyVectorService?.();
      return json(200, { ok: true });
    }
    if (path === '/api/v1/admin/vector-service/test' && req.method === 'POST') {
      const vs = this.cfg.get('vector_service', {}) || {};
      if (vs.mode !== 'direct' || !vs.base_url || !vs.model) return json(400, { error: 'not_configured' });
      let apiKey = '';
      if (vs.api_key_envelope) { try { apiKey = this.cred.open(this.credKey, vs.api_key_envelope); } catch {} }
      if (!apiKey) return json(400, { error: 'no_api_key' });
      try {
        const base = String(vs.base_url).replace(/\/+$/, '');
        const url = base.endsWith('/embeddings') ? base : base + '/embeddings';
        const t0 = Date.now();
        const res = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + apiKey },
          body: JSON.stringify({ model: vs.model, input: ['connectivity test'], ...(vs.dimensions ? { dimensions: Number(vs.dimensions) } : {}) }),
          signal: AbortSignal.timeout(30000),
        });
        const j = await res.json().catch(() => null);
        if (!res.ok) return json(502, { error: 'http_' + res.status, detail: String(JSON.stringify(j) || '').slice(0, 200) });
        const dim = j?.data?.[0]?.embedding?.length || 0;
        return json(200, { ok: true, dimensions: dim, latencyMs: Date.now() - t0 });
      } catch (e) { return json(502, { error: e.message }); }
    }
    // 决策日志（所有智能路由模型的路由决策）
    if (path === '/api/v1/admin/smart-routing/decision-logs') {
      const page = Math.min(Number(url.searchParams.get('page') || 1), 1000);
      const pageSize = Math.min(Number(url.searchParams.get('pageSize') || 20), 200);
      const days = Number(url.searchParams.get('days') || 7);
      const kw = url.searchParams.get('keyword');
      const where = ['created_at_ms >= ?']; const args = [Date.now() - days * 86400000];
      if (kw) { where.push('(request_id LIKE ? OR selected_model LIKE ? OR route_label LIKE ?)'); args.push('%' + kw + '%', '%' + kw + '%', '%' + kw + '%'); }
      const w = 'WHERE ' + where.join(' AND ');
      const total = this.db.prepare(`SELECT COUNT(*) c FROM smart_route_decision_logs ${w}`).get(...args).c;
      const logs = this.db.prepare(`SELECT * FROM smart_route_decision_logs ${w} ORDER BY id DESC LIMIT ? OFFSET ?`).all(...args, pageSize, (page - 1) * pageSize);
      return json(200, { total, page, pageSize, logs });
    }
    if (path === '/api/v1/admin/smart-routing' && req.method === 'GET') return json(200, { policy: this.cfg.get('routing', {}), samples: this.db.prepare('SELECT COUNT(*) c FROM smart_route_samples').get().c, byLabel: this.db.prepare('SELECT label, COUNT(*) c FROM smart_route_samples GROUP BY label').all() });
    if (path === '/api/v1/admin/routing' && req.method === 'GET') return json(200, this.cfg.get('routing', {}));
    if (path === '/api/v1/admin/routing' && req.method === 'PUT') { this.cfg.set('routing', body || {}); return json(200, { ok: true }); }
    if (path === '/api/v1/admin/smart-routing' && req.method === 'PUT') {
      const routing = { ...(this.cfg.get('routing', {}) || {}) };
      for (const [k, v] of Object.entries(body || {})) routing[k] = v;
      this.cfg.set('routing', routing);
      return json(200, { ok: true });
    }
    if (path === '/api/v1/admin/settings' && req.method === 'GET') return json(200, this.cfg.get('routing', {}));
    if (path === '/api/v1/admin/settings' && req.method === 'PUT') {
      // merge 进完整 routing 对象（GET/engine 都读完整对象；旧实现写扁平键导致"保存成功但读回旧值"）
      const routing = { ...(this.cfg.get('routing', {}) || {}) };
      for (const [k, v] of Object.entries(body || {})) routing[k] = v;
      this.cfg.set('routing', routing);
      return json(200, { ok: true });
    }
    // 分组设置（性能 / 健康 / 网关）
    if ((m = M(/^\/api\/v1\/admin\/settings\/(\w+)$/))) {
      const ns = m[1];
      const namespaces = ['performance', 'health_policy', 'gateway', 'log'];
      if (req.method === 'GET') {
        if (!namespaces.includes(ns)) return json(404, { error: 'unknown_namespace' });
        return json(200, this.cfg.get(ns, {}));
      }
      if (req.method === 'PUT') {
        this.cfg.set(ns, body || {});
        return json(200, { ok: true });
      }
    }
    // 上游模型发现：调上游 /models 列出可用模型
    if (path === '/api/v1/admin/upstream-accounts/discover-models') {
      const id = Number(url.searchParams.get('accountId'));
      const a = this.db.prepare('SELECT * FROM upstream_accounts WHERE id=?').get(id);
      if (!a) return json(404, { error: 'not_found' });
      const key = this.cred.open(this.credKey, a.credential_envelope);
      if (!key) return json(400, { error: 'no_credential' });
      const route = this.db.prepare('SELECT route FROM upstream_account_protocols WHERE account_id=? ORDER BY sort LIMIT 1').get(id)?.route || '/';
      const { buildHeaders, joinUrl } = require('./upstream');
      try {
        const res = await fetch(joinUrl(a.service_base_url, route, '/models'), { headers: buildHeaders(a, key), signal: AbortSignal.timeout(30000) });
        const j = await res.json().catch(() => null);
        const ids = (j?.data || j?.models || []).map(x => x.id || x.name || x).filter(x => typeof x === 'string');
        return json(200, { models: ids });
      } catch (e) { return json(502, { error: e.message }); }
    }
    if (path === '/api/v1/admin/call-logs') return this.callLogs(req, res, url, json);
    if (path === '/api/v1/admin/overview/runtime') return this.overview(json);
    if (path === '/api/v1/admin/overview/trend' || path === '/api/v1/admin/overview/token-trend') return this.trend(url, json);
    if (path === '/api/v1/admin/usage-statistics') return this.usage(url, json);
    if (path === '/api/v1/admin/content-compliance') return this.compliance(req, res, body, json);
    if (path === '/api/v1/admin/me/password' && req.method === 'POST') {
      return this.changePassword(session.user_id, body.oldPassword, body.newPassword) ? json(200, { ok: true }) : json(400, { error: 'old_password_invalid' });
    }
    // 模型视图：网关提供的模型 + 各自上游（账号/上游名/优先级/健康）+ 智能路由开关
    if (path === '/api/v1/admin/models') {
      const accounts = this.db.prepare('SELECT id,name,priority,enabled,health_status FROM upstream_accounts').all();
      const acct = Object.fromEntries(accounts.map(a => [a.id, a]));
      const rows = this.db.prepare(`SELECT m.request_model_name, m.upstream_model_name, m.model_type, m.account_id, m.priority AS model_priority, COALESCE(m.priority, a.priority) AS eff_priority
        FROM upstream_account_models m JOIN upstream_accounts a ON a.id=m.account_id
        WHERE a.enabled=1 ORDER BY m.request_model_name, COALESCE(m.priority, a.priority) DESC, a.id`).all();
      const byModel = {};
      for (const r of rows) {
        (byModel[r.request_model_name] = byModel[r.request_model_name] || []).push({
          accountId: r.account_id, accountName: acct[r.account_id]?.name,
          upstreamModel: r.upstream_model_name, modelType: r.model_type || '',
          priority: r.eff_priority ?? 0, modelPriority: r.model_priority,
          accountPriority: acct[r.account_id]?.priority ?? 0, health: acct[r.account_id]?.health_status,
        });
      }
      const mrules = this.cfg.get('routing', {}).model_rules || {};
      const hidden = new Set(this.cfg.get('routing', {}).hidden_models || []);
      const models = Object.entries(byModel).map(([name, upstreams]) => ({ name, upstreams, smartRoute: !!mrules[name]?.enabled, rules: mrules[name]?.rules || [], defaultModel: mrules[name]?.default_model || '', fallbackSimple: mrules[name]?.fallback_simple || '', fallbackComplex: mrules[name]?.fallback_complex || '', hidden: hidden.has(name) }));
      // 虚拟模型（auto/auto-vision 等无上游映射、仅存在于 model_rules 的路由入口）
      for (const [name, mr] of Object.entries(mrules)) {
        if (mr?.enabled && !byModel[name]) models.push({ name, upstreams: [], smartRoute: true, rules: mr.rules || [], defaultModel: mr.default_model || '', fallbackSimple: mr.fallback_simple || '', fallbackComplex: mr.fallback_complex || '', virtual: true, hidden: hidden.has(name) });
      }
      // 调用者的用户组模型白名单（普通用户用户中心过滤用）
      const allowedByGroup = {};
      for (const g of this.db.prepare('SELECT id FROM user_groups').all()) {
        allowedByGroup[g.id] = this.db.prepare('SELECT model_name FROM user_group_models WHERE user_group_id=?').all(g.id).map(x => x.model_name);
      }
      return json(200, { models, groupAllowedModels: allowedByGroup });
    }
    // 模型 CRUD：POST 新建 / PUT 改名+覆写上游映射 / DELETE 删除
    if ((m = M(/^\/api\/v1\/admin\/models(?:\/([^/]+))?$/)) && path !== '/api/v1/admin/models') {
      const modelName = m[1] ? decodeURIComponent(m[1]) : null;
      const nowStr = new Date().toISOString();
      const cleanRules = (name) => { const routing = this.cfg.get('routing', {}); const mr = { ...(routing.model_rules || {}) }; delete mr[name]; routing.model_rules = mr; this.cfg.set('routing', routing); };
      if (req.method === 'POST' && body?.name) {
        // body: { name, mappings: [{ accountId, upstreamModel, modelType }] }
        const exists = this.db.prepare('SELECT 1 FROM upstream_account_models WHERE request_model_name=? LIMIT 1').get(body.name);
        if (exists) return json(409, { error: 'duplicate_model' });
        for (const mp of body.mappings || []) {
          if (!mp.accountId || !mp.upstreamModel) continue;
          this.db.prepare('INSERT INTO upstream_account_models (account_id, request_model_name, upstream_model_name, model_type, priority) VALUES (?,?,?,?,?) ON CONFLICT (account_id, request_model_name) DO UPDATE SET upstream_model_name=excluded.upstream_model_name, model_type=excluded.model_type, priority=excluded.priority')
            .run(mp.accountId, body.name, mp.upstreamModel, mp.modelType || '', (mp.priority===undefined||mp.priority===null||mp.priority==='')?null:Number(mp.priority));
        }
        return json(200, { ok: true, name: body.name });
      }
      if (req.method === 'PUT' && modelName) {
        // body: { name?(新名，改名), modelType?(统一类别), mappings: [{ accountId, upstreamModel, modelType }] 覆写该模型全部上游映射 }
        const newName = (body.name || '').trim();
        if (newName && newName !== modelName) {
          const exists = this.db.prepare('SELECT 1 FROM upstream_account_models WHERE request_model_name=? LIMIT 1').get(newName);
          if (exists) return json(409, { error: 'duplicate_model' });
          this.db.prepare('UPDATE upstream_account_models SET request_model_name=? WHERE request_model_name=?').run(newName, modelName);
          this.db.prepare('UPDATE model_group_members SET request_model_name=? WHERE request_model_name=?').run(newName, modelName);
          cleanRules(modelName);
        }
        const effName = newName || modelName;
        if (Array.isArray(body.mappings)) {
          this.db.prepare('DELETE FROM upstream_account_models WHERE request_model_name=?').run(effName);
          for (const mp of body.mappings) {
            if (!mp.accountId || !mp.upstreamModel) continue;
            this.db.prepare('INSERT INTO upstream_account_models (account_id, request_model_name, upstream_model_name, model_type, priority) VALUES (?,?,?,?,?) ON CONFLICT (account_id, request_model_name) DO UPDATE SET upstream_model_name=excluded.upstream_model_name, model_type=excluded.model_type, priority=excluded.priority')
              .run(mp.accountId, effName, mp.upstreamModel, mp.modelType || body.modelType || '', (mp.priority===undefined||mp.priority===null||mp.priority==='')?null:Number(mp.priority));
          }
        }
        return json(200, { ok: true, name: effName });
      }
      if (req.method === 'DELETE' && modelName) {
        const used = this.db.prepare('SELECT COUNT(*) c FROM upstream_account_models WHERE request_model_name=?').get(modelName).c;
        this.db.prepare('DELETE FROM upstream_account_models WHERE request_model_name=?').run(modelName);
        this.db.prepare('DELETE FROM model_group_members WHERE request_model_name=?').run(modelName);
        cleanRules(modelName);
        return json(200, { ok: true, deleted: modelName, mappings: used });
      }
    }
    // 模型隐藏切换：PUT /admin/models/:name/visibility {hidden:bool}
    if ((m = M(/^\/api\/v1\/admin\/models\/([^/]+)\/visibility$/)) && req.method === 'PUT') {
      const modelName = decodeURIComponent(m[1]);
      const routing = this.cfg.get('routing', {});
      const list = new Set(routing.hidden_models || []);
      if (body?.hidden) list.add(modelName); else list.delete(modelName);
      routing.hidden_models = [...list];
      this.cfg.set('routing', routing);
      return json(200, { ok: true, hidden: body?.hidden === true });
    }
    // 模型级智能路由规则：PUT 单个模型的规则
    if ((m = M(/^\/api\/v1\/admin\/models\/([^/]+)\/smart-route$/))) {
      const modelName = decodeURIComponent(m[1]);
      if (req.method === 'PUT') {
        const routing = this.cfg.get('routing', {});
        const mr = { ...(routing.model_rules || {}) };
        if (body?.enabled) {
          mr[modelName] = { ...(mr[modelName] || {}), enabled: true };
          if (body.defaultModel !== undefined) mr[modelName].default_model = String(body.defaultModel || '').trim();
          if (body.fallbackSimple !== undefined) mr[modelName].fallback_simple = String(body.fallbackSimple || '').trim();
          if (body.fallbackComplex !== undefined) mr[modelName].fallback_complex = String(body.fallbackComplex || '').trim();
          if (Array.isArray(body.rules)) {
            mr[modelName].rules = body.rules.filter(r => r && r.type && r.target)
              .map((r, i) => ({ id: r.id ?? i, name: r.name || '', type: r.type, value: r.value ?? '', target: r.target, enabled: r.enabled !== false }));
          }
        } else delete mr[modelName];
        routing.model_rules = mr;
        this.cfg.set('routing', routing);
        return json(200, { ok: true });
      }
    }
    // 智能路由规则引擎读写：GET 返回规则列表 + auto 全局默认；PUT 整组覆写 rules
    if (path === '/api/v1/admin/route-rules' && req.method === 'GET') {
      const routing = this.cfg.get('routing', {});
      return json(200, {
        rules: (routing.rules || []).map((r, i) => ({ id: r.id ?? i, ...r })),
        defaults: { default_model: routing.default_model, simple_model: routing.simple_model, complex_model: routing.complex_model, route_threshold: routing.route_threshold, default_label: routing.default_label || 'complex' },
      });
    }
    if (path === '/api/v1/admin/route-rules' && req.method === 'PUT') {
      const routing = this.cfg.get('routing', {});
      const list = Array.isArray(body?.rules) ? body.rules.filter(r => r && r.type && r.target) : [];
      routing.rules = list.map((r, i) => ({ id: r.id ?? i, name: r.name || '', type: r.type, value: r.value ?? '', target: r.target, enabled: r.enabled !== false }));
      for (const k of ['default_model', 'simple_model', 'complex_model', 'route_threshold', 'default_label']) {
        if (body?.[k] !== undefined) routing[k] = body[k];
      }
      this.cfg.set('routing', routing);
      return json(200, { ok: true, count: routing.rules.length });
    }
    // ES 正文审计
    if (path === '/api/v1/admin/body-audit' && req.method === 'GET') {
      const s = this.cfg.get('log.body_audit', {});
      const es = s.elasticsearch || {};
      return json(200, {
        enabled: !!s.enabled, requestMaxKiB: s.requestMaxKiB ?? 1024, responseMaxKiB: s.responseMaxKiB ?? 1024,
        retentionDays: s.retentionDays ?? 30, endpoint: es.endpoint || null, username: es.username || 'elastic',
        hasCredential: !!es.credentialEnvelope, configured: !!(es.endpoint && es.credentialEnvelope),
        runtime: this.audit?.stats() || {},
      });
    }
    if (path === '/api/v1/admin/body-audit' && (req.method === 'PUT' || req.method === 'POST')) {
      const cur = this.cfg.get('log.body_audit', {});
      const es = { ...(cur.elasticsearch || {}) };
      if (body.endpoint !== undefined) es.endpoint = body.endpoint || '';
      if (body.username !== undefined) es.username = body.username || 'elastic';
      if (body.password) es.credentialEnvelope = this.audit.sealPassword(body.password); // 明文仅本次传输，落库即信封
      const next = {
        enabled: body.enabled ?? cur.enabled ?? false,
        requestMaxKiB: body.requestMaxKiB ?? cur.requestMaxKiB ?? 1024,
        responseMaxKiB: body.responseMaxKiB ?? cur.responseMaxKiB ?? 1024,
        retentionDays: body.retentionDays ?? cur.retentionDays ?? 30,
        elasticsearch: es,
      };
      this.cfg.set('log.body_audit', next);
      const on = this.audit.applySettings();
      return json(200, { ok: true, active: on });
    }
    if (path === '/api/v1/admin/body-audit/test' && req.method === 'POST') {
      return json(200, await this.audit.healthCheck());
    }
    if (path === '/api/v1/admin/body-audit/search') {
      const r = await this.audit.search({
        requestId: url.searchParams.get('requestId') || '',
        model: url.searchParams.get('model') || '',
        result: url.searchParams.get('result') || '',
        days: Number(url.searchParams.get('days') || 7), size: Number(url.searchParams.get('size') || 20),
      });
      return json(200, r);
    }
    if (path === '/api/v1/admin/body-audit/doc') {
      const r = await this.audit.get(url.searchParams.get('id') || '', url.searchParams.get('index') || '');
      return json(200, r);
    }
    return json(404, { error: 'not_found' });
  }

  // ---------- 上游账号 ----------
  accounts(req, res, m, body, json) {
    const [, idStr, action] = m;
    const id = idStr ? Number(idStr) : null;
    if (req.method === 'GET' && !id) {
      const rows = this.db.prepare('SELECT * FROM upstream_accounts ORDER BY id').all();
      for (const a of rows) {
        delete a.credential_envelope;
        a.models = this.db.prepare('SELECT request_model_name, upstream_model_name, model_type, priority FROM upstream_account_models WHERE account_id=? ORDER BY id').all(a.id);
        a.protocols = this.db.prepare('SELECT protocol, route, auth_mode FROM upstream_account_protocols WHERE account_id=? ORDER BY sort').all(a.id);
        const st = this.engine._state(a.id);
        a.inflight = st.inflight;
      }
      return json(200, { total: rows.length, accounts: rows });
    }
    if (action === 'balance') {
      this.queryBalance(id).then(r => json(r.status, r.data)).catch(e => json(500, { error: e.message }));
      return true;
    }
    if (req.method === 'GET' && id) {
      const a = this.db.prepare('SELECT * FROM upstream_accounts WHERE id=?').get(id);
      if (!a) return json(404, { error: 'not_found' });
      delete a.credential_envelope;
      a.models = this.db.prepare('SELECT request_model_name, upstream_model_name, model_type, priority FROM upstream_account_models WHERE account_id=? ORDER BY id').all(id);
      a.protocols = this.db.prepare('SELECT protocol, route, auth_mode FROM upstream_account_protocols WHERE account_id=? ORDER BY sort').all(id);
      return json(200, a);
    }
    if (action === 'enable' || action === 'disable') {
      this.db.prepare('UPDATE upstream_accounts SET enabled=?, updated_at=? WHERE id=?').run(action === 'enable' ? 1 : 0, new Date().toISOString(), id);
      return json(200, { ok: true });
    }
    if (action === 'test-model') {
      this.testModel(id, body?.requestModelName).then(r => json(r.status, r.data)).catch(e => json(500, { error: e.message }));
      return true;
    }
    if (req.method === 'POST') return this.upsertAccount(null, body, json);
    if (req.method === 'PUT' && id) return this.upsertAccount(id, body, json);
    if (req.method === 'DELETE' && id) {
      const a = this.db.prepare('SELECT name FROM upstream_accounts WHERE id=?').get(id);
      this.db.prepare('DELETE FROM upstream_accounts WHERE id=?').run(id);
      this.db.prepare('DELETE FROM upstream_account_models WHERE account_id=?').run(id);
      this.db.prepare('DELETE FROM upstream_account_protocols WHERE account_id=?').run(id);
      return json(200, { ok: true, deleted: a?.name });
    }
    return json(400, { error: 'invalid' });
  }

  accountModelItem(req, res, m, json) {
    const [, id, model] = m;
    if (req.method === 'DELETE') {
      this.db.prepare('DELETE FROM upstream_account_models WHERE account_id=? AND request_model_name=?').run(Number(id), decodeURIComponent(model));
      return json(200, { ok: true });
    }
    return json(404, { error: 'not_found' });
  }

  upsertAccount(id, b, json) {
    if (!b || !b.name || !b.serviceBaseURL) return json(400, { error: 'name_and_base_url_required' });
    const t = new Date().toISOString();
    const envelope = b.credential ? this.cred.seal(this.credKey, b.credential) : null;
    const maskv = b.credential ? this.cred.mask(b.credential) : null;
    const models = b.models || [];
    const protocols = (b.protocols && b.protocols.length) ? b.protocols : (b.protocol
      ? [{ protocol: b.protocol, route: '/', authMode: b.protocol === 'anthropicMessages' ? 'x-api-key' : 'bearer' }]
      : [{ protocol: 'openaiChatCompletions', route: '/', authMode: 'bearer' }]);
    if (id) {
      const q = `UPDATE upstream_accounts SET name=?, provider=?, protocol_type=?, service_base_url=?, validation_model=?, priority=?, max_concurrency=?, note=?, enabled=?, updated_at=?${envelope ? ', credential_envelope=?, credential_mask=?' : ''} WHERE id=?`;
      const args = [b.name, b.provider || 'custom', b.protocolType || 'text', b.serviceBaseURL, b.validationModel || '', b.priority ?? 0, b.maxConcurrency ?? 0, b.note || '', b.enabled === undefined ? 1 : (b.enabled ? 1 : 0), t];
      if (envelope) args.push(envelope, maskv);
      args.push(id);
      this.db.prepare(q).run(...args);
      this.db.prepare('DELETE FROM upstream_account_models WHERE account_id=?').run(id);
      this.db.prepare('DELETE FROM upstream_account_protocols WHERE account_id=?').run(id);
    } else {
      this.db.prepare(`INSERT INTO upstream_accounts (name,provider,protocol_type,service_base_url,credential_envelope,credential_mask,validation_model,priority,max_concurrency,enabled,health_status,note,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,1,'unknown',?,?,?)`)
        .run(b.name, b.provider || 'custom', b.protocolType || 'text', b.serviceBaseURL, envelope, maskv, b.validationModel || '', b.priority ?? 0, b.maxConcurrency ?? 0, b.note || '', t, t);
    }
    const target = id || this.db.prepare("SELECT id FROM upstream_accounts WHERE name=?").get(b.name).id;
    // 先 UPSERT 全部模型行（成功后再删多余行，避免 PG 上 UPSERT 失败把已有映射清空）
    for (const mm of models) {
      this.db.prepare('INSERT INTO upstream_account_models (account_id,request_model_name,upstream_model_name,model_type,priority) VALUES (?,?,?,?,?) ON CONFLICT (account_id, request_model_name) DO UPDATE SET upstream_model_name=EXCLUDED.upstream_model_name, model_type=EXCLUDED.model_type, priority=EXCLUDED.priority')
        .run(target, mm.requestModelName, mm.upstreamModelName || mm.requestModelName, mm.modelType || '', (mm.priority===undefined||mm.priority===null)?null:Number(mm.priority));
    }
    {
      const keep = models.map(mm => mm.requestModelName);
      const ph = keep.length ? keep.map(() => '?').join(',') : "''";
      this.db.prepare(`DELETE FROM upstream_account_models WHERE account_id=? AND request_model_name NOT IN (${ph})`).run(target, ...keep);
    }
    for (const [i, p] of protocols.entries()) {
      this.db.prepare('INSERT INTO upstream_account_protocols (account_id,protocol,route,auth_mode,sort) VALUES (?,?,?,?,?) ON CONFLICT DO NOTHING')
        .run(target, p.protocol, p.route || '/', p.authMode || 'bearer', i);
    }
    const out = this.db.prepare('SELECT * FROM upstream_accounts WHERE id=?').get(target);
    delete out.credential_envelope;
    return json(200, out);
  }

  // 供应商余额查询：不同供应商 API 不同；不支持的返回 supported:false
  async queryBalance(id) {
    const a = this.db.prepare('SELECT * FROM upstream_accounts WHERE id=?').get(id);
    if (!a) return { status: 404, data: { error: 'not_found' } };
    const key = this.cred.open(this.credKey, a.credential_envelope);
    if (!key) return { status: 400, data: { error: 'no_credential' } };
    const t0 = Date.now();
    const noSupport = { status: 200, data: { supported: false, error: '该供应商暂不支持余额查询' } };
    try {
      let amount = null, currency = 'CNY', raw = null;
      if (a.provider === 'deepseek') {
        const r = await fetch('https://api.deepseek.com/user/balance', { headers: { Authorization: 'Bearer ' + key }, signal: AbortSignal.timeout(15000) });
        const j = await r.json().catch(() => null);
        raw = j;
        const bal = (j?.balance_infos || []).find(b => b.currency === 'CNY');
        amount = bal ? Number(bal.total_balance) : null;
      } else return noSupport;   // 硅基 /v1/user/info 已官方废弃且无替代端点，暂不支持
      return { status: 200, data: { supported: true, amount, currency, latencyMs: Date.now() - t0 } };
    } catch (e) { return { status: 502, data: { supported: true, error: e.message } }; }
  }

  async testModel(id, requestModelName) {
    const a = this.db.prepare('SELECT * FROM upstream_accounts WHERE id=?').get(id);
    if (!a) return { status: 404, data: { error: 'not_found' } };
    const model = requestModelName || a.validation_model ||
      this.db.prepare('SELECT request_model_name FROM upstream_account_models WHERE account_id=? LIMIT 1').get(id)?.request_model_name;
    const key = this.cred.open(this.credKey, a.credential_envelope);
    if (!key) return { status: 500, data: { error: 'decrypt_failed' } };
    const mapping = this.db.prepare('SELECT upstream_model_name FROM upstream_account_models WHERE account_id=? AND request_model_name=?').get(id, model);
    const upstreamModel = mapping?.upstream_model_name || model;
    const kind = Engine.modelKind(model);
    const route = this.db.prepare('SELECT route FROM upstream_account_protocols WHERE account_id=? ORDER BY sort LIMIT 1').get(id)?.route || '/';
    const { postJson, buildHeaders, joinUrl } = require('./upstream');
    const t0 = Date.now();
    try {
      let path = '/chat/completions';
      let body = { model: upstreamModel, messages: [{ role: 'user', content: 'hi' }], max_tokens: 4 };
      if (kind === 'embedding') { path = '/embeddings'; body = { model: upstreamModel, input: ['hi'] }; }
      else if (kind === 'rerank') { path = '/rerank'; body = { model: upstreamModel, query: 'hi', documents: ['a', 'b'], top_n: 1 }; }
      const r = await postJson({ url: joinUrl(a.service_base_url, route, path), headers: buildHeaders(a, key), body, timeoutMs: 60000 });
      const ms = Date.now() - t0;
      if (r.status === 200) { this.engine.markSuccess(a); return { status: 200, data: { ok: true, upstreamModelName: upstreamModel, kind, latencyMs: ms } }; }
      return { status: 502, data: { ok: false, error: 'upstream_' + r.status, detail: String(r.text || '').slice(0, 300), latencyMs: ms } };
    } catch (e) { return { status: 502, data: { ok: false, error: e.message } }; }
  }

  // ---------- 模型组 ----------
  modelGroups(req, res, m, body, json) {
    const id = m[1] ? Number(m[1]) : null;
    if (req.method === 'GET') {
      const groups = this.db.prepare('SELECT * FROM model_groups ORDER BY id').all();
      for (const g of groups) {
        g.models = this.db.prepare('SELECT request_model_name FROM model_group_members WHERE model_group_id=? ORDER BY sort').all(g.id).map(x => x.request_model_name);
        g.userGroupIds = this.db.prepare('SELECT user_group_id FROM user_group_model_groups WHERE model_group_id=?').all(g.id).map(x => x.user_group_id);
      }
      return json(200, { total: groups.length, groups });
    }
    if (req.method === 'POST' || (req.method === 'PUT' && id)) {
      const t = new Date().toISOString();
      let target = id;
      if (id) this.db.prepare('UPDATE model_groups SET name=?, protocol_type=?, note=?, updated_at=? WHERE id=?').run(body.name, body.protocolType || 'text', body.note || '', t, id);
      else {
        this.db.prepare('INSERT INTO model_groups (name,protocol_type,note,created_at,updated_at) VALUES (?,?,?,?,?)').run(body.name, body.protocolType || 'text', body.note || '', t, t);
        target = this.db.prepare('SELECT id FROM model_groups WHERE name=?').get(body.name).id;
      }
      if (body.models) {
        this.db.prepare('DELETE FROM model_group_members WHERE model_group_id=?').run(target);
        for (const [i, mm] of body.models.entries()) this.db.prepare('INSERT INTO model_group_members (model_group_id,request_model_name,sort) VALUES (?,?,?) ON CONFLICT DO NOTHING').run(target, mm, i);
      }
      if (body.userGroupIds) {
        this.db.prepare('DELETE FROM user_group_model_groups WHERE model_group_id=?').run(target);
        for (const ug of body.userGroupIds) this.db.prepare('INSERT INTO user_group_model_groups (user_group_id,model_group_id) VALUES (?,?) ON CONFLICT DO NOTHING').run(ug, target);
      }
      return json(200, { ok: true, id: target });
    }
    if (req.method === 'DELETE' && id) {
      this.db.prepare('DELETE FROM model_groups WHERE id=?').run(id);
      this.db.prepare('DELETE FROM model_group_members WHERE model_group_id=?').run(id);
      this.db.prepare('DELETE FROM user_group_model_groups WHERE model_group_id=?').run(id);
      return json(200, { ok: true });
    }
    return json(400, { error: 'invalid' });
  }

  // ---------- 用户 ----------
  users(req, res, m, body, json) {
    const id = m[1] ? Number(m[1]) : null;
    if (req.method === 'GET') {
      const scoped = req._scopedUser;
      const users = this.db.prepare(`SELECT id,username,role,user_group_id,disabled,must_change_password,last_login_at,created_at FROM users${scoped ? ' WHERE id=' + Number(scoped.user_id) : ''} ORDER BY id`).all();
      for (const u of users) {
        const usage = this.db.prepare('SELECT COALESCE(SUM(total_tokens),0) t, COUNT(*) c FROM call_logs WHERE user_id=?').get(u.id);
        u.totalTokens = Number(usage.t); u.requestCount = Number(usage.c);
      }
      return json(200, { total: users.length, users });
    }
    const t = new Date().toISOString();
    if (req.method === 'POST') {
      if (!body.username || !body.password) return json(400, { error: 'username_and_password_required' });
      const dup = this.db.prepare('SELECT id FROM users WHERE username=?').get(body.username);
      if (dup) return json(400, { error: 'username_exists' });
      this.db.prepare('INSERT INTO users (username,password_hash,role,user_group_id,created_at,updated_at) VALUES (?,?,?,?,?,?)')
        .run(body.username, this.cred.hashPassword(body.password, body.username), body.role || 'user', body.userGroupId || 1, t, t);
      return json(200, { ok: true });
    }
    if (req.method === 'PUT' && id) {
      if (body.password) this.db.prepare('UPDATE users SET password_hash=?, must_change_password=?, updated_at=? WHERE id=?')
        .run(this.cred.hashPassword(body.password, body.username || ''), body.mustChangePassword ? 1 : 0, t, id);
      if (body.userGroupId !== undefined) this.db.prepare('UPDATE users SET user_group_id=?, updated_at=? WHERE id=?').run(body.userGroupId, t, id);
      if (body.disabled !== undefined) this.db.prepare('UPDATE users SET disabled=?, updated_at=? WHERE id=?').run(body.disabled ? 1 : 0, t, id);
      return json(200, { ok: true });
    }
    if (req.method === 'DELETE' && id) {
      const u = this.db.prepare('SELECT role FROM users WHERE id=?').get(id);
      if (!u) return json(404, { error: 'not_found' });
      if (u.role === 'admin') return json(400, { error: 'cannot_delete_admin' });
      this.db.prepare('DELETE FROM users WHERE id=?').run(id);
      return json(200, { ok: true });
    }
    return json(400, { error: 'invalid' });
  }

  userGroups(req, res, m, body, json) {
    const id = m[1] ? Number(m[1]) : null;
    if (req.method === 'GET') {
      const groups = this.db.prepare('SELECT * FROM user_groups ORDER BY id').all();
      for (const g of groups) {
        g.modelGroupIds = this.db.prepare('SELECT model_group_id FROM user_group_model_groups WHERE user_group_id=?').all(g.id).map(x => x.model_group_id);
        g.allowedModels = this.db.prepare('SELECT model_name FROM user_group_models WHERE user_group_id=?').all(g.id).map(x => x.model_name);
        g.userCount = this.db.prepare('SELECT COUNT(*) c FROM users WHERE user_group_id=?').get(g.id).c;
      }
      return json(200, { total: groups.length, groups });
    }
    const t = new Date().toISOString();
    if (req.method === 'POST') {
      this.db.prepare('INSERT INTO user_groups (name,enabled,max_concurrency,token_quota,note,queue_size,queue_timeout_sec,is_default,created_at,updated_at) VALUES (?,?,?,?,?,?,?,0,?,?)')
        .run(body.name, body.enabled === undefined ? 1 : (body.enabled ? 1 : 0), body.maxConcurrency ?? 0, body.tokenQuota ?? 0, body.note || '', Math.max(0, Number(body.queueSize) || 0), Math.max(0, Number(body.queueTimeoutSec) || 0), t, t);
      const gid = this.db.prepare('SELECT id FROM user_groups WHERE name=?').get(body.name).id;
      for (const mg of (body.modelGroupIds || [])) this.db.prepare('INSERT INTO user_group_model_groups (user_group_id,model_group_id) VALUES (?,?) ON CONFLICT DO NOTHING').run(gid, mg);
      for (const mn of (body.allowedModels || [])) this.db.prepare('INSERT INTO user_group_models (user_group_id,model_name) VALUES (?,?) ON CONFLICT DO NOTHING').run(gid, mn);
      return json(200, { ok: true, id: gid });
    }
    if (req.method === 'PUT' && id) {
      const cur = this.db.prepare('SELECT * FROM user_groups WHERE id=?').get(id);
      this.db.prepare('UPDATE user_groups SET name=?, enabled=?, max_concurrency=?, token_quota=?, note=?, queue_size=?, queue_timeout_sec=?, updated_at=? WHERE id=?')
        .run(body.name ?? cur.name, body.enabled === undefined ? cur.enabled : (body.enabled ? 1 : 0), body.maxConcurrency ?? cur.max_concurrency, body.tokenQuota ?? cur.token_quota, body.note ?? cur.note, body.queueSize !== undefined ? Math.max(0, Number(body.queueSize) || 0) : (cur.queue_size ?? 0), body.queueTimeoutSec !== undefined ? Math.max(0, Number(body.queueTimeoutSec) || 0) : (cur.queue_timeout_sec ?? 0), t, id);
      if (body.modelGroupIds) {
        this.db.prepare('DELETE FROM user_group_model_groups WHERE user_group_id=?').run(id);
        for (const mg of body.modelGroupIds) this.db.prepare('INSERT INTO user_group_model_groups (user_group_id,model_group_id) VALUES (?,?) ON CONFLICT DO NOTHING').run(id, mg);
      }
      if (body.allowedModels) {
        this.db.prepare('DELETE FROM user_group_models WHERE user_group_id=?').run(id);
        for (const mn of body.allowedModels) this.db.prepare('INSERT INTO user_group_models (user_group_id,model_name) VALUES (?,?) ON CONFLICT DO NOTHING').run(id, mn);
      }
      return json(200, { ok: true });
    }
    if (req.method === 'DELETE' && id) {
      const g = this.db.prepare('SELECT is_default FROM user_groups WHERE id=?').get(id);
      if (!g) return json(404, { error: 'not_found' });
      if (g.is_default) return json(400, { error: 'cannot_delete_default' });
      const used = this.db.prepare('SELECT COUNT(*) c FROM users WHERE user_group_id=?').get(id).c;
      if (used > 0) return json(400, { error: 'group_in_use', users: used });
      this.db.prepare('DELETE FROM user_groups WHERE id=?').run(id);
      this.db.prepare('DELETE FROM user_group_model_groups WHERE user_group_id=?').run(id);
      this.db.prepare('DELETE FROM user_group_models WHERE user_group_id=?').run(id);
      return json(200, { ok: true });
    }
    return json(400, { error: 'invalid' });
  }

  // ---------- API Keys ----------
  apiKeys(req, res, m, body, json) {
    const id = m[1] ? Number(m[1]) : null;
    if (req.method === 'GET') {
      const scoped = req._scopedUser;
      const keys = this.db.prepare(`SELECT k.id,k.user_id,k.name,k.prefix,k.mask,k.disabled,k.max_concurrency,k.created_at,k.last_used_at,u.username FROM api_keys k JOIN users u ON u.id=k.user_id${scoped ? ' WHERE k.user_id=' + Number(scoped.user_id) : ''} ORDER BY k.id`).all();
      for (const k of keys) {
        const s = this.db.prepare('SELECT COUNT(*) c, COALESCE(SUM(total_tokens),0) t FROM call_logs WHERE api_key_id=?').get(k.id);
        k.requestCount = Number(s.c); k.totalTokens = Number(s.t);
      }
      return json(200, { total: keys.length, keys });
    }
    if (req.method === 'POST') {
      // 普通用户只能给自己建 key（scoped）；admin 可指定 userId
      const owner = req._scopedUser ? Number(req._scopedUser.user_id) : (Number(body.userId) || 1);
      const raw = 'sk-' + crypto.randomBytes(24).toString('base64url');
      this.db.prepare('INSERT INTO api_keys (user_id,name,key_hash,prefix,mask,created_at) VALUES (?,?,?,?,?,?)')
        .run(owner, body.name || 'key', this.cred.sha256(raw), raw.slice(0, 11), raw.slice(0, 11) + '...' + raw.slice(-4), new Date().toISOString());
      return json(200, { key: raw });
    }
    if (id && req._scopedUser) {
      const own = this.db.prepare('SELECT 1 FROM api_keys WHERE id=? AND user_id=?').get(id, Number(req._scopedUser.user_id));
      if (!own) return json(403, { error: 'forbidden' });
    }
    if (req.method === 'PUT' && id) {
      if (body.name) this.db.prepare('UPDATE api_keys SET name=? WHERE id=?').run(body.name, id);
      if (body.disabled !== undefined) this.db.prepare('UPDATE api_keys SET disabled=? WHERE id=?').run(body.disabled ? 1 : 0, id);
      if (body.maxConcurrency !== undefined) this.db.prepare('UPDATE api_keys SET max_concurrency=? WHERE id=?').run(Math.max(0, Number(body.maxConcurrency) || 0), id);
      return json(200, { ok: true });
    }
    if (req.method === 'DELETE' && id) { this.db.prepare('DELETE FROM api_keys WHERE id=?').run(id); return json(200, { ok: true }); }
    return json(400, { error: 'invalid' });
  }

  // ---------- 调用日志 ----------
  callLogs(req, res, url, json) {
    const page = Number(url.searchParams.get('page') || 1);
    const pageSize = Math.min(Number(url.searchParams.get('pageSize') || 20), 200);
    const where = []; const args = [];
    const model = url.searchParams.get('model'); if (model) { where.push('request_model LIKE ?'); args.push('%' + model + '%'); }
    const accountId = url.searchParams.get('accountId'); if (accountId) { where.push('upstream_account_id = ?'); args.push(Number(accountId)); }
    const status = url.searchParams.get('status'); if (status === 'ok') where.push('result_kind = 1'); else if (status === 'fail') where.push('result_kind <> 1');
    const days = Number(url.searchParams.get('days') || 0); if (days > 0) { where.push('started_at_ms >= ?'); args.push(Date.now() - days * 86400000); }
    const kw = url.searchParams.get('keyword');
    if (kw) { where.push('(request_id LIKE ? OR upstream_model LIKE ? OR error_code LIKE ?)'); args.push('%' + kw + '%', '%' + kw + '%', '%' + kw + '%'); }
    const w = where.length ? 'WHERE ' + where.join(' AND ') : '';
    const total = this.db.prepare(`SELECT COUNT(*) c FROM call_logs ${w}`).get(...args).c;
    const logs = this.db.prepare(`SELECT * FROM call_logs ${w} ORDER BY id DESC LIMIT ? OFFSET ?`).all(...args, pageSize, (page - 1) * pageSize);
    const accountNames = {};
    for (const a of this.db.prepare('SELECT id,name FROM upstream_accounts').all()) accountNames[a.id] = a.name;
    for (const l of logs) l.accountName = l.upstream_account_id ? (accountNames[l.upstream_account_id] || String(l.upstream_account_id)) : null;
    return json(200, { total, page, pageSize, logs });
  }

  overview(json) {
    const accounts = this.db.prepare('SELECT id,name,health_status,enabled,protocol_type,max_concurrency,priority FROM upstream_accounts ORDER BY id').all();
    for (const a of accounts) a.inflight = this.engine._state(a.id).inflight;
    const startOfDay = Date.parse(new Date().toISOString().slice(0, 10));
    const today = this.db.prepare('SELECT COUNT(*) c FROM call_logs WHERE started_at_ms >= ?').get(startOfDay).c;
    const ok = this.db.prepare('SELECT COUNT(*) c FROM call_logs WHERE result_kind=1 AND started_at_ms >= ?').get(startOfDay).c;
    const tokens = this.db.prepare('SELECT COALESCE(SUM(total_tokens),0) t FROM call_logs WHERE started_at_ms >= ?').get(startOfDay).t;
    const activeUsers = this.db.prepare('SELECT COUNT(DISTINCT user_id) c FROM call_logs WHERE started_at_ms >= ?').get(Date.now() - 3600000).c;
    const apiKeyCount = this.db.prepare('SELECT COUNT(*) c FROM api_keys WHERE disabled=0').get().c;
    return json(200, {
      accounts, todayCalls: today, todayOk: ok, todayTokens: Number(tokens),
      activeUsers, apiKeyCount, streaming: this.engine.streaming || 0, gatewayConcurrency: this.engine.inflight || 0,
      concurrencyLimit: this.cfg.get('performance', {}).max_concurrency || 0,
      uptimeSec: Math.floor(process.uptime()),
    });
  }

  // 时序聚合：按小时（hours=24）或按天（days=N），返回 Token 分量与请求成功/失败
  trend(url, json) {
    const hours = url.searchParams.get('hours') ? Math.min(Number(url.searchParams.get('hours')), 168) : 0;
    const days = Math.min(Number(url.searchParams.get('days') || 14), 90);
    const pg = this.db.dialect === 'pg';
    const tz = pg ? " AT TIME ZONE 'Asia/Shanghai'" : '';
    const bucket = hours
      ? (pg ? `to_char(to_timestamp(started_at_ms/1000)${tz}, 'YYYY-MM-DD HH24:00')` : `strftime('%Y-%m-%d %H:00', started_at_ms/1000, 'unixepoch', 'localtime')`)
      : (pg ? `to_char(to_timestamp(started_at_ms/1000)${tz}, 'YYYY-MM-DD')` : `date(started_at_ms/1000,'unixepoch','localtime')`);
    const span = hours ? hours * 3600000 : days * 86400000;
    const rows = this.db.prepare(`SELECT ${bucket} bucket, COUNT(*) calls,
        SUM(CASE WHEN result_kind=1 THEN 1 ELSE 0 END) ok,
        COALESCE(SUM(input_tokens),0) input, COALESCE(SUM(output_tokens),0) output,
        COALESCE(SUM(total_tokens),0) tokens, COALESCE(SUM(cached_tokens),0) cached,
        COALESCE(AVG(duration_ms),0) avgMs
      FROM call_logs WHERE started_at_ms >= ? GROUP BY bucket ORDER BY bucket`).all(Date.now() - span);
    const num = (r) => ({ day: r.bucket, calls: Number(r.calls), ok: Number(r.ok), fail: Number(r.calls) - Number(r.ok),
      input: Number(r.input), output: Number(r.output), tokens: Number(r.tokens), cached: Number(r.cached), avgMs: Math.round(Number(r.avgMs)) });
    return json(200, { granularity: hours ? 'hour' : 'day', days: rows.map(num) });
  }

  usage(url, json) {
    const days = Number(url.searchParams.get('days') || 30);
    const since = Date.now() - days * 86400000;
    const agg = this.db.prepare(`SELECT COUNT(*) calls, SUM(CASE WHEN result_kind=1 THEN 1 ELSE 0 END) ok,
      COALESCE(SUM(input_tokens),0) input, COALESCE(SUM(output_tokens),0) output,
      COALESCE(SUM(total_tokens),0) total, COALESCE(SUM(cached_tokens),0) cached FROM call_logs WHERE started_at_ms >= ?`).get(since);
    const byModel = this.db.prepare(`SELECT request_model, COUNT(*) calls, COALESCE(SUM(total_tokens),0) tokens FROM call_logs WHERE started_at_ms >= ? GROUP BY request_model ORDER BY calls DESC LIMIT 30`).all(since);
    // 模型分布（解析虚拟模型）：auto 等虚拟模型按实际转发落点换算成对外模型名（upstream_model 反查映射表），
    // 真实模型保持 request_model。展示名与模型页一致，不出现上游内部名。
    const byUpstreamModel = this.db.prepare(`
      SELECT COALESCE(m.request_model_name, c.request_model) AS request_model, COUNT(*) calls, COALESCE(SUM(c.total_tokens),0) tokens
      FROM call_logs c
      LEFT JOIN upstream_account_models m ON lower(m.upstream_model_name) = lower(c.upstream_model) AND m.account_id = c.upstream_account_id
      WHERE c.started_at_ms >= ? AND c.upstream_model IS NOT NULL AND c.upstream_model <> ''
      GROUP BY COALESCE(m.request_model_name, c.request_model)
      ORDER BY calls DESC LIMIT 30`).all(since);
    const byAccount = this.db.prepare(`SELECT upstream_account_id, COUNT(*) calls, COALESCE(SUM(total_tokens),0) tokens FROM call_logs WHERE started_at_ms >= ? GROUP BY upstream_account_id ORDER BY calls DESC LIMIT 30`).all(since);
    const accountNames = {};
    for (const a of this.db.prepare('SELECT id,name FROM upstream_accounts').all()) accountNames[a.id] = a.name;
    const byUser = this.db.prepare(`SELECT u.username, COUNT(*) calls, COALESCE(SUM(c.total_tokens),0) tokens FROM call_logs c JOIN users u ON u.id=c.user_id WHERE c.started_at_ms >= ? GROUP BY u.username ORDER BY calls DESC LIMIT 20`).all(since);
    const num = (r) => Object.fromEntries(Object.entries(r).map(([k, v]) => [k, typeof v === 'bigint' ? Number(v) : (typeof v === 'string' && /^\d+$/.test(v) && k !== 'request_model' ? Number(v) : v)]));
    return json(200, {
      totals: num(agg),
      byModel: byModel.map(num),
      byUpstreamModel: byUpstreamModel.map(num),
      byAccount: byAccount.map(r => ({ ...num(r), id: Number(r.upstream_account_id), name: accountNames[r.upstream_account_id] || '未关联' })),
      byUser: byUser.map(num),
    });
  }

  // ---------- 智能路由样本 ----------
  samples(req, res, m, body, url, json) {
    const id = m[1] ? Number(m[1]) : null;
    if (req.method === 'GET') {
      const page = Number(url.searchParams.get('page') || 1), pageSize = Math.min(Number(url.searchParams.get('pageSize') || 20), 200);
      const label = url.searchParams.get('label'), kw = url.searchParams.get('keyword');
      const where = []; const args = [];
      if (label) { where.push('label=?'); args.push(label); }
      if (kw) { where.push('text LIKE ?'); args.push('%' + kw + '%'); }
      const w = where.length ? 'WHERE ' + where.join(' AND ') : '';
      const total = this.db.prepare(`SELECT COUNT(*) c FROM smart_route_samples ${w}`).get(...args).c;
      const rows = this.db.prepare(`SELECT id,label,text,remark,vector_dim,created_at FROM smart_route_samples ${w} ORDER BY id DESC LIMIT ? OFFSET ?`).all(...args, pageSize, (page - 1) * pageSize);
      return json(200, { total, page, pageSize, samples: rows });
    }
    if (req.method === 'POST') {
      const items = Array.isArray(body.items) ? body.items : [body];
      const t = new Date().toISOString();
      let n = 0;
      for (const it of items) {
        if (!it.text || !it.label) continue;
        this.db.prepare('INSERT INTO smart_route_samples (label,text,normalized_text,remark,created_at,updated_at) VALUES (?,?,?,?,?,?)')
          .run(it.label, it.text, it.text.toLowerCase().trim(), it.remark || '', t, t);
        n++;
      }
      this.engine.vectorizeSamples?.().catch(e => this.logger('vectorize: ' + e.message));
      return json(200, { ok: true, inserted: n });
    }
    if (req.method === 'PUT' && id) {
      const cur = this.db.prepare('SELECT * FROM smart_route_samples WHERE id=?').get(id);
      if (!cur) return json(404, { error: 'not_found' });
      this.db.prepare('UPDATE smart_route_samples SET label=?, text=?, normalized_text=?, remark=?, vector=NULL, vector_dim=0, updated_at=? WHERE id=?')
        .run(body.label ?? cur.label, body.text ?? cur.text, (body.text ?? cur.text).toLowerCase().trim(), body.remark ?? cur.remark, new Date().toISOString(), id);
      this.engine.vectorizeSamples?.().catch(() => {});
      return json(200, { ok: true });
    }
    if (req.method === 'DELETE') {
      if (id) this.db.prepare('DELETE FROM smart_route_samples WHERE id=?').run(id);
      else if (body?.ids) for (const i of body.ids) this.db.prepare('DELETE FROM smart_route_samples WHERE id=?').run(i);
      return json(200, { ok: true });
    }
    return json(400, { error: 'invalid' });
  }

  async vectorize(req, res, body, json) {
    const rows = this.db.prepare('SELECT id,text FROM smart_route_samples WHERE vector IS NULL').all();
    if (!this.engine.embedder) return json(400, { error: 'no_embedder' });
    let done = 0, failed = 0;
    for (const r of rows) {
      try { const v = await this.engine.embedder(r.text); this.db.prepare('UPDATE smart_route_samples SET vector=?, vector_dim=? WHERE id=?').run(JSON.stringify(v), v.length, r.id); done++; }
      catch { failed++; if (failed > 5) break; }
    }
    return json(200, { ok: true, vectorized: done, failed, pending: Math.max(0, rows.length - done - failed) });
  }

  // ---------- 内容合规 ----------
  compliance(req, res, body, json) {
    if (req.method === 'GET') {
      const groups = this.db.prepare('SELECT * FROM content_policy_groups ORDER BY id').all();
      for (const g of groups) g.words = this.db.prepare('SELECT id,word,enabled FROM content_sensitive_words WHERE policy_group_id=?').all(g.id);
      return json(200, { groups, settings: this.cfg.get('content_compliance', { enabled: false }) });
    }
    const t = new Date().toISOString();
    if (req.method === 'POST') {
      if (body.word && body.policyGroupId) {
        this.db.prepare('INSERT INTO content_sensitive_words (policy_group_id,word,normalized_word) VALUES (?,?,?) ON CONFLICT DO NOTHING')
          .run(body.policyGroupId, body.word, body.word.toLowerCase().trim());
        this._policy = null;
        return json(200, { ok: true });
      }
      this.db.prepare('INSERT INTO content_policy_groups (name,action,risk,enabled,description,created_at,updated_at) VALUES (?,?,?,?,?,?,?)')
        .run(body.name, body.action || 'block', body.risk || 'high', 1, body.description || '', t, t);
      return json(200, { ok: true });
    }
    if (req.method === 'PUT') {
      if (body.enabled !== undefined) { this.cfg.set('content_compliance', { enabled: !!body.enabled }); this._policy = null; return json(200, { ok: true }); }
      if (body.policyGroupId !== undefined) {
        this.db.prepare('UPDATE content_policy_groups SET name=?, action=?, risk=?, enabled=?, description=?, updated_at=? WHERE id=?')
          .run(body.name, body.action, body.risk, body.enabled === undefined ? 1 : (body.enabled ? 1 : 0), body.description || '', t, body.policyGroupId);
        this._policy = null;
        return json(200, { ok: true });
      }
      return json(400, { error: 'invalid' });
    }
    if (req.method === 'DELETE') {
      if (body?.wordId) { this.db.prepare('DELETE FROM content_sensitive_words WHERE id=?').run(body.wordId); return json(200, { ok: true }); }
      if (body?.groupId) {
        this.db.prepare('DELETE FROM content_sensitive_words WHERE policy_group_id=?').run(body.groupId);
        this.db.prepare('DELETE FROM content_policy_groups WHERE id=?').run(body.groupId);
        this._policy = null;
        return json(200, { ok: true });
      }
    }
    return json(400, { error: 'invalid' });
  }

  // 敏感词表 30s 内存缓存：原实现每请求按组逐条查库（同步 PG 桥），词表大时是 N 次阻塞查询
  _policyCache() {
    const nowT = Date.now();
    if (this._policy && nowT - this._policy.t < 30000) return this._policy.v;
    const groups = this.db.prepare('SELECT * FROM content_policy_groups WHERE enabled=1').all();
    const v = groups.map(g => ({
      action: g.action, risk: g.risk, name: g.name,
      words: this.db.prepare('SELECT word FROM content_sensitive_words WHERE policy_group_id=? AND enabled=1').all(g.id).map(w => String(w.word).toLowerCase()),
    }));
    this._policy = { v, t: nowT };
    return v;
  }

  checkContent(text) {
    if (!this.cfg.get('content_compliance', {}).enabled) return null;
    const t = (text || '').toLowerCase();
    for (const g of this._policyCache()) {
      for (const w of g.words) if (t.includes(w)) return { blocked: g.action === 'block', risk: g.risk, groupName: g.name, word: w };
    }
    return null;
  }
}

function parseCookies(header) {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

module.exports = { Api, parseCookies };
