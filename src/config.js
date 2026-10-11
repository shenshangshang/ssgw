// 配置层：settings 表 + 默认值（对齐 enhance 环境变量语义）
'use strict';

const DEFAULTS = {
  'gateway.listen_port': 8080,
  'gateway.max_body_mb': 32,
  'routing.default_model': 'glm-5.2',
  'routing.simple_model': 'deepseek-ai/DeepSeek-V3.2',
  'routing.complex_model': 'deepseek-v4-flash',
  'routing.vision_model': 'deepseek-v4-flash-vision-exp',
  'routing.vision_models': ['Qwen3-VL', 'vision', 'VL-', 'glm-4v', 'gpt-4o'],
  'routing.cheap_vision_model': 'Qwen/Qwen3-VL-8B-Instruct',
  'routing.local_retry_model': 'qwen38-gsq-uncensored',
  'routing.confirm_model': 'aigw-refusal-check',
  'routing.rerank_model': 'Qwen/Qwen3-Reranker-8B',
  'routing.route_threshold': 0.15,
  'routing.refusal_retry': true,
  'embedding.model': 'Qwen/Qwen3-Embedding-8B',
  'embedding.fallback_model': 'Qwen/Qwen3-Embedding-4B',
  'health_policy.cooldownBaseSec': 60,
  'health_policy.quotaLatchSec': 1800,
  'health_policy.errorFails': 3,
  'log.call_retention_days': 30,
};

class Config {
  constructor(db) { this.db = db; }
  get(key, def) {
    const fallback = def !== undefined ? def : DEFAULTS[key];
    const row = this.db.prepare('SELECT value FROM settings WHERE key=?').get(key);
    if (!row) {
      // 命名空间回退：get('routing', {...}) 可吃到 routing.xxx 扁平键（含无点前缀）
      if (def && typeof def === 'object' && !Array.isArray(def)) {
        const ns = {};
        let found = false;
        for (const dk of Object.keys(DEFAULTS)) {
          if (dk.startsWith(key + '.') || dk.startsWith('routing.')) {
            if (dk.startsWith(key + '.')) {
              const v = this.get(dk);
              if (v !== undefined) { ns[dk.slice(key.length + 1)] = v; found = true; }
            }
          }
        }
        if (key === 'routing' || key.includes('.')) {
          for (const dk of Object.keys(DEFAULTS)) {
            if (dk.startsWith('routing.')) {
              const v = this.get(dk);
              if (v !== undefined) { ns[dk.slice('routing.'.length)] = v; found = true; }
            }
          }
        }
        return found ? { ...def, ...ns } : def;
      }
      return fallback;
    }
    try { return JSON.parse(row.value); } catch { return row.value; }
  }
  set(key, value) {
    this.db.prepare('INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value')
      .run(key, JSON.stringify(value));
  }
  // routing 命名空间便捷访问
  getRouting() { return this.get('routing', {}); }
}

module.exports = { Config, DEFAULTS };
