const { openDb } = require('/app/src/db');
const db = openDb('/app/data');
const models = [
  ['deepseek-ai/DeepSeek-V3.2','deepseek-ai/DeepSeek-V3.2'],
  ['Qwen/Qwen3.5-35B-A3B','Qwen/Qwen3.5-35B-A3B'],
  ['zai-org/GLM-4.5-Air','zai-org/GLM-4.5-Air'],
  ['Qwen/Qwen3-Coder-30B-A3B-Instruct','Qwen/Qwen3-Coder-30B-A3B-Instruct'],
  ['Qwen/Qwen3-VL-32B-Instruct','Qwen/Qwen3-VL-32B-Instruct'],
  ['Qwen/Qwen3-VL-8B-Instruct','Qwen/Qwen3-VL-8B-Instruct'],
  ['Qwen/Qwen3-Embedding-8B','Qwen/Qwen3-Embedding-8B'],
  ['Qwen/Qwen3-Embedding-4B','Qwen/Qwen3-Embedding-4B'],
  ['Qwen/Qwen3-Embedding-0.6B','Qwen/Qwen3-Embedding-0.6B'],
  ['BAAI/bge-m3','BAAI/bge-m3'],
  ['Qwen/Qwen3-Reranker-8B','Qwen/Qwen3-Reranker-8B'],
  ['BAAI/bge-reranker-v2-m3','BAAI/bge-reranker-v2-m3'],
  ['Qwen/Qwen-Image','Qwen/Qwen-Image'],
  ['Qwen/Qwen-Image-Edit','Qwen/Qwen-Image-Edit'],
  ['Qwen/Qwen-Image-Edit-2509','Qwen/Qwen-Image-Edit-2509'],
];
for (const [r, u] of models) db.prepare('INSERT INTO upstream_account_models (account_id,request_model_name,upstream_model_name) VALUES (3,?,?) ON CONFLICT DO NOTHING').run(r, u);
db.prepare("UPDATE upstream_accounts SET name='硅基流动', protocol_type='text', note='文本/向量/重排/生图统一账号，类别由模型名决定' WHERE id=3").run();
db.prepare('DELETE FROM upstream_accounts WHERE id IN (2,4)').run();
db.prepare('DELETE FROM upstream_account_models WHERE account_id IN (2,4)').run();
db.prepare('DELETE FROM upstream_account_protocols WHERE account_id IN (2,4)').run();
db.prepare("INSERT INTO model_groups (name,protocol_type,note,created_at,updated_at) VALUES ('重排','text','reranker 模型组','2026-09-17T00:00:00Z','2026-09-17T00:00:00Z') ON CONFLICT DO NOTHING").run();
const gid = db.prepare("SELECT id FROM model_groups WHERE name='重排'").get().id;
db.prepare('INSERT INTO model_group_members (model_group_id,request_model_name,sort) VALUES (?,?,0) ON CONFLICT DO NOTHING').run(gid, 'Qwen/Qwen3-Reranker-8B');
db.prepare('INSERT INTO model_group_members (model_group_id,request_model_name,sort) VALUES (?,?,1) ON CONFLICT DO NOTHING').run(gid, 'BAAI/bge-reranker-v2-m3');
db.prepare('INSERT INTO user_group_model_groups (user_group_id,model_group_id) VALUES (1,?) ON CONFLICT DO NOTHING').run(gid);
console.log('merged. account count:', db.prepare('SELECT COUNT(*) c FROM upstream_accounts').get().c);
db.prepare('SELECT id,name FROM upstream_accounts').all().forEach(a => console.log(a.id, a.name));
console.log('account 3 models:', db.prepare('SELECT COUNT(*) c FROM upstream_account_models WHERE account_id=3').get().c);
process.exit(0);
