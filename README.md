# ssgw — 自研 AI 网关

替代 1Panel ai-gateway + aigw-enhance 前置代理的统一网关服务。

## 功能全景（对齐 1Panel ai-gateway + enhance 外挂层）

- OpenAI 兼容代理：`/v1/chat/completions`（含 SSE 流式）、`/v1/embeddings`、`/v1/rerank`、`/v1/models`、`/v1/images/generations`
- 上游账号管理：多上游、优先级、并发上限、协议（openaiChatCompletions/embeddings/images/rerank）、凭据加密存储（AES-256-GCM envelope）
- 模型组：text/image/embedding 分组、组内成员排序、用户组→模型组授权
- 智能路由（auto）：请求文本 embedding → 与种子样本余弦相似分类 simple/complex → 按组路由；置信度不足回退默认模型
- 视觉分流：请求含图片 → 改写模型为 vision 模型；图片描述回填（describeHistoryImages）
- 拒答检测与重试：looksLikeRefusal（关键词+refusal 字段）→ confirmRefusal（LLM 结构化确认）→ localRetryBody（本地无审查模型重写重试）
- 忙碌降级：isBusyError（429/overloaded/busy）→ 按优先级降级链自动切换账号
- 健康管理：请求驱动熔断 + **半开探测自动恢复**（修复 1Panel 版闩锁缺陷）+ 周期主动健康检查
- 用户/用户组/API Key：SHA-256 key 哈希、并发与 token 配额
- 调用日志：call_logs + attempts + 每分钟并发统计，用量汇总
- 内容合规：敏感词组（block/audit_only）+ 语义样本审核
- 管理 API：`/api/v1/admin/*`（兼容 1Panel ai-gateway 端点形态）+ 会话/CSRF 认证
- Web 管理面板：单页应用（原生 JS，无构建步骤）
- ntfy 告警：上游配额异常/熔断推送（凭据在实例环境变量，不落库）

## 运行

```
node src/server.js          # 环境变量见 config 段
```

数据目录 `data/`（SQLite ssgw.db）。首启自动建表并从环境变量 `SSGW_SEED_*` 或迁移脚本导入配置。

## 与 aigw 的关系

部署在新端口（如 docker:145 → 容器内 8080 → 宿主 3061），不动 aigw.shenshang.online。验证稳定后由用户决定切换。
