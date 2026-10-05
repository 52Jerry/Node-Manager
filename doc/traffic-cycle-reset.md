# 固定周期流量重置接口

网站使用带 Bearer Token 和 Idempotency-Key 的 POST /api/user/{userId}/traffic/reset。

- 自动周期请求包含 cycleStart（UTC ISO-8601，已经开始的固定 30 天周期边界）。
- 手工重置请求为 {}，调用方每次确认操作生成一个新的 Idempotency-Key，同一次网络重试沿用相同键。
- 周期水位持久化在流量记录的 lastTrafficCycleStart 字段。相同或更旧周期即使幂等缓存过期也不重复清零。
- 操作只清零已用流量和相关流量阻断，不修改过期时间、连接凭据、额度和连接采样基线。
- 已过期用户不会因为清零流量被恢复连接；到期拒绝规则保持不变。
- 网站后端每个节点绑定分别记录确认周期，单个节点失败可独立重试。
- 主备复制的用户快照包含 trafficCycleStart。新周期同步清零，相同周期继续累计，旧周期不回灌流量。
- 手工清零另有 manualTrafficResetAt 水位，防止同一固定周期内复制旧用量覆盖管理员清零。
- 默认 POST /api/user/{userId}/renew 已改为 resetTraffic=false。显式传 true 的旧客户端兼容行为仍保留；网站新版不会传 true。

需要先升级 Node Manager，再执行网站的 backend/sql/20261005_traffic_cycle.sql，最后升级网站后端和前端。
自动任务由网站执行，必须保持网站后端运行；中断后按当前固定周期补偿一次，不逐个补跑所有历史周期。
