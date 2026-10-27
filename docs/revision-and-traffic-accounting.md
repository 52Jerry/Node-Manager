# 完整发布与来源计量的兼容及恢复说明

本说明对应 2026-10-26 的 N-01～N-04 修复。只说明代码行为和待审核的恢复步骤；未执行真实节点迁移、恢复或部署。

## 发布协议

- `POST /api/agent/revision/apply` 的请求仍为 `revisionId/config/registry/allowUserDeletion`；鉴权及 `X-Revision-Signature=HMAC-SHA256({config,registry})` 保持原协议。签名采用 sorted keys、compact JSON、UTF-8。此兼容签名没有新增绑定 revisionId；完整回执摘要绑定该字段及本机 nodeId。
- 发布包为 `{version:2,nodeId,revisionId,config,registry}`。`registry` 先归一化，再计算摘要；空对象归一化为 `{version:1,users:{}}`。
- `currentHash` 改为完整包的 SHA-256；纯配置哈希通过 `configHash` 取得。新增 `registryHash`、`bundleHash`。旧消费者若把 `currentHash` 与纯配置哈希相比，必须改用 `configHash`。本仓库没有发现依赖旧比较语义的运行调用方；网站本轮仅调用 reload-existing，不使用此发布接口。
- 同 revision ID 内容不同返回冲突；已被较新版本替代的已知 ID 不允许迟到重放，回退只能调用显式 rollback。同 ID 幂等成功也要重新读取配置与 registry；HTTP 幂等缓存不能跳过此检查。
- `GET /api/agent/revision/state` 返回 `observedBundleHash/filesVerified/recoveryRequired/verificationScope`；实际文件漂移时 `status=drifted`，有未处理日志时为 `recovery-required`。`verificationScope=files-and-reload` 只证明文件一致及发布时 reload 成功，不证明四协议公网入口、住宅出口或进程内部完整配置指纹。
- 用户增删、续期等普通管理修改可能合法改变文件；此时旧发布包的状态应显示漂移。下一次发布前保存该本地状态时使用 `local-<digest>` 的独立回滚身份，避免把不同内容归于旧 revision ID。

## 发布事务与异常恢复

发布、显式回滚、普通 `mutate_config` 和 reload 接口共用配置锁。发布前检查配置、写入持久化 undo journal，随后替换 config/registry、reload、落盘完整快照和元数据，回读成功后写 committed 标志。registry 写失败或必需元数据写失败不会返回 applied。

revision 目录包含 `current.bundle.json`、`last_good.bundle.json`、`transaction.json`；旧 `current.json/last_good.json` 仅作配置快照兼容，不能单独用于回滚。事务日志包含敏感凭据，权限为 0600；禁止贴入工单、集中日志或非受控审计快照。

- 启动在迁移与采集任务之前恢复日志。`prepared` 恢复旧 config、registry、revision state 与全部快照，再 reload 并回读；`committed` 校验完整包及状态后清理日志。
- 恢复失败、日志损坏或首次发布失败且无旧 config 可证实恢复时，保留日志，启动失败，修改和 reload 被拒绝。不会把“文件已移除”称为“运行态已回退”。
- 首先只读核对节点身份、受控备份时间、文件存在性、state 中预期/观察摘要及日志阶段；不导出完整凭据。确认磁盘权限、空间及 sing-box 可用性后，**经维护审批重启 Node Manager** 会重试已有自动恢复。不能删除 journal 来绕过门禁。
- 首次部署无旧配置、日志校验失败或需恢复其他备份时，须离线保全原文件，在隔离副本验证完整 config+registry 组合与预期权益，形成单独的维护恢复计划；本轮没有提供自动清零、强制解锁或历史数据写入接口。

## 流量来源与重置

`upload/download` 始终表示本机采样累积。复制导出的用户新增 `trafficOrigins`（稳定 node ID → upload/download/epoch）及 `trafficEpoch`。导出 `upload/download` 为来源合计，供旧展示参考；接收方必须保留来源字段，不能再把合计写入本机计量。网站现有 JsonNode 透传路径保留这些字段。

本地 traffic store 使用 `replicatedTrafficOrigins` 保存复制基线，`sharedQuotaEvidence` 保存对端观测，`nativeAccountingVersion=2` 标记新语义。相同来源、相同 reset epoch 取较高的已知计数；来源推进到新 epoch 时替代旧 epoch，不把两条证据相加。往返复制遇到本机来源不会再次计入对端。超过 8 个来源拒绝，避免无界扩张。

`/api/users/shared-quota/inspect` 只把本机测量返回为 `nativeTotalBytes`。用户流量响应新增 `quotaUsedBytes/peerObservedBytes/nativeAccountingProven`；`total/upload/download` 保持本机数语义，不代表整组配额。共享配额协调方仍应只交换 native observation，不能把 quotaUsedBytes 作为 native 再发送。

重置必须使用现有明确的本地 reset/续费流程。复制遇到已有计量且 epoch 不同，返回 `TRAFFIC_RESET_RECONCILIATION_REQUIRED`；不会借复制覆盖 native。重置退役旧来源证据，拒绝旧 epoch 再导入。发布新空 epoch 时仍导出零计数标记，避免旧来源基线被保留。

## 历史数据只读定位与迁移计划

- 旧快照非零计量但没有 `trafficOrigins`：拒绝 `TRAFFIC_ORIGIN_REQUIRED`，先升级来源并取得有来源的新快照。
- store 已有 `replicationCycle`、非零计量，但无版本 2 标记：视为混合来源候选。导出/共享配额拒绝 `LEGACY_REPLICATED_TRAFFIC_REVIEW_REQUIRED`；inspect 的 `issues` 标明候选用户，保留原数。采集仍保留本机新增量，但不据混合计数变更配额封禁；既有路由决策保持。
- 旧候选不能简单减去源数、取主备最大值或清零。须只读收集同一匿名用户的源/目标原生观测、历史复制时刻、reset epoch 与采样基线，证明来源后才设计迁移。不能证明时维持待核对，不人工伪造 `nativeAccountingVersion=2`。
- 迁移计划必须保存旧副本，定义逐来源旧值/新值、证据摘要、预期总用量与回退点，在隔离副本验证重复执行不改变结果后再单独审核。本文不包含生产执行脚本。

验证使用临时目录、Mock reload 和禁用应用 TCP 连接的 runner；尚未验证真实 Linux fsync/flock、systemd/sing-box reload 或断电恢复。不能把离线通过当作已部署。
