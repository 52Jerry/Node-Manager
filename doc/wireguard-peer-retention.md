# WG peer 保留与故障恢复（2026-10-22）

生产于北京时间 09:31:13 发布。用户明确要求取消批处理/临时异常触发的内核 peer 删除。

## 行为

- 正常 ACTIVE peer 的相同身份刷新保持 ACTIVE，不再整批先写 APPLYING。
- 路由同步、运行检查、配置快照读取失败时保留已有内核身份，记录恢复原因，调谐线程在每轮结束后等待 15 秒重试。共享运行状态未恢复时，状态接口仍返回 `routingReady=false`，不会把保留 peer 冒充可联网。
- BLOCKED、失败的新开通、进程中断遗留 APPLYING 均保留已经存在的内核 peer；由来源地址防火墙与住宅出口拒绝规则隔离。不会为原本已不在内核的 BLOCKED 记录重新添加 peer。
- 真实住宅 owner/绑定变更只阻断对应 peer。其余正常 peer 保留。明确 revoke 和 peer 到期仍会从内核清理，REVOKED 墓碑防止复活。
- 批次失败回滚已有 ACTIVE 记录的原参数；新开通记 FAILED。清理时重新读取当前住宅绑定，不能用批次开始前的旧快照放行。
- 内容相同的路由刷新不重启专用代理。真正增加/删除可用出口仍沿用已有路由更新流程，不能据此保证所有配置变更都无连接中断。

## 状态接口

`GET /api/wireguard/status` 新增非敏感诊断字段：

| 字段 | 意义 |
| --- | --- |
| `peers[].stateReason` | 单条 BLOCKED/FAILED/EXPIRED/REVOKED 的具体原因 |
| `recoveryReason` | 共享同步故障，下一次成功调谐后清除 |
| `runtimeReason` | 防火墙命令退出码、策略路由/入口跳转缺失或代理不可用 |
| `peers[].kernelPresent` | 公钥存在且实际 AllowedIPs 精确等于登记的单个 /32；不再只检查公钥存在 |

示例原因包括 `NODE_USER_MISSING`、`NODE_USER_EXPIRED`、`PEER_EXCEEDS_ENTITLEMENT`、`NODE_USER_ACCESS_DISABLED`、`NODE_USER_TRAFFIC_BLOCKED`、`RESIDENTIAL_BINDING_CHANGED`、`KERNEL_INSTALL_FAILED`、`BINDING_SNAPSHOT_UNAVAILABLE`。日志记录阶段、原因码和异常类型，不输出私钥、住宅口令或命令标准错误中的敏感材料。

生产剩余 11 条均为 `NODE_USER_MISSING`：旧 nodeUserId 引用未迁移，住宅出口已有新的 owner。需要通过正式迁移流程修复所有权；保留内核并不能补出住宅路由。原本被旧版本删除的这 11 条没有在本次发布中重新安装。

## 验证与回滚

- 91 项 Python 测试通过，包括 4000 peer 批次、锁等待、正常刷新、失败回滚、局部绑定变更、读取故障、到期和撤销。
- Linux 私有网络/挂载命名空间及私有 xtables 锁中验证真实 wg 内核和 iptables；代理服务管理被替代，未操作生产接口或代理服务。
- 生产发布前后全部内核身份一致，代理 PID 550373 保持不变，3224 ACTIVE 全部内核地址匹配。
- 09:33:25—09:34:47 五轮观察中状态、内核身份摘要、代理 PID 均稳定，恢复失败日志为零。
- 管理员空闲订阅 3994 / 资源 3998 抽验：WG 域名、深圳 IP、香港 IP 均完成新握手、HTTPS、UDP DNS；出口 198.65.2.61 与购买资源一致。不是 3224 条全量网络验收，也没有做大包/MTU 验收。

源文件 SHA256：

- `wireguard.py`: `3ec2fbdc237725f91cd0686ee3df74fe945190ea762d04bc5bc0012abd59da3e`
- `wireguard_routes.py`: `ab465715d745cfc3f14b5d750a83345d6b121b216bafb4a8a9ddd083f839236a`

备份 `/opt/node-manager-releases/wg-retain-20261022-backup/` 中保存原两份源文件及发布前状态、发布回执。需要回滚时先核对当前源码仍为本次 SHA，取得 `/run/lock/niusu-node-manager-deploy.lock`，恢复两份文件并重启 `node-manager.service`。不回滚 peer 注册表，不重建 wg0。旧版本会重新引入运行故障批量删除 peer 的行为。

本地证据：`outputs/wg-retain-20261022/`；脚本：`.codex_tmp/wg-retain-20261022/`。
