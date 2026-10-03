# ECS993 Node Manager 部署记录

## 部署范围

- 日期：2026-10-03；最终管理进程于北京时间 19:47:39 完成启动。
- 服务器：ECS993，168.93.208.118，节点 ID `ECS993-3d78e9a785e0`。
- 运行代码提交：`4872d82cf0b294e163892f20114a56acaaae8b1f`。
- 发布目录：`/opt/node-manager-releases/4872d82-20261003/node-manager`。
- 使用原有 Python 环境：`/opt/node-manager/venv311`，Python 3.11.14。
- 仅更新 Node Manager；未部署网站、未推送 Git、未启动本地服务。

## 更新方式

发布包来自已提交代码，校验本地与服务器 SHA256 一致后解包到独立目录。保留原应用目录，通过 systemd drop-in 切换工作目录，重启管理进程，不执行 sing-box 重启或配置重载。最终切换期间管理接口短暂不可用约 3 秒。

保留 `90-recovery-expiration.conf` 中的 `NODE_MANAGER_EXPIRATION_ENABLED=false`。不得因本次部署重新启用到期处理或推断历史用户到期时间。现有账号未新增 `maxConnections` 限制，原有流量、来源 IP 策略不变。

## 验证结果

- 最新版本测试：276 项通过。
- 发布预检查：应用可导入，启动迁移不会修改线上配置，现有凭证不替换。
- 健康检查、节点身份、鉴权检查通过；未鉴权管理请求被拒绝。
- sing-box PID 始终为 `723880`，启动时间始终为 `2026-10-03 09:22:09 UTC`。
- 原有 3954 名用户全部保留；部署期间正常创建接口新增 2 名用户，最终为 3956 名，归档用户为 0。
- 对比首次切换备份：原有注册信息、入站凭证、出站和路由均保留。
- 对比最终切换前备份：配置和用户注册文件完全相同；流量累计值未回退。
- 最后一轮快照有 9466 条在线连接，其中 2698 条在最终切换前已存在。连接数是动态快照，不是设备数，也不是保活 SLA。
- Node Manager 最终 PID 为 `748653`，服务 active/running，自动重启次数为 0。
- 共享 VLESS 未提供可靠物理设备 ID，仍不能将在线连接数宣称为真实设备数；新连接限制默认不启用。

复查期间曾发生单用户流量查询超时，随后重试正常；同期控制端批量分页和复制快照读取与流量采集共用锁。此次未修改这部分既有性能逻辑。日志还存在既有的 WebSocket 可选依赖警告，未安装新依赖。

## 备份

服务器目录：`/root/node-manager-backups/ecs993-20261003-b85bae0`。

| 文件 | 内容 | SHA256 |
| --- | --- | --- |
| `pre-update-full.tar.gz` | 更新前应用、Python 环境、配置、用户与流量数据、systemd 配置 | `c2941b4f0d9d377f9864ae3fc811e64be5c9df4cf3f7891441b6545df4c58dc9` |
| `pre-switch-state.tar.gz` | 首次切换前管理进程停止后的运行状态备份 | `7839e66940d343d613f31efb8a5d93c265f009b31d4a70b2482ac4d0eaf84a5a` |
| `pre-4872d82-state.tar.gz` | 最终版本切换前运行状态与 systemd drop-in 备份 | `ca463d6981f847da6749a67ae32a1247cdf6ea2c2f174a3a3bad7514fc732383` |

三份备份均在服务器通过校验，也已下载到本地 `E:\Learn\Vibe Coding\NiuSu\niusuip-project\.codex_tmp`，文件名前缀为 `ECS993-20261003-`。该目录还保存 `SHA256SUMS` 和最终 `verification.json` 的本地副本。备份含敏感账号信息，不纳入 Git，不上传公共存储。

## 回滚

在 ECS993 上执行：

```bash
bash /root/node-manager-backups/ecs993-20261003-b85bae0/rollback-manager.sh
```

脚本移走本次发布的两个工作目录 drop-in，恢复原 `/opt/node-manager` 管理代码并仅重启 Node Manager。保留到期处理暂停设置，不替换当前用户、流量文件或 sing-box 配置，避免覆盖部署后新增订单和累计流量。数据恢复不是常规代码回滚步骤，应单独核对差异后处理。
