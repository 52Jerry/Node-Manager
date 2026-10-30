# 原生用户与路由写入队列（r3）

本功能配套定制核心 `1.13.18-niusu-runtime-20261028-r3`，不是上游官方发行版自带的管理 API。需要同时更新核心和 Node Manager；旧的 VLESS 多代发布模式不启用本队列，不自动迁移生产旧代或 WireGuard。

## 已接通的链路

`HTTP 用户变更 → 幂等身份 → 每节点有界队列 → 单执行器 → 同批工作副本 → 预检 → 配置/注册表/任务回执持久事务 → 原生 CAS 用户及路由发布 → 实际指纹核对 → 任务成功`。

普通旧接口仍返回原有成功结构，内部通过 `manager.mutate_config` 排队。同步等待超过 60 秒时返回 HTTP 503、`RUNTIME_TASK_PENDING`、`taskId` 和 `Location`，操作继续执行。应查询任务，重试沿用原 `Idempotency-Key`；不要因超时改用新键重发。一个旧请求中的多次配置变更使用不同序号，避免批量删除等操作错误复用第一笔结果。

复制等携带关联文件的变更独立成批；已经持有配置锁的 revision/维护事务保留原有锁和原子边界，不与普通批次合并。所有这些路径仍使用节点统一配置锁，禁止同时发布两份配置；不把 WireGuard 的独立内核操作混入 sing-box 用户批次。

默认边界：

| 项目 | 值 |
| --- | --- |
| 未完成操作上限（含正在执行） | 4096 |
| 未完成请求预算 | 16 MiB；旧 HTTP 请求按实际请求体计入 |
| 每个任务的操作数 | 1–128 |
| 每批最多合并操作数 | 128 |
| 合并等待窗口 | 25 毫秒 |
| 合并请求预算 | 1 MiB；较大的独立复合事务不合并 |
| Agent 受保护写请求同时处理数 | 32；大复制请求最多 1 个 |
| Agent 请求体上限 | 普通用户 64 KiB、任务 1 MiB、复制 8 MiB |
| 核心全配置/预检/路由请求解析并发 | 1，解析前拒绝其余请求 |
| 核心全配置请求体上限 | 8 MiB |

4096 是队列成本单位：普通单用户变更和新任务按每个操作计数；旧复制等复合事务按独立请求计数，同时受请求字节预算及其原有用户数量上限限制，不能将队列统计直接当成复合请求中的 IP 总数。

超限返回 429 和 `Retry-After`，不默默丢弃。队列使用进程生命周期文件锁，一个节点的该服务只运行一个 API worker；第二个写入执行器不能抢占同一节点。不要依靠增加 Uvicorn worker 数来提高配置写吞吐。

## 顺序和恢复

- 不同用户可合并为一次发布。同一用户的后续变更跨批提交，避免“删除→同凭据重建”“停用→启用”被折叠后漏掉撤销旧连接。
- 一个任务内同一用户只能出现一次。后续动作另交任务；依赖前一笔成功的业务应先确认前一任务结果。
- 可用 `expectedUserVersion` 核对用户变更计数。它由任务接口和可识别的单用户旧接口维护，并在删除后保留。复合维护/归属迁移仍遵守其原业务契约，不能把这个可选计数当成全平台业务所有权版本。
- 不合法任务的中途内存修改不会落盘，其他合法任务按原顺序重新组批处理。
- SQLite 保存请求指纹和任务状态，结果使用节点令牌派生密钥加密。每批成功证明文件与配置、注册表一起写入已有 WAL 事务；不只凭 HTTP 200 判定成功。
- 发布结果不确定时任务标记 `UNKNOWN`，暂停新写入和后续执行。先调用原有 `POST /api/singbox/runtime/reconcile`，证明已应用或未应用，再恢复队列。禁止删除事务日志来强制恢复。
- 进程重启时先恢复原生 WAL，再根据事务回执恢复已执行任务。未开始的任务标记 `CANCELLED`，已证明没应用的标记 `NOT_APPLIED`，不会盲目重放。调用方核实状态后可用新键重新提交；成功任务继续通过原键和任务号查询。
- 任务历史达到 50000 条会停止新受理，需归档已完成历史并维护幂等保留期。不会后台自动删除未知结果或业务审计证据。

状态文件位于 `NODE_MANAGER_RUNTIME_STATE_DIR/write-queue/`：`tasks.sqlite3`、`writer.lock`、`receipts/`。目录和文件按私有权限创建。状态接口不返回连接凭据；只有单独的成功结果接口返回原操作结果，应按连接信息接口同样保护。更换节点令牌前需安排历史加密结果的迁移。

## 异步任务接口

以下接口均沿用 Node Manager Bearer Token，新任务必须提供 `Idempotency-Key`。这是节点运维接口，网站订单/退款/用户归属授权仍由控制面先核对。

| 方法与路径 | 功能 |
| --- | --- |
| `POST /api/singbox/tasks` | 受理任务，返回 202、任务号及状态地址 |
| `GET /api/singbox/tasks` | 队列数量、操作/字节预算及暂停状态 |
| `GET /api/singbox/tasks/{taskId}` | 查询状态，不含凭据 |
| `GET /api/singbox/tasks/{taskId}/result` | 仅成功任务可读取结果，响应禁止缓存 |
| `GET /api/singbox/tasks/user-version/{userId}` | 查询该用户任务版本计数 |

请求示例：

```json
{
  "commands": [
    {
      "action": "create",
      "expectedUserVersion": 0,
      "user": {
        "userId": "example-user",
        "protocols": ["vless", "vmess", "socks"],
        "socksUsername": "example-user",
        "socksPassword": "example-only",
        "expiresAt": "2030-01-01T00:00:00Z"
      }
    }
  ]
}
```

操作类型：

| action | 参数 | 行为 |
| --- | --- | --- |
| `create` | `user`，与旧创建请求一致 | 创建用户、认证、出口与路由 |
| `route` | `binding`，与旧 bind-proxy 请求一致 | 新增或替换该用户 SOCKS 出口和路由；支持随绑定轮换凭据 |
| `direct` | `userId` | 移除住宅 SOCKS 绑定，改为独立 direct 路由 |
| `credentials` | `userId`、可选 `uuid`、成对 SOCKS 用户名/密码 | 轮换认证并同步路由认证名 |
| `access` | `userId`、`enabled` | 开启或拒绝该用户的访问 |
| `delete` | `userId` | 删除认证、独立出口和路由，保留审计/用量历史 |

`expectedUserVersion` 可加在每个操作上。`SUCCEEDED` 表示配置、注册表和运行指纹一致，不表示住宅上游可达；仍需原有连接检测。`QUEUED`、`RUNNING`、`UNKNOWN`、`FAILED`、`CANCELLED`、`NOT_APPLIED` 均不能当作开通成功。历史过期超过 24 小时的删除仍要求数据库归档和 SOCKS 探测流程，不通过新接口绕过。

## 定制核心的原生路由接口

只监听权限 0600 的 Unix socket，没有新增公网管理端口。

| 方法与路径 | 行为 |
| --- | --- |
| `PUT /management/v1/configuration` | 用户、独立出口、认证路由一起原子更新，Node Manager 正式发布使用此接口 |
| `PUT /management/v1/users` | 保留的兼容入口，能力与 configuration 相同，不是仅追加用户 |
| `PUT /management/v1/routes` | 保留用户认证表，只原子替换 `rules` 与 `outbounds` 快照 |
| `GET /management/v1/status` | 查询进程、版本与已提交配置指纹，使用轻量快照 |
| `POST /management/v1/preview` | 用当前二进制 schema 预检支持范围 |
| `POST /management/v1/fence` | 超时结果核对时阻止迟到旧版本写入 |

路由接口请求为 `expectedInstanceId`、`expectedRevision`、完整 `rules` 数组和完整 `outbounds` 数组。可以新增、更换或删除用户的简单路由/独立出站；保留非用户配置，缺失默认/共享出站会被拒绝。旧版本冲突返回 409，不直接覆盖新状态。

Agent 不直接绕过 WAL 调用 routes 接口，而是将用户和路由通过 configuration 一起提交，避免磁盘/注册表与核心漂移。直接调用核心路由接口的工具必须承担同样的文件事务责任。

支持普通认证匹配、route/reject 和独立 direct/SOCKS 出站；不支持动态修改监听/TLS/DNS、默认共享出口、selector/urltest、依赖型出站或复杂 rule-set 拓扑。这些变更会明确拒绝，不回退为重启共享代理。

## 验证边界

队列与事务测试覆盖合并、同用户顺序、坏请求隔离、容量、超时幂等、多次旧变更、任务回执重启恢复、未知结果暂停、关联文件和版本墓碑。核心测试覆盖原生路由变更、撤销受影响连接并保留其他用户、CAS、解析前限流和状态查询；Go race 已通过。

Windows 真实进程容量验收记录位于网站仓库的 `docs/SINGBOX_RUNTIME_QUEUE_A2_20261028.md`，不能直接当成 Linux 生产吞吐保证。

2026-10-28 已在用户指定服务器执行 [Linux 隔离验收](../../niusuip-project/docs/LINUX_RUNTIME_ACCEPTANCE_20261028.md)：原生 Unix socket、三协议真实数据流、3000 独立任务落盘、目标连接撤销、32 并发原生写入限流及目标事务前后崩溃恢复均有记录。实测修复了合并创建预检误用工作副本的问题，保留完整事务基线检查；最终相关 Python 回归 243 项通过。

报告保留后台维护排队超时，以及未使用 Expect: 100-continue 的大请求被提前拒绝时可能遇到 Broken pipe 的问题。上线前仍需按生产硬件优化并复测延迟，核对真实入口与旧代 NAT/计量迁移；本次没有替换生产核心。

2026-10-28 下午补充了生产深港专线的持续变更测试，见 [真实专线与持续变更报告](../../niusuip-project/docs/SZHK_LIVE_CAPACITY_WITH_MUTATIONS_A2_20261028.md)。SOCKS 1000/3000/5000 小流量连接通过，约 8000 时因尾延迟保护停止；期间通过正式队列循环创建、A/B 路由切换和删除测试身份。这不是几千个并发写入吞吐结论。

该轮还复现 direct 任务沿用已有 SOCKS 出站的问题。修复由显式 direct 命令传入 `replace_existing=True`，替换本用户出站/路由并清理旧住宅出口元数据；后台补齐缺失路由的默认调用继续保留已有代理。22 项队列回归与本机真实核心 B→直连 C 验证通过，其他 8 条连接 176 次校验无失败；生产容量测试只验收了 A→B→A。

2026-10-30 已将上述 direct 修复发布至当前生产节点的管理服务，完整 Python 回归为 999 项通过，另有 127 项子测试通过。发布只更新管理代码并重启 Node Manager，sing-box 核心 PID 前后相同；保留运行配置、现有连接与 WG 暂停设置。配置模板新增的 `runtime_socket` 仍默认为空，不覆盖服务器实际配置。没有使用真实客户执行直连切换来充当发布测试，也不将隔离环境吞吐结果作为生产容量保证。

测试配置在仓库根目录 `conftest.py` 中提前载入合成身份，避免嵌入测试中的离线导入先初始化随机令牌，导致全量回归依赖导入顺序。运行时 Python 兼容检查继续覆盖实际代码，不将嵌入测试文件作为部署模块。
