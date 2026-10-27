# Node Manager 接入 sing-box 单进程用户更新

该模式让现有创建、删除、凭据轮换、用户路由、额度拒绝规则、复制和 revision 发布流程，使用同一运行中 sing-box 的私有接口。无需控制面更换原有用户接口。VLESS、AEAD VMess、需要认证的 SOCKS 共用这一发布流程。

这是显式启用功能。未配置 `runtime_socket` 的节点继续使用原发布方式。这里提供接入步骤，不表示已替换生产二进制或完成生产迁移。

## 启用条件

使用仓库 `runtime/sing-box/` 中配套的 `1.13.18-niusu-runtime-20261028-r3` 核心源码构建二进制；上游原版及仅提供 PUT 的早期定制版不具备此次所需的 preview/fence 接口。Agent 启动时校验磁盘配置与运行时指纹，版本不兼容、socket 不可用或配置漂移均会拒绝启动，不回退到 systemctl reload/restart。

先在 sing-box 配置里设置受管 SOCKS 入站的 `"require_auth": true`，即使用户表为空也保持此值。旧配置中没有这一选项时，需要在迁移窗口安装新核心、更新配置并启动一次。运行时模式不会把历史匿名连接变成已认证连接。

sing-box 启动命令示例（按节点现有服务参数调整）：

```sh
/usr/local/bin/sing-box run -c /etc/sing-box/config.json \
  --management-socket /run/sing-box/users.sock
```

socket 父目录须预先存在。systemd 可设置 `RuntimeDirectory=sing-box`、`RuntimeDirectoryMode=0700`。socket 权限为 0600，Node Manager 需使用有权访问它的同一 UID；不要把它暴露为公网 HTTP 接口。核心拒绝覆盖已有 socket 路径；异常退出留下的路径只能在确认没有存活进程后处理。

Node Manager 配置示例：

```yaml
singbox:
  config: /etc/sing-box/config.json
  binary: /usr/local/bin/sing-box
  runtime_socket: /run/sing-box/users.sock
  api_port: 9090
  api_secret: YOUR_LOCAL_CLASH_SECRET
```

也可用 `NODE_MANAGER_SINGBOX_RUNTIME_SOCKET` 覆盖 socket 配置，必须是绝对路径。`binary` 用于配置检查和版本读取，应指向正在运行的配套核心。

启动 Node Manager 前，清除旧的 `NODE_MANAGER_VLESS_PUBLICATION_SPEC`。两种发布方式不能同时启用。旧槽位进程、定时任务及 NAT 规则需要另行在迁移窗口核对、排空和移除；此次代码不会自动接管或停止它们。不要在旧进程仍承载流量时直接切换统计来源。

Clash API 仍用于在线连接、来源 IP、连接限制和关闭指定连接；原生用户计数器负责计费字节。Clash API 应保留在回环地址并配置鉴权。

## 发布与恢复

1. Agent 在统一配置锁内，请核心按其实际 schema 规范化旧配置和目标配置，核对运行时基线并判断变更是否支持。
2. 持久化事务日志，然后写入并回读配置、用户注册表及本次关联的 revision/流量文件。
3. 以 `instanceId + revision` 发起 CAS 用户更新，核对回执与实际运行指纹后提交。
4. 请求超时只核对状态，不盲目重试。若目标已经生效，则完成文件提交；若仍是基线，先通过 CAS fence 使迟到的旧请求失效，再恢复原文件。无法证明结果时保留事务，拒绝后续写入。

状态文件默认位于注册表同目录下 `runtime/`，可用 `NODE_MANAGER_RUNTIME_STATE_DIR` 调整。`transaction.json` 为恢复日志，`current.json` 保存最后确认配置、运行时回执及历史认证名归属。文件包含凭据，权限 0600，禁止上传到普通日志或工单。不能通过删日志或禁用 runtime 模式绕过未决事务。

接口继续使用 Node Manager 原 Bearer Token：

| 方法与路径 | 行为 |
| --- | --- |
| `GET /api/singbox/runtime/status` | 当前进程标识、版本、配置指纹、是否存在未决事务 |
| `POST /api/singbox/runtime/reconcile` | 在配置锁内恢复事务并核对磁盘/运行时一致性 |
| `POST /api/singbox/reload` | 此模式下仅发布支持的用户变更，失败不重启 |

Agent 启动也会恢复未决事务。发生第三方配置漂移时，恢复接口不会覆盖它；需核对运行配置与保留事务后处理。revision 的应用、重放和显式回滚同样走这一事务，成功回执标记 `verificationScope: files-and-runtime`，证明文件和运行指纹一致，不代表远端住宅出口可达。

## 支持范围

用户增删、凭据变化，以及可按用户隔离的简单路由规则和独立 direct/SOCKS 出站，可以原位更新。变更只关闭受影响身份的现有会话，其他用户保留原连接。删除最后一个 SOCKS 用户后依然拒绝匿名认证。

监听端口、TLS、DNS、默认/共享出站、selector/urltest、依赖型出站及其他协议的变更不在此模式范围内，提交前拒绝，磁盘保持原样。Trojan/WireGuard 不能据此宣称已实现同样的单进程热更新。需要拓扑变更时应另行安排明确的维护窗口。

Agent 保存的历史认证名持续保留归属，不能重新分配给另一个 userId；同一用户可轮换认证名。这避免把已删除用户的累计字节计入另一个用户。

## 流量口径

累计字节按进程 `instanceId`、入站标签和认证名记基线，合并 VLESS/VMess/SOCKS，包含已经关闭或删除用户的连接尾量。重复采集不重复计费，也不叠加 Clash 连接采样字节。计费归属使用认证身份，不依赖出站标签命名。

从旧采样账本首次切换时，保留已有用量，以首次原生快照作为新基线，避免把历史字节再记一遍。它不能补全旧模式漏掉的流量，也不能把旧的混合归属账本自动认证为准确账本。进程重启后开启新计数周期，异常退出可能损失上次采集后的尾量；状态保留 `epochGapPossible`。清零用户用量保留计数基线，防止下次采集把已清零历史重新加回。

Clash API 不可用时仍保存原生累计字节，但在线/限额执行健康状态降级，并保留原有执行策略。已有原生基线后直接关闭 runtime 模式不会自动降级成采样计费，需要明确的账本迁移。

## 验证

本地验证包括事务故障注入、revision 应用/重放/回滚、复制关联文件恢复、累计计数去重，以及真实 Node Manager API 到定制核心的 SOCKS/VMess 数据流联调。Windows Python 本机缺少 AF_UNIX，联调仅通过 Go 小工具适配 HTTP 传输，使用真实 Unix socket、CAS、配置指纹和实际协议连接；生产 Linux 客户端使用 Python 原生 Unix socket。Linux 二进制已交叉编译，仍需在 Linux 预发布环境验收服务权限、systemd 和实际线路。


## r3 后续实现（2026-10-28，未上线）

[r3 写入队列、任务查询和原生路由接口](runtime-write-queue.md) 已在本地实现。旧用户接口保留，内部排队；新增异步任务接口，支持用户及路由变更。上线需配套 r3 定制二进制，不能将此记录理解为已迁移生产旧代。
