# 来源 IP 限制与专线接入

## 限制语义

共享 VLESS / VMess / SOCKS 凭据按节点用户归属汇总，`maxSourceIps: 5` 表示最多五个活跃来源 IP，不表示五台物理设备。相同家庭 NAT 后的多台设备只算一个来源；IPv4 与对应 IPv4-mapped IPv6 合并。不同 IPv4 / IPv6 地址仍算不同来源。

采样默认每 2 秒一次，并非握手阶段零延迟拒绝。已准入来源保持名额，新来源超限后关闭连接，并按用户认证身份及来源写入 sing-box 拒绝规则。来源离线后默认保留名额 60 秒，随后释放名额和相应旧拒绝规则。不要用连接数上限代替设备限制，浏览器会正常产生许多连接。

## 为什么现有专线只看到一个来源

入口做 DNAT 后再做 SNAT/MASQUERADE，或由普通 TCP 代理重新建立连接，出口只会看到入口地址。无法从源端口、会话 ID 或共享 UUID 还原原始设备/用户来源。Node Manager 不信任 `realIP`、转发头或客户端自报设备 ID。

当前 sing-box 上游的 `proxy_protocol` 与 `proxy_protocol_accept_no_header` 已标为移除，不能直接照搬 Xray / 3x-ui 的 PROXY protocol 配置，也不能在普通 Reality 监听前盲目加 PROXY 头。

参考：[sing-box Listen Fields](https://sing-box.sagernet.org/configuration/shared/listen/)、[上游 ListenOptions](https://github.com/SagerNet/sing-box/blob/testing/option/inbound.go)、[3x-ui 来源说明](https://github.com/MHSanaei/3x-ui/blob/main/docs/real-client-ip.md)。具体内核版本在部署前仍须核验。

## 推荐接入方式：保留源地址的专线转发

本次仅准备代码与方案，不执行防火墙、路由、服务重启或部署。不能单独删除生产 SNAT，否则回包路径错误会使连接中断。改动前保存两端网络配置，保留独立 SSH 管理通道，并准备回滚。

两端需要满足以下合同：

1. 深圳入口仅对代理入口端口进行 DNAT 到香港内网地址，保留客户端源 IP。不使用会重建连接且丢失源地址的普通 TCP 代理。
2. 对这一条入口转发流量绕过所有现有 SNAT/MASQUERADE；其他住宅出口、管理及本机公网流量的 NAT 不变。先审计现有 nftables / iptables，不能整体清空规则。
3. 香港 sing-box 代理监听连接的回包必须经专线回到原深圳入口，让入口 conntrack 完成反向 DNAT。香港默认公网路由不满足此要求。可使用专用网络命名空间，或精准匹配监听地址/端口的 OUTPUT 标记与策略路由。
4. 策略路由只覆盖入站代理连接的回复，不能把 sing-box 到住宅 SOCKS 上游的新建连接、Node Manager 或 SSH 一并改走专线。需覆盖 IPv4；支持 IPv6 用户时也需独立校验 IPv6 转发与回程。
5. 两端启用所需转发，审计 FORWARD 规则与 `rp_filter`，避免严格反向路径检查丢弃从专线收到的公网源地址；仅在相关接口调整，不全局关闭安全检查。
6. 专线及出口防火墙仅允许受控入口路径，防止旁路绕开限制。Node Manager/Clash API 不开放给用户公网。

以下是 DNAT 规则表达示意，不是可直接执行的生产脚本；接口、地址、端口及已有 NAT 优先级必须由实际拓扑确定：

```text
入口匹配：iifname <公网接口> ip daddr <入口公网IP> tcp dport { <VLESS端口>, <VMess端口>, <SOCKS端口> }
DNAT目标：<香港专线内网IP>（保留对应目标端口）
SNAT豁免：匹配同一入口到该目标的代理转发连接，在所有可能的 SNAT/MASQUERADE 规则前豁免
香港回复：源地址为监听内网IP、源端口为代理端口的本机回复，经策略路由表到 <深圳专线网关>
住宅上游：香港 -> 住宅 SOCKS 上游保持原公网出站路径
```

应用策略路由时还要保留专线直连网段路由，并检查路由表编号、mark 与已有规则是否冲突。多入口同时活跃时，单一回程网关不够，必须按每个入站路径分别标记/路由，不能直接套用单主线路示例。

## 主备边界

目前限额在每个 Node Manager 本地执行。主备同步用户凭据和策略，但不共享实时来源名额。采用一个活跃入口、备用待切换，主备都配置相同来源保留路径并阻止旧入口旁路。切换后名额按备用节点采样重新建立。

不能让多个独立出口同时接受同一凭据，然后声称全组总共五个来源；该模式还需要中心租约/配额协调，不在本次实现中。DNS 切换不会立即迁移已有 TCP 会话，须在故障切换时处理旧链路残留连接。

## 配置与诊断

```yaml
monitoring:
  traffic_sample_interval_seconds: 2
  device_active_window_seconds: 60
  relay_source_cidrs: "172.16.208.118/32"
```

已知公网中转地址也加入 `relay_source_cidrs`。CIDR 格式错误在配置加载时拒绝。该配置不是 IP 白名单，不会添加 PROXY 支持或修改防火墙。

`sourceIpVisibility`：`observed` 已观察到来源（不保证没有 NAT），`relay_detected` 存在私网/共享/已知中转来源，`missing` 部分来源缺失，`idle` 没有在线连接，`unavailable` 无遥测或执行失败。诊断不会直接停用用户，防止误伤。缺少来源的连接不能按来源限额拦截，需要修复遥测；流量与连接数限额仍独立执行。

## 验收

1. 从两个不同公网网络使用同一测试用户，确认出口抓包和后台来源汇总显示两个客户端公网来源，不再统一显示入口内网地址。
2. 设置来源上限 5，五个不同来源保持连接；每个来源开多个 VLESS / VMess / SOCKS 会话仍只占一个名额。
3. 第六个来源连接应在采样后被关闭，出现在 `blockedSourceIps`，重连仍被拒绝；前五个保持可用。
4. 让一个已准入来源完全离线，等待活跃窗口及下一次采样，第六个来源重连获得名额。
5. 检查住宅出口 IP、上下行、长连接、IPv6（如启用）、SSH 和控制面仍正常。关闭节点 API 模拟采集故障时，后台显示不可用而不是误报零设备。
6. 演练备用线路切换及回滚，在备用路径重复上述来源与限额验收。应用代码测试不能替代真实专线回程验收。
