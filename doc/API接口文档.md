# Python Node Manager API 接口文档

当前版本：`1.2.0`

部署节点：`http://198.13.46.231:8088`

在线文档：

- Swagger UI：`http://198.13.46.231:8088/docs`
- OpenAPI JSON：`http://198.13.46.231:8088/openapi.json`

> 本文以 `1.2.0` 已上线接口为准。节点列表当前返回本机节点；多节点注册和心跳将在下一阶段开发。

## 1. 快速接入

### 1.1 API Token

当前生产环境 Bearer Token：

```text
<NODE_TOKEN>
```

除 `/`、`/health`、`/docs` 和 `/openapi.json` 外，业务接口均需携带：

```http
Authorization: Bearer <NODE_TOKEN>
Content-Type: application/json
```

Token 同时保存在服务器的 `/etc/node-manager/config.yaml` 和仅 root 可读的
`/root/node-manager-info.txt` 中。本文包含生产 Token，应按敏感文档管理；Token 轮换后必须同步更新本文和调用方配置。

### 1.2 通用错误

| HTTP 状态码 | 含义 |
| --- | --- |
| `401` | Token 缺失或错误 |
| `404` | 用户或节点不存在 |
| `409` | 用户已存在、sing-box 配置校验失败或服务重载失败 |
| `422` | 请求字段格式不合法 |
| `500` | 未处理的服务器错误 |

FastAPI 错误响应示例：

```json
{
  "detail": "user already exists: user-10001"
}
```

## 2. 当前已上线接口

### 2.1 健康检查

#### `GET /health`

无需认证，用于 systemd、负载均衡器和部署脚本检查 Node Manager 进程。

```json
{
  "status": "ok"
}
```

### 2.2 查询当前节点状态

#### `GET /api/node/status`

```bash
curl http://198.13.46.231:8088/api/node/status \
  -H "Authorization: Bearer <NODE_TOKEN>"
```

响应：

```json
{
  "node": "vultr",
  "name": "sing-box-node",
  "host": "198.13.46.231",
  "singbox": "running",
  "cpu": 3.2,
  "memory": 12.6,
  "connections": 41,
  "api_available": true
}
```

### 2.3 创建用户

#### `POST /api/user/create`

调用方可以指定 SOCKS5 用户名和密码，也可以留空由 Node Manager 自动生成。用户共享固定的 VLESS、VMess 和 SOCKS5 入站端口，不会为每个用户额外开放公网端口。

不绑定住宅出口时的请求：

```json
{
  "userId": "user-10001",
  "protocols": ["vless", "vmess", "socks"],
  "socksUsername": "residential-user",
  "socksPassword": "residential-password"
}
```

创建用户并自动绑定住宅 SOCKS5 出口：

```json
{
  "userId": "user-10001",
  "protocols": ["vless", "vmess", "socks"],
  "proxy": {
    "type": "socks5",
    "server": "203.0.113.20",
    "port": 1080,
    "username": "residential-user",
    "password": "residential-password"
  }
}
```

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `userId` | string | 是 | 1 到 64 位，仅允许字母、数字、`.`、`_`、`-` |
| `protocols` | string[] | 否 | 可选值为 `vless`、`vmess`、`socks`；默认全部创建且不允许重复 |
| `socksUsername` | string | 否 | SOCKS5 入站账号；优先使用该值，其次复用 `proxy.username`，最后生成 `node-manager:{userId}`；仅在包含 `socks` 协议时允许传入 |
| `socksPassword` | string | 否 | SOCKS5 入站密码；优先使用该值，其次复用 `proxy.password`，最后生成高强度随机密码；不能脱离 `socks` 协议单独传入 |
| `proxy` | object | 否 | 创建时需要自动绑定的住宅 SOCKS5 出口；不传则只创建用户，以后可调用绑定接口 |
| `proxy.server` | string | 是 | 住宅 SOCKS5 的 IP 或域名；仅在传入 `proxy` 时必填 |
| `proxy.port` | integer | 是 | 住宅 SOCKS5 端口，范围 1 到 65535 |
| `proxy.username` | string | 否 | 住宅 SOCKS5 用户名 |
| `proxy.password` | string | 否 | 住宅 SOCKS5 密码 |

使用规则：

1. 普通用户建议不传 SOCKS5 账号密码，由 Node Manager 自动生成。
2. 创建时传入完整 `proxy`，用户认证、住宅出站和路由会在同一个配置事务中生效；任一步失败都不会留下半成品用户。
3. 创建时不传 `proxy`，用户不会绑定住宅出口，以后仍可调用 `POST /api/user/bind-proxy` 完成绑定。
4. 包含 `socks` 协议时，每个凭据字段都按“显式本节点值、住宅出口值、自动生成值”的顺序独立选择。
5. 若住宅出口没有认证信息，本节点 SOCKS5 用户名和密码仍按默认规则自动生成。
6. SOCKS5 用户名在整个节点的认证标识中必须唯一，冲突时返回 `409`。

调用示例：

```bash
curl -X POST http://198.13.46.231:8088/api/user/create \
  -H "Authorization: Bearer <NODE_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"userId":"user-10001","protocols":["vless","vmess","socks"],"proxy":{"type":"socks5","server":"203.0.113.20","port":1080,"username":"residential-user","password":"residential-password"}}'
```

响应：

```json
{
  "success": true,
  "userId": "user-10001",
  "uuid": "19cbb87d-a20f-40f2-89a8-d92332c46999",
  "protocols": ["vless", "vmess", "socks"],
  "vless": "vless://...",
  "vmess": "vmess://...",
  "proxyBound": true,
  "socks": {
    "host": "198.13.46.231",
    "port": 5001,
    "username": "residential-user",
    "password": "residential-password"
  }
}
```

配置修改采用文件锁、临时文件校验和失败回滚。接口成功返回前，新配置已经通过 `sing-box check` 并完成服务重载。

用户与自定义 SOCKS5 账号的关联保存在 `/var/lib/node-manager/users.json`。文件权限为 `600`，升级部署会保留该文件。

### 2.4 用户列表

#### `GET /api/users?page=1&pageSize=20&keyword=user`

支持按用户 ID 或 SOCKS5 用户名搜索。`pageSize` 范围为 1 到 100，列表不会返回明文密码。

```bash
curl 'http://198.13.46.231:8088/api/users?page=1&pageSize=20' \
  -H "Authorization: Bearer <NODE_TOKEN>"
```

```json
{
  "items": [
    {
      "userId": "user-10001",
      "protocols": ["vless", "vmess", "socks"],
      "socksUsername": "residential-user",
      "proxyBound": true,
      "proxyServer": "203.0.113.20:1080",
      "upload": 1024,
      "download": 2048,
      "total": 3072,
      "status": "active",
      "createdAt": "2026-07-22T10:00:00Z"
    }
  ],
  "page": 1,
  "pageSize": 20,
  "total": 1
}
```

### 2.5 节点列表

#### `GET /api/nodes?page=1&pageSize=20&status=online`

当前版本返回本机节点，支持 `online`、`offline` 状态过滤。接口结构已经为下一阶段多节点管理预留分页字段。

```bash
curl 'http://198.13.46.231:8088/api/nodes?page=1&pageSize=20' \
  -H "Authorization: Bearer <NODE_TOKEN>"
```

```json
{
  "items": [
    {
      "nodeId": "vultr",
      "name": "sing-box-node",
      "host": "198.13.46.231",
      "domain": null,
      "managerVersion": "1.2.0",
      "singboxVersion": "1.13.14",
      "status": "online",
      "singbox": "running",
      "cpu": 3.2,
      "memory": 12.6,
      "connections": 41,
      "userCount": 1,
      "apiAvailable": true,
      "lastHeartbeatAt": "2026-07-22T10:00:00Z"
    }
  ],
  "page": 1,
  "pageSize": 20,
  "total": 1
}
```

### 2.6 绑定原生住宅 SOCKS5 出口

#### `POST /api/user/bind-proxy`

请求：

```json
{
  "userId": "user-10001",
  "proxy": {
    "type": "socks5",
    "server": "203.0.113.20",
    "port": 1080,
    "username": "residential-user",
    "password": "residential-password"
  }
}
```

`proxy.username` 和 `proxy.password` 当前均可为空。绑定成功后，该用户通过 VLESS、VMess 或 SOCKS5 接入的流量都会路由到同一个住宅出口。重复绑定会替换原住宅出口配置。

```bash
curl -X POST http://198.13.46.231:8088/api/user/bind-proxy \
  -H "Authorization: Bearer <NODE_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"userId":"user-10001","proxy":{"type":"socks5","server":"203.0.113.20","port":1080,"username":"residential-user","password":"residential-password"}}'
```

响应：

```json
{
  "success": true,
  "userId": "user-10001",
  "message": "proxy bound"
}
```

### 2.7 删除用户

#### `DELETE /api/user/delete/{userId}`

删除该用户在全部共享入站中的认证信息、住宅出口和路由规则。

```bash
curl -X DELETE http://198.13.46.231:8088/api/user/delete/user-10001 \
  -H "Authorization: Bearer <NODE_TOKEN>"
```

```json
{
  "success": true,
  "userId": "user-10001",
  "message": "user deleted"
}
```

### 2.8 查询用户流量

#### `GET /api/user/{userId}/traffic`

```json
{
  "userId": "user-10001",
  "upload": 0,
  "download": 0,
  "total": 0
}
```

当前实现读取 `/var/log/sing-box/user-{userId}-traffic.json`。sing-box 尚未自动生成该文件，因此未接入统计采集器时返回 `0`。

### 2.9 重载 sing-box

#### `POST /api/singbox/reload`

```json
{
  "success": true
}
```

Node Manager 优先执行 `systemctl reload sing-box`，失败时回退到 `systemctl restart sing-box`。

### 2.10 Clash API 状态

#### `GET /api/singbox/api/status`

```json
{
  "available": true,
  "usage": "metrics-only"
}
```

Clash API 仅监听 `127.0.0.1:9090`，不对公网开放。它用于状态和后续流量采集，不用于动态新增 sing-box 入站。

## 3. 域名绑定方案

建议把管理 API 和代理节点分成两个子域名：

| 用途 | 示例域名 | DNS/代理方式 |
| --- | --- | --- |
| Node Manager API | `api.example.com` | A 记录指向 `198.13.46.231`，可使用 HTTPS 反向代理 |
| sing-box/SOCKS 节点 | `node.example.com` | A 记录指向 `198.13.46.231`，必须使用仅 DNS 模式 |

### 3.1 配置 DNS

在域名服务商控制台增加：

```text
类型  主机记录  记录值
A     api       198.13.46.231
A     node      198.13.46.231
```

如果使用 Cloudflare：

- `api.example.com` 可以开启代理，并将 SSL/TLS 模式设为 `Full (strict)`。
- `node.example.com` 应设为 `DNS only`。普通 Cloudflare 代理不能直接转发 SOCKS5、VLESS、VMess 等任意 TCP 端口。

### 3.2 为 API 配置 HTTPS

推荐使用 Caddy 自动申请和续期证书。将 `api.example.com` 替换为真实域名：

```caddyfile
api.example.com {
    reverse_proxy 127.0.0.1:8088
}
```

域名生效并启用 HTTPS 后：

1. Node Manager 改为只监听 `127.0.0.1:8088`。
2. 防火墙开放 `80/tcp` 和 `443/tcp`。
3. 从公网防火墙中移除 `8088/tcp`，避免绕过 HTTPS 直接访问。
4. API 基础地址改为 `https://api.example.com`。
5. Swagger 地址改为 `https://api.example.com/docs`。

节点协议连接地址可从 IP 改为 `node.example.com`，端口保持现有配置。Reality 的 `serverName` 属于 Reality 握手配置，不应仅因为绑定了 API 域名就随意修改。

## 4. 开发进度清单

完成一项后，将该项状态更新为 `✔`。

### 已完成

- ✔ `1.1.0` Node Manager 服务和 FastAPI/OpenAPI 文档
- ✔ Bearer Token API 认证
- ✔ 查询单节点运行状态
- ✔ 创建 VLESS、VMess、SOCKS5 用户
- ✔ 绑定和替换原生住宅 SOCKS5 出口
- ✔ 删除用户及其出站和路由配置
- ✔ sing-box 配置加锁、校验、原子替换与失败回滚
- ✔ sing-box 与 Node Manager 版本感知的一键部署
- ✔ 重复部署时保留 Token、UUID、Reality 密钥和用户配置
- ✔ Clash API 仅监听本机，避免 `9090` 暴露公网
- ✔ 创建用户时支持可选 `socksUsername` 和 `socksPassword`
- ✔ 创建用户时可选自动绑定住宅 SOCKS5 出口
- ✔ 自动复用住宅账号密码作为本节点 SOCKS5 凭据
- ✔ 创建用户与住宅绑定使用同一个配置事务，失败时完整回滚
- ✔ 用户注册表持久化，并兼容旧版 `node-manager:{userId}` 用户
- ✔ 用户列表接口，支持分页、搜索、协议和住宅绑定信息
- ✔ 节点列表接口，返回本机状态、版本、负载和用户数量
- ✔ 管理页支持填写 SOCKS5 凭据并查看用户、节点列表
- ✔ 下一阶段核心接口自动化回归测试

### 下一阶段

- 待开发 用户级真实上传、下载和累计流量采集
- 待开发 用户数据与流量数据持久化
- 待开发 多节点注册、心跳、离线判定和幂等请求
- 待配置 API 域名、Caddy HTTPS 和证书自动续期
- 待配置 Node Manager 仅监听本机并关闭公网 `8088`
- 待测试 创建、重复创建、自定义账号、绑定、替换绑定、删除和回滚
- 待开发 Token 轮换、权限分级和敏感字段加密存储
