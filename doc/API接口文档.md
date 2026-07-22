# Python Node Manager API 接口文档

版本：`1.1.0`

部署节点：`http://198.13.46.231:8088`

在线文档：

- Swagger UI：`http://198.13.46.231:8088/docs`
- OpenAPI JSON：`http://198.13.46.231:8088/openapi.json`

## 1. 认证

除 `/`、`/health`、`/docs` 和 `/openapi.json` 外，业务接口均使用 Bearer Token：

```http
Authorization: Bearer <NODE_TOKEN>
Content-Type: application/json
```

Token 保存在服务器的 `/etc/node-manager/config.yaml` 和仅 root 可读的
`/root/node-manager-info.txt` 中。不要把生产 Token 提交到 Git。

## 2. 通用错误

| HTTP 状态码 | 含义 |
| --- | --- |
| `401` | Token 缺失或错误 |
| `409` | 用户已存在、用户不存在、sing-box 配置校验失败或重载失败 |
| `422` | 请求字段格式不合法 |
| `500` | 未处理的服务器错误 |

FastAPI 错误响应示例：

```json
{
  "detail": "user already exists: user-10001"
}
```

## 3. 健康检查

### `GET /health`

无需认证，用于 systemd、负载均衡器和部署脚本检查 Node Manager 进程。

响应：

```json
{
  "status": "ok"
}
```

## 4. 查询节点状态

### `GET /api/node/status`

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

调用示例：

```bash
curl -H "Authorization: Bearer $NODE_TOKEN" \
  http://198.13.46.231:8088/api/node/status
```

## 5. 创建用户

### `POST /api/user/create`

用户共享固定的 VLESS、VMess 和 SOCKS5 入站端口，不会为每个用户额外开放公网端口。

请求：

```json
{
  "userId": "user-10001",
  "protocols": ["vless", "vmess", "socks"]
}
```

字段：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `userId` | string | 是 | 1 到 64 位，仅允许字母、数字、`.`、`_`、`-` |
| `protocols` | string[] | 否 | 可选值为 `vless`、`vmess`、`socks`，默认全部创建，不允许重复 |

响应：

```json
{
  "success": true,
  "userId": "user-10001",
  "uuid": "19cbb87d-a20f-40f2-89a8-d92332c46999",
  "protocols": ["vless", "vmess", "socks"],
  "vless": "vless://...",
  "vmess": "vmess://...",
  "socks": {
    "host": "198.13.46.231",
    "port": 5001,
    "username": "node-manager:user-10001",
    "password": "generated-password"
  }
}
```

调用示例：

```bash
curl -X POST http://198.13.46.231:8088/api/user/create \
  -H "Authorization: Bearer $NODE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"userId":"user-10001","protocols":["vless","vmess","socks"]}'
```

说明：配置修改采用文件锁、临时文件校验和失败回滚。接口成功返回前，新的 sing-box 配置已经通过 `sing-box check` 并完成服务重载。

## 6. 绑定住宅 SOCKS5 出口

### `POST /api/user/bind-proxy`

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

`proxy.username` 和 `proxy.password` 可为空。绑定后，该用户在 VLESS、VMess、SOCKS5 三种协议中的流量都会按认证用户名路由到同一个住宅出口。

响应：

```json
{
  "success": true,
  "userId": "user-10001",
  "message": "proxy bound"
}
```

调用示例：

```bash
curl -X POST http://198.13.46.231:8088/api/user/bind-proxy \
  -H "Authorization: Bearer $NODE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"userId":"user-10001","proxy":{"type":"socks5","server":"203.0.113.20","port":1080,"username":"u","password":"p"}}'
```

重复绑定同一用户会替换该用户原来的住宅出口配置。

## 7. 删除用户

### `DELETE /api/user/delete/{userId}`

删除该用户在所有共享入站中的认证信息、住宅出口和路由规则。

响应：

```json
{
  "success": true,
  "userId": "user-10001",
  "message": "user deleted"
}
```

调用示例：

```bash
curl -X DELETE \
  -H "Authorization: Bearer $NODE_TOKEN" \
  http://198.13.46.231:8088/api/user/delete/user-10001
```

## 8. 查询用户流量

### `GET /api/user/{userId}/traffic`

响应：

```json
{
  "userId": "user-10001",
  "upload": 0,
  "download": 0,
  "total": 0
}
```

当前实现读取 `/var/log/sing-box/user-{userId}-traffic.json`。sing-box 尚未自动生成该文件，因此未接入统计采集器时返回 `0`。下一阶段应通过 Clash API 的连接数据、V2Ray API 或独立流量采集模块实现可靠的用户级累计统计。

## 9. 重载 sing-box

### `POST /api/singbox/reload`

响应：

```json
{
  "success": true
}
```

Node Manager 优先执行 `systemctl reload sing-box`，失败时回退到 `systemctl restart sing-box`。

## 10. Clash API 状态

### `GET /api/singbox/api/status`

响应：

```json
{
  "available": true,
  "usage": "metrics-only"
}
```

Clash API 仅监听 `127.0.0.1:9090`，不对公网开放。它用于状态与后续流量采集，不用于动态新增 sing-box 入站。

## 11. 下一阶段开发建议

1. 增加用户列表接口，将 sing-box 中带 `node-manager:` 标记的用户转换为可分页 DTO。
2. 实现真实的用户级流量采集与持久化，明确累计值和增量值的语义。
3. 为配置事务增加自动化测试，覆盖创建、重复创建、绑定、替换绑定、删除和重载回滚。
4. 在控制中心增加节点注册、Token 加密保存、心跳、超时重试和幂等请求 ID。
5. 配置域名与 HTTPS，并通过 UFW 白名单限制 `8088` 只允许控制中心访问。
