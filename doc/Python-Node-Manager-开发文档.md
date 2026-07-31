# Python Node Manager 开发文档

当前版本：`1.4.1`

## 1. 项目定位

Python Node Manager 是部署在每台 sing-box 服务器上的单节点 Agent，负责：

- 管理本机 sing-box 配置与服务状态
- 创建、删除 VLESS、VMess、SOCKS5 用户
- 为用户绑定或更换住宅 SOCKS5 出口
- 返回用户完整连接信息
- 采集节点状态、连接数和用户累计流量
- 向 Spring Boot 控制面提供能力声明和心跳快照

Node Manager 不负责用户注册、订单、支付、套餐、跨节点调度和全局业务数据。这些能力由 Spring Boot 与数据库实现。

## 2. 总体架构

```text
Spring Boot 控制面
        |
        | HTTPS + Bearer Token
        v
Python Node Manager
        |
        v
sing-box Core
        |
        +---- direct
        |
        +---- Residential SOCKS5
```

每台代理服务器部署一个 Node Manager。Spring Boot 保存节点地址和独立 Token，定时读取心跳，并把用户操作分发到指定节点。

## 3. 技术栈

- Python 3.11+
- FastAPI / Uvicorn
- Pydantic
- psutil
- requests
- PyYAML
- cryptography
- systemd
- sing-box Clash API

## 4. 目录结构

```text
Node-Manager/
├── install.sh                    # 版本感知的一键部署脚本
├── VERSION
├── README.md
├── doc/
│   ├── API接口文档.md
│   ├── Python-Node-Manager-开发文档.md
│   └── singbox架构方案.md
├── node-manager/
│   ├── main.py                   # FastAPI 路由与应用生命周期
│   ├── auth.py                   # Bearer Token 校验
│   ├── config.py                 # YAML 配置加载
│   ├── idempotency.py            # 写接口幂等响应持久化
│   ├── models/request.py         # 请求与响应模型
│   ├── monitor/status.py         # CPU、内存、连接指标
│   ├── monitor/traffic.py        # 用户流量采样与累计
│   ├── singbox/manager.py        # 配置事务、用户和出口管理
│   ├── singbox/api.py            # Clash API 客户端
│   └── static/index.html         # 单节点管理页面
└── tests/test_next_stage.py      # 节点端自动化回归测试
```

## 5. 配置与本地状态

生产配置：

```text
/etc/node-manager/config.yaml
/etc/sing-box/config.json
```

Node Manager 本地状态：

```text
/var/lib/node-manager/users.json
/var/lib/node-manager/traffic.json
/var/lib/node-manager/idempotency.json
```

这些文件权限为 `600`，不应提交到 GitHub。仓库中的 `node-manager/config.yaml` 仅是无真实凭据的开发示例。

用户注册表保存 Node Manager 管理用户的 SOCKS5 用户名和创建时间；业务用户资料仍由 Spring Boot 保存。

## 6. sing-box 用户模型

一个用户可同时启用：

- VLESS Reality
- VMess TCP
- SOCKS5

协议认证名使用稳定标识：

```text
node-manager:{userId}
```

每个用户拥有独立出站标签：

```text
node-manager-out:{userId}
```

未绑定住宅出口时，该标签指向 `direct`；绑定后替换为对应的 SOCKS5 出站。路由规则通过 `auth_user` 把用户的三种入站协议统一导向同一出站。

## 7. 配置事务

所有用户写操作遵循：

```text
读取当前配置与注册表
        |
复制并修改内存对象
        |
写入临时注册表
        |
写入临时 sing-box 配置
        |
sing-box check
        |
原子替换正式配置
        |
reload，失败则 restart
        |
失败时恢复旧配置和注册表
```

配置操作同时使用线程锁和 Linux 文件锁，避免并发请求覆盖彼此修改。

## 8. 主要 API

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/api/node/status` | 节点状态和连接指标 |
| GET | `/api/agent/info` | Agent 版本和能力声明 |
| GET | `/api/agent/heartbeat` | Spring Boot 心跳快照 |
| GET | `/api/nodes` | 当前节点列表兼容接口 |
| GET | `/api/users` | 分页查询用户，不返回密码 |
| POST | `/api/user/create` | 创建用户，可同时绑定住宅出口 |
| GET | `/api/user/{userId}/connections` | 获取完整三协议连接信息 |
| POST | `/api/user/bind-proxy` | 绑定或替换住宅 SOCKS5 出口 |
| DELETE | `/api/user/delete/{userId}` | 删除用户、路由和独立出站 |
| GET | `/api/user/{userId}/traffic` | 获取用户累计流量 |
| POST | `/api/singbox/reload` | 重新加载 sing-box |

完整请求和响应以 [API 接口文档](API接口文档.md) 与运行时 `/openapi.json` 为准。

## 9. 创建用户和住宅出口

创建用户时可传入：

```json
{
  "userId": "user-10001",
  "protocols": ["vless", "vmess", "socks"],
  "socksUsername": "optional-local-username",
  "socksPassword": "optional-local-password",
  "proxy": {
    "type": "socks5",
    "server": "203.0.113.20",
    "port": 1080,
    "username": "residential-user",
    "password": "residential-password"
  }
}
```

规则：

- `socksUsername` 不传时，优先复用住宅用户名，否则使用 `node-manager:{userId}`。
- `socksPassword` 不传时，优先复用住宅密码，否则生成随机密码。
- `proxy` 不传时先创建直连用户，后续可调用绑定接口。
- 创建、绑定、删除接口应由 Spring Boot 发送唯一 `Idempotency-Key`。

## 10. 连接和流量指标

节点状态包含两个不同指标：

- `connections`：sing-box Clash API 当前活跃代理连接数量。
- `systemConnections`：操作系统全部网络套接字数量，包括 SSH、DNS 和其他进程。

连接数不是在线用户数，一个用户可能同时建立多个连接。

用户流量由 Clash API 定时采样并累计到本地状态文件。Spring Boot 可定时汇总节点数据，但账单和套餐判断应在控制面完成。

## 11. 一键部署行为

根目录 `install.sh` 支持 Debian 和 Ubuntu：

1. 检查 GitHub 最新 Node Manager 版本。
2. 版本相同则保留当前应用，版本变化才升级。
3. 检查 sing-box 已安装版本和最新稳定版。
4. sing-box 已是最新则继续使用；版本过旧才卸载并更新。
5. 始终备份并保留已有 sing-box 配置、Reality 密钥、Token 和用户。
6. 全新安装时创建 `node-manager-test` 三协议测试用户。
7. Clash API 仅监听 `127.0.0.1:9090`。

一键部署：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/52Jerry/Node-Manager/main/install.sh)
```

## 12. 安全要求

- 每个节点使用独立高强度 Token。
- GitHub 文档和示例只使用 `<NODE_TOKEN>`、`CHANGE_ME` 等占位符。
- 不提交服务器密码、API Token、Reality 私钥、SOCKS5 真实凭据和生产配置。
- 用户连接详情接口返回明文 SOCKS5 密码，响应使用 `Cache-Control: no-store`，不得写入普通业务日志。
- Clash API 不对公网开放。
- 上线后使用 Caddy 或 Nginx 提供 HTTPS。
- 防火墙仅允许 Spring Boot 控制面访问 Node Manager API。

## 13. Spring Boot 控制面职责

Node Manager `1.4.1` 已具备单服务器 Agent 的核心能力。下一阶段主要在 Spring Boot 开发：

- 节点注册表与每节点 Token 管理
- 15 至 30 秒心跳调度、快照保存和离线判定
- 全局用户与节点分配
- 套餐、订单、账单和业务数据库
- 写接口幂等键生成与持久化
- 跨节点用户和流量汇总
- 节点停用、维护和版本升级编排
- 订阅地址生成与用户自助页面

## 14. 测试与发布

本地回归：

```bash
python tests/test_next_stage.py
python -m compileall -q node-manager tests
```

发布前还需检查：

```bash
git diff --check
bash -n install.sh
```

生产部署后验证 `/health`、`/api/node/status`、`/api/agent/info`、`/api/agent/heartbeat` 和用户连接详情接口。
