# Python Node Manager

![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![FastAPI](https://img.shields.io/badge/fastapi-0.100+-green.svg)
![License](https://img.shields.io/badge/license-MIT-yellow.svg)

Python Node Manager 是部署在每台 sing-box 节点服务器上的管理 Agent，用于管理 sing-box 配置、创建用户节点、绑定住宅 SOCKS5 出口等功能。

## 功能特性

- ✅ 管理本机 sing-box 配置
- ✅ 动态创建/删除用户节点
- ✅ 支持 VLESS / VMess / SOCKS5 协议
- ✅ 绑定用户住宅 SOCKS5 出口
- ✅ 获取节点状态（CPU、内存、连接数）
- ✅ 采样并持久化用户累计流量
- ✅ 提供 Agent 能力声明和标准心跳快照
- ✅ 写接口支持持久化幂等键
- ✅ sing-box 配置校验、原子替换和失败回滚
- ✅ 可视化管理界面
- ✅ 一键部署脚本

## 架构设计

```
                    Spring Boot
                    控制中心
                         |
                         | HTTPS API
                         |
              Python Node Manager
                         |
                 sing-box Core
                         |
              Residential SOCKS5
```

## 技术栈

- **Python**: 3.11+
- **Web框架**: FastAPI
- **进程管理**: psutil
- **配置管理**: PyYAML
- **认证**: HTTP Bearer Token

## 项目结构

```
node-manager/
├── main.py              # FastAPI主应用
├── config.py            # 配置管理（自动获取公网IP）
├── config.yaml          # 配置文件
├── auth.py              # Token认证模块
├── install.sh           # 一键安装部署脚本
├── requirements.txt     # Python依赖
├── models/              # 请求/响应模型
├── monitor/             # 监控模块（状态、流量）
├── singbox/             # sing-box管理模块
│   ├── manager.py       # 配置读写
│   ├── api.py           # Clash API热更新
│   ├── inbound.py       # 入站配置
│   ├── outbound.py      # 出站配置
│   └── route.py         # 路由规则
└── static/              # 可视化管理界面
```

## 快速开始

### 本地开发

```bash
# 克隆仓库
git clone https://github.com/52Jerry/Node-Manager.git
cd Node-Manager/node-manager

# 安装依赖
pip install -r requirements.txt

# 启动服务
python main.py

# 访问可视化界面
http://localhost:8088
```

### 服务器一键部署

```bash
# 一键部署命令（推荐）
bash <(curl -Ls https://raw.githubusercontent.com/52Jerry/Node-Manager/main/install.sh)
```

部署流程：
```
[1/4] 安装系统依赖
    |
    ↓
[2/4] 安装 sing-box
    |
    ↓
[3/4] 获取服务器信息（公网IP、UUID、密钥等）
    |
    ↓
[4/4] 配置并启动服务
    |
    ↓
部署完成！
```

#### 备用方案

```bash
# 方式二：使用 gh-proxy 镜像
bash <(curl -Ls https://gh.api.99988866.xyz/https://raw.githubusercontent.com/52Jerry/Node-Manager/main/install.sh)

# 方式三：使用 jsdelivr CDN
bash <(curl -Ls https://cdn.jsdelivr.net/gh/52Jerry/Node-Manager@main/install.sh)

# 方式四：分步执行
curl -Ls -o install.sh https://raw.githubusercontent.com/52Jerry/Node-Manager/main/install.sh
chmod +x install.sh
./install.sh
```

## API 接口

| 接口 | 方法 | 描述 |
|------|------|------|
| `/api/node/status` | GET | 获取节点状态 |
| `/api/agent/info` | GET | 获取 Agent 版本、能力和职责边界 |
| `/api/agent/heartbeat` | GET | 获取 Spring Boot 心跳快照 |
| `/api/nodes` | GET | 获取节点列表 |
| `/api/users` | GET | 获取用户列表 |
| `/api/user/create` | POST | 创建用户，可指定 SOCKS5 账号密码 |
| `/api/user/bind-proxy` | POST | 绑定住宅代理 |
| `/api/user/delete/{userId}` | DELETE | 删除用户 |
| `/api/user/{userId}/traffic` | GET | 获取用户流量 |
| `/api/singbox/reload` | POST | 重启 sing-box |
| `/api/singbox/api/status` | GET | 检查 API 可用性 |

### API 使用示例

**获取节点状态**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" http://node-ip:8088/api/node/status
```

**创建用户**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Idempotency-Key: order-10001-create" \
     -H "Content-Type: application/json" \
     -d '{"userId":"10001","protocols":["vless","vmess","socks"],"proxy":{"type":"socks5","server":"1.2.3.4","port":1080,"username":"residential-user","password":"residential-password"}}' \
     http://node-ip:8088/api/user/create
```

`socksUsername` 和 `socksPassword` 均为可选字段。不传用户名时使用
`node-manager:{userId}`，不传密码时由服务端生成随机密码。创建请求可选携带 `proxy`，
一次完成住宅 SOCKS5 出口绑定；不传 `proxy` 时可在以后调用绑定接口。未单独指定本节点
SOCKS5 凭据时，会自动复用住宅出口的用户名和密码。用户列表不会返回明文密码。
Spring Boot 调用创建、绑定和删除接口时应始终发送唯一 `Idempotency-Key`；相同键和相同请求会返回首次结果，响应头 `Idempotency-Replayed: true` 表示本次为重放。

**Agent 能力与心跳**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" http://node-ip:8088/api/agent/info
curl -H "Authorization: Bearer YOUR_TOKEN" http://node-ip:8088/api/agent/heartbeat
```

Node Manager 只管理当前服务器。节点注册、定时心跳、离线判定、全局用户分配和业务数据由 Spring Boot 控制面负责。

**查询用户和节点列表**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" "http://node-ip:8088/api/users?page=1&pageSize=20"
curl -H "Authorization: Bearer YOUR_TOKEN" "http://node-ip:8088/api/nodes?page=1&pageSize=20"
```

**绑定代理**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"userId":"10001","proxy":{"type":"socks5","server":"1.2.3.4","port":1080,"username":"user","password":"pass"}}' \
     http://node-ip:8088/api/user/bind-proxy
```

**删除用户**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" -X DELETE http://node-ip:8088/api/user/delete/10001
```

## 配置说明

### config.yaml

```yaml
node:
  id: tokyo-01          # 节点ID（自动获取主机名）
  name: 东京节点        # 节点名称
  host: auto            # 公网IP（auto自动获取）

server:
  port: 8088            # Node Manager端口

security:
  token: YOUR_TOKEN     # API认证Token

singbox:
  config: /etc/sing-box/config.json  # sing-box配置路径
  api_port: 9090                    # Clash API端口
  api_secret: ""                    # Clash API密钥
```

### sing-box 端口规划

| 用途 | 端口 |
|------|------|
| VLESS Reality | 20168 |
| VMess TCP | 20169 |
| SOCKS5 | 5001 |
| Clash API | 9090 |
| Node Manager | 8088 |

## 工作模式

### 方式一：配置文件模式（默认）
修改 `config.json` → 执行 `systemctl restart sing-box`

### Clash API 指标采集
Clash API 仅监听 `127.0.0.1`，用于连接和流量指标采集：

```json
{
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "secret": "YOUR_SECRET"
    }
  }
}
```

## 可视化界面

访问 `http://localhost:8088` 即可打开管理界面：

- 📊 状态监控：节点状态、CPU、内存、连接数
- 👥 用户管理：创建、删除用户
- ➕ 创建用户：选择协议类型，自动生成配置
- 🔗 绑定代理：配置住宅 SOCKS5 出口
- 🔄 重启服务：一键重启 sing-box

## 安全设计

- ✅ Token 认证：所有接口需要 Authorization 头
- ⏳ IP 白名单：部署 Spring Boot 后限制为控制面服务器 IP
- ⏳ HTTPS：绑定 API 域名后使用 Caddy 反向代理

## 部署流程

```
1. 安装依赖 → 2. 安装 sing-box → 3. 配置 sing-box → 4. 安装 Node Manager → 5. 启动服务
```

## 日志

日志文件位于 `logs/node-manager.log`

## 许可证

MIT License
