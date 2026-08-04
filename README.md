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
- ✅ 获取节点状态（CPU、内存、代理活跃连接、整机网络套接字）
- ✅ 按用户查看完整 VLESS / VMess / SOCKS5 连接信息
- ✅ 采样并持久化用户累计流量
- ✅ 提供 Agent 能力声明和标准心跳快照
- ✅ 写接口支持持久化幂等键
- ✅ sing-box 配置校验、原子替换和失败回滚
- ✅ 可视化管理界面
- ✅ 一键部署脚本
- ✅ 安装完成后自动注册到 Spring Boot control-plane
- ✅ 全新安装自动创建三协议测试用户

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

## 项目文档

- [API 接口文档](doc/API接口文档.md)
- [Node Manager 开发文档](doc/Python-Node-Manager-开发文档.md)
- [sing-box 架构方案](doc/singbox架构方案.md)

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

### 从 Control Plane 页面一键部署并注册（推荐）

登录牛速控制中心，在“全部节点”区域点击“一键安装 Node Manager”，复制页面生成的命令到目标 VPS 的 root 终端执行。命令会携带一个短时、仅可成功使用一次的安装码，无需查找或手动输入长期注册令牌。

页面生成的命令形态如下，其中实际安装码不会写入本文档：

```bash
bash <(curl -fsSL 'https://raw.githubusercontent.com/52Jerry/Node-Manager/main/install.sh') 'https://control.example.com' 'niusu_一次性安装码'
```

脚本会自动完成以下事情：

- 获取当前 VPS 公网 IP
- 使用主机名作为稳定节点 ID 和显示名称
- 生成并保存 Node Manager API Token
- 使用 `http://公网IP:8088` 注册到 Control Plane
- 默认设置最大用户数为 `500`
- 重装时复用原节点 ID 和 API Token，不重复创建节点

`1.4.2` 起，脚本会安全识别尚未安装 sing-box 的全新服务器，并直接从 GitHub Release 下载与 CPU 架构匹配的 Debian 软件包；下载包含重试和明确错误提示，不再依赖 `sing-box.app` 安装入口。软件包自动生成的默认示例配置会被 Node Manager 初始化配置替换，用户自行维护过的现有配置仍会备份并保护。

`1.4.3` 起，安装器会在 Ubuntu/Debian 自动更新占用 `dpkg` 时等待锁释放，默认最多等待 300 秒，避免新开通 VPS 首次执行时随机失败。必要时可在执行前通过 `APT_LOCK_TIMEOUT_SECONDS` 调整等待秒数。

`1.4.4` 起，一次性安装注册发生网络超时时会直接提示检查云防火墙/安全组的 TCP `8088` 入站规则，并要求修复网络后重新生成短时安装命令，避免继续复用已处于不确定状态的一次性安装码而误报 `401`。

一次性安装码默认 10 分钟有效，注册成功立即作废。它只用于本次安装注册，不会写入 `/root/node-manager-info.txt`。命令可能短暂停留在 VPS Shell 历史中，但安装码成功使用或过期后无法再次注册；不要把尚未使用的命令转发给其他人。

需要保证 VPS 能访问 Control Plane，并在云安全组中允许 Control Plane 服务器访问 VPS 的 TCP `8088` 端口。

### 只安装、不注册

```bash
bash <(curl -Ls https://raw.githubusercontent.com/52Jerry/Node-Manager/main/install.sh)
```

### 兼容的长期注册令牌方式

如果不从页面生成命令，也可以只传 Control Plane 地址，随后在终端隐藏输入长期注册令牌：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/52Jerry/Node-Manager/main/install.sh) https://control.example.com
```

### 自动化和高级覆盖

无人值守安装可以预先提供令牌：

```bash
CONTROL_PLANE_REGISTRATION_TOKEN="registration-secret" \
bash <(curl -Ls https://raw.githubusercontent.com/52Jerry/Node-Manager/main/install.sh) https://control.example.com
```

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `CONTROL_PLANE_INSTALL_TOKEN` | 页面命令第二参数 | 短时一次性安装码，优先于长期注册令牌，不写入信息文件 |
| `CONTROL_PLANE_REGISTRATION_TOKEN` | 交互输入 | 安装脚本专用注册令牌，不会写入信息文件 |
| `NODE_MANAGER_PUBLIC_URL` | `http://公网IP:8088` | control-plane 回调本节点使用的地址 |
| `NODE_MANAGER_NAME` | 节点 ID | 控制面显示名称 |
| `NODE_MANAGER_NODE_ID` | 已有 ID 或主机名 | 稳定节点 ID，重装时用于更新原记录 |
| `NODE_MANAGER_MAX_USERS` | `500` | 节点最大用户容量 |

旧的 `CONTROL_PLANE_URL`、`CONTROL_PLANE_REGISTRATION_REQUIRED` 等环境变量方式继续兼容。脚本会在 Node Manager 健康检查通过后注册，并以 `0/2/4/8/16` 秒退避重试。升级或重装会沿用已有 API Token 和节点 ID。注册状态及 Control Plane 分配的节点 UUID 会写入 `/root/node-manager-info.txt`。注册令牌、Node Manager API Token 和生成密码通过权限为 `0600` 的文件传递或保存，不会出现在安装末尾的控制台输出中。

注册请求会提交稳定节点 ID、显示名称、Node Manager 公网 URL、Node Manager API Token、VPS 公网 IP、Node Manager 版本和最大用户数。Control Plane 保存注册信息后会主动访问 `/api/agent/info` 和 `/api/agent/heartbeat`，补充在线状态、sing-box 版本、CPU、内存、连接数、用户数和流量等运行信息。要完成这一过程，VPS 必须能访问 `CONTROL_PLANE_URL`，同时 Control Plane 必须能访问 `NODE_MANAGER_PUBLIC_URL`；默认直连部署需放行 VPS 的 TCP 8088 端口。

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
| `/api/user/{userId}/connections` | GET | 按需获取 VLESS、VMess、SOCKS5 完整连接信息 |
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

**查询用户连接信息**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://node-ip:8088/api/user/10001/connections
```

该接口会返回完整 VLESS、VMess 和 SOCKS5 凭据，响应使用 `Cache-Control: no-store`。不要把响应写入普通业务日志。

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

- 📊 状态监控：节点状态、CPU、内存、代理活跃连接、整机网络套接字
- 👥 用户管理：创建、删除用户
- 🔑 连接信息：按需查看用户 VLESS、VMess、SOCKS5 连接参数
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
