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
- ✅ 获取用户流量数据
- ✅ 支持 sing-box Clash API 热更新（无需重启）
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
curl -sL -o install.sh https://raw.githubusercontent.com/52Jerry/Node-Manager/main/install.sh && chmod +x install.sh && ./install.sh
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
# 使用 gh-proxy 镜像
curl -sL -o install.sh https://gh.api.99988866.xyz/https://raw.githubusercontent.com/52Jerry/Node-Manager/main/install.sh && chmod +x install.sh && ./install.sh

# 使用 jsdelivr CDN
curl -sL -o install.sh https://cdn.jsdelivr.net/gh/52Jerry/Node-Manager@main/install.sh && chmod +x install.sh && ./install.sh
```

## API 接口

| 接口 | 方法 | 描述 |
|------|------|------|
| `/api/node/status` | GET | 获取节点状态 |
| `/api/user/create` | POST | 创建用户 |
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
     -H "Content-Type: application/json" \
     -d '{"userId":"10001","protocols":["vless","vmess","socks"]}' \
     http://node-ip:8088/api/user/create
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

### 方式二：Clash API 热更新（推荐）
通过 sing-box experimental API 动态管理，无需重启：

```json
{
  "experimental": {
    "clash_api": {
      "external_controller": "0.0.0.0:9090",
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
- ✅ IP 白名单：可配置只允许特定 IP 访问
- ✅ HTTPS：生产环境建议使用 HTTPS

## 部署流程

```
1. 安装依赖 → 2. 安装 sing-box → 3. 配置 sing-box → 4. 安装 Node Manager → 5. 启动服务
```

## 日志

日志文件位于 `logs/node-manager.log`

## 许可证

MIT License