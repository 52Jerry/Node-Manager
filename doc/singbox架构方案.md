你的调整方向是合理的。你的新架构可以直接去掉 3x-ui，让 **sing-box 作为核心代理引擎**，后面你的 Spring Boot 管理系统直接生成和管理 sing-box 配置。

你的目标：

```
用户
 |
 | VLESS / Trojan / SOCKS5
 |
 ↓
东京服务器（sing-box）
 |
 | outbound socks5
 |
 ↓
住宅 SOCKS5 IP
 |
 ↓
目标网站
```

也就是：

- sing-box = 节点核心
- 住宅 SOCKS5 = 出口代理
- Spring Boot = 控制面 API

------

## 新架构设计

建议拆成三个部分：

### 1. 数据控制层

Spring Boot：

```
Spring Boot
     |
     |
 MySQL
     |
     |
 Node Manager API
```

负责：

- 用户管理
- 套餐管理
- IP池管理
- 生成 UUID
- 创建代理账号
- 分配住宅出口
- 禁用账号
- 流量统计

### 2. 节点管理层

Python Node Manager（部署在每个 sing-box 节点上）：

```
Spring Boot
     |
     | HTTP API
     |
  Node Manager (FastAPI)
     |
     ├── 配置文件方式
     │     └── 修改 config.json → reload
     │
     └── Clash API 方式 (推荐)
           └── 热更新用户/路由/出口 (不重启)
```

负责：
- 管理本机 sing-box 配置
- 动态创建/删除用户节点
- 支持 VLESS / VMess / SOCKS5 协议
- 绑定住宅 SOCKS5 出口
- 获取节点状态（CPU、内存、连接数）
- 获取用户流量数据
- 支持 sing-box Clash API 热更新

### 3. 节点执行层

东京 VPS：

```
/etc/sing-box/

config.json

sing-box
```

负责：

- 接收用户连接
- 判断用户
- 转发流量
- 出口 SOCKS5

------

# 一键部署

直接在服务器上执行以下命令，完成全流程部署：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/52Jerry/Node-Manager/main/node-manager/install.sh)
```

部署流程：

```
[1/4] 安装 sing-box
    |
    | 更新系统包 → 安装依赖 → 清理旧环境 → 安装 sing-box
    |
    ↓
[2/4] 配置基础节点
    |
    | 获取公网IP → 生成参数 → 写入配置 → 开放端口
    |
    ↓
[3/4] 测试 sing-box 运行
    |
    | 检查配置 → 启动服务 → 验证状态
    |
    ↓
[4/4] 安装 Python Node Manager
    |
    | 创建虚拟环境 → 安装依赖 → 创建项目文件 → 启动服务
    |
    ↓
部署完成！
```

------

# 第一步：安装 sing-box

东京 VPS：

Ubuntu：

```bash
apt update
apt install curl unzip -y
```

安装：

```bash
curl -fsSL https://sing-box.app/install.sh | sh
```

检查：

```bash
sing-box version
```

------

# 第二步：生成基础配置

目录：

```bash
mkdir -p /etc/sing-box
```

配置：

```bash
nano /etc/sing-box/config.json
```

## sing-box 核心配置

例如：

用户：

```
UUID:
11111111-2222-3333-4444-555555555555
```

住宅 SOCKS5：

```
server:
res.proxy.com

port:
12345

username:
abc

password:
123
```

配置：

```json
{
  "log": {
    "level": "info"
  },

  "inbounds": [
    {
      "type": "vless",
      "tag": "user-vless",
      "listen": "::",
      "listen_port": 443,
      "users": [
        {
          "uuid": "11111111-2222-3333-4444-555555555555"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "your.domain.com",
        "certificate_path": "/etc/sing-box/fullchain.pem",
        "key_path": "/etc/sing-box/private.key"
      }
    }
  ],

  "outbounds": [
    {
      "type": "socks",
      "tag": "residential-ip",
      "server": "住宅SOCKS5地址",
      "server_port": 12345,
      "username": "用户名",
      "password": "密码"
    }
  ]
}
```

------

# 第三步：启动

创建服务：

```bash
nano /etc/systemd/system/sing-box.service
```

内容：

```
[Unit]
Description=sing-box
After=network.target

[Service]
ExecStart=/usr/bin/sing-box run \
-c /etc/sing-box/config.json
Restart=always

[Install]
WantedBy=multi-user.target
```

启动：

```bash
systemctl daemon-reload
systemctl enable sing-box
systemctl start sing-box
```

查看：

```bash
journalctl -u sing-box -f
```

------

# 第四步：验证出口

客户端连接东京：

然后：

```bash
curl ipinfo.io
```

应该看到：

```
住宅IP
```

而不是：

```
东京VPS IP
```

------

# 使用 sing-box experimental API

不要每个用户修改 config.json 然后重启 sing-box。

正确方式：

```json
{
 "experimental":{
   "clash_api":{
      "external_controller":"0.0.0.0:9090",
      "secret":"your-secret"
   }
 }
}
```

Spring Boot 通过 Node Manager 调用：

```
POST http://节点服务器:8088/api/user/create
```

动态管理。

------

# 最终架构

```
                  Web前端
                     |
                     |
              Spring Boot
                     |
              MySQL数据库
                     |
        ------------------------
        |                      |
     用户表                 IP池表
        |
        |
 Node Manager API
        |
        |
-----------------------------
|                           |
东京节点1                 东京节点2

Node Manager             Node Manager
FastAPI                  FastAPI
    |                        |
sing-box                  sing-box

|                           |
住宅 SOCKS5池           住宅 SOCKS5池

|                           |
目标网站               目标网站
```

------

# 实施顺序

## 阶段1（已完成）

单节点跑通：

✅ sing-box
✅ VLESS入口
✅ SOCKS5住宅出口
✅ IP检测成功

## 阶段2（已完成）

加入：

✅ 多住宅IP
✅ 多出口选择
✅ routing规则

例如：

用户A：

```
UUID-A
 |
住宅IP-美国
```

用户B：

```
UUID-B
 |
住宅IP-日本
```

## 阶段3（已完成）

Python Node Manager：

实现：

```
创建用户
 ↓
生成UUID
 ↓
写入sing-box配置 / Clash API热更新
 ↓
reload / 热更新
 ↓
返回vless://链接
```

## 阶段4

商业系统：

```
注册
充值
购买套餐
自动生成节点
流量统计
到期关闭
```

------

# Node Manager API 接口

| 接口 | 方法 | 描述 |
|------|------|------|
| `/api/node/status` | GET | 获取节点状态 |
| `/api/user/create` | POST | 创建用户 |
| `/api/user/bind-proxy` | POST | 绑定住宅代理 |
| `/api/user/delete/{userId}` | DELETE | 删除用户 |
| `/api/user/{userId}/traffic` | GET | 获取用户流量 |
| `/api/singbox/reload` | POST | 重启 sing-box |
| `/api/singbox/api/status` | GET | 检查 API 可用性 |

## API 使用示例

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

------

# 端口设计

| 用途 | 端口 |
|------|------|
| VLESS Reality | 20168 |
| VMess TCP | 20169 |
| SOCKS5 | 5001 |
| sing-box API | 9090 |
| Node Manager | 8088 |

------

# 部署完成输出示例

```
====================================
  Node Manager 部署完成
====================================

服务器信息:
  IP: 198.13.46.231
  主机名: tokyo-01

sing-box:
  状态: active
  API: http://198.13.46.231:9090
  API Secret: xxxxxx

Node Manager:
  API: http://198.13.46.231:8088
  Token: xxxxxx
  Web UI: http://198.13.46.231:8088
  测试: curl -H "Authorization: Bearer xxxxxx" http://198.13.46.231:8088/api/node/status

节点链接:
  VLESS Reality: vless://xxx@198.13.46.231:20168?...
  VMess: vmess://base64...
  SOCKS5: 198.13.46.231:5001

端口配置:
  VLESS: 20168
  VMESS: 20169
  SOCKS5: 5001
  API: 9090
  Node Manager: 8088

====================================
```

------

# 项目结构

```
node-manager/
├── main.py              # FastAPI主应用
├── config.py            # 配置管理（自动获取公网IP）
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

------

你的这个方案比 3x-ui 更适合 **20~30人团队 + 住宅IP代理平台** 场景，因为控制权完全在你自己的 Spring Boot 后台里。下一步建议直接设计 **sing-box 节点 API 管理方案（Spring Boot 如何热更新用户和出口，不重启 sing-box）**。