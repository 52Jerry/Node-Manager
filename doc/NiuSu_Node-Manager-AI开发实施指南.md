# NiuSu Node Manager AI 开发实施指南（分步执行）

> 版本：v1.0（2026-08-05）
> 用途：给 AI/开发者执行的**分步任务清单**。按顺序执行，每步含目标、改动文件、验收标准。
> 代码库：`Node Manager/node-manager`（Python FastAPI）
> 前置阅读：《Python-Node-Manager-开发文档.md》《API接口文档.md》《singbox架构方案.md》《NiuSu_优化修改报告.md》

---

## 阶段 0：环境准备（先做）

**目标**：确认 Node Manager 可运行、可测试。

**每一步做什么：**
1. 确认 Python 3.10+ 已安装。命令：`python --version`
2. 安装依赖：`pip install -r node-manager/requirements.txt`
3. 确认 `config.yaml` 存在；`node.acceleration_domain` 可选，未配置时回退到当前节点 `host`。
4. 运行全部测试：
   ```powershell
   cd "Node Manager"
   python -m unittest discover -s tests -v
   ```
5. 确认当前 **49 个用例全部通过**（含 `test_protocols.py` 的协议/住宅校验，以及节点身份、动态端口和安装契约回归用例）。

**验收**：测试全绿，无 ModuleNotFoundError。

---

## 阶段 1：多协议生成模块（已完成，核验）

> 已实现 `protocols.py`。核对以下行为，不符则修正。

### 步骤 1.1 核验协议格式
**改动文件**：`node-manager/protocols.py`
**做什么**（逐项核验）：
1. `socks5_original` → `socks://user:pass@ip:port#US-1.2.3.4`
2. `bitbrowser` → `ip:port:user:pass`
3. `vless` → `vless://uuid@域名:20168?encryption=none&security=reality&sni=...&pbk=...&sid=...&spx=...&type=tcp&headerType=none&flow=xtls-rprx-vision#备注`
4. `socks_acceleration` → `socks://b64user:b64pass@域名:5001#备注`（账号密码 Base64）
5. `vmess` → `vmess://base64(JSON)`，JSON 含 `v/ps/add/port/id/aid/scy/net/type/host/path/tls/sni/alpn/fp`

**验收**：`test_protocols.py` 全部通过；住宅请求生成五种格式，直连用户只生成三种加速格式。

### 步骤 1.2 核验统一数据源 `ProtocolData`
**做什么**：确认 `ProtocolData` 覆盖通用/IP/端口/账号/密码、加速域名/uuid、VLESS 与 VMess 专属参数。底层 `generate_all(data)` 仍提供五种纯函数格式；用户创建接口根据是否绑定住宅出口筛选返回集合。

**验收**：`test_generate_all` 断言五键齐全。

---

## 阶段 2：住宅 SOCKS 配置与校验（已完成，核验）

> 已实现 `residential.py`。

### 步骤 2.1 核验校验规则
**做什么**：
1. `validate_ip`：IPv4 四段、每段 0-255，用 `ipaddress.IPv4Address` 严格校验。
2. `validate_port`：数字且 `1-65535`。
3. `validate_credential`：非空、≤255、无空白/控制字符。
4. `validate_config`：组装 `ResidentialSocksConfig`。
5. `validate_batch`：逐行 `IP 端口 账号 密码`，空行跳过。

**验收**：`test_protocols.py` 住宅校验用例通过；非法输入抛 `ResidentialConfigError`。

### 步骤 2.2 安全约定确认
**做什么**：确认 `ResidentialSocksConfig` **不打印、不落盘**明文密码；凡需加密存储的，注释注明由 Control Plane 用 AES-GCM 完成。

### 步骤 2.3 批量住宅节点字段语义

批量输入的五列格式为：

```text
住宅出口 IP    上游 SOCKS 地址    上游端口    上游用户名    上游密码
```

可选的六列格式在最前面增加序号。第一列住宅出口 IP 只用于 GeoIP、国家/代码和备注；第二列才是 Node Manager 连接的上游 SOCKS 地址。创建用户后，Node Manager 在本机 sing-box 上生成入口，住宅 SOCKS 仅作为出站路由，不能直接替代最终入口地址。

---

## 阶段 3：接入 FastAPI 路由（已完成，核验）

> 已实现 `/api/residential/protocols`。

### 步骤 3.1 核验端点
**改动文件**：`node-manager/main.py`、`node-manager/models/request.py`
**做什么**：
1. 确认新增 `POST /api/residential/protocols`，请求体含 `ip/port/username/password/uuid?/accelerationDomain?`。
2. 确认 `ResidentialSocksRequest.uuid` 校验为合法 UUID（非空时）。
3. 确认住宅请求响应含 `protocolsAll`（五协议）与 `meta`（国家/地区）；该端点本身就是住宅信息生成端点。
4. 确认端点要求 `Bearer` 鉴权（复用现有 auth）。

**验收**：用 `curl -H "Authorization: Bearer <token>"` 调用住宅端点返回五协议；非法 UUID 返回 422。调用 `/api/user/create` 且不传 `proxy` 时应只返回三种加速链接。

### 步骤 3.2 入口端口来源

五协议中的加速入口端口从实际 sing-box inbound 的 `listen_port` 读取：

| 协议 | 配置标签 | 默认回退端口 |
| --- | --- | --- |
| VLESS Reality | `vless-reality` | 20168 |
| VMess TCP | `vmess` | 20169 |
| SOCKS 加速 | `socks` | 5001 |

因此手工调整 sing-box 端口后，重新获取连接信息即可得到新端口；只有配置缺失或非法时才使用默认回退值。

### 步骤 3.2 核验连接接口扩展
**改动文件**：`node-manager/singbox/manager.py`
**做什么**：确认 `GET /api/user/{userId}/connections` 响应含 `protocolsAll`，且保留旧 `vless/vmess/socks` 字段（向后兼容）。

**验收**：`test_next_stage.py` 连接相关用例通过。

---

## 阶段 4：审计日志与可观测性（已完成，核验）

### 步骤 4.1 核验 `_audit`
**改动文件**：`node-manager/singbox/manager.py`
**做什么**：
- 确认 `create_user/bind_proxy/delete_user` 调用 `_audit(action, user_id, **fields)`。
- 确认 `_audit` 自动剔除 `password/token/secret/connection` 键，超长字段截断 256。
- 确认日志格式 `audit <action> modules={"action":...,"userId":...}`。

**验收**：操作日志出现 `audit` 行；不含明文密码。

---

## 阶段 5：性能与稳定性优化（部分完成）

> 参考《NiuSu_系统优化文档》。以下为**待实施**步骤。

### 步骤 5.1 sing-box 增量更新（已完成基础版）
**目标**：减少 `config.json` 全量重写与 reload。
**改动文件**：`node-manager/singbox/manager.py`、`singbox/inbound.py`、`singbox/outbound.py`、`singbox/route.py`
**做什么**：
1. 新增 `diff_write(new_config)`：仅当配置 JSON 变化时才写盘。
2. 仅 reload 涉及变更的 inbound/outbound，而非整机 reload（若 sing-box 支持）。
3. 在 reload 前先 `sing-box check`，失败回滚旧配置。

**当前状态**：`_write_and_reload()` 已先做结构比较；配置完全一致时不写盘、不执行 `sing-box check`、不触发 reload。配置变化仍使用临时文件校验、原子替换和失败回滚。

**验收**：`tests/test_next_stage.py` 覆盖配置不变跳过校验/写入/reload；现有回滚测试继续保留。

### 步骤 5.2 流量采样降频（已完成基础版）
**改动文件**：`node-manager/monitor/traffic.py`
**做什么**：
1. 采集间隔改为可配置（`config.yaml`）。
2. 大批量连接时抽样上报，减少 CPU 占用。

**当前状态**：`monitoring.traffic_sample_interval_seconds` 已加入配置，允许范围 `0.5-300` 秒，默认 `2` 秒；采集线程和停止等待统一使用该值。

**验收**：测试覆盖 `0.5`、`300` 边界以及越界拒绝；大批量节点建议按资源情况调高到 `5-10` 秒。

### 步骤 5.3 幂等与并发
**改动文件**：`node-manager/idempotency.py`、`main.py`
**做什么**：
1. 确认 `create_user` 幂等键冲突返回 409。
2. 并发创建同一用户加锁或原子占用，避免重复开两套配置。

**验收**：`test_next_stage.py` 幂等用例通过。

---

## 阶段 6：安全边界（P0）

### 步骤 6.1 网关收口（配合运维）
**做什么**：
1. 确认 Node Manager 8088 仅允许 Control Plane 网关 IP 访问。
2. 生产经 `proxy.xinxinip.com/nodes/{id}/*` 反向代理，关闭公网 8088。
3. 确认 `Authorization: Bearer <token>` 全程校验。

**验收**：公网直接访问 8088 被拒；经网关可通。

### 步骤 6.2 敏感信息防护
**做什么**：
1. grep 全库确认无 `print(password)`、无日志打印完整连接。
2. 确认 `config.yaml` 不含明文 Token（由环境/文件注入）。

**验收**：代码扫描无敏感信息泄露点。

---

## 阶段 7：测试与交付

**做什么：**
1. `python -m unittest discover -s tests -v` 全绿（≥ 42 用例）。
2. 若新增代码，补对应单元/集成测试。
3. 用 `curl` 走一遍：创建用户 → 绑上游 → 查连接（含五协议）→ 删除。
4. 确认错误码语义（400/409/422/429/5xx）与文档一致。

**验收**：全量测试通过 + 端到端主流程可用。

### 当前交付基线

- Node Manager：49 个 Python 单元/集成测试。
- `protocolsAll` 按出口模式返回：无 `proxy` 时为 `vless`、`socksAcceleration`、`vmess`；有 `proxy` 时为 `socks5`、`bitbrowser`、`vless`、`socksAcceleration`、`vmess`。
- 审计日志仅记录操作类型、用户 ID、节点元数据，不记录密码、Token 或完整连接链接。
- 普通用户列表不返回明文凭据；连接详情仅按需读取。

---

## 附：文档索引（同目录）
- `Python-Node-Manager-开发文档.md`：权威规格与模块说明。
- `API接口文档.md`：Node Manager API 参考。
- `singbox架构方案.md`：sing-box 架构与部署。
- `NiuSu_优化修改报告.md`：本次代码改动前后对比。

## 本轮实施状态（2026-08-06）

- Node Manager 保持五协议格式兼容输出，但按出口模式动态返回：无住宅为 `vless`、`socksAcceleration`、`vmess`，有住宅才增加 `socks5`、`bitbrowser`；旧版 `vless/vmess/socks` 字段继续保留。
- 住宅批量输入继续区分住宅出口 IP 与上游 SOCKS 地址：住宅 IP 用于 GeoIP/备注，上游地址用于出站路由，协议入口使用实际 sing-box 动态端口。
- 当前测试基线为 **49 个用例全部通过**。新增实现必须同时补协议格式、住宅校验、动态端口和敏感信息脱敏测试。
- 生产安装仍建议使用 Control Plane 生成的十分钟一次性安装命令；安装令牌不写入普通日志，Node Manager API Token 仅通过环境/配置注入。
