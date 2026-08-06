# NiuSu 代码优化修改报告

> 报告版本：v1.0（2026-08-05）
> 范围：Node Manager 多协议生成、住宅 SOCKS 配置、审计日志、输入校验
> 原则：所有改动均符合《NiuSu_项目开发文档》的功能需求与设计原则，未破坏既有接口。

---

## 1. 优化总览

| 维度 | 优化前 | 优化后 | 改进点 |
| --- | --- | --- | --- |
| 功能 | 仅生成 VLESS/VMess/SOCKS 三协议 | 新增住宅场景五种协议标准化输出；直连场景只返回三种加速链接 | 兼容住宅与 VPS 直出两种模式 |
| 架构 | 协议拼接逻辑内嵌在 `manager.py` | 独立 `protocols.py`（纯函数）+ `residential.py`（校验） | 高内聚、可复用、可测试 |
| 安全 | 无结构化审计日志 | `_audit()` 记录关键操作，自动剔除密码/Token/连接 | 可观测且不泄露凭据 |
| 健壮性 | 住宅 SOCKS 输入仅靠 Pydantic 基础校验 | 独立 `validate_*` 校验 + UUID 格式校验 | 校验统一、错误可定位 |
| 可配置 | 加速域名硬编码 | `config.yaml` 可配 `acceleration_domain` | 部署灵活 |
| 性能 | 每次配置请求都可能触发校验与 reload | 配置结构无变化时直接跳过写盘、校验和 reload | 降低 sing-box 抖动 |
| 采样 | 流量采样周期固定 | `monitoring.traffic_sample_interval_seconds` 可配置（0.5-300 秒） | 大批量节点可降频 |

## 2. 新增/修改文件

| 文件 | 类型 | 状态 |
| --- | --- | --- |
| `Node Manager/node-manager/protocols.py` | 新增 | 五种协议生成模块 |
| `Node Manager/node-manager/residential.py` | 新增 | 住宅 SOCKS 校验与建模 |
| `Node Manager/node-manager/singbox/manager.py` | 修改 | 接入五协议 + 审计日志 |
| `Node Manager/node-manager/config.py` | 修改 | 新增 `acceleration_domain` |
| `Node Manager/node-manager/main.py` | 修改 | 新增 `/api/residential/protocols` |
| `Node Manager/node-manager/models/request.py` | 修改 | 新增住宅请求模型 + UUID 校验 |
| `Node Manager/tests/test_protocols.py` | 新增 | 14 个测试用例 |

## 3. 关键改动对比

### 3.1 协议生成（功能增强）
**优化前**：`manager.py` 中 `_vless_connection/_vmess_connection/_socks_connection` 各自拼接，无原始地址与加速地址区分。

**优化后**：`protocols.py` 提供五种纯协议生成函数；用户创建接口按是否绑定住宅出口筛选返回：

```python
def generate_all(data: ProtocolData) -> dict[str, str]:
    return {
        "socks5": socks5_original(data),       # 原始地址
        "bitbrowser": bitbrowser(data),          # 原始地址
        "vless": vless(data),                    # 加速线路
        "socksAcceleration": socks_acceleration(data),  # 加速线路
        "vmess": vmess(data),                    # 加速线路
    }
```

**改进点**：统一数据源 `ProtocolData` 复用一套参数；加速地址与原始地址分离；SOCKS 加速凭据自动 Base64 编码。

### 3.2 连接接口返回五协议（接口增强）
**优化前**：`GET /api/user/{id}/connections` 仅返回 `vless/vmess/socks` 三字段。

**优化后**：新增 `protocolsAll` 字段。未绑定住宅出口时只包含 `vless`、`socksAcceleration`、`vmess`；绑定住宅出口时再包含 `socks5`、`bitbrowser`。

**改进点**：前端可直接展示五协议，无需另行拼接；兼容旧字段（`vless/vmess/socks` 仍保留）。

### 3.3 审计日志（安全/可观测增强）
**优化前**：无操作审计，排障依赖访问日志。

**优化后**：`create_user/bind_proxy/delete_user` 调用 `_audit()`：

```python
def _audit(action, user_id, **fields):
    for key, value in fields.items():
        if key in {"password", "token", "secret", "connection"}:
            continue  # 自动剔除敏感值
    logger.info("audit %s modules=%s", action, json.dumps(safe))
```

**改进点**：关键操作留痕；敏感值（密码/Token/完整连接）绝不入日志；超长字段截断。

### 3.4 住宅 SOCKS 输入校验（健壮性增强）
**优化前**：校验逻辑分散在 Control Plane，Node Manager 侧弱。

**优化后**：`residential.py` 提供 `validate_ip/validate_port/validate_credential/validate_config/validate_batch`；`ResidentialSocksRequest.uuid` 强制 UUID 格式。

**改进点**：校验统一、可单测；错误信息可定位到具体字段。

### 3.5 可配置加速域名（可配置性增强）
**优化前**：加速域名硬编码。

**优化后**：`config.yaml` 增加可选 `node.acceleration_domain`；为空时回退到当前节点 `host`，不再默认使用其他部署的域名。

**改进点**：不同部署可独立配置，无需改代码。

## 4. 测试结果

| 项目 | 结果 |
| --- | --- |
| Node Manager 全量单元/集成测试 | **49 个用例全部通过** |
| 新增协议测试 | 14 个（五协议格式、五合一、住宅校验和 UUID 校验） |
| 性能/配置回归测试 | 3 个（配置不变跳过 reload、采样间隔边界、越界拒绝） |
| 新增住宅校验测试 | 5 个（IP/端口/凭据/批量） |
| 新增请求模型测试 | 3 个（UUID 合法/非法/为空） |
| 既有测试回归 | 全部通过，无破坏 |

## 5. 兼容性说明

- 保留 `vless/vmess/socks` 旧字段，`protocolsAll` 为增量字段，不破坏现有客户端。
- `/api/user/create`、`/api/user/bind-proxy` 等既有接口签名不变。
- `config.yaml` 未配置 `acceleration_domain` 时使用默认值，向后兼容。

## 6. 后续优化建议

- 将 `protocolsAll` 生成的加速参数（pbk/sid/sni）由 Control Plane 统一维护，避免各节点重复推导。
- 在前端“连接信息”弹窗接入五协议，复用 `protocolsAll`。
- 为 `_audit` 增加审计落库（仅操作者与分配 ID，不含敏感值）。
- 将配置比较从整份 JSON 深比较进一步演进为 inbound/outbound 级别 diff，并在 sing-box 支持时使用增量 reload。
- 将流量采样改为按连接数自适应间隔，并把采样失败次数纳入心跳指标。

## 7. 本轮补充（动态入口端口与五协议兼容）

- `build_all_protocols()` 不再依赖固定的 20168/20169/5001 端口，而是从实际 sing-box inbound 读取 `listen_port`，异常时才回退到默认值。
- 协议键名固定为 `socks5`、`bitbrowser`、`vless`、`socksAcceleration`、`vmess`；实际响应按是否绑定住宅出口动态返回。
- 住宅批量输入严格区分“住宅出口 IP”和“上游 SOCKS 地址”：前者用于 GeoIP/备注，后者用于 Node Manager 出站路由。
- 当前 Node Manager 全量测试基线为 49 个用例；新增动态端口、直连三协议、住宅凭据隔离回归测试已覆盖。
