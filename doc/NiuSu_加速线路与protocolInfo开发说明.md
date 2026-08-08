# NiuSu Node Manager 加速线路与 protocolInfo 结构化参数开发说明

> 版本：v1.0（2026-08-05）
> 适用范围：Node Manager（Python FastAPI）+ Control Plane（前端拼接）
> 依据：《IPVelo_代理连接信息生成分析文档》11.9 节参数清单。
> 代码：`Node Manager/node-manager/protocols.py`、`singbox/manager.py`、`config.py`

---

## 1. 概述

Node Manager 为每个节点用户返回两类连接信息：

1. **兼容链接**（`vless` / `vmess` / `socks` / `protocolsAll`）：完整 URI，供旧版 Control Plane 直接使用。
2. **结构化参数**（`protocolInfo`）：一组参数，供前端按协议模板**本地拼接** VLESS、VMess、SOCKS 等链接，与 IPVelo 的前端动态生成方式一致。

两者统一使用**同一个加速地址**，保证兼容性与一致性。

---

## 2. acceleration_domain 配置说明

### 2.1 配置位置
`Node Manager/node-manager/config.yaml`：

```yaml
node:
  id: tokyo-01
  host: auto
  # 加速线路对外公网地址。支持：域名、IPv4、IPv6。
  acceleration_domain: ""
```

### 2.2 支持的值与回退规则
| 值类型 | 示例 | 说明 |
| --- | --- | --- |
| 域名 | `proxy.tkip.xin` | 直接作为 VLESS/VMess/SOCKS 的 `add`/`host` |
| IPv4 | `198.13.46.231` | 直接使用 |
| IPv6 | `2001:db8::10` | 生成 URI 时自动加方括号 `[2001:db8::10]` |
| 空（未配置） | `""` | 回退到 `node.host`（自动获取的公网 IP） |

### 2.3 IPv6 格式化
`singbox/manager.py::_uri_host()`：

```python
def _uri_host(value: str) -> str:
    raw = str(value or "").strip()
    if ":" in raw and not raw.startswith("["):
        return f"[{raw}]"
    return raw
```

- 含 `:` 且未加 `[` → 自动加方括号（视为 IPv6）。
- 域名/IPv4 不变。
- VLESS、SOCKS 加速链接用 `_uri_host()`；VMess 的 JSON `add` 字段直接用原始地址。

---

## 3. protocolInfo 字段完整清单

由 `protocols.py::protocol_info()` 生成，键为 camelCase。

### 3.1 通用字段（所有协议共用）
| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 协议标识，优先为节点用户 UUID（`user_uuid`） |
| `ip` | string | 本地节点地址（加速域名或 host） |
| `port` | integer | 本地端口（SOCKS 原始） |
| `username` / `password` | string | **本地节点用户** SOCKS 凭据（非上游住宅凭据） |
| `countryCode` / `countryName` / `cityName` | string | 地区信息 |
| `status` / `expireTime` / `remark` | — | 状态与备注 |

### 3.2 加速线路共用
| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `accelerationDomain` | string | 加速公网地址（域名/IPv4/IPv6） |
| `uuid` | string | VLESS/VMess 用户 UUID |
| `accelerationPortSocks` | integer | SOCKS 加速端口 |

### 3.3 VLESS 专属
`vlessPort`、`vlessEncryption`、`vlessSecurity`、`vlessSni`、`vlessFp`、`vlessPbk`、`vlessSid`、`vlessSpx`、`vlessType`、`vlessHeaderType`、`vlessFlow`

### 3.4 VMess 专属
`vmessPort`、`vmessV`、`vmessAid`、`vmessScy`、`vmessNet`、`vmessType`、`vmessHost`、`vmessPath`、`vmessTls`、`vmessSni`、`vmessAlpn`、`vmessFp`

### 3.5 原始地址（仅住宅节点）
`rawPort`、`rawProtocol`（= `socks5`）

---

## 4. 直连节点与住宅节点的协议差异

| 场景 | 返回的协议 | protocolInfo 是否含 raw* |
| --- | --- | --- |
| **直连节点**（未绑定上游住宅 SOCKS） | 仅 **3 种加速**：VLESS、SOCKS 加速、VMess | 否（`rawPort/rawProtocol` 被移除） |
| **住宅节点**（已绑定住宅 SOCKS） | **5 种**：VLESS、SOCKS 加速、VMess + **SOCKS5 原始、BitBrowser** | 是 |

判断逻辑（`build_all_protocols`、`build_protocol_info`）：
- `include_original = proxy is not None`（create_user）或 `proxyBound`（list_users）。
- 仅当 `include_original and socks is not None` 时追加 SOCKS5 原始 + BitBrowser。

---

## 5. 凭据安全约定

- `protocolInfo.username/password` 与 `protocolsAll` 中的凭据，**都是本地节点用户的 SOCKS 凭据**，不是上游住宅 SOCKS 凭据。
- 上游住宅代理账号/密码**只用于 per-user outbound**（`_set_proxy_binding`），绝不进入任何公开节点链接。
- 该约定由测试 `test_proxy_credentials_are_used_only_by_outbound` 强制保证。

---

## 6. 前端拼接链接示例

前端拿到 `protocolInfo` 后本地拼接（不需要额外请求）：

```javascript
// VLESS 加速
const vless = `vless://${p.uuid}@${bracket(p.accelerationDomain)}:${p.vlessPort}` +
  `?encryption=${p.vlessEncryption}&security=${p.vlessSecurity}` +
  `&sni=${p.vlessSni}&fp=${p.vlessFp}&pbk=${p.vlessPbk}&sid=${p.vlessSid}` +
  `&spx=${p.vlessSpx}&type=${p.vlessType}&headerType=${p.vlessHeaderType}` +
  `&flow=${p.vlessFlow}#${encodeURIComponent(p.remark)}`;

// SOCKS 加速（账号密码 Base64）
const socksAcc = `socks://${b64(p.username)}:${b64(p.password)}` +
  `@${bracket(p.accelerationDomain)}:${p.accelerationPortSocks}#${p.remark}`;

// VMess 加速
const vmessConfig = {
  v: p.vmessV, ps: p.remark, add: p.accelerationDomain, port: String(p.vmessPort),
  id: p.uuid, aid: p.vmessAid, scy: p.vmessScy, net: p.vmessNet,
  type: p.vmessType, host: p.vmessHost, path: p.vmessPath,
  tls: p.vmessTls, sni: p.vmessSni, alpn: p.vmessAlpn, fp: p.vmessFp,
};
const vmess = `vmess://${b64(JSON.stringify(vmessConfig))}`;

// 原始地址（仅住宅节点有 rawProtocol）
const socks5 = `socks://${p.username}:${p.password}@${p.ip}:${p.rawPort}#${p.countryCode}-${p.ip}`;
const bitbrowser = `${p.ip}:${p.rawPort}:${p.username}:${p.password}`;

function b64(s){ return btoa(unescape(encodeURIComponent(s))); }
function bracket(h){ return h.includes(':') && !h.startsWith('[') ? `[${h}]` : h; }
```

**推荐做法**：优先读取 Node Manager 已生成好的 `protocolsAll`（完整 URI），`protocolInfo` 用于需要自定义拼接或兼容老前端时。

---

## 7. 旧版 protocolsAll 的兼容策略

- `protocolsAll`（完整 URI 字典）**保留并继续返回**，键为 `socks5/bitbrowser/vless/socksAcceleration/vmess`。
- `vless` / `vmess` / `socks` 三个顶层 legacy 字段**保持兼容**；其中 `vless`、`vmess` 现复用 `protocolsAll` 的生成结果，保证与结构化参数一致。
- 旧版 Control Plane 无需改动即可继续使用 `protocolsAll`；新版可改用 `protocolInfo` 本地拼接。
- 结构化参数 `protocolInfo.id` 优先取节点用户 UUID（与 VLESS/VMess 的 `uuid` 一致）。

---

## 8. 回归测试覆盖

| 测试 | 验证点 |
| --- | --- |
| `test_direct_user_returns_only_three_acceleration_links` | 直连仅返回 3 种加速协议 |
| `test_structured_protocol_info_uses_configured_domain_and_uuid` | 域名进入链接、`id`=UUID、vmess 与 protocolsAll 一致 |
| `test_structured_protocol_info_supports_ipv6_acceleration_endpoint` | IPv6 生成 `[IPv6]:端口` |
| `test_protocol_info_contains_documented_fields_and_can_use_ipv6_endpoint` | 字段清单完整、IPv6 端点 |
| `test_protocol_info_can_include_original_fields_only_for_residential_mode` | 住宅才含 raw* 字段 |
| `test_proxy_credentials_are_used_only_by_outbound` | 上游凭据不出现在节点链接 |
| `test_socks_acceleration_uses_base64_credentials` | SOCKS 加速账号密码 Base64 |