# WG 定向交付查询

完整发布记录见网站项目 `docs/EXPORT_LATENCY_DIAGNOSIS_20261023.md`。

## 接口契约

`GET /api/wireguard/peer-status?peerId=...&nodeUserId=...&includeRuntime=true`

沿用节点 Bearer 鉴权，成功响应 `Cache-Control: no-store`。两个身份参数仅接受 1–128 位字母、数字、点、下划线和连字符。`includeRuntime` 默认 true。

返回 `success`、`serverPublicKey`、`peers`（最多一个）、`accessByUser`（仅所请求用户）、`runtimeChecked`、`routingReady`、`recoveryReason`、`runtimeReason`。不包含私钥、SOCKS 凭据或出口指纹。peer 不存在或与 nodeUserId 不符时返回 HTTP 200、空 peers 和 false；并发文件变更重试后仍不稳定返回 HTTP 409；参数错误 422；未鉴权 401。

网站继续核对本地客户归属、订阅有效期、peer 及服务端公钥、内核状态、地址和远端到期时间。严格模式额外核对 routingReady 与 accessByUser。


节点预备目录：`/opt/node-manager-releases/wg-delivery-candidate-20261023-015209`。激活脚本未执行，需用户确认应用重启。
