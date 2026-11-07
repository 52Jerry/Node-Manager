共享节点用户面板
================

用途
用户独立注册、登录，在一个账号下创建多条命名连接。
每条连接分别生成 VLESS / VMess / SOCKS5，拥有独立 UUID、SOCKS 凭据、有效期、流量及住宅出口配置。
页面统一使用“默认出口”“住宅代理”等名称，公开页面不展示地区和底层链路信息。
未配置上游时从香港直接出网；用户可填写自己的公网 SOCKS5 上游，并恢复香港直出。
网页登录密码与代理密码分别管理。VLESS、VMess 使用 UUID；SOCKS5 使用用户名和密码。

本实例入口
网页：https://panel.aliproxy.cc.cd
代理：proxy.aliproxy.cc.cd
VLESS Reality：6666；VMess TCP：7777；SOCKS5 TCP：9999。
路径：用户 -> 深圳 150.242.80.15 -> WG1 深港专线 -> 香港 168.93.208.118。
新部署默认使用深港私网 ens19：深圳 172.16.80.15 → 香港 172.16.208.118。
深圳使用 6666/7777/9999 专用 DNAT/SNAT；香港只在私网地址监听，并限定深圳来源及本机健康检查。
不需要内网 WireGuard。已有实例需先迁移监听、转发、启动依赖和旧 20166 入口，再停内网隧道；不能直接删除网卡。
firewall.py 与 transport.py 需一并部署到入口脚本目录，部署参数支持 --entry-private、--exit-private、--interface。
网页、管理 API、Clash 指标 API 分别在香港 127.0.0.1 的 8090、8089、9091 监听。
Caddy 在香港提供 80/443 TCP 的 HTTPS 和自动证书，保留原有 UDP 443 服务。

隔离范围
源码在 Node Manager 仓库的 shared_manager/；没有接入官网的用户、订单或数据库。
部署目录 /opt/shared-node-manager，独立账户 JSON 文件，独立用户库、流量、幂等和配置锁。
服务：sing-box-shared、node-manager-shared、shared-node-portal、shared-node-web。
香港规则持久化服务 shared-node-firewall；深圳规则持久化服务 shared-node-forward。
sing-box-shared 使用专属共享核心用户运行，出站新连接不允许访问服务器内网管理地址。
不启用原生产实例的多代 VLESS 发布模式，不读取原生产状态文件。

默认策略
每条新连接有效期 30 天，该连接的三协议默认合计 300 GiB，最多 3 个活跃来源 IP。
用户创建时可输入流量额度，之后也可单独修改；支持正数和小数，修改额度不清零已用流量。
每账号最多 100 条连接；住宅代理单次批量导入最多 50 条。
支持地址:端口:账号:密码、SOCKS5 URI、名称/地址/端口/账号/密码五列 CSV。
支持 TXT/CSV 文件、UTF-8 BOM 与 CRLF。预览不显示密码；导入逐行展示 READY/PENDING/FAILED。
住宅出口和认证身份在首次创建请求中一起提交，验证配置后才发布连接；失败项按原内容重试。
相同批次内容即使用新的客户端请求标识，也会复用先前连接和首次固定的解析地址。
连接删除先冻结并核对远端结果，确认后移出订阅；删除墓碑阻止旧请求重新创建身份。
来源 IP 是转发后节点实际可见的 IP，不是物理设备数；DNAT/SNAT 线路不能还原用户公网源 IP。
当前实例注册容量 1500 账号，包含现有、管理员及停用账号；达到上限后拒绝新注册。
注册、登录、连接生成和订阅请求有独立速率限制。
当前实例注册防刷为每来源 15 分钟 5 次、全站每 24 小时窗口 1500 次注册尝试。
账号订阅是 Base64 编码的所有可用连接协议链接，每条连接贡献三行，适用于 V2Ray 类客户端。
连接名称同步用于客户端备注；重名时添加短标识区分，不暴露管理端节点标识。
原单连接账户、凭据、会话、住宅配置及订阅地址会原样迁移，原连接成为列表中的一条。
重置订阅仅更换订阅地址，不轮换已有代理凭据；旧订阅地址立即失效。
SOCKS5 入口当前实现并验收 TCP；没有提供 SOCKS5 UDP Associate 的公网动态端口转发。

配置
/opt/shared-node-manager/state/portal.env：面板原始密钥、Node Manager Token、域名和策略。
/opt/shared-node-manager/state/agent.yaml：独立 Node Manager 配置（JSON 是 YAML 的严格子集）。
/opt/shared-node-manager/config/sing-box.json：新核心配置、认证及用户出口。
portal.env 中可覆盖：
  SHARED_ORIGIN=https://panel.aliproxy.cc.cd
  SHARED_DATABASE=/opt/shared-node-manager/state/portal/accounts.json
  SHARED_REGISTRATION_ENABLED=true
  SHARED_REGISTRATION_DAILY_ATTEMPTS=1500
  SHARED_LIFETIME_DAYS=30
  SHARED_TRAFFIC_LIMIT_BYTES=322122547200
  SHARED_MAX_SOURCE_IPS=3
  SHARED_MAX_ACCOUNTS=1500
修改面板配置后，仅重启 shared-node-portal。策略默认值只影响新创建的连接身份。
当前公开注册开启；达到账号总上限后，已有账号可以继续登录，新注册返回名额已满。
SHARED_MAX_ACCOUNTS 控制账号总量，SHARED_REGISTRATION_DAILY_ATTEMPTS 控制每日尝试次数；
后者统计实际进入注册流程的请求，重复账号等失败尝试也会计入，窗口从首次尝试起算。
账号、密码只要求非空，不限制字符种类或长度；账号首尾空白自动去除，密码保留原样。
账号按小写形式保存和登录匹配，可使用中文、邮箱、符号或单个字符；注册确认密码须一致。
账户数据持久化到本机 accounts.json，无 MySQL 服务连接；文件只允许面板服务用户读写。
密码保存为带随机盐的哈希，节点身份、住宅代理密码和订阅令牌仍加密保存。
文件写入使用跨进程锁和原子替换，损坏文件不会被自动清空重建。
从原 SQLite 切换时先停面板并做私有备份，逐表核对后再切换 SHARED_DATABASE。
原 accounts.sqlite3 保留为迁移前备份，新面板不再向该文件写入。
SHARED_SECRET 用于加密已保存的节点身份与出口配置；保留原密钥和数据库的配套备份。
状态包含凭据，应只保存在受控目录；不要将实际状态目录或 env 提交到 GitHub。

本地启动
安装 shared_manager/requirements.txt 中依赖，设置 SHARED_SECRET、SHARED_AGENT_TOKEN、
SHARED_AGENT_URL、SHARED_ORIGIN 后，在仓库根运行：
  python -m uvicorn shared_manager.app:create_app --factory --host 127.0.0.1 --port 8090 --workers 1
本机预览可用 http://127.0.0.1:8090；公网注册登录使用 HTTPS。
面板通过 HTTP 访问新 Node Manager，管理 Token 只在服务器端使用，不发送给浏览器。
deploy.py 用于准备新的隔离安装目录，拒绝覆盖已有目录；不自动替换原实例。
firewall.py 使用带共享实例标记的精确规则，不清空系统现有规则。

面板 API
  GET    /api/me/profiles                         本账号连接列表
  POST   /api/me/profiles                         {name,idempotencyKey,trafficLimitBytes?} 创建并生成一组协议
  PATCH  /api/me/profiles/{id}                    修改连接名称
  DELETE /api/me/profiles/{id}                    删除本人连接
  GET/POST /api/me/profiles/{id}/connections      查询或重试生成本人连接的三协议
  GET/PUT/DELETE /api/me/profiles/{id}/upstream    查询、绑定住宅代理或恢复默认出口
  GET    /api/me/profiles/{id}/traffic             当前连接流量
  PATCH  /api/me/profiles/{id}/policy              {trafficLimitBytes} 修改该连接额度，不清零流量
  POST   /api/me/profiles/import/preview           {text} 脱敏预览
  POST   /api/me/profiles/import                   {text,idempotencyKey} 逐行导入
以下原接口保持兼容，connections/upstream/traffic 操作账号的默认连接：
  GET    /api/site                   公开站点名称与默认额度
  POST   /api/auth/register          注册并登录
  POST   /api/auth/login             账号密码登录
  POST   /api/auth/logout            退出并撤销会话
  GET    /api/me                     当前账号与 CSRF Token
  GET    /api/admin/users            管理员用户列表、全站及每用户连接统计
  GET    /api/me/connections         获取本人的三协议连接
  POST   /api/me/connections         幂等生成或取回本人连接
  GET    /api/me/traffic             本人的聚合流量与策略
  GET    /api/me/upstream            查询本人的上游配置，不返回上游密码
  PUT    /api/me/upstream            配置本人的公网 SOCKS5 上游
  DELETE /api/me/upstream            恢复香港直出
  GET    /api/me/subscription        查询已生成的订阅地址
  POST   /api/me/subscription        {"rotate":false} 创建/取回，true 重置
  GET    /subscription/{token}       持订阅令牌读取账号全部连接的三协议订阅
  GET    /health                    面板健康检查
  GET    /docs                      在线接口说明

需要会话的接口通过 HttpOnly Cookie 认证。所有写请求带 Origin，认证后的写请求还需
X-CSRF-Token，并使用 application/json。上游出口格式：
  {"server":"公网 IP 或域名","port":1080,"username":"可留空","password":"可留空"}

管理员视图
管理员登录后可进入“用户管理”，查看注册用户、注册时间、账号状态、每个用户的
连接总数、已生成、待生成和删除中数量；支持用户名搜索、分页和刷新。
全站统计不随用户名搜索改变。一条连接组包含 VLESS、VMess 和 SOCKS5 三种协议，
统计按连接组计算；已删除的连接不计入，删除尚未确认的连接单列为“删除中”。
权限持久化在独立账号数据库 users.is_admin，默认关闭；注册请求不能指定权限。
已授权现有账号 111。授权与撤销仅由服务端运维调用 Store.set_admin 对既有账号操作，
没有公开的提权接口。现有会话下一次请求即可识别权限变化，刷新页面显示入口。
GET /api/me 返回本账号 user.isAdmin；普通账号访问 /api/admin/users 返回 403，未登录返回 401。
列表参数：search 为最长 64 字符的用户名子串（% 和 _ 按字面搜索），page 为 1–1000000，
pageSize 为 1–100，默认 20。响应包含 summary、items、total、page、pageSize、totalPages。
此接口只读取账号元数据与连接数量，不解密节点配置，不调用节点，不提供其他用户的
登录密码、订阅令牌、代理认证信息或住宅代理配置。
上游认证须同时填写用户名和密码；域名在提交时验证并固定到公网地址，重试不重新解析。
新增 Node Manager 管理接口 POST /api/user/{userId}/direct，使用管理 Token、幂等键、
expectedUuid 和 expectedSocksUsername 双身份核对后恢复单用户直出。

常见状态
401：需要登录或登录失败。403：来源/CSRF 校验或账号访问受限。
409：用户配置冲突、账号受限、或节点未就绪。422：输入不符合要求。
429：频率或节点容量限制。503：节点暂不可用或变更待核对。
网络超时后可按原请求重试；服务复用已经持久化的身份和变更键，不生成另一套账号。

验证
本地测试：tests/test_shared_manager.py、test_shared_direct.py、test_shared_subscription.py、
test_shared_instance_isolation.py 与既有 test_provisioning_readiness.py。
真实上线和三协议出网证据保存于工作区 outputs/shared-node-manager-20261105/。
