# 主节点 sing-box r3 切换记录（2026-10-28）

- 范围：生产主节点 6。备用节点已弃用，没有参与切换。
- 新核心：`/usr/local/libexec/sing-box-niusu-r3`，版本 `1.13.18-niusu-runtime-20261028-r3`，SHA-256 `9c8d93bef60c25039df9dcf5e0d92daede13d1bdae535563dbea72eb4d935547`。
- Node Manager：`/opt/node-manager-releases/runtime-r3-20261028-01/node-manager/main.py`，通过 `/run/sing-box/users.sock` 更新单进程运行时。
- 新连接已直接进入主服务的 VLESS 20168 端口；旧的 `NIUSU_VLESS_ACTIVE` NAT 跳转已撤除。旧代进程独立运行，已有连接继续排空。
- `/etc/systemd/system/niusu-old-vless-drain.timer` 每五分钟调用 `ops/drain_old_generations.py`。脚本校验新核心、运行时 socket、NAT 路由和旧引导服务状态，并使用原有双重连接及原生 socket 检查，仅停用确认为空的旧代进程。切换时 32 个旧代进程均有连接，首次检查未停用任何一个。
- 旧引导服务 `niusu-vless-publication-bootstrap.service` 已禁用；Node Manager 的新 drop-in 清除了旧发布模式环境变量和该服务依赖。
- 进程归属复核：除主核心与 32 个旧 VLESS 代进程外，另有 10 个 `niusu-wireguard-proxy` 进程服务 WireGuard 链路，属于独立业务，不纳入 VLESS 排空。
- 测试：生产真实配置在隔离网络命名空间中通过启动、预览和无变更 CAS；正式切换后，运行时状态和 Node Manager 健康检查成功；通过 `/api/singbox/tasks` 创建并删除隔离测试用户，两个任务均成功，注册表和 VLESS 配置均无残留。

旧连接数和进程数可通过 `output/full-node-release-20261028/verify_node6.py` 复核。排空状态保存在 `/opt/node-manager-releases/runtime-r3-20261028-01/old-generation-drain.json`。不要根据进程存在就手动强制结束；旧连接未归零时停止进程会断开用户连接。
