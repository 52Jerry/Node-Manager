# Node Manager 文档导航

应用代码位于 `../node-manager/`，主要测试位于 `../tests/`；根目录 `install.sh` 是安装入口。节点 Agent 与官网是两个独立 Git 仓库，发布状态分别查对应记录。

| 说明 | 位置 |
| --- | --- |
| 功能、结构和运行方式 | [项目 README](../README.md) |
| API 接口 | [API 接口文档](../doc/API接口文档.md) |
| Python Agent 开发 | [开发文档](../doc/Python-Node-Manager-开发文档.md) |
| sing-box 设计 | [架构方案](../doc/singbox架构方案.md) |
| 发布包、恢复日志及流量去重 | [revision-and-traffic-accounting.md](revision-and-traffic-accounting.md) |
| sing-box 单进程用户更新接入 | [singbox-runtime-integration.md](singbox-runtime-integration.md) |
| 连接快照性能 | [connection-snapshot-performance.txt](connection-snapshot-performance.txt) |
| 来源 IP 限制 | [SOURCE_IP_LIMITS.md](SOURCE_IP_LIMITS.md) |

构建缓存、Python 缓存和运行日志由 `.gitignore` 排除；真实运行配置、Token、用户注册表和流量数据不能作为示例配置提交。现有未提交的节点整改代码保持原样。
