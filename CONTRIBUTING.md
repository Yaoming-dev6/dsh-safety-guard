# 贡献指南

请使用独立的 DSH_HOME 或临时测试数据；不要拿日常配置验证破坏性操作。测试需 Node.js 24.9+，无须安装依赖：

    node --test test/safety.test.mjs

提交 PR 时，请说明系统、DSH 版本、行为变化和验证结果。只提交源码和合成测试数据，不要提交本机配置、鉴权信息、用户路径、日志、会话或快照。涉及安全问题，请先看[安全说明](./SECURITY.md)。

从仓库根目录可用 npm pack --ignore-scripts 生成本地 tarball。这不是 npm 发布命令；请用 DSH 插件管理器对新包做一次隔离试装再上传 Release。
