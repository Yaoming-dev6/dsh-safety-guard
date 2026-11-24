# DSH Safety Guard 1.0.2

[English](./README.en.md) · [MIT](./LICENSE) · [更新记录](./CHANGELOG.md)

非官方插件。**DSH Safety Guard** 是 DeepSeek Harness 的第三方配置保护工具：改前留快照，改后查差异，改坏了可离线恢复。它还能自检关键配置、提示异常改动，默认只告警、不拦截。它防的是配置误改，不是应用闪退或卡死，也不能替代你自己的备份。

初次使用请保持 `warn`。安装前请核对发布包的 SHA-256，并保留 `.tgz`（DSH 可能把它记录为本地依赖）。详见[安装与恢复](./INSTALL.md)。

## 适用与已验证范围

- 目标版本：DSH **0.2.2-rc.5**（`package.json` 声明 `>=0.2.2-rc.5 <0.2.3-0`），Node.js **24.9 或更高**。
- 原附件说明称已在 Windows / DSH Desktop 0.2.2-rc.5 / Node.js 24.21.0 验证热加载、只读面板、自检和快照预览；恢复写回在隔离配置验证。**本仓库维护者未在本轮复测 Windows。**
- **macOS 隔离测试（2026-11-23，Asia/Shanghai）：** 在 DSH 0.2.2-rc.5 上，用自带 Node 24.21.0 和系统 Node 25.8.0，对官方 `test/safety.test.mjs`（源码包与安装 tarball 各一遍）均为 5/5 通过。在隔离 `DSH_HOME` 中验证了安装、自检、快照、差异、默认告警、工具内只读恢复预览、离线脚本恢复、非法目标与损坏备份拒绝，以及卸载。隔离通过不能写成真实宿主通过。
- **macOS 真实 Desktop（2026-11-24，Asia/Shanghai）：** 在确认任务看板「运行中 0」、无未保存编辑后，正常退出 DSH（未强制结束进程），用包内 `maintenance.mjs install --home ~/.dsh --profile desktop --apply` 写入 `desktop` profile 并保留启用。随后重新打开 DSH Desktop 0.2.2-rc.5，插件完成启动基线（7 个监控文件），`GET /dsh-safety/status` 返回 1.0.2，健康度为 yellow（自检 14/15），`guardMode` 为 `warn`，未声明改动 0，相对基线变化 0；只读面板 `/dsh-safety/panel` 可打开；`POST /dsh-safety/status` 为 405，不存在 `/dsh-safety/action`。自检未通过的一项是可选文件 `storages/schedule.json` 不存在（黄，文案为「第一次启动？」），不是安装失败。现有 PTC 委派预设所在的 `cordis.patch.yml` 哈希未变；同一 `DSH_HOME` 下的 acp / headless / web 清单与补丁哈希未变。本轮未通过模型会话调用 `safety_*` 工具（避免调用付费模型）；工具与只读 HTTP 在同一 `apply()` 中注册。未在真实 profile 上做恢复写回（工具只预览；写回须退出 DSH 后用离线脚本，隔离环境已测过）。
- 本机这次未能走通官方「插件 → 添加插件 → 安装第三方插件」：rc.5 桌面布局里「插件」控件出现在辅助功能树中，但高度为 1 像素且被遮挡，无法完成界面安装。因此改用上面的离线安装路径。其他机器若界面可用，仍以官方插件界面为推荐方式。
- Mac 上 `lib/core.js` 的 `nodeExe()` 会先找 Windows 文件名 `node.exe`；本机该路径不存在。同一目录下有可执行的 `node`（v24.21.0）。应用包里的 `runtime/bin/node` 包装脚本在本机无法 exec，应使用 `runtime/primary-runtime/dependencies/node/bin/node`，或 `~/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/node/bin/node`。JS 语法预演（`safety_preflight`）未在真实宿主上单独实操。
- 不要把上述范围写成「已在全部平台验证」或「全部功能测试通过」。

## 安装

先核对 SHA-256。请保留 `.tgz`。初次使用请保持 `warn`。不要对正在运行的目标 DSH 执行 `--apply`。不要用 `dsh plugin ... add` 代替本插件提供的安装方式（那会转给 pnpm，也可能访问网络）。试装请使用独立的 `DSH_HOME`；只新建 profile 并不会隔离全局文件。

### 推荐：DSH 插件界面

在 DSH 打开「插件 → 添加插件 → 安装第三方插件」，输入本地 `dsh-safety-guard-1.0.2-dsh-rc5.tgz` 的完整路径，安装后点击「立即启用」。移除时请用同一插件管理器，不要和服务已关闭后的离线卸载脚本混用。

### 备选：离线脚本（必须先完全退出目标 DSH）

维护逻辑在跨平台的 `maintenance.mjs`。Windows 可用仓库里的 `install.ps1` / `uninstall.ps1` / `restore.ps1`（包装同一脚本，默认寻找 `node.exe`）。macOS 或 Linux 若没有可用的 PowerShell，直接调用 Node 24.9+：

```bash
unset NODE_OPTIONS NODE_PATH
# 使用真实的 Node 二进制（node -v 应能打印版本），例如：
NODE="$HOME/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/node/bin/node"
# 或 DeepSeek Harness.app 内的：
# ".../Contents/Resources/runtime/primary-runtime/dependencies/node/bin/node"
"$NODE" ./maintenance.mjs install --home "$HOME/.dsh" --profile desktop          # 预览
# 完全退出目标 DSH 后再写入：
"$NODE" ./maintenance.mjs install --home "$HOME/.dsh" --profile desktop --apply
```

只对需要保护的 profile 执行。安装后会留下 `package.json.bak-safety-<UUID>`，请保留。

## 使用要点

1. 用 `safety_status` 或只读页面 `/dsh-safety/panel` 查看状态。默认每 15 秒检查；未提供 Web 服务时只注册工具。
2. 修改前用 `safety_snap` 创建快照，建议用 `files` 指定：`profile.patch`、`profile.package`、`global.patch`、`global.agents`。对匹配的工具写入会开放约 30 分钟声明窗口。
3. 修改后用 `safety_check` 自检、`safety_verify` 对照快照。无差异不会改基线；确认变化后才用 `safety_verify {"accept":true}` 接受当前基线。
4. 要撤回时先用 `safety_restore` 预览，再退出 DSH 用离线脚本。恢复会先确认允许的目标并校验整份备份，然后另存原文件，逐个原子替换。多文件不是一个事务。工作区与调度存储只监测、不由本插件覆盖。旧版快照不会用来写回。离线恢复需要该 profile 下的本版（v2）快照；仅有首次启动基线、没有 `safety_snap` 状态文件时，恢复命令会报没有可回滚的快照。

默认 `guardMode: warn`，只记录已识别的写入，不阻止。外部进程和不易确认目标的路径不在事前拦截范围。数据在 `DSH_HOME/safety-guard/profiles/<profile>/`，同一 `DSH_HOME` 下的全局文件仍共享。快照含配置原文，勿公开分享；插件不自动清理。

## 首发仓库范围

拟公开仓库：`Yaoming-dev6/dsh-safety-guard`。首次内容为源码快照中的下列 20 个文件，不含旧 Git 历史，也不把可安装 `.tgz` 当作仓库主树（tgz 可作日后 Release 资产）。

**包含** `.github/workflows/test.yml`：仅在 `windows-latest` 上以 `contents: read` 运行 `node --test test/safety.test.mjs`，动作为 pinned 的 `actions/checkout` 与 `actions/setup-node`，Node 24.21.0，`persist-credentials: false`。不调用外部付费测试，也不应再为此工作流配置额外秘密或扩大权限。

许可证为 MIT，版权行保持 `Copyright (c) 2026 dsh-safety-guard contributors`，不要改成未经核验的其他署名，也不要补未经核验的上游版权行。

不要把真实 `DSH_HOME` 配置、快照、审计日志、本机私有路径或测试残留放入仓库。

详见 [安装与恢复](./INSTALL.md) 和 [回归测试](./test/safety.test.mjs)。遵循 [MIT](./LICENSE)。
