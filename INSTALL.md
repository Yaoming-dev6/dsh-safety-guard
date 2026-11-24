# 安装、验收、恢复和卸载

适用目标：DSH Desktop **0.2.2-rc.5**，使用自带 Node **24.21.0**；脚本要求 Node.js 24.9 或更高。不调用 pnpm 或访问网络。请保留解压后的 ZIP / 目录，DSH 起不来时也能执行恢复脚本。

Windows 可用下面的 PowerShell 包装脚本（不用管理员权限，也不要为运行脚本更改机器的全局执行策略）。macOS / Linux 请用同一目录里的 `maintenance.mjs`，不要指望 `*.ps1` 在没有 PowerShell 或 `node.exe` 的机器上直接可用。

## 推荐：通过 DSH 插件界面安装

1. 下载 Release 里的 `dsh-safety-guard-1.0.2-dsh-rc5.tgz`，核对发布的 SHA-256（Windows 可用 `Get-FileHash -Algorithm SHA256`，macOS / Linux 可用 `shasum -a 256` 或 `sha256sum`）。
2. 打开「插件 → 添加插件 → 安装第三方插件」，输入本地 `.tgz` 的完整路径，点「安装」→「立即启用」。请保留压缩包；DSH 可能把它记录为本地依赖。
3. 需要移除时使用同一插件管理器，不要混用下文的手动卸载脚本。离线恢复脚本在源码包里。

若「插件」入口在当前桌面布局里不可见或无法点击，不要强行点不可见控件。可在确认没有正在执行的任务和未保存编辑后，正常退出目标 DSH，再改用下面的离线安装。2026-11-24 在一台 macOS、DSH 0.2.2-rc.5 的 Desktop 上曾遇到「插件」控件在辅助功能树中高度为 1 像素且被遮挡，因而改用离线安装；这是该次布局观察，不是说所有机器都无法走界面。

## 备选：Windows 离线安装

先备份相应 profile 的清单和补丁。保守做法是用已经准备好、独立的 DSH_HOME 和测试数据做试装。仅新增一个 profile 不会隔离全局文件。下面只演示本机主环境；如果要测试，请将路径和 profile 名换成隔离环境的实际值。

```powershell
$dsh = Join-Path $env:USERPROFILE '.dsh'
.\install.ps1 -DshHome $dsh -Profile desktop          # 预览
# 完全退出 DSH（包括该实例的后台进程）后：
.\install.ps1 -DshHome $dsh -Profile desktop -Apply   # 确认安装
```

脚本复制本地包、备份并原子更新 profile 清单，不会覆盖同名现有安装。旧版如已安装，先用原方式卸载。非默认 Node 路径可显式传 `-Node 'C:\path\to\node.exe'`。

## 备选：macOS / Linux 离线安装

维护逻辑与 Windows 包装脚本相同，都进入 `maintenance.mjs`。请使用真实的 Node 二进制（`node -v` 能打印 24.9+），并先 `unset NODE_OPTIONS NODE_PATH`。常见路径：

- `$HOME/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/node/bin/node`
- DeepSeek Harness.app 内的 `Contents/Resources/runtime/primary-runtime/dependencies/node/bin/node`

不要使用某些应用布局里的 `Contents/Resources/runtime/bin/node` 包装脚本：2026-11-24 在一台 Mac 上该包装脚本无法 exec。`lib/core.js` 的 `nodeExe()` 会先查找 Windows 文件名 `node.exe`，在 Mac 上通常不存在；这主要影响 JS 语法预演，不影响 `maintenance.mjs` 安装本身。

```bash
unset NODE_OPTIONS NODE_PATH
NODE="$HOME/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/node/bin/node"
"$NODE" ./maintenance.mjs install --home "$HOME/.dsh" --profile desktop          # 预览
# 完全退出目标 DSH 后再写入：
"$NODE" ./maintenance.mjs install --home "$HOME/.dsh" --profile desktop --apply
```

只对目标 profile 传入 `--profile`。不要对仍在运行的目标实例执行 `--apply`。其他 profile、模型、网络代理和账号设置应保持不动。安装成功会留下 `package.json.bak-safety-<UUID>`，请保留。

## 启用后验收

- 用 `safety_status` 和 `safety_check` 确认出现工具、目标是正确 profile，辨认并解释所有自检异常。可选文件缺失（例如尚无 `storages/schedule.json`）可能使健康度为 yellow，需要对照详情判断，不能把它直接当成安装失败。
- 加载独立页面 `http://127.0.0.1:<DSH端口>/dsh-safety/panel`，确认只读状态；没有悬浮按钮、也没有网页写入口。`GET /dsh-safety/status` 应返回当前版本和 `guard.mode`（默认 `warn`）；对该路径的 POST 应被拒绝。
- 先保持 `warn`。用测试配置验证快照、差异、恢复和卸载。正式切换 `block` 前，观察是否干扰日常操作。不要在真实常用配置上为了演示而故意写坏文件。

2026-11-24 在一台 macOS 真实 Desktop 上：安装并重新打开后，只读面板与状态接口已按上面方式验收；`guardMode` 为 `warn`；相对首次启动基线无变化。该次未通过模型会话调用工具，也未对真实 profile 做恢复写回。

## 退出 DSH 后恢复

恢复只支持当前 profile 下本版（v2）快照以及内置清单内的目标。若尚未做过 `safety_snap`、目录里没有可回滚的状态文件，预览会提示没有快照。快照里当时不存在的文件**不会被删除**。目标当前文件保留为 `*.rollback-bad-<UUID>`，恢复有部分成功时先检查报告再操作。多文件不是一个事务。

Windows：

```powershell
.\restore.ps1 -DshHome $dsh -Profile desktop         # 对比最近快照，不写回
.\restore.ps1 -DshHome $dsh -Profile desktop -Apply  # 确认恢复
```

可以加 `-State` 指向预览的状态文件，避免重新选择“最近”快照。

macOS / Linux：

```bash
unset NODE_OPTIONS NODE_PATH
"$NODE" ./maintenance.mjs restore --home "$HOME/.dsh" --profile desktop
# 完全退出 DSH 后再写回：
"$NODE" ./maintenance.mjs restore --home "$HOME/.dsh" --profile desktop --apply
# 可选：--state /path/to/state.json
```

## 卸载

Windows：

```powershell
.\uninstall.ps1 -DshHome $dsh -Profile desktop
# 完全退出 DSH 后：
.\uninstall.ps1 -DshHome $dsh -Profile desktop -Apply
```

macOS / Linux：

```bash
unset NODE_OPTIONS NODE_PATH
"$NODE" ./maintenance.mjs uninstall --home "$HOME/.dsh" --profile desktop
# 完全退出 DSH 后：
"$NODE" ./maintenance.mjs uninstall --home "$HOME/.dsh" --profile desktop --apply
```

卸载会保留快照并为清单和旧插件目录保留备份。若安装后 DSH 无法重启，可在外部用上述命令卸载；如果 manifest 无法解析，退出 DSH 后，使用安装输出中的准确备份路径恢复原清单。
