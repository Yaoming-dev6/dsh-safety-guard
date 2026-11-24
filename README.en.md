# DSH Safety Guard 1.0.2

[简体中文](./README.md) · [MIT license](./LICENSE)

An unofficial configuration guard for DeepSeek Harness. Create snapshots of selected configuration files, check for unexpected changes, and recover offline. **It does not prevent app crashes or replace your backups.** Keep `warn` mode for first use. Verify the SHA-256 of the `.tgz` and keep the tarball in place if DSH records it as a local dependency.

## Verified scope

- Target: DSH **0.2.2-rc.5** (`>=0.2.2-rc.5 <0.2.3-0`) and Node.js **24.9+**.
- The original package notes describe Windows / DSH Desktop 0.2.2-rc.5 / Node.js 24.21.0 checks. **Windows was not retested in this release-prep pass.**
- On 2026-11-23 (Asia/Shanghai), official `node --test test/safety.test.mjs` passed 5/5 on macOS with DSH-bundled Node 24.21.0 and system Node 25.8.0, for both the source zip and the install tarball. Isolated `DSH_HOME` fixtures covered install, self-check, snapshots, diffs, default warn, preview-only restore, offline restore, illegal-target and damaged-backup rejection, and uninstall. Isolated results are not live-host results.
- On 2026-11-24 (Asia/Shanghai), after confirming no running task and no unsaved editor, DSH was quit normally (not force-killed) and the plugin was installed into the real `desktop` profile with `maintenance.mjs install --home ~/.dsh --profile desktop --apply`, then kept enabled. After reopen on DSH Desktop 0.2.2-rc.5: startup baseline of 7 watched files; `GET /dsh-safety/status` returned 1.0.2, health yellow (14/15 checks), `guardMode: warn`, 0 undeclared changes and 0 diffs versus baseline; `/dsh-safety/panel` is read-only; POST to the status route returns 405; `/dsh-safety/action` is absent. The failed check was the optional `storages/schedule.json` missing (yellow, “first start?”), not an install failure. The existing PTC preset in `cordis.patch.yml` was unchanged; `acp` / `headless` / `web` hashes in the same `DSH_HOME` were unchanged. `safety_*` tools were not invoked through a model session (no paid-model calls). Live restore writes were not performed.
- The official in-app plugin installer was tried first on that Mac. In this rc.5 desktop layout the Plugins control was present in the accessibility tree but 1 px tall and occluded, so the UI path could not be completed. Use the in-app installer where it is actually clickable; otherwise quit the target DSH and use `maintenance.mjs`.
- `nodeExe()` looks for `node.exe` first (a Windows filename). That path was absent on the test Mac; a `node` binary v24.21.0 exists in the same `dsh-runtimes` directory. The app wrapper `runtime/bin/node` failed to exec; use `runtime/primary-runtime/dependencies/node/bin/node` or `~/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/node/bin/node`. Live-host JS preflight was not exercised separately.
- Do not describe this as “verified on every platform” or “all features tested.”

## Install and recovery

In DSH, open Plugins → Add plugin → Install third-party plugin, paste the full local path of `dsh-safety-guard-1.0.2-dsh-rc5.tgz`, install, then enable. See the [installation and recovery guide (Chinese)](./INSTALL.md) for offline use.

On Windows, `install.ps1` / `uninstall.ps1` / `restore.ps1` wrap `maintenance.mjs` and look for `node.exe`. On macOS or Linux, call `maintenance.mjs` directly with Node 24.9+ after `unset NODE_OPTIONS NODE_PATH`. Never run `--apply` while the target DSH instance is still running.

Use `safety_check` or open `/dsh-safety/panel` on your local DSH server to check status. Use `safety_snap` before editing and `safety_verify` afterward. `safety_restore` previews only; after fully quitting DSH, use `restore.ps1` (Windows) or `maintenance.mjs restore` (macOS / Linux). Offline restore needs a v2 snapshot from `safety_snap`; a first-boot baseline alone is not enough.

The default `warn` mode logs recognized writes without blocking them. External programs are not intercepted. Workspace and schedule storage are monitored, not restored. Backups may contain sensitive configuration and must not be published. See the [security policy](./SECURITY.md).

## First-release tree

The intended public repository is `Yaoming-dev6/dsh-safety-guard`. The first snapshot is the 20 source files listed in the Chinese README, with no prior Git history. **`.github/workflows/test.yml` is included:** it runs `node --test test/safety.test.mjs` on `windows-latest` with `contents: read` only, pinned actions, Node 24.21.0, and `persist-credentials: false`. It does not call paid external tests and should not be given extra secrets or wider permissions.

The MIT license copyright line stays `Copyright (c) 2026 dsh-safety-guard contributors`. Do not invent additional copyright lines.

Run `node --test test/safety.test.mjs` with Node.js 24.9+ from the repository root. The tests use temporary fixtures, not your everyday DSH profile. They are not a full desktop integration test.
