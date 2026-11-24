/**
 * dsh-safety-guard · 服务端插件（随 DSH 启动自动加载，不依赖 skill）
 *
 * 做了什么：
 *  P0 ① 关键配置改动检测（未声明就报警，含 change-gate 审计联动）
 *  P0 ② 启动自检（patch YAML/编码/结构、bundles 数量与解析、workspace/schedule JSON）
 *  P0 ③ 状态可查：safety_status 工具 + GET /dsh-safety/status
 *  P1 ④ 快照 / 校验 / 回滚：safety_snap / safety_verify / safety_restore（含读 change-gate 老 state）
 *  P1 ⑤ 写保护：工具调用层拦截对受保护文件的写（默认 block，机制不支持时自动退化为事后报警）
 *  P2 ⑥ G0–G3 分级：safety_gate
 *  P2 ⑦ 危险动作预演：safety_preflight（YAML/JSON/JS 语法，只写临时文件）
 *
 * 插件纪律：apply 里任何异常都不许抛给宿主；工具必须能在「什么都没有」的环境里返回可读的错误。
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import * as core from './core.js'

export const name = 'dsh-safety-guard'
export const inject = ['tools']
export { core }

const PLUGIN_DIR = path.resolve(fileURLToPath(new URL('..', import.meta.url)))
const DEFAULTS = {
  watchMs: 15000,
  profileName: 'auto', // 自动探测当前 profile；也可显式写 profiles 下的目录名
  guardMode: 'warn', // warn | block | off
  watch: true,
}
const textBlock = (s) => [{ type: 'text', text: String(s) }]

export function apply(ctx, config) {
  try { return mount(ctx, config) } catch (err) {
    try { ctx.logger?.warn('[safety] 插件未启动：' + String(err.message || err)) } catch {}
  }
}

function mount(ctx, config) {
  const cfg = Object.assign({}, DEFAULTS, config || {})
  if (!['warn', 'off', 'block'].includes(cfg.guardMode)) cfg.guardMode = 'warn'
  const home = path.resolve(core.dshHome())
  const profileName = core.profileId(!cfg.profileName || cfg.profileName === 'auto' ? core.detectProfileName(home) : cfg.profileName)
  const profileDir = core.profileDirOf(home, profileName)
  const dataDir = core.dataDir(home, profileName)
  const baselinePath = path.join(dataDir, 'baseline.json')
  const intentPath = path.join(dataDir, 'intent.json')
  const gateDir = path.join(home, 'patch-guard', 'gate')

  const st = {
    startedAt: Date.now(),
    lastError: null,
    lastStatus: null,
    lastSig: '',
    lastDriftSig: '',
    baseline: null,
    checkCache: { key: '', value: null },
    timer: null,
    guardBlocked: 0,
    guardWarned: 0,
    actions: 0,
    ticks: 0,
  }

  const files = () => core.criticalFiles({ home, profile: profileDir })
  const snapshotOpts = () => ({ home, profile: profileName, files: files() })
  const log = (msg) => { try { ctx.logger && ctx.logger.info && ctx.logger.info('[safety] ' + msg) } catch { /* ignore */ } }
  const audit = (rec) => { try { core.appendAudit(home, rec, profileName) } catch { /* ignore */ } }

  // ---------------- 基线
  function loadBaseline() {
    try {
      const r = core.readTextFile(baselinePath)
      if (!r.ok) return null
      const j = core.safeJson(r.text)
      if (!j.ok || !j.value || !Array.isArray(j.value.files)) return null
      return j.value
    } catch { return null }
  }

  function pkgBundles() {
    try {
      const r = core.readTextFile(path.join(profileDir, 'package.json'))
      if (!r.ok) return { bundles: [], deps: [] }
      const j = core.safeJson(r.text)
      const b = j.ok && j.value && j.value.dsh && j.value.dsh.profile && j.value.dsh.profile.bundles
      return { bundles: Array.isArray(b) ? b.map(String) : [], deps: j.ok && j.value && j.value.dependencies ? Object.keys(j.value.dependencies) : [] }
    } catch { return { bundles: [], deps: [] } }
  }

  function writeBaseline(label, note) {
    const manifest = core.buildManifest(files(), { reason: String(label || 'baseline'), note: String(note || '') })
    const pkg = pkgBundles()
    manifest.pkg = { bundles: pkg.bundles, deps: pkg.deps, at: core.nowIso() }
    core.ensureDir(dataDir)
    core.atomicWrite(baselinePath, JSON.stringify(manifest, null, 2))
    st.baseline = manifest
    return manifest
  }

  function ensureBaseline() {
    if (st.baseline) return st.baseline
    const b = loadBaseline()
    if (b) { st.baseline = b; return b }
    const created = writeBaseline('install', '插件首次启动，把当前配置记为基线')
    audit({ kind: 'BASELINE-INIT', at: created.at, files: created.files.length })
    log(`初始基线：${created.files.length} 个文件`)
    return created
  }

  // ---------------- 状态计算
  function cacheKey() {
    const parts = []
    for (const f of files()) {
      try { const s = fs.statSync(f.path); parts.push(f.key + ':' + s.size + ':' + Math.round(s.mtimeMs)) } catch { parts.push(f.key + ':-') }
    }
    return parts.join('|')
  }

  function checksFor(baseline) {
    const key = cacheKey()
    if (st.checkCache.key === key && st.checkCache.value) return st.checkCache.value
    const value = core.selfCheck({
      home, profile: profileDir, pluginDir: PLUGIN_DIR,
      requiredBundles: cfg.requiredBundles,
      baselinePkg: baseline && baseline.pkg ? baseline.pkg : null,
    })
    st.checkCache = { key, value }
    return value
  }

  function computeStatus(opts) {
    const baseline = ensureBaseline()
    const current = core.buildManifest(files(), {})
    const gate = core.readGateLog(home)
    const records = gate.records.concat(core.ownGateRecords(home, profileName))
    const changes = core.assessChanges({ baseline, current, records, pendingMs: core.PENDING_GRACE_MS })
    const checks = checksFor(baseline)
    const health = core.healthOf({ checks: checks.checks, changes, hasBaseline: !!baseline, lastError: st.lastError })
    const lastBackup = core.latestState(home, profileName) || core.latestGateBackup(gateDir)
    const lastGate = gate.records.length ? gate.records.reduce((a, b) => (b.atMs > (a && a.atMs || 0) ? b : a), null) : null
    st.lastStatus = {
      v: 1,
      tool: core.TOOL,
      version: core.VERSION,
      at: core.nowIso(),
      pid: process.pid,
      startedAt: st.startedAt,
      uptimeMs: Date.now() - st.startedAt,
      profileDir,
      dataDir,
      watchMs: Math.max(2000, Number(cfg.watchMs) || 15000),
      health: { level: health.level, reasons: health.reasons },
      checks: { total: checks.total, passed: checks.passed, ok: checks.ok, failed: checks.failed },
      changes: {
        counts: changes.counts,
        hasUndeclared: changes.hasUndeclared,
        worstUndeclared: changes.worstUndeclared,
        undeclared: changes.undeclared.map((i) => ({ key: i.key, label: i.label, path: i.path, status: i.status, severity: i.severity, at: i.at, sha256: i.sha256, evidence: i.evidence })),
        pending: changes.pending.map((i) => ({ key: i.key, label: i.label, path: i.path, status: i.status, at: i.at, evidence: i.evidence })),
        declared: changes.declared.map((i) => ({ key: i.key, label: i.label, path: i.path, status: i.status, at: i.at, evidence: i.evidence })),
        drifted: changes.drifted.map((i) => ({ key: i.key, label: i.label, path: i.path, status: i.status, grade: i.grade, gradeDetail: i.gradeDetail, at: i.at, sha256: i.sha256, hotStats: i.hotStats })),
        items: changes.items,
      },
      gate: lastGate ? { at: lastGate.at, file: lastGate.file, verdict: lastGate.verdict, label: lastGate.label, kind: lastGate.kind, ageMs: Date.now() - lastGate.atMs } : null,
      gateLog: { file: gate.file, ok: gate.ok, records: gate.records.length, error: gate.error },
      backup: lastBackup ? { at: lastBackup.at, label: lastBackup.label, statePath: lastBackup.statePath, ageMs: Date.now() - (lastBackup.atMs || 0) } : null,
      guard: { mode: cfg.guardMode, blocked: st.guardBlocked, warned: st.guardWarned },
      errors: st.lastError ? [st.lastError] : [],
      bootedAt: st.bootedAt || null,
    }
    return st.lastStatus
  }

  // ---------------- 定时检测 + 报警
  function tick() {
    try {
      st.ticks++
      const prev = st.lastStatus
      const s = computeStatus()
      const sig = s.changes.undeclared.map((i) => i.key + ':' + i.sha256).join('|')
      if (sig !== st.lastSig) {
        if (sig) {
          audit({ kind: 'UNDECLARED', items: s.changes.undeclared.map((i) => ({ label: i.label, path: i.path, status: i.status, severity: i.severity })) })
          log(`发现未声明改动：${s.changes.undeclared.map((i) => i.label).join(', ')}`)
        } else if (st.lastSig) {
          audit({ kind: 'CLEARED' })
        }
        st.lastSig = sig
      }
      // 热文件的正常变化单独记一条：它不该刷「未声明」，但值得留痕
      const driftSig = s.changes.drifted.map((i) => i.key + ':' + i.sha256).join('|')
      if (driftSig !== st.lastDriftSig) {
        if (driftSig) {
          audit({ kind: 'DRIFT', items: s.changes.drifted.map((i) => ({ label: i.label, grade: i.grade, detail: i.gradeDetail })) })
          log(`热文件正常变化（结构完好）：${s.changes.drifted.map((i) => i.label).join(', ')}`)
        }
        st.lastDriftSig = driftSig
      }
      if (!prev || prev.health.level !== s.health.level) {
        audit({ kind: 'HEALTH', from: prev ? prev.health.level : null, to: s.health.level, reasons: s.health.reasons.slice(0, 6) })
      }
    } catch (err) {
      st.lastError = String(err && err.message || err)
      audit({ kind: 'ERROR', where: 'tick', error: st.lastError })
    }
  }

  // ---------------- 写保护
  function hasFreshIntent(target) {
    try {
      const r = core.readTextFile(intentPath)
      if (r.ok) {
        const j = core.safeJson(r.text)
        const rec = j.ok && j.value ? j.value[core.normPath(target)] : null
        if (rec && Date.now() - Number(rec.atMs || 0) <= core.INTENT_TTL_MS) return true
      }
    } catch { /* ignore */ }
    try {
      for (const n of fs.readdirSync(gateDir)) {
        if (!/\.json$/i.test(n) || /\.content\./i.test(n)) continue
        const file = path.join(gateDir, n)
        const s = fs.statSync(file)
        if (Date.now() - s.mtimeMs > core.INTENT_TTL_MS) continue
        const r = core.readStateFile(file)
        if (r.ok && (r.state.files || []).some((f) => core.normPath(f.path) === core.normPath(target))) return true
      }
    } catch { /* gate 目录不在 = 没声明 */ }
    return false
  }

  function guardTool(exec) {
    try {
      if (!exec || !core.WRITE_TOOLS.has(String(exec.name || ''))) return undefined
      const args = exec.arguments ?? exec.args ?? exec.input ?? exec.parameters
      if (args == null) return undefined
      const hit = core.matchProtected(args, files().filter(core.isRestorable), exec.name)
      if (!hit) return undefined
      if (hasFreshIntent(hit.path)) return undefined
      const msg = '【dsh-safety-guard】' + hit.label + ' 是受保护配置，改它之前先声明：先 safety_snap {"label":"改什么"}（或你本机的 change-gate 走 begin/verify），改完 safety_verify 并贴 DECLARE。'
      if (cfg.guardMode === 'block') {
        st.guardBlocked++
        audit({ kind: 'GUARD-BLOCK', tool: exec.name, target: hit.path })
        return msg
      }
      st.guardWarned++
      audit({ kind: 'GUARD-WARN', tool: exec.name, target: hit.path })
      return undefined
    } catch { return undefined }
  }

  // ---------------- 动作（工具和 HTTP 共用）
  function writeIntent(targets, label) {
    try {
      const r = core.readTextFile(intentPath)
      const j = r.ok ? core.safeJson(r.text) : { ok: true, value: {} }
      const map = j.ok && j.value && typeof j.value === 'object' ? j.value : {}
      for (const t of targets) map[core.normPath(t)] = { atMs: Date.now(), at: core.nowIso(), label: String(label || '') }
      core.ensureDir(dataDir)
      core.atomicWrite(intentPath, JSON.stringify(map, null, 2))
      return true
    } catch { return false }
  }

  function doSnap(args) {
    const list = files().filter(core.isRestorable)
    const chosen = Array.isArray(args.files) && args.files.length
      ? list.filter((f) => args.files.includes(f.key) || args.files.includes(f.path) || args.files.includes(f.label))
      : list
    if (!chosen.length || (Array.isArray(args.files) && args.files.some((key) => !chosen.some(f => [f.key, f.path, f.label].includes(key))))) return { ok: false, error: '请选择可恢复配置；热存储与生成文件不能拍快照' }
    const r = core.snapFiles({ home, profile: profileName, files: chosen, label: args.label || 'snap', note: args.note || '' })
    if (r.ok) {
      writeIntent(chosen.map((f) => f.path), args.label)
      audit({ kind: 'SNAP', label: r.state.label, state: r.statePath, files: chosen.map((f) => f.key), targets: chosen.map((f) => f.path) })
    }
    return { ok: r.ok, state: r.statePath, label: r.state.label, at: r.state.at, files: r.state.files.map((f) => ({ key: f.key, label: f.label, exists: f.exists, bytes: f.bytes, sha256: f.sha256 })) }
  }

  function doVerify(args) {
    const target = args.state || (core.latestState(home, profileName) || {}).statePath
    if (!target) return { ok: false, error: '没有可校验的 state：先 safety_snap' }
    const r = core.verifyState(target, snapshotOpts())
    if (r.error) return r
    if (args.accept === true) {
      const checks = core.selfCheck({ home, profile: profileDir, pluginDir: PLUGIN_DIR, requiredBundles: cfg.requiredBundles })
      if (!checks.ok) return { ok: false, error: '关键配置自检未通过，不能接受新基线', failed: checks.failed }
      const manifest = writeBaseline(args.label || 'accepted', args.note || '')
      audit({ kind: 'ACCEPT', state: target, at: r.at, changed: r.changed.map((c) => c.path) })
      st.checkCache = { key: '', value: null }
      return { ok: true, accepted: true, before: r, declare: buildDeclare(manifest, r), baselineAt: manifest.at }
    }
    if (r.ok) {
      return { ...r, accepted: false, rebaselined: false }
    }
    audit({ kind: 'VERIFY-DIFF', state: target, changed: (r.changed || []).map((c) => c.path) })
    return { ok: false, accepted: false, ...r }
  }

  function buildDeclare(manifest, verify) {
    const f = (manifest.files || [])[0] || {}
    return 'DECLARE ' + JSON.stringify({
      tool: core.TOOL, verdict: 'PASS-DECLARED', at: core.nowIso(),
      files: (manifest.files || []).length, first: f.path, sha256: f.sha256 || '', bytes: f.bytes || 0,
      changed: (verify && verify.changed || []).length,
    })
  }

  function doRestore(args) {
    const target = args.state || core.latestState(home, profileName)?.statePath
    if (!target) return { ok: false, error: '没有可回滚的快照' }
    const r = core.verifyState(target, snapshotOpts())
    if (r.error) return r
    if (r.ok) return { ok: true, skipped: true, reason: '当前内容与快照一致，不需要回滚', state: target }
    return { ...r, ok: true, dryRun: true, error: 'DSH 工具仅预览；请退出 DSH 后用包内的 restore.ps1 人工确认恢复。', diff: r.changed }
  }

  function doBaseline(args) {
    const checks = core.selfCheck({ home, profile: profileDir, pluginDir: PLUGIN_DIR, requiredBundles: cfg.requiredBundles })
    if (!checks.ok) return { ok: false, error: '关键配置自检未通过，不能建立基线' }
    const manifest = writeBaseline(args.label || 'adopt', args.note || '')
    st.checkCache = { key: '', value: null }
    audit({ kind: 'BASELINE', label: manifest.reason, files: manifest.files.length })
    return { ok: true, baseline: { at: manifest.at, label: manifest.reason, files: manifest.files.map((f) => ({ key: f.key, sha256: f.sha256, bytes: f.bytes })) }, declare: 'DECLARE ' + JSON.stringify({ tool: core.TOOL, verdict: 'BASELINE', at: manifest.at, files: manifest.files.length }) }
  }

  function doPreflight(args) {
    if (args.file) {
      let text = args.text
      if (text == null) {
        const spec = files().find(f => core.normPath(f.path) === core.normPath(args.file))
        if (!spec) return { ok: false, error: '只允许读取受保护配置；其他文件请显式提供 text' }
        core.checkPlainPath(spec.path, 'file')
        const r = core.readTextFile(spec.path)
        if (!r.ok) return { ok: false, error: '读不到文件：' + r.error }
        text = r.text
      }
      const r = core.preflightText({ file: String(args.file), text: String(text) })
      audit({ kind: 'PREFLIGHT', file: r.file, ok: r.ok })
      return r
    }
    return { ok: false, error: '给 file 或 dir' }
  }

  // ---------------- 工具注册（必须在 apply 顶层）
  const defs = [
    {
      name: 'safety_status',
      description: '防崩溃插件状态：健康度（绿/黄/红）、未声明改动、最近 change-gate 记录、最近备份、自检失败项。工作区会话也能直接调。',
      parameters: { type: 'object', properties: {} },
      execute: async () => {
        const s = computeStatus()
        return { ok: true, health: s.health.level, summary: summarize(s), status: s }
      },
      render: (_a, v) => textBlock(v && v.summary ? v.summary : JSON.stringify(v, null, 2)),
    },
    {
      name: 'safety_check',
      description: '跑一遍配置完整性自检（cordis.patch.yml 编码/YAML/结构、profile package.json 的 bundles 数量与解析、workspace/schedule JSON），返回逐项 PASS/FAIL。',
      parameters: { type: 'object', properties: {} },
      execute: async () => {
        st.checkCache = { key: '', value: null }
        const s = computeStatus()
        return { ok: s.health.level !== 'red', level: s.health.level, checks: s.checks, failed: s.checks.failed, reasons: s.health.reasons }
      },
      render: (_a, v) => textBlock(formatChecks(v)),
    },
    {
      name: 'safety_snap',
      description: '给受保护文件拍快照（改前称重）：写 state 到当前 profile 的快照目录，并给写保护留 30 分钟声明窗口。参数 label 写清这次改什么。',
      parameters: {
        type: 'object',
        properties: {
          label: { type: 'string', description: '这次改动叫什么（会写进 state 和审计）' },
          note: { type: 'string', description: '可选：为什么要改' },
          files: { type: 'array', items: { type: 'string' }, description: '可选：只快照指定 key/label/路径，默认全部' },
        },
      },
      execute: async (args) => doSnap(args || {}),
      render: (_a, v) => textBlock(v.ok ? `已快照 ${v.files.length} 个文件\\nstate=${v.state}\\nlabel=${v.label}` : `快照失败：${v.error || ''}`),
    },
    {
      name: 'safety_verify',
      description: '对照最近一次快照校验受保护文件：无差异=ok；有差异会列出。确认差异是本次预期的，传 accept:true 建新基线并输出 DECLARE 行（等同 change-gate 的 PASS-DECLARED）。',
      parameters: {
        type: 'object',
        properties: {
          state: { type: 'string', description: '可选：指定 state.json 路径，默认最近一次快照' },
          accept: { type: 'boolean', description: '差异是预期的：接受并更新基线，返回 DECLARE' },
          note: { type: 'string', description: '可选：声明理由' },
        },
      },
      execute: async (args) => doVerify(args || {}),
      render: (_a, v) => textBlock(formatVerify(v)),
    },
    {
      name: 'safety_restore',
      description: '只读预览恢复差异；真正写回须退出 DSH 后由用户运行 restore.ps1。',
      parameters: {
        type: 'object',
        properties: {
          state: { type: 'string', description: '可选：state.json 路径，默认最近一次快照' },
        },
      },
      execute: async (args) => doRestore(args || {}),
      render: (_a, v) => textBlock(formatRestore(v)),
    },
    {
      name: 'safety_baseline',
      description: '把当前配置状态接受为新基线（声明后的收尾）：之后只对「基线之后的变化」报警。',
      parameters: { type: 'object', properties: { label: { type: 'string' }, note: { type: 'string' } } },
      execute: async (args) => doBaseline(args || {}),
      render: (_a, v) => textBlock(v.ok ? `新基线：${v.baseline.files.length} 个文件 @ ${v.baseline.at}\\n${v.declare}` : '更新基线失败'),
    },
    {
      name: 'safety_gate',
      description: '把一次改动按 crash-guard 五维判成 G0–G3，返回该带的证据包、要不要预演、回滚建议。kind 可填：doc/code/plugin-source/skill/config-value/patch-structure/bundles/install/register/data-delete/external-send/system。',
      parameters: {
        type: 'object',
        properties: {
          kind: { type: 'string' },
          layer: { type: 'string', description: 'L0-L4' },
          reversible: { type: 'string', description: 'V0-V2' },
          verifiable: { type: 'string', description: 'T0-T2' },
          blastRadius: { type: 'string', description: 'R0-R4' },
          firstTime: { type: 'string', description: 'F0-F2' },
          hasGolden: { type: 'boolean' },
        },
      },
      execute: async (args) => core.classifyGate(args || {}),
      render: (_a, v) => textBlock(formatGate(v)),
    },
    {
      name: 'safety_preflight',
      description: '危险动作预演：给 file + 新内容，检查 YAML/JSON/JS 语法与结构，不碰原文件。',
      parameters: {
        type: 'object',
        properties: {
          file: { type: 'string', description: '要预演的文件路径（按扩展名选校验方式）' },
          text: { type: 'string', description: '可选：新内容；不给就校验当前内容' },
        },
      },
      execute: async (args) => doPreflight(args || {}),
      render: (_a, v) => textBlock(formatPreflight(v)),
    },
  ]

  for (const def of defs) {
    try {
      ctx.effect(() => ctx.tools.register({
        name: def.name,
        description: def.description,
        parameters: { ...def.parameters, additionalProperties: false },
        output: { schema: { type: 'object', additionalProperties: true }, render: def.render || ((_a, v) => textBlock(JSON.stringify(v, null, 2))) },
        execute: async (args, exec) => {
          try { st.actions++; return await def.execute(args || {}, exec) } catch (err) {
            st.lastError = String(err && err.message || err)
            return { ok: false, error: st.lastError }
          }
        },
      }))
    } catch (err) {
      st.lastError = 'register ' + def.name + ': ' + String(err && err.message || err)
      log(st.lastError)
    }
  }

  // Browser status is optional and deliberately provides no write path.
  try {
    ctx.inject(['webServer'], (scope) => {
      const web = scope.webServer
      const headers = { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }
      const send = (req, res, type, body, extra = {}) => {
        if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405, { allow: 'GET, HEAD', ...headers }); res.end(); return }
        res.writeHead(200, { 'content-type': type, ...headers, ...extra })
        res.end(req.method === 'HEAD' ? undefined : body())
      }
      scope.effect(() => web.register({ kind: 'exact', path: '/dsh-safety/status', handler: (req, res) => send(req, res, 'application/json; charset=utf-8', () => {
        const snapshot = st.lastStatus
        return JSON.stringify(snapshot ? {
          version: snapshot.version, at: snapshot.at, health: snapshot.health.level,
          checks: { passed: snapshot.checks.passed, total: snapshot.checks.total },
          changes: snapshot.changes.counts, guard: snapshot.guard,
        } : { version: core.VERSION, health: 'unknown' })
      }) }))
      scope.effect(() => web.register({ kind: 'exact', path: '/dsh-safety/panel', handler: (req, res) => send(req, res, 'text/html; charset=utf-8', () => fs.readFileSync(path.join(PLUGIN_DIR, 'lib', 'panel.html'), 'utf8'), {
        'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
      }) }))
      scope.effect(() => web.register({ kind: 'exact', path: '/dsh-safety/panel.js', handler: (req, res) => send(req, res, 'text/javascript; charset=utf-8', () => fs.readFileSync(path.join(PLUGIN_DIR, 'lib', 'panel.js'), 'utf8')) }))
    })
  } catch (err) { log('未加载只读面板：' + String(err.message || err)) }

  // ---------------- 写保护接线
  if (cfg.guardMode !== 'off') {
    try { ctx.effect(() => ctx.tools.guard((exec) => guardTool(exec))) } catch (err) {
      st.lastError = 'guard: ' + String(err && err.message || err)
      log(st.lastError + '（写保护降级为事后报警）')
    }
  }

  // ---------------- 启动
  try {
    core.ensureDir(dataDir)
    core.checkPlainPath(dataDir, 'dir')
    ensureBaseline()
    const s = computeStatus()
    st.bootedAt = s.at
    st.lastSig = s.changes.undeclared.map((i) => i.key + ':' + i.sha256).join('|')
    audit({
      kind: 'BOOT', version: core.VERSION, pid: process.pid, health: s.health.level,
      checks: { total: s.checks.total, passed: s.checks.passed, failed: s.checks.failed.length },
      undeclared: s.changes.counts.undeclared, gateRecords: s.gateLog.records,
    })
    log(`启动自检完成：${s.health.level}，检查 ${s.checks.passed}/${s.checks.total}，未声明 ${s.changes.counts.undeclared}`)
  } catch (err) {
    st.lastError = 'boot: ' + String(err && err.message || err)
    audit({ kind: 'ERROR', where: 'boot', error: st.lastError })
  }

  if (cfg.watch !== false) {
    try {
      st.timer = setInterval(tick, Math.max(2000, Number(cfg.watchMs) || 15000))
      if (st.timer && typeof st.timer.unref === 'function') st.timer.unref()
    } catch (err) {
      st.lastError = 'timer: ' + String(err && err.message || err)
    }
    try {
      if (typeof ctx.effect === 'function') ctx.effect(() => () => { try { clearInterval(st.timer) } catch { /* ignore */ } })
    } catch { /* ignore */ }
  }

  log(`插件就绪（${core.VERSION}）：工具 ${defs.length} 个`)
  return { status: () => st.lastStatus, computeStatus, files }
}

// ---------------- 渲染
function summarize(s) {
  const lines = []
  lines.push(`健康度：${badge(s.health.level)}（检查 ${s.checks.passed}/${s.checks.total}）· v${s.version}`)
  lines.push(`未声明改动：${s.changes.counts.undeclared} 个（待声明 ${s.changes.counts.pending}，已声明 ${s.changes.counts.declared}）`)
  if (s.changes.undeclared.length) for (const u of s.changes.undeclared) lines.push(`  ✗ ${u.label}（${u.status}）${u.path}`)
  if (s.changes.counts && s.changes.counts.drifted) {
    lines.push(`热文件正常变化（结构完好，不算未声明）：${s.changes.counts.drifted} 个`)
    for (const d of s.changes.drifted) lines.push(`  ~ ${d.label}（${d.gradeDetail || d.status}）`)
  }
  lines.push(`最近 change-gate：${s.gate ? `${s.gate.verdict} · ${s.gate.label || ''} · ${s.gate.at}` : '无记录'}`)
  lines.push(`最近备份：${s.backup ? `${s.backup.at} · ${s.backup.label}` : '无'}`)
  if (s.health.reasons.length) {
    lines.push('原因：')
    for (const r of s.health.reasons.slice(0, 6)) lines.push(`  [${r.level}] ${r.why}`)
  }
  lines.push(`写保护：${s.guard.mode}（已拦 ${s.guard.blocked} / 已告警 ${s.guard.warned}）`)
  return lines.join('\n')
}

function badge(level) {
  return level === 'red' ? '🔴 RED（有真问题）' : level === 'yellow' ? '🟡 YELLOW（要留意）' : '🟢 GREEN（正常）'
}

function formatChecks(v) {
  const out = [`自检：${v.level} · ${v.checks.passed}/${v.checks.total} 通过`]
  for (const c of v.checks.failed || []) out.push(`  ✗ [${c.severity}] ${c.title} — ${c.detail}`)
  if (!(v.checks.failed || []).length) out.push('  全部通过')
  return out.join('\n')
}

function formatVerify(v) {
  if (v.error) return '校验失败：' + v.error
  if (v.accepted) {
    const lines = ['差异已接受（新基线已建，DECLARE 见末尾）']
    for (const c of (v.before && v.before.changed) || []) lines.push(`  ~ ${c.path}（${c.status}，${c.delta >= 0 ? '+' : ''}${c.delta} B）`)
    lines.push('', v.declare)
    return lines.join('\n')
  }
  if (v.ok) return `校验通过：${(v.items || []).length} 个文件与快照一致\\nstate=${v.state}`
  const lines = [`校验发现差异（${(v.changed || []).length} 个文件）`]
  for (const c of v.changed || []) lines.push(`  ~ ${c.path}（${c.status}，${c.delta >= 0 ? '+' : ''}${c.delta} B）`)
  lines.push('', '如果差异是本次预期：重跑 safety_verify {"accept":true,"note":"理由"} 建新基线并拿 DECLARE。')
  return lines.join('\n')
}

function formatRestore(v) {
  if (v.error) return '回滚未执行：' + v.error + (v.diff ? '\\n' + JSON.stringify(v.diff, null, 2) : '')
  if (v.skipped) return '不需要回滚：' + v.reason
  const lines = [v.ok ? '回滚完成（sha 已核对）' : '回滚有失败项（见下）']
  for (const i of v.items || []) lines.push(`  ${i.action} ${i.path}${i.bad ? '（坏文件另存 ' + i.bad + '）' : ''}`)
  return lines.join('\n')
}

function formatGate(v) {
  const lines = [`判定：${v.level}${v.g2b ? '（G2b 双区）' : ''}`]
  for (const r of v.reasons || []) lines.push('  · ' + r)
  lines.push('证据包：' + ((v.evidence || []).join(' / ') || '无'))
  lines.push('预演：' + (v.preflight ? '必须（danger-preflight）' : '不强制'))
  lines.push('建议：' + v.advice)
  return lines.join('\n')
}

function formatPreflight(v) {
  if (v.error) return '预演失败：' + v.error
  const lines = [`预演：${v.ok ? 'PASS' : 'FAIL'} · ${v.file || v.dir}`]
  for (const c of v.checks || []) lines.push(`  ${c.ok ? '✓' : '✗'} ${c.id} — ${c.detail}`)
  return lines.join('\n')
}
