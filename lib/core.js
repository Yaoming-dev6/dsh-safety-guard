/**
 * dsh-safety-guard · core.js — 纯逻辑层（不依赖 DSH，可在 node 里直接单测）
 * 文件指纹 / 清单差分 / change-gate 审计解析 / 未声明判定状态机 / 配置自检 /
 * G0-G3 分级 / 快照·校验·回滚 / 危险动作预演。
 *
 * 设计口径：
 *  - 只读为主；写只写自己的数据目录（默认 %USERPROFILE%\.dsh\safety-guard）。
 *  - 任何函数都不抛异常给宿主：返回 {ok:false,error} 让调用方决定。
 *  - 判定不猜：拿不到证据就是 unknown，绝不假装 PASS。
 */
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import crypto from 'node:crypto'
import { createRequire } from 'node:module'
import { execFileSync } from 'node:child_process'

export const VERSION = '1.0.2'
export const TOOL = 'dsh-safety-guard'
export const DATA_DIRNAME = 'safety-guard'
export const SNAP_VERSION = 2
/** 未声明改动在「待声明」状态里允许停留的时长（毫秒），超时降级为红。 */
export const PENDING_GRACE_MS = 10 * 60 * 1000
/** 写保护认可的「刚声明过」时间窗：snap/begin 之后多久内允许改文件。 */
export const INTENT_TTL_MS = 30 * 60 * 1000

export const dshHome = () => process.env.DSH_HOME || path.join(os.homedir(), '.dsh')
export function profileId(name) {
  if (typeof name !== 'string' || !/^[\p{L}\p{N}_-][\p{L}\p{N}_.-]{0,100}$/u.test(name) || name.endsWith('.') || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(name)) throw new Error('Invalid DSH profile name')
  return name
}
export const dataDir = (home, profile) => path.join(home || dshHome(), DATA_DIRNAME, 'profiles', profileId(profile || detectProfileName(home)))
export const normPath = (p) => String(p || '').replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase()
export const nowIso = (d) => new Date(d == null ? Date.now() : d).toISOString()
export const pad2 = (n) => String(n).padStart(2, '0')
export function stamp(d) {
  const x = new Date(d == null ? Date.now() : d)
  return `${x.getFullYear()}${pad2(x.getMonth() + 1)}${pad2(x.getDate())}-${pad2(x.getHours())}${pad2(x.getMinutes())}${pad2(x.getSeconds())}`
}
export const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex')
export const isUtf8 = (buf) => {
  try { return Buffer.compare(Buffer.from(buf.toString('utf8'), 'utf8'), buf) === 0 && !buf.toString('utf8').includes('\uFFFD') } catch { return false }
}
export const hasBom = (buf) => !!(buf && buf.length >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF)
export function ensureDir(dir) { fs.mkdirSync(dir, { recursive: true }); return dir }
export function readJsonText(file) {
  const raw = fs.readFileSync(file, 'utf8')
  return raw.replace(/^\uFEFF/, '')
}
export function safeJson(text) {
  try { return { ok: true, value: JSON.parse(String(text).replace(/^\uFEFF/, '')) } } catch (err) { return { ok: false, error: String(err && err.message || err) } }
}

/** 文件事实：存在/字节/sha256/mtime/UTF-8/BOM。读不到就 exists:false，不抛。 */
export function fileFacts(file) {
  try {
    const st = checkPlainPath(file, 'file')
    const buf = readBounded(file, MAX_CONFIG_BYTES)
    return {
      exists: true,
      path: file,
      bytes: buf.length,
      sha256: sha256(buf),
      mtime: st.mtime.toISOString(),
      mtimeMs: st.mtimeMs,
      utf8: isUtf8(buf),
      bom: hasBom(buf),
    }
  } catch (err) {
    return { exists: false, path: file, error: String(err && err.code || err) }
  }
}

export function readTextFile(file) {
  try {
    const buf = readBounded(file, MAX_CONFIG_BYTES)
    return { ok: true, text: buf.toString('utf8'), bytes: buf.length, utf8: isUtf8(buf), bom: hasBom(buf) }
  } catch (err) {
    return { ok: false, error: String(err && err.code || err) }
  }
}

// ---------------------------------------------------------------- YAML
// 宿主进程里能拿到 js-yaml（asar 内），拿不到就退化成结构校验：宁可「看不清」，不可假装「没问题」。
let yamlCache
export function loadYaml(profileDir) {
  if (yamlCache !== undefined) return yamlCache
  const list = []
  if (process.env.SAFETY_YAML) list.push(process.env.SAFETY_YAML)
  if (profileDir) list.push(path.join(profileDir, 'node_modules', 'js-yaml', 'index.js'))
  list.push(path.join(dshHome(), 'node_modules', 'js-yaml', 'index.js'))
  const res = process.resourcesPath || path.join(path.dirname(process.execPath), 'resources')
  list.push(path.join(res, 'app.asar', 'dsh', 'node_modules', 'js-yaml', 'index.js'))
  const req = createRequire(import.meta.url)
  yamlCache = { parse: null, source: '' }
  for (const file of list) {
    try {
      if (!fs.existsSync(file)) continue
      const mod = req(file)
      const parse = typeof mod.load === 'function' ? mod.load : (typeof mod.parse === 'function' ? mod.parse : null)
      if (parse) { yamlCache = { parse, source: file }; break }
    } catch { /* 试下一个 */ }
  }
  if (!yamlCache.parse) {
    try {
      const mod = req('js-yaml')
      if (mod && typeof mod.load === 'function') yamlCache = { parse: mod.load, source: 'js-yaml (resolver)' }
    } catch { /* ignore */ }
  }
  return yamlCache
}

export function parseYaml(text, opts = {}) {
  const y = loadYaml(opts.profileDir)
  if (typeof y.parse !== 'function') return { state: 'unavailable' }
  try { return { state: 'ok', doc: y.parse(String(text)), source: y.source } } catch (err) {
    const msg = String(err && err.message || err)
    // cordis 支持 !!js 自定义 tag；js-yaml 不认，不代表文件坏了
    if (/unknown tag|!!js|unexpected tag/i.test(msg)) return { state: 'opaque', error: msg, source: y.source }
    return { state: 'invalid', error: msg, source: y.source }
  }
}

/**
 * 不依赖解析器的结构校验：BOM / UTF-8 / tab 缩进 / 顶层条目 / 重复 id / insert 块。
 * 这段是「YAML 解析器不可用时」的兜底证据，也是解析成功后的交叉核对。
 */
export function analyzeYamlStruct(text) {
  const src = String(text == null ? '' : text)
  const issues = []
  const bom = src.charCodeAt(0) === 0xFEFF
  if (bom) issues.push('文件带 BOM（YAML 解析器可能直接报错）')
  if (src.includes('\uFFFD')) issues.push('内容里有替换字符 U+FFFD（编码很可能被写坏）')
  const lines = src.split(/\r?\n/)
  const notes = []
  if (src.length && !src.endsWith('\n')) notes.push('文件末尾没有换行（合法，但追加式写入容易粘连）')
  const entries = []
  const insertIds = []
  const topIds = []
  let current = null
  let inInsert = false
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    if (/^\t+\S/.test(line)) issues.push(`第 ${i + 1} 行用 tab 缩进（YAML 不允许）`)
    const mTop = /^-\s+id:\s*(.+)$/.exec(line)
    if (mTop) {
      current = { id: mTop[1].trim().replace(/^['"]|['"]$/g, ''), name: '', line: i + 1 }
      entries.push(current)
      topIds.push(current.id)
      inInsert = false
      continue
    }
    if (/^-\s+insert:\s*$/.test(line)) {
      current = { id: '__insert__', name: '', line: i + 1 }
      entries.push(current)
      inInsert = true
      continue
    }
    const mName = /^\s{2}name:\s*(.+)$/.exec(line)
    if (mName && current && !current.name) current.name = mName[1].trim().replace(/^['"]|['"]$/g, '')
    const mInsertId = /^\s{4,}-\s+id:\s*(.+)$/.exec(line)
    if (mInsertId) {
      const id = mInsertId[1].trim().replace(/^['"]|['"]$/g, '')
      insertIds.push(id)
      if (!inInsert) issues.push(`第 ${i + 1} 行缩进像 insert 子条目，但不在 insert 块里`)
    }
  }
  const dupTop = topIds.filter((id, i) => topIds.indexOf(id) !== i)
  if (dupTop.length) issues.push(`顶层条目 id 重复：${[...new Set(dupTop)].join(', ')}`)
  const dupInsert = insertIds.filter((id, i) => insertIds.indexOf(id) !== i)
  if (dupInsert.length) issues.push(`insert 子条目 id 重复：${[...new Set(dupInsert)].join(', ')}`)
  return { ok: issues.length === 0, bom, issues, notes, lines: lines.length, entries, topIds, insertIds, bytes: Buffer.byteLength(src, 'utf8') }
}
// ---------------------------------------------------------------- 受保护文件 + 清单
/** 探测「当前正在跑」的 profile：先看宿主进程 argv 里的 profiles/<name>，再看哪个 profile 的 bundles 里装了本插件。 */
export function detectProfileName(home, pluginName) {
  const h = home || dshHome()
  const root = path.join(h, 'profiles')
  const isProfile = (name) => {
    try { return fs.statSync(path.join(root, profileId(name))).isDirectory() } catch { return false }
  }
  if (process.env.DSH_PROFILE_DIR) {
    const dir = path.resolve(process.env.DSH_PROFILE_DIR)
    const name = path.basename(dir)
    if (normPath(path.dirname(dir)) === normPath(root) && isProfile(name)) return name
  }
  if (isProfile(process.env.DSH_PROFILE)) return process.env.DSH_PROFILE
  const argRe = /[\\/]profiles[\\/]([^\\/]+)[\\/]?$/i
  for (const arg of process.argv || []) {
    const m = argRe.exec(String(arg || ''))
    if (m && isProfile(m[1])) return m[1]
  }
  let names = []
  try { names = fs.readdirSync(root, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name) } catch { names = [] }
  const want = String(pluginName || 'dsh-safety-guard')
  for (const n of names) {
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(root, n, 'package.json'), 'utf8').replace(/^﻿/, ''))
      const b = pkg && pkg.dsh && pkg.dsh.profile && pkg.dsh.profile.bundles
      if (Array.isArray(b) && b.map(String).indexOf(want) >= 0) return n
    } catch { /* 下一个 */ }
  }
  for (const n of ['desktop', 'default']) if (names.indexOf(n) >= 0) return n
  return names[0] || 'desktop'
}

export function profileDirOf(home, name) {
  return path.join(home || dshHome(), 'profiles', profileId(name || detectProfileName(home)))
}

/** 默认受保护清单：全是「改坏了 DSH 起不来 / 起错」的配置。severity=red 的出事是真事故。 */
export function criticalFiles(opts = {}) {
  const h = opts.home || dshHome()
  const profile = opts.profile || profileDirOf(h, opts.profileName)
  const join = (...a) => path.join(h, ...a)
  return [
    { key: 'profile.patch', label: 'cordis.patch.yml', path: path.join(profile, 'cordis.patch.yml'), required: true, severity: 'red', kind: 'yaml' },
    { key: 'profile.package', label: 'package.json（profile）', path: path.join(profile, 'package.json'), required: true, severity: 'red', kind: 'json' },
    { key: 'profile.cordis', label: 'cordis.yml', path: path.join(profile, 'cordis.yml'), monitorOnly: true, required: false, severity: 'red', kind: 'yaml' },
    { key: 'global.patch', label: '全局 cordis.patch.yml', path: join('cordis.patch.yml'), required: false, severity: 'red', kind: 'yaml' },
    { key: 'global.agents', label: 'AGENTS.md', path: join('AGENTS.md'), required: false, severity: 'yellow', kind: 'text' },
    { key: 'storage.workspace', label: 'storages/workspace.json', path: join('storages', 'workspace.json'), required: false, severity: 'red', kind: 'json', hot: true,
      expect: { unit: 'workspace', tables: ['workspaces'], globalArrays: ['workspaceIds'], refs: [{ from: 'global.workspaceIds', to: 'tables.workspaces' }] } },
    { key: 'storage.schedule', label: 'storages/schedule.json', path: join('storages', 'schedule.json'), required: false, severity: 'red', kind: 'json', hot: true,
      expect: { unit: 'schedule', tables: ['tasks'], globalArrays: [], refs: [] } },
  ]
}

export function buildManifest(files, extra = {}) {
  return {
    v: SNAP_VERSION,
    tool: TOOL,
    at: nowIso(),
    atMs: Date.now(),
    ...extra,
    files: (files || []).map((f) => {
      const facts = fileFacts(f.path)
      return {
        key: f.key, label: f.label, path: f.path, pathKey: normPath(f.path),
        severity: f.severity || 'yellow', required: !!f.required, kind: f.kind || '',
        hot: !!f.hot, expect: f.expect || null,
        at: facts.exists ? facts.mtime : '', atMs: facts.exists ? facts.mtimeMs : 0,
        exists: facts.exists, bytes: facts.bytes || 0, sha256: facts.sha256 || '', utf8: facts.utf8 !== false, bom: !!facts.bom,
      }
    }),
  }
}

export function diffManifest(baseline, current) {
  const baseByKey = new Map(((baseline && baseline.files) || []).map((f) => [f.key, f]))
  return ((current && current.files) || []).map((cur) => {
    const base = baseByKey.get(cur.key) || null
    let status = 'unchanged'
    if (!base || !base.exists) status = cur.exists ? 'added' : 'absent'
    else if (!cur.exists) status = 'removed'
    else if (base.sha256 !== cur.sha256) status = 'changed'
    return { ...cur, base, status, baseSha: base ? base.sha256 : null }
  })
}

// ---------------------------------------------------------------- 热文件（DSH 自己天天写的）结构体检
/**
 * storages 里那两个文件是 DSH 的 unit 存储：
 *   { unit:{name,version}, global:{...}, tables:{ <表名>:{ <id>:<条目> } } }
 * 它们每天都在变（开/关会话、增删定时任务）。用 sha 一刀切 = 天天报红 = 报警疲劳；
 * 一刀切移出监控 = 真写坏了也没人知道。所以按「内容质量」分级，只看骨架还在不在：
 *   - 解析不了 / 根不是对象 / tables 没了 / 关键表或关键数组类型变了 / 引用断了 → fatal（红）
 *   - 骨架都在，只是条目增减 / 软删除残留                                   → warn（不升级）
 */
const hasOwnKey = (o, k) => !!o && Object.prototype.hasOwnProperty.call(o, k)
const isPlainObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v)

/** 按 'global.workspaceIds' 这种点路径取值；取不到返回 undefined。 */
export function pickPath(root, dotted) {
  let cur = root
  for (const seg of String(dotted || '').split('.')) {
    if (!isPlainObj(cur) && !Array.isArray(cur)) return undefined
    if (!hasOwnKey(cur, seg)) return undefined
    cur = cur[seg]
  }
  return cur
}

/**
 * 给一个 JSON 热文件做结构体检：{ ok, kind, file, exists, fatal[], warn[], stats, facts }
 * ok=true 只代表「骨架没坏」，不代表和基线一致 —— 条目增减本来就是正常写入。
 */
export function analyzeHotJson(file, expect = {}) {
  const facts = fileFacts(file)
  const fatal = []
  const warn = []
  const stats = { tables: {}, entries: 0 }
  const pack = (kind) => ({ ok: fatal.length === 0, kind: fatal.length ? kind : 'ok', file, exists: !!facts.exists, fatal, warn, stats, facts })
  if (!facts.exists) { fatal.push({ code: 'missing', detail: '文件不存在' }); return pack('missing') }
  const rd = readTextFile(file)
  if (!rd.ok) { fatal.push({ code: 'unreadable', detail: '读不了：' + rd.error }); return pack('unreadable') }
  const text = String(rd.text || '').replace(/^\uFEFF/, '')
  if (!text.trim()) { fatal.push({ code: 'empty', detail: '文件是空的（0 字节 / 只有空白）' }); return pack('empty') }
  const j = safeJson(text)
  if (!j.ok) { fatal.push({ code: 'json', detail: 'JSON 解析失败：' + j.error }); return pack('invalid-json') }
  const root = j.value
  if (!isPlainObj(root)) { fatal.push({ code: 'root', detail: '顶层不是对象，而是 ' + (Array.isArray(root) ? 'array' : typeof root) }); return pack('invalid-root') }

  // unit 元信息：名字对不上 = 有东西把别的文件的内容写进了这个路径
  if (!isPlainObj(root.unit)) warn.push({ code: 'unit', detail: '缺 unit 元信息（unit.name / unit.version）' })
  else {
    if (expect.unit && String(root.unit.name || '') !== String(expect.unit)) fatal.push({ code: 'unit.name', detail: 'unit.name=' + JSON.stringify(root.unit.name) + '，这里应该是 ' + expect.unit + '（内容错位）' })
    if (!Number.isInteger(root.unit.version)) warn.push({ code: 'unit.version', detail: 'unit.version 不是整数：' + JSON.stringify(root.unit.version) })
  }

  // global：DSH 真的会把它写成 null（schedule.json 现在就是 null），所以 null/缺失合法；
  // 只有「类型乱掉」或「expect 要的关键数组没了」才算骨架被破坏。
  const glob = root.global
  if (glob !== null && glob !== undefined && !isPlainObj(glob)) {
    fatal.push({ code: 'global', detail: 'global 类型不对（应为对象或 null，实际 ' + (Array.isArray(glob) ? 'array' : typeof glob) + '）' })
  } else {
    for (const name of expect.globalArrays || []) {
      if (!isPlainObj(glob)) fatal.push({ code: 'global.' + name, detail: 'global 是 ' + (glob === null ? 'null' : '缺失') + '，缺 global.' + name + ' 数组（结构被破坏）' })
      else if (!hasOwnKey(glob, name)) fatal.push({ code: 'global.' + name, detail: '缺 global.' + name + '（结构被破坏）' })
      else if (!Array.isArray(glob[name])) fatal.push({ code: 'global.' + name, detail: 'global.' + name + ' 类型变了（应为数组，实际 ' + (glob[name] === null ? 'null' : typeof glob[name]) + '）' })
    }
  }

  // tables：关键表还在不在、还是不是「id → 条目」
  if (!isPlainObj(root.tables)) fatal.push({ code: 'tables', detail: '缺 tables 对象（结构被破坏）' })
  else {
    for (const name of expect.tables || []) {
      const t = root.tables[name]
      if (!hasOwnKey(root.tables, name)) fatal.push({ code: 'tables.' + name, detail: '缺 tables.' + name + ' 表（结构被破坏）' })
      else if (!isPlainObj(t)) fatal.push({ code: 'tables.' + name, detail: 'tables.' + name + ' 类型变了（应为对象，实际 ' + (Array.isArray(t) ? 'array' : typeof t) + '）' })
      else { const n = Object.keys(t).length; stats.tables[name] = n; stats.entries += n }
    }
  }

  // 引用完整性：global 里的 id 列表和表里的 id 对不上 = 真断了
  for (const ref of expect.refs || []) {
    const ids = pickPath(root, ref.from)
    const table = pickPath(root, ref.to)
    if (!Array.isArray(ids) || !isPlainObj(table)) continue // 上面已经报过了
    const dangling = ids.filter((id) => !hasOwnKey(table, String(id)))
    if (dangling.length) fatal.push({ code: 'ref.' + ref.from, detail: ref.from + ' 里有 ' + dangling.length + ' 个 id 在 ' + ref.to + ' 里找不到（引用断了）：' + dangling.slice(0, 5).join(', ') })
    const orphan = Object.keys(table).filter((id) => !ids.includes(id))
    if (orphan.length) warn.push({ code: 'orphan.' + ref.to, detail: ref.to + ' 里有 ' + orphan.length + ' 个条目不在 ' + ref.from + ' 里（软删除残留？）' })
  }
  return pack('broken-structure')
}

/** 把体检结果压成一句人话（状态面板 / 报告用）。 */
export function describeHotStats(analysis) {
  const a = analysis || {}
  const bits = []
  for (const [k, n] of Object.entries((a.stats && a.stats.tables) || {})) bits.push(n + ' 个 ' + k)
  if (!bits.length) bits.push(((a.facts && a.facts.bytes) || 0) + ' B')
  return bits.join(' / ')
}

// ---------------------------------------------------------------- change-gate 审计
export function gateLogPath(home) { return path.join(home || dshHome(), 'patch-guard', 'gate', 'audit.log') }

export function parseJsonl(text, maxLines = 20000) {
  const out = []
  const lines = String(text || '').split(/\r?\n/)
  const start = Math.max(0, lines.length - maxLines)
  for (let i = start; i < lines.length; i++) {
    const line = lines[i].trim()
    if (!line) continue
    const r = safeJson(line)
    if (r.ok && r.value && typeof r.value === 'object') out.push(r.value)
  }
  return out
}

/** 两种来源的记录都归一化：patch-guard 原生（c/verdict）+ change-gate journal（action/gate）。 */
export function normalizeGateRecord(rec) {
  if (!rec || typeof rec !== 'object') return null
  const at = String(rec.at || '')
  const atMs = Date.parse(at)
  if (!isFinite(atMs)) return null
  if (rec.c && rec.file) {
    const kind = String(rec.c)
    let verdict = String(rec.verdict || '')
    if (!verdict) verdict = kind === 'snap' ? 'SNAPPED' : 'UNKNOWN'
    const sha = kind === 'verify' ? String(rec.after || rec.sha || '') : String(rec.sha || '')
    return {
      source: 'patch-guard', kind, at, atMs, file: String(rec.file), pathKey: normPath(rec.file),
      verdict, sha, before: String(rec.before || ''), bytes: Number(rec.bytesAfter != null ? rec.bytesAfter : rec.bytes) || 0,
      bytesBefore: Number(rec.bytesBefore || 0) || 0, label: String(rec.label || ''), bypass: rec.bypass ? String(rec.bypass) : '',
    }
  }
  if (rec.action && rec.target) {
    const kind = String(rec.action)
    const gate = String(rec.gate || '')
    const verdict = kind === 'verify' ? (gate === 'PASS' ? 'PASS' : gate === 'FAIL' ? 'FAIL' : gate || 'UNKNOWN') : gate || 'UNKNOWN'
    return {
      source: 'change-gate', kind, at, atMs, file: String(rec.target), pathKey: normPath(rec.target),
      verdict, sha: String(rec.sha256 || ''), before: '', bytes: Number(rec.bytes) || 0, bytesBefore: 0,
      label: String(rec.label || ''), bypass: '', state: String(rec.state || ''),
    }
  }
  return null
}

export function isVerifyPass(rec) { return !!rec && rec.kind === 'verify' && (/^PASS/i.test(rec.verdict) || rec.verdict === 'OK') }
export function isSnapLike(rec) { return !!rec && (rec.kind === 'snap' || rec.kind === 'begin') }

export function readGateLog(home) {
  const file = gateLogPath(home)
  const r = readTextFile(file)
  if (!r.ok) return { ok: false, file, records: [], error: r.error }
  const records = parseJsonl(r.text).map(normalizeGateRecord).filter(Boolean)
  return { ok: true, file, records, error: null }
}

export function indexGateRecords(records) {
  const byFile = new Map()
  for (const rec of records || []) {
    if (!rec || !rec.pathKey) continue
    let e = byFile.get(rec.pathKey)
    if (!e) { e = { last: null, lastPass: null, lastSnap: null }; byFile.set(rec.pathKey, e) }
    if (!e.last || rec.atMs >= e.last.atMs) e.last = rec
    if (isVerifyPass(rec) && (!e.lastPass || rec.atMs >= e.lastPass.atMs)) e.lastPass = rec
    if (isSnapLike(rec) && (!e.lastSnap || rec.atMs >= e.lastSnap.atMs)) e.lastSnap = rec
  }
  return byFile
}

/**
 * 未声明判定状态机：
 *   unchanged  → ok
 *   changed/added/removed：
 *     declared   = 存在 SHA 与当前一致的 verify PASS，且发生在基线之后
 *     pending    = 基线之后有人 snap/begin、还没有对应 PASS（正在改，黄）
 *     undeclared = 两者都没有（红：这就是要报警的那种）
 */
export function assessChanges(opts = {}) {
  const now = opts.now || Date.now()
  const baselineAtMs = Number(opts.baseline && opts.baseline.atMs) || 0
  const byFile = indexGateRecords(opts.records)
  const items = []
  for (const cur of diffManifest(opts.baseline, opts.current)) {
    const key = cur.pathKey
    const gate = byFile.get(key) || null
    let verdict = 'ok'
    let evidence = null
    if (cur.status !== 'unchanged' && cur.status !== 'absent') {
      const pass = gate && gate.lastPass && gate.lastPass.atMs >= baselineAtMs && gate.lastPass.sha && gate.lastPass.sha === cur.sha256 ? gate.lastPass : null
      if (pass) {
        verdict = 'declared'; evidence = pass
      } else {
        const snap = gate && gate.lastSnap && gate.lastSnap.atMs >= baselineAtMs ? gate.lastSnap : null
        const fresh = snap && now - snap.atMs <= opts.pendingMs
        // 快照的 sha 就是当前内容 = 有人按「这个内容」声明过；仍算已声明（但要新）
        // 只有「最后一次快照比最后一次 PASS 还新」才是进行中的一轮（待声明）；
        // 上一轮已经 PASS 闭环、之后又被改过的，就是未声明 —— 宁可报红，不许装作没事。
        if (fresh && snap.sha && snap.sha === cur.sha256) { verdict = 'declared'; evidence = snap }
        else if (fresh && (!gate.lastPass || gate.lastPass.atMs < snap.atMs)) { verdict = 'pending'; evidence = snap }
        else { verdict = 'undeclared'; evidence = snap || (gate && gate.last) || null }
      }
    }
    // 热 JSON（DSH 自己天天写）：按内容质量分级，不按 sha 一刀切。
    //   解析失败 / 骨架被破坏 → 红（还是 undeclared，真问题不许放过）
    //   骨架在、只是条目变化 → drifted / 黄（提示，不算「未声明」）
    let severity = cur.severity
    let grade = ''
    let gradeDetail = ''
    let hotStats = null
    if (cur.hot && verdict === 'undeclared') {
      if (!cur.exists) { grade = 'missing'; severity = 'red'; gradeDetail = '热文件不见了' }
      else {
        const a = analyzeHotJson(cur.path, cur.expect || {})
        hotStats = { kind: a.kind, tables: a.stats.tables, entries: a.stats.entries, bytes: (a.facts && a.facts.bytes) || 0 }
        if (a.ok) {
          verdict = 'drifted'
          severity = 'yellow'
          grade = 'content-drift'
          gradeDetail = describeHotStats(a) + (a.warn.length ? '（' + a.warn.map((w) => w.detail).join('；') + '）' : '')
        } else {
          grade = a.kind
          severity = 'red'
          gradeDetail = a.fatal.map((f) => f.detail).join('；')
        }
      }
    }
    items.push({
      key: cur.key, label: cur.label, path: cur.path, severity,
      status: cur.status, verdict, grade, gradeDetail, hotStats,
      bytes: cur.exists ? cur.bytes : 0, baseBytes: cur.base ? cur.base.bytes : 0,
      sha256: cur.exists ? cur.sha256 : '', baseSha: cur.baseSha,
      at: cur.at || '', evidence: evidence ? { at: evidence.at, kind: evidence.kind, verdict: evidence.verdict, label: evidence.label, source: evidence.source } : null,
    })
  }
  return { items, ...summarizeChanges(items) }
}

export function summarizeChanges(items) {
  const undeclared = (items || []).filter((i) => i.verdict === 'undeclared')
  const pending = (items || []).filter((i) => i.verdict === 'pending')
  const declared = (items || []).filter((i) => i.verdict === 'declared')
  const drifted = (items || []).filter((i) => i.verdict === 'drifted')
  const changed = (items || []).filter((i) => i.status !== 'unchanged' && i.status !== 'absent')
  const redUndeclared = undeclared.filter((i) => i.severity === 'red')
  return {
    undeclared, pending, declared, drifted,
    counts: { total: (items || []).length, changed: changed.length, declared: declared.length, pending: pending.length, undeclared: undeclared.length, drifted: drifted.length },
    hasUndeclared: undeclared.length > 0,
    hasDrifted: drifted.length > 0,
    worstUndeclared: redUndeclared.length ? 'red' : undeclared.length ? 'yellow' : null,
  }
}
// ---------------------------------------------------------------- 启动自检
const DEFAULT_REQUIRED_BUNDLES = ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-web-app']

/**
 * 配置完整性自检（crash-guard 的核心）。只读。
 * opts: { home, profile, profileName, pluginDir, requiredBundles, baselinePkg }
 */
export function selfCheck(opts = {}) {
  const home = opts.home || dshHome()
  const profile = opts.profile || profileDirOf(home, opts.profileName)
  const checks = []
  const add = (id, title, ok, severity, detail) => checks.push({ id, title, ok: !!ok, severity: severity || 'yellow', detail: String(detail == null ? '' : detail) })
  const cfgFiles = criticalFiles({ home, profile })
  const byKey = new Map(cfgFiles.map((f) => [f.key, f]))

  // 1) cordis.patch.yml：存在 / 编码 / YAML / 结构
  const patchF = byKey.get('profile.patch')
  const patchFacts = patchF ? fileFacts(patchF.path) : { exists: false }
  add('profile.patch.exists', 'cordis.patch.yml 存在', patchFacts.exists, 'red', patchFacts.exists ? `${patchFacts.bytes} B` : '文件不存在')
  if (patchFacts.exists) {
    const txt = readTextFile(patchF.path)
    add('profile.patch.encoding', 'cordis.patch.yml 编码', txt.ok && txt.utf8 && !txt.bom, 'red', !txt.ok ? `读不了：${txt.error}` : txt.bom ? '带 BOM' : !txt.utf8 ? '不是合法 UTF-8' : 'UTF-8 无 BOM')
    const parsed = parseYaml(txt.text || '', { profileDir: profile })
    if (parsed.state === 'ok') {
      add('profile.patch.yaml', 'cordis.patch.yml 可被 YAML 解析', true, 'red', `js-yaml OK（${parsed.source}）`)
      const isArr = Array.isArray(parsed.doc)
      add('profile.patch.array', 'patch 顶层是数组', isArr, 'red', isArr ? `${parsed.doc.length} 条` : `实际类型 ${Array.isArray(parsed.doc) ? 'array' : typeof parsed.doc}`)
    } else if (parsed.state === 'opaque') {
      add('profile.patch.yaml', 'cordis.patch.yml 可被 YAML 解析', true, 'yellow', '含 !!js 自定义 tag，js-yaml 不识别（cordis 合法）')
    } else if (parsed.state === 'invalid') {
      add('profile.patch.yaml', 'cordis.patch.yml 可被 YAML 解析', false, 'red', `YAML 解析失败：${parsed.error}`)
    } else {
      add('profile.patch.yaml', 'cordis.patch.yml 可被 YAML 解析', true, 'yellow', '找不到 js-yaml，退化为结构校验')
    }
    const struct = analyzeYamlStruct(txt.text || '')
    add('profile.patch.structure', 'patch 结构（缩进/重复 id/UTF-8 痕迹）', struct.ok, 'red', struct.ok ? `顶层 ${struct.entries.length} 条，insert 子条目 ${struct.insertIds.length} 个` : struct.issues.join('；'))
  }

  // 2) profile package.json + bundles
  const pkgF = byKey.get('profile.package')
  const pkgTxt = pkgF ? readTextFile(pkgF.path) : { ok: false, error: 'missing' }
  const pkg = pkgTxt.ok ? safeJson(pkgTxt.text) : { ok: false, error: 'missing' }
  add('profile.package.json', 'profile package.json 可解析', pkg.ok, 'red', pkg.ok ? `${pkgTxt.bytes} B` : `解析失败：${pkg.error}`)
  let bundles = []
  if (pkg.ok) {
    const b = pkg.value && pkg.value.dsh && pkg.value.dsh.profile && pkg.value.dsh.profile.bundles
    bundles = Array.isArray(b) ? b.map(String) : []
    add('profile.package.bundles', 'dsh.profile.bundles 是数组', Array.isArray(b), 'red', Array.isArray(b) ? `${bundles.length} 项` : '找不到 bundles 数组')
    if (bundles.length) {
      const dup = bundles.filter((x, i) => bundles.indexOf(x) !== i)
      add('profile.package.bundles.dup', 'bundles 无重复项', dup.length === 0, 'yellow', dup.length ? `重复：${[...new Set(dup)].join(', ')}` : '无重复')
      const required = (opts.requiredBundles || DEFAULT_REQUIRED_BUNDLES).map(String)
      const missing = required.filter((r) => !bundles.includes(r))
      add('profile.package.bundles.required', 'bundles 含必要项', missing.length === 0, 'red', missing.length ? `缺：${missing.join(', ')}` : `含：${required.join(', ')}`)
      const baseBundles = opts.baselinePkg && Array.isArray(opts.baselinePkg.bundles) ? opts.baselinePkg.bundles : []
      if (baseBundles.length) {
        const lost = baseBundles.filter((x) => !bundles.includes(x))
        add('profile.package.bundles.regress', 'bundles 没比基线少', bundles.length >= baseBundles.length && lost.length === 0, 'red',
          lost.length ? `少了 ${lost.length} 项：${lost.slice(0, 6).join(', ')}` : `基线 ${baseBundles.length} 项，现在 ${bundles.length} 项`)
      }
      const unresolved = bundles.filter((n) => !/^@deepseek-ai\//.test(n) && !fs.existsSync(path.join(profile, 'node_modules', n)))
      add('profile.package.bundles.resolve', '本地 bundle 都装进了 node_modules', unresolved.length === 0, 'red',
        unresolved.length ? `找不到：${unresolved.join(', ')}` : '本地 bundle 均可解析')
    }
  }

  // 3) DSH 热文件（storages）：能解析 + 骨架还在（条目增减不算问题，写坏才红）
  for (const key of ['storage.workspace', 'storage.schedule']) {
    const f = byKey.get(key)
    if (!f) continue
    const a = analyzeHotJson(f.path, f.expect || {})
    if (!a.exists) { add(`${key}.exists`, `${f.label} 存在`, false, 'yellow', '文件不存在（第一次启动？）'); continue }
    add(`${key}.exists`, `${f.label} 存在`, true, 'yellow', `${a.facts.bytes} B`)
    add(`${key}.structure`, `${f.label} 结构完整（unit / global / tables / 关键字段）`, a.ok, 'red',
      a.ok ? `骨架在：${describeHotStats(a)}${a.warn.length ? '；' + a.warn.map((w) => w.detail).join('；') : ''}` : a.fatal.map((x) => x.detail).join('；'))
  }

  // 4) 插件自身 + 数据目录
  if (opts.pluginDir) {
    const ok = ['panel.html', 'panel.js'].every(name => fs.existsSync(path.join(opts.pluginDir, 'lib', name)))
    add('self.panel', '只读面板资源完整', ok, 'yellow', ok ? '面板资源齐全' : '面板资源不完整')
  }
  try {
    const dir = ensureDir(dataDir(home, path.basename(profile)))
    checkPlainPath(dir, 'dir')
    const probe = path.join(dir, '.probe-' + crypto.randomUUID())
    fs.writeFileSync(probe, 'ok', { flag: 'wx', mode: 0o600 })
    fs.unlinkSync(probe)
    add('data.writable', '数据目录可写', true, 'yellow', dir)
  } catch (err) {
    add('data.writable', '数据目录可写', false, 'red', `写不了：${err.message}`)
  }

  const failedRed = checks.filter((c) => !c.ok && c.severity === 'red')
  const failedYellow = checks.filter((c) => !c.ok && c.severity !== 'red')
  return { at: nowIso(), ok: failedRed.length === 0, passed: checks.filter((c) => c.ok).length, total: checks.length, failed: checks.filter((c) => !c.ok), checks, bundles }
}

// ---------------------------------------------------------------- G0-G3
const G3_KINDS = new Set(['data-delete', 'external-send', 'system', 'asar'])
const G2_KINDS = new Set(['patch-structure', 'bundles', 'junction', 'register', 'lifecycle', 'install', 'uninstall', 'upgrade', 'master-skill'])

/**
 * G0–G3 分级（照 crash-guard SKILL.md 的「五维 + 先命中先定档」）。
 * 输入尽量用原档位：layer L0-L4 / reversible V0-V2 / verifiable T0-T2 / blastRadius R0-R4 / firstTime F0-F2。
 */
export function classifyGate(input = {}) {
  const layer = String(input.layer || '').toUpperCase()
  const reversible = String(input.reversible || input.rollback || '').toUpperCase()
  const verifiable = String(input.verifiable || '').toUpperCase()
  const blast = String(input.blastRadius || input.blast || '').toUpperCase()
  const first = String(input.firstTime || input.first || '').toUpperCase()
  const kind = String(input.kind || '').toLowerCase()
  const reasons = []
  const hasGolden = input.hasGolden === true
  let level = 'G0'

  if (layer === 'L4') { level = 'G3'; reasons.push('触及 L4（app.asar / 打包产物）') }
  if (reversible === 'V2' && !hasGolden) { level = 'G3'; reasons.push('V2 不可逆且没有 golden') }
  if (G3_KINDS.has(kind)) { level = 'G3'; reasons.push(`动作类型 ${kind} 一票阻断`) }
  if (blast === 'R4') { level = 'G3'; reasons.push('爆炸半径 R4（启动/路由/依赖/配置）且不可控') }
  if (level !== 'G3') {
    if (G2_KINDS.has(kind) || layer === 'L3') { level = 'G2'; reasons.push(G2_KINDS.has(kind) ? `结构性动作：${kind}` : '触及 L3 运行配置/依赖') }
    else if (layer === 'L1' || layer === 'L2' || kind === 'skill' || kind === 'plugin-source' || kind === 'config-value') { level = 'G1'; reasons.push('写入 ~/.dsh / 插件源码 / skill / 脚本或单个配置值') }
    else { level = 'G0'; reasons.push('文档 / 只读 / 副本试跑') }
  }
  const g2b = first === 'F0' && level === 'G2' && verifiable === 'T2' && reversible === 'V2'
  return {
    level, g2b, reasons,
    dims: { layer, reversible, verifiable, blastRadius: blast, firstTime: first },
    evidence: level === 'G0' ? [] : ['00-baseline.md', '01-plan.md', '02-diff.txt', '03-verify.txt', '04-rollback.ps1', '05-risk.md'],
    preflight: ['G2', 'G3'].includes(level),
    advice: level === 'G3' ? '不派不改，升级给人。' : level === 'G2' ? '先在副本跑通完整流程 + 回滚（danger-preflight），再动真的。' : level === 'G1' ? '带证据包：基线 / 计划 / 退出码 / 回滚命令。' : '免检，但别顺手改受保护文件。',
  }
}

// ---------------------------------------------------------------- 健康度
export function healthOf(opts = {}) {
  const reasons = []
  let level = 'green'
  const bump = (lv, why) => {
    const rank = { green: 0, yellow: 1, red: 2 }
    if (rank[lv] > rank[level]) level = lv
    reasons.push({ level: lv, why })
  }
  for (const c of opts.checks || []) {
    if (c.ok) continue
    if (c.severity === 'red') bump('red', `自检红：${c.title} — ${c.detail}`)
    else bump('yellow', `自检黄：${c.title} — ${c.detail}`)
  }
  const changes = opts.changes || {}
  for (const u of changes.undeclared || []) bump(u.severity === 'red' ? 'red' : 'yellow', `未声明改动：${u.label}（${u.status}）`)
  for (const d of changes.drifted || []) bump('yellow', `热文件内容变化（结构完好，不算未声明）：${d.label}${d.gradeDetail ? ' — ' + d.gradeDetail : ''}`)
  for (const p of changes.pending || []) bump('yellow', `已快照未校验：${p.label}`)
  if (opts.hasBaseline === false) bump('yellow', '还没有基线：先跑一次 safety_snap 或让插件初始化')
  if (opts.lastError) bump('yellow', `插件内部错误：${opts.lastError}`)
  return { level, reasons, at: nowIso() }
}
// ---------------------------------------------------------------- 自己的审计日志
export const auditLogFile = (home, profile) => path.join(dataDir(home, profile), 'audit.log')
const AUDIT_MAX_BYTES = 512 * 1024
const AUDIT_KEEP_LINES = 400

export function appendAudit(home, rec, profile) {
  try {
    const file = auditLogFile(home, profile)
    ensureDir(path.dirname(file))
    checkPlainPath(file, 'file', true)
    try {
      const st = fs.statSync(file)
      if (st.size > AUDIT_MAX_BYTES) {
        const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean)
        fs.writeFileSync(file, lines.slice(-AUDIT_KEEP_LINES).join('\n') + '\n', 'utf8')
      }
    } catch { /* 没日志文件是常态 */ }
    fs.appendFileSync(file, JSON.stringify({ at: nowIso(), tool: TOOL, ...rec }) + '\n', 'utf8')
    return true
  } catch { return false }
}

export function ownGateRecords(home, profile) {
  const out = []
  for (const r of readAudit(home, 500, profile)) {
    const atMs = Date.parse(String(r.at || ''))
    if (!isFinite(atMs)) continue
    const targets = Array.isArray(r.targets) ? r.targets : []
    const kind = r.kind === 'SNAP' ? 'snap' : (r.kind === 'ACCEPT' ? 'verify' : '')
    if (!kind) continue
    for (const p of targets) {
      if (typeof p !== 'string' || !p) continue
      out.push({ source: 'safety-guard', kind, at: String(r.at), atMs, file: p, pathKey: normPath(p), verdict: kind === 'snap' ? 'SNAPPED' : 'PASS', sha: String(r.sha256 || ''), label: String(r.label || ''), bytes: 0 })
    }
  }
  return out
}

export function readAudit(home, limit = 50, profile) {
  const r = readTextFile(auditLogFile(home, profile))
  if (!r.ok) return []
  const out = []
  const lines = r.text.split(/\r?\n/)
  for (let i = lines.length - 1; i >= 0 && out.length < limit; i--) {
    const line = lines[i].trim()
    if (!line) continue
    const j = safeJson(line)
    if (j.ok) out.push(j.value)
  }
  return out.reverse()
}

// ---------------------------------------------------------------- 快照 / 校验 / 回滚
export const statesDir = (home, profile) => path.join(dataDir(home, profile), 'states')
export function slug(s, max = 40) {
  const t = String(s || '').replace(/[\\/:*?"<>|\s]+/g, '-').replace(/^-+|-+$/g, '')
  return (t || 'snap').slice(0, max)
}

// Refuse junctions/symlinks and non-regular files, and bound in-memory reads.
const MAX_CONFIG_BYTES = 8 * 1024 * 1024
const MAX_STATE_BYTES = 128 * 1024
const samePath = (a, b) => process.platform === 'win32' ? normPath(a) === normPath(b) : a === b
export function checkPlainPath(file, kind, missing = false) {
  const full = path.resolve(file)
  const parent = path.dirname(full)
  if (!samePath(fs.realpathSync.native(parent), parent)) throw new Error('Linked parent is not allowed')
  let info
  try { info = fs.lstatSync(full) } catch (err) { if (missing && err.code === 'ENOENT') return null; throw err }
  if (info.isSymbolicLink() || (kind === 'file' ? !info.isFile() : !info.isDirectory()) || !samePath(fs.realpathSync.native(full), full)) throw new Error('Not a plain ' + kind)
  if (kind === 'file' && info.nlink !== 1) throw new Error('Hard-linked files are not allowed')
  return info
}
function readBounded(file, max, missing = false) {
  if (!checkPlainPath(file, 'file', missing)) return null
  const fd = fs.openSync(file, 'r')
  try {
    const st = fs.fstatSync(fd)
    if (!st.isFile() || st.nlink !== 1 || st.size > max) throw new Error('Unexpected file type or size')
    const buf = Buffer.alloc(st.size + 1)
    let used = 0
    while (used < buf.length) {
      const n = fs.readSync(fd, buf, used, buf.length - used, null)
      if (!n) break
      used += n
    }
    if (used !== st.size) throw new Error('File changed while being read')
    return buf.subarray(0, used)
  } finally { fs.closeSync(fd) }
}
export function atomicWrite(file, contents) {
  const tmp = file + '.safety-' + crypto.randomUUID() + '.tmp'
  checkPlainPath(file, 'file', true)
  try {
    fs.writeFileSync(tmp, contents, { flag: 'wx', mode: 0o600, flush: true })
    fs.renameSync(tmp, file)
  } finally { try { fs.unlinkSync(tmp) } catch { /* already moved */ } }
}
export const isRestorable = (file) => !file.hot && !file.monitorOnly
export function snapFiles({ home, profile, files, label = 'snap', note = '' }) {
  if (!files.length || files.some((f) => !isRestorable(f))) throw new Error('Select at least one restorable configuration file')
  const root = ensureDir(statesDir(home, profile))
  checkPlainPath(root, 'dir')
  const dir = path.join(root, stamp() + '-' + slug(label) + '-' + crypto.randomUUID())
  fs.mkdirSync(dir, { mode: 0o700 })
  try {
    const entries = files.map((f, i) => {
      const bytes = readBounded(f.path, MAX_CONFIG_BYTES, true)
      const backupRel = bytes === null ? '' : String(i).padStart(2, '0') + '.backup'
      if (backupRel) fs.writeFileSync(path.join(dir, backupRel), bytes, { flag: 'wx', mode: 0o600, flush: true })
      return { key: f.key, label: f.label, path: f.path, exists: bytes !== null, bytes: bytes?.length ?? 0, sha256: bytes === null ? '' : sha256(bytes), backupRel }
    })
    const state = { v: SNAP_VERSION, tool: TOOL, profile, label: String(label).slice(0, 200), note: String(note).slice(0, 400), at: nowIso(), atMs: Date.now(), files: entries }
    const statePath = path.join(dir, 'state.json')
    atomicWrite(statePath, JSON.stringify(state, null, 2))
    return { ok: true, statePath, dir, state }
  } catch (err) { try { fs.rmSync(dir, { recursive: true, force: true }) } catch {} throw err }
}

export function readStateFile(file) {
  const r = readTextFile(file)
  if (!r.ok) return { ok: false, error: `读不到 state：${r.error}` }
  const j = safeJson(r.text)
  if (!j.ok) return { ok: false, error: `state 不是合法 JSON：${j.error}` }
  const st = j.value
  if (!st || !Array.isArray(st.files)) {
    const legacy = normalizeLegacyState(st)
    if (legacy) return { ok: true, state: legacy, legacy: true }
    return { ok: false, error: 'state 里没有 files 数组，也不是 change-gate 老格式' }
  }
  return { ok: true, state: st, legacy: false }
}

/** change-gate / patch-guard 的老 state（单文件）→ 统一结构，保证老文件还能读。 */
export function normalizeLegacyState(rec) {
  if (!rec || typeof rec !== 'object') return null
  const file = String(rec.file || '')
  if (!file) return null
  const backup = String(rec.contentPath || rec.backup || '')
  return {
    v: SNAP_VERSION, legacy: true, tool: String(rec.tool || 'change-gate'), label: String(rec.label || ''),
    at: String(rec.at || ''), atMs: Date.parse(rec.at || '') || 0, dir: path.dirname(String(rec.contentPath || rec.backup || '')) || '',
    files: [{
      key: 'legacy', label: path.basename(file), path: file, pathKey: normPath(file), severity: 'red',
      exists: true, bytes: Number(rec.bytes) || 0, sha256: String(rec.sha256 || ''), mtime: String(rec.mtime || ''),
      utf8: rec.utf8 !== false, bom: !!rec.bom, backup, backupRel: '',
    }],
  }
}

export function listStates(home, limit = 10, profile) {
  const root = statesDir(home, profile)
  let names = []
  try { checkPlainPath(root, 'dir'); names = fs.readdirSync(root, { withFileTypes: true }).filter((n) => n.isDirectory() && !n.isSymbolicLink()).map((n) => n.name) } catch { return [] }
  const out = []
  for (const n of names) {
    const file = path.join(root, n, 'state.json')
    let r
    try { r = { state: JSON.parse(readBounded(file, MAX_STATE_BYTES)) } } catch { continue }
    if (r.state?.v !== SNAP_VERSION || r.state.tool !== TOOL || !Array.isArray(r.state.files)) continue
    out.push({ dirName: n, statePath: file, at: r.state.at, atMs: r.state.atMs || Date.parse(r.state.at || '') || 0, label: r.state.label, files: (r.state.files || []).length })
  }
  return out.sort((a, b) => b.atMs - a.atMs).slice(0, limit)
}

export function latestState(home, profile) { const l = listStates(home, 1, profile); return l.length ? l[0] : null }

/** 没有自己的快照时，把 change-gate 的 state 也当「最近备份」（它每次 snap 都留了内容副本）。 */
export function latestGateBackup(gateDir) {
  let names = []
  try { names = fs.readdirSync(gateDir).filter((n) => /\.json$/i.test(n) && !/\.content\./i.test(n)) } catch { return null }
  let best = null
  for (const n of names) {
    const file = path.join(gateDir, n)
    try {
      const st = fs.statSync(file)
      const r = safeJson(readTextFile(file).text || '')
      const at = r.ok ? String(r.value.at || '') : ''
      const atMs = Date.parse(at) || st.mtimeMs
      if (!best || atMs > best.atMs) {
        best = { atMs, at: at || st.mtime.toISOString(), label: r.ok ? String(r.value.label || '') : '', statePath: file, source: 'change-gate', files: 1 }
      }
    } catch { /* 跳过坏文件 */ }
  }
  return best
}

// Resolve all writes from the hard-coded allowlist, never from the manifest.
function inspectSnapshot(statePath, { home, profile, files }) {
  const root = statesDir(home, profile)
  const file = path.resolve(statePath)
  const dir = path.dirname(file)
  if (path.basename(file) !== 'state.json' || !samePath(path.dirname(dir), root)) throw new Error('Only snapshots from this profile may be used')
  checkPlainPath(root, 'dir')
  checkPlainPath(dir, 'dir')
  const state = JSON.parse(readBounded(file, MAX_STATE_BYTES))
  const allowed = new Map(files.filter(isRestorable).map(f => [f.key, f]))
  if (state?.v !== SNAP_VERSION || state.tool !== TOOL || state.profile !== profile || !Array.isArray(state.files) || !state.files.length || state.files.length > allowed.size) throw new Error('Invalid or unsupported snapshot')
  const seen = new Set()
  const entries = state.files.map((row, i) => {
    const f = allowed.get(row?.key)
    if (!f || seen.has(f.key) || typeof row.path !== 'string' || !samePath(row.path, f.path) || typeof row.exists !== 'boolean') throw new Error('Snapshot target is not an allowed configuration file')
    seen.add(f.key)
    let saved = null
    if (row.exists) {
      const expectedName = String(i).padStart(2, '0') + '.backup'
      if (row.backupRel !== expectedName || !/^[0-9a-f]{64}$/.test(row.sha256)) throw new Error('Invalid backup metadata')
      saved = readBounded(path.join(dir, expectedName), MAX_CONFIG_BYTES)
      if (sha256(saved) !== row.sha256 || saved.length !== row.bytes) throw new Error('Backup hash or size mismatch; nothing was restored')
    } else if (row.backupRel !== '' || row.sha256 !== '' || row.bytes !== 0) throw new Error('Invalid absent-file metadata')
    const current = readBounded(f.path, MAX_CONFIG_BYTES, true)
    const hash = current === null ? '' : sha256(current)
    const status = hash === row.sha256 ? 'unchanged' : !row.exists ? 'added' : current === null ? 'missing' : 'changed'
    return { f, saved, current, item: { key: f.key, label: f.label, path: f.path, status, before: row.sha256, after: hash, delta: (current?.length ?? 0) - row.bytes } }
  })
  return { entries, label: state.label }
}
export function verifyState(statePath, opts) {
  try {
    const { entries, label } = inspectSnapshot(statePath, opts)
    const items = entries.map(({ item }) => item)
    const changed = items.filter((i) => i.status !== 'unchanged')
    return { ok: changed.length === 0, at: nowIso(), state: statePath, label, items, changed }
  } catch (err) { return { ok: false, error: String(err.message || err), changed: [] } }
}

export function restoreState(statePath, opts) {
  let plan
  try { plan = inspectSnapshot(statePath, opts) } catch (err) { return { ok: false, error: String(err.message || err), items: [] } }
  const items = []
  const work = []
  try {
    // Save original bytes for every replacement before writing any target.
    for (const entry of plan.entries) {
      const { f, saved, current, item } = entry
      if (saved === null || item.status === 'unchanged') {
        items.push({ path: f.path, action: saved === null ? 'skipped-not-in-snapshot' : 'already-matches' })
        continue
      }
      const bad = current === null ? '' : f.path + '.rollback-bad-' + crypto.randomUUID()
      if (bad) fs.writeFileSync(bad, current, { flag: 'wx', mode: 0o600, flush: true })
      work.push({ ...entry, bad })
    }
  } catch (err) { return { ok: false, error: 'Could not save originals: ' + err.message, items } }
  for (const { f, saved, current, bad } of work) {
    try {
      const now = readBounded(f.path, MAX_CONFIG_BYTES, true)
      if ((now === null) !== (current === null) || (now !== null && !now.equals(current))) throw new Error('Destination changed during restore')
      atomicWrite(f.path, saved)
      items.push({ path: f.path, action: 'restored', bad })
    } catch (err) {
      items.push({ path: f.path, action: 'restore-failed', bad, error: String(err.message || err) })
      return { ok: false, partial: items.some((item) => item.action === 'restored'), at: nowIso(), state: statePath, items }
    }
  }
  return { ok: true, at: nowIso(), state: statePath, label: plan.label, items }
}

/** 扫 change-gate 的 gate 目录，确认老 state 还能被读（回归用）。 */
export function listLegacyStates(gateDir) {
  let names = []
  try { names = fs.readdirSync(gateDir).filter((n) => /\.json$/i.test(n) && !/\.content\./i.test(n)) } catch (err) {
    return { ok: false, gateDir, total: 0, valid: 0, items: [], invalid: [{ file: gateDir, error: String(err.message || err) }] }
  }
  const items = []
  const invalid = []
  for (const n of names) {
    const file = path.join(gateDir, n)
    const st = readStateFile(file)
    if (!st.ok) { invalid.push({ file, error: st.error }); continue }
    const f = st.state.files[0] || {}
    items.push({ file, at: st.state.at, label: st.state.label, target: f.path, sha256: f.sha256, bytes: f.bytes, backupExists: f.backup ? fs.existsSync(f.backup) : false, legacy: true })
  }
  return { ok: invalid.length === 0, gateDir, total: names.length, valid: items.length, items, invalid }
}

// ---------------------------------------------------------------- 危险动作预演
function nodeExe() {
  const candidates = [
    process.env.SAFETY_NODE,
    path.join(process.env.USERPROFILE || os.homedir(), '.dsh', 'dsh-runtimes', 'dsh-primary-runtime', 'dependencies', 'node', 'bin', 'node.exe'),
    process.execPath,
  ].filter(Boolean)
  for (const c of candidates) { try { if (fs.existsSync(c) && !/electron/i.test(c)) return c } catch { /* ignore */ } }
  return candidates.find((c) => { try { return fs.existsSync(c) } catch { return false } }) || ''
}

export function checkNodeSyntax(file, text) {
  const exe = nodeExe()
  if (!exe) return { ok: true, skipped: true, detail: '找不到 node，跳过语法检查' }
  const tmp = path.join(os.tmpdir(), 'safety-preflight-' + crypto.randomUUID() + (path.extname(file) || '.js'))
  try {
    if (Buffer.byteLength(text) > MAX_CONFIG_BYTES) throw new Error('Text exceeds preflight size limit')
    fs.writeFileSync(tmp, text, { flag: 'wx', mode: 0o600 })
    const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^NODE_(OPTIONS|PATH)$/i.test(k)))
    execFileSync(exe, ['--check', tmp], { stdio: 'pipe', timeout: 10000, env })
    return { ok: true, detail: 'node --check OK' }
  } catch (err) {
    const msg = String((err && (err.stderr && err.stderr.toString())) || (err && err.message) || err).replace(/\s+/g, ' ').slice(0, 400)
    return { ok: false, detail: msg }
  } finally { try { fs.unlinkSync(tmp) } catch { /* ignore */ } }
}

/** 预演一段新内容：只写临时文件，不碰原文件。 */
export function preflightText(opts = {}) {
  const file = String(opts.file || '')
  const text = String(opts.text == null ? '' : opts.text)
  const ext = path.extname(file).toLowerCase()
  const checks = []
  const utfOk = !text.includes('\uFFFD') && !/[\uD800-\uDFFF]/.test(text.replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/g, ''))
  checks.push({ id: 'utf8', ok: utfOk, detail: utfOk ? 'UTF-8 无非法字符' : '含替换字符 U+FFFD' })
  checks.push({ id: 'size', ok: text.length > 0, detail: `${Buffer.byteLength(text, 'utf8')} B` })
  if (ext === '.json') {
    const j = safeJson(text)
    checks.push({ id: 'json', ok: j.ok, detail: j.ok ? 'JSON 可解析' : `JSON 解析失败：${j.error}` })
  } else if (ext === '.yml' || ext === '.yaml') {
    const s = analyzeYamlStruct(text)
    checks.push({ id: 'yaml-struct', ok: s.ok, detail: s.ok ? `结构 OK，顶层 ${s.entries.length} 条` : s.issues.join('；') })
    const py = parseYaml(text)
    if (py.state === 'ok') checks.push({ id: 'yaml-parse', ok: true, detail: 'js-yaml 可解析' })
    else if (py.state === 'invalid') checks.push({ id: 'yaml-parse', ok: false, detail: `YAML 解析失败：${py.error}` })
    else checks.push({ id: 'yaml-parse', ok: true, detail: 'js-yaml 不可用，仅结构校验' })
  } else if (['.js', '.mjs', '.cjs'].includes(ext)) {
    const r = checkNodeSyntax(file, text)
    checks.push({ id: 'node-check', ok: r.ok, detail: r.detail })
  }
  return { ok: checks.every((c) => c.ok), file, bytes: Buffer.byteLength(text, 'utf8'), checks, at: nowIso() }
}

/** 预演一个插件目录：package.json / patch / 入口语法 / 客户端。 */
export function preflightPluginDir(dir) {
  const checks = []
  const add = (id, ok, detail) => checks.push({ id, ok: !!ok, detail: String(detail || '') })
  if (!fs.existsSync(dir)) return { ok: false, dir, checks: [{ id: 'exists', ok: false, detail: '目录不存在' }] }
  const pkgPath = path.join(dir, 'package.json')
  const pkgTxt = readTextFile(pkgPath)
  const pkg = pkgTxt.ok ? safeJson(pkgTxt.text) : { ok: false, error: pkgTxt.error || 'missing' }
  add('package.json', pkg.ok, pkg.ok ? 'JSON 可解析' : `解析失败：${pkg.error}`)
  let patchRel = ''
  if (pkg.ok) {
    const d = pkg.value && pkg.value.dsh
    patchRel = d && d.bundle && d.bundle.patch ? String(d.bundle.patch) : ''
    add('dsh.bundle.patch', !!patchRel, patchRel || 'package.json 缺 dsh.bundle.patch')
    const clientDecl = !!(d && d.client)
    const clientFile = path.join(dir, 'lib', 'client.js')
    add('dsh.client', clientDecl, clientDecl ? (fs.existsSync(clientFile) ? '声明 + lib/client.js 都在' : '声明了 dsh.client 但缺 lib/client.js') : '没声明客户端（只有服务端）')
    const main = pkg.value.main ? path.resolve(dir, pkg.value.main) : ''
    add('main', !!main && fs.existsSync(main), main && fs.existsSync(main) ? 'main 存在' : 'main 不存在')
    if (main && fs.existsSync(main)) {
      const r = checkNodeSyntax(main, fs.readFileSync(main, 'utf8'))
      add('main.syntax', r.ok, r.detail)
    }
    for (const p of ['lib/client.js']) {
      const f = path.join(dir, p)
      if (!fs.existsSync(f)) continue
      const r = checkNodeSyntax(f, fs.readFileSync(f, 'utf8'))
      add(`${p}.syntax`, r.ok, r.detail)
    }
  }
  if (patchRel) {
    const patchFile = path.resolve(dir, patchRel)
    const txt = readTextFile(patchFile)
    add('patch.exists', txt.ok, txt.ok ? 'patch 存在' : 'patch 不存在')
    if (txt.ok) {
      const s = analyzeYamlStruct(txt.text)
      add('patch.struct', s.ok, s.ok ? `顶层 ${s.entries.length} 条，insert ${s.insertIds.length} 个` : s.issues.join('；'))
      const py = parseYaml(txt.text)
      add('patch.yaml', py.state !== 'invalid', py.state === 'ok' ? 'js-yaml 可解析' : py.state === 'invalid' ? `解析失败：${py.error}` : 'js-yaml 不可用，仅结构校验')
    }
  }
  return { ok: checks.every((c) => c.ok), dir, checks, at: nowIso() }
}

// ---------------------------------------------------------------- 写保护（工具层拦截）
export const WRITE_TOOLS = new Set([
  'write', 'write_file', 'edit', 'edit_file', 'apply_patch', 'multiedit', 'multi_edit',
  'create_file', 'str_replace', 'str_replace_editor', 'fs_write', 'file_write', 'notebook_edit', 'delete', 'move', 'copy',
])

/** Match filesystem operands only, not file contents or descriptive strings. */
export function matchProtected(args, files, toolName) {
  const wanted = new Map(files.map(f => [normPath(path.resolve(f.path)), f]))
  const candidates = []
  const collect = (obj, depth = 0) => {
    if (!obj || typeof obj !== 'object' || depth > 3 || candidates.length >= 400) return
    for (const key of ['file_path', 'path', 'filePath', 'source_path', 'destination_path', 'from', 'to', 'src', 'dest']) {
      if (typeof obj[key] === 'string') candidates.push(obj[key])
    }
    for (const key of ['files', 'edits', 'operations']) if (Array.isArray(obj[key])) for (const item of obj[key].slice(0, 400)) {
      if (key === 'files' && typeof item === 'string') candidates.push(item)
      else collect(item, depth + 1)
      if (candidates.length >= 400) break
    }
  }
  collect(args)
  if (toolName === 'apply_patch') {
    const patch = typeof args === 'string' ? args : args?.patch ?? args?.input
    if (typeof patch === 'string' && patch.length <= 2 * 1024 * 1024) {
      for (const m of patch.matchAll(/^\*\*\* (?:(?:Add|Update|Delete) File|Move to):[ \t]*(.+)$/gm)) {
        candidates.push(m[1].trimEnd())
        if (candidates.length >= 400) break
      }
    }
  }
  for (const raw of candidates) {
    if (raw.length > 4096 || !path.isAbsolute(raw) || (process.platform === 'win32' && /^[\\/](?![\\/])/.test(raw))) continue
    const hit = wanted.get(normPath(path.resolve(raw)))
    if (hit) return hit
  }
  return null
}

