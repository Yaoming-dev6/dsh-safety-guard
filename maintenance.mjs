import fs from 'node:fs'
import path from 'node:path'
import { randomUUID } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'
import { atomicWrite, checkPlainPath, criticalFiles, latestState, profileId, restoreState, verifyState, TOOL } from './lib/core.js'

const source = path.dirname(fileURLToPath(import.meta.url))
const managed = '.safety-guard-local.json'
const runtimeFiles = ['package.json', 'cordis.patch.yml', 'LICENSE', 'lib/core.js', 'lib/index.js', 'lib/panel.html', 'lib/panel.js']
const exists = (file) => { try { fs.lstatSync(file); return true } catch (err) { if (err.code === 'ENOENT') return false; throw err } }
function log(data) { console.log(JSON.stringify(data, null, 2)) }
function maint() {
  const [action, ...args] = process.argv.slice(2)
  const { values: v } = parseArgs({ args, options: { home: { type: 'string' }, profile: { type: 'string' }, state: { type: 'string' }, apply: { type: 'boolean' } } })
  if (!['install', 'uninstall', 'restore'].includes(action) || !v.home || !v.profile) throw new Error('Specify --home and --profile explicitly')
  const home = path.resolve(v.home)
  const profile = profileId(v.profile)
  const profileDir = path.join(home, 'profiles', profile)
  checkPlainPath(profileDir, 'dir')
  if (action === 'restore') {
    const state = v.state || latestState(home, profile)?.statePath
    if (!state) throw new Error('No v2 snapshot in the selected profile')
    const opts = { home, profile, files: criticalFiles({ home, profile: profileDir }) }
    const result = v.apply ? restoreState(state, opts) : verifyState(state, opts)
    log(result)
    if (result.error || (v.apply && !result.ok)) process.exitCode = 2
    return
  }
  const pkgFile = path.join(profileDir, 'package.json')
  const pkgInfo = checkPlainPath(pkgFile, 'file')
  if (pkgInfo.size > 1024 * 1024) throw new Error('Profile manifest too large')
  const original = fs.readFileSync(pkgFile)
  const pkg = JSON.parse(original.toString('utf8').replace(/^\uFEFF/, ''))
  const bundles = pkg.dsh?.profile?.bundles
  if (!Array.isArray(bundles) || bundles.some(x => typeof x !== 'string')) throw new Error('Expected dsh.profile.bundles array')
  if (['dependencies','devDependencies','optionalDependencies','peerDependencies'].some(k => Object.hasOwn(pkg[k] ?? {}, TOOL))) throw new Error('Existing package-manager installation must be removed through its original manager')
  const modules = path.join(profileDir, 'node_modules')
  const target = path.join(modules, TOOL)
  const present = exists(target)
  if (present) checkPlainPath(target, 'dir')
  if (action === 'install' && (present || bundles.includes(TOOL))) throw new Error('Plugin already declared or present; will not replace it')
  if (action === 'uninstall' && present) {
    const marker = path.join(target, managed)
    checkPlainPath(marker, 'file')
    if (JSON.parse(fs.readFileSync(marker, 'utf8')).tool !== TOOL) throw new Error('This install is not managed by this script')
  }
  log({ mode: v.apply ? 'apply' : 'preview', action, profileDir, packagePath: target })
  if (!v.apply || (action === 'uninstall' && !present && !bundles.includes(TOOL))) return
  const id = randomUUID()
  const backup = pkgFile + '.bak-safety-' + id
  fs.writeFileSync(backup, original, { flag: 'wx', mode: 0o600, flush: true })
  const replaceManifest = () => {
    if (!fs.readFileSync(pkgFile).equals(original)) throw new Error('Profile manifest changed concurrently; try again with DSH closed')
    const newline = original.includes('\r\n') ? '\r\n' : '\n'
    const json = JSON.stringify(pkg, null, 2).replaceAll('\n', newline) + newline
    atomicWrite(pkgFile, json)
  }
  if (action === 'install') {
    fs.mkdirSync(modules, { recursive: true })
    checkPlainPath(modules, 'dir')
    const staged = fs.mkdtempSync(path.join(modules, '.safety-guard-stage-'))
    let placed = false
    try {
      for (const file of runtimeFiles) {
        const orig = path.join(source, file)
        checkPlainPath(orig, 'file')
        const dest = path.join(staged, file)
        fs.mkdirSync(path.dirname(dest), { recursive: true })
        fs.copyFileSync(orig, dest, fs.constants.COPYFILE_EXCL)
      }
      fs.writeFileSync(path.join(staged, managed), JSON.stringify({ tool: TOOL }), { flag: 'wx' })
      if (exists(target)) throw new Error('Plugin directory appeared during installation')
      fs.renameSync(staged, target)
      placed = true
      bundles.push(TOOL)
      replaceManifest()
    } catch (err) {
      if (placed) fs.renameSync(target, path.join(profileDir, '.safety-install-failed-' + id))
      else fs.rmSync(staged, { recursive: true, force: true })
      throw err
    }
    log({ ok: true, backup })
  } else {
    const retired = path.join(profileDir, '.safety-uninstalled-' + id)
    if (present) fs.renameSync(target, retired)
    try {
      pkg.dsh.profile.bundles = bundles.filter(x => x !== TOOL)
      replaceManifest()
    } catch (err) { if (present) fs.renameSync(retired, target); throw err }
    log({ ok: true, backup, retired: present ? retired : null })
  }
}
try { maint() } catch (err) { console.error(err.message); process.exitCode = 2 }
