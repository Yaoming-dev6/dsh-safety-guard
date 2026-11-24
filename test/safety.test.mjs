import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { spawnSync } from 'node:child_process'
import { fileURLToPath, pathToFileURL } from 'node:url'
import test from 'node:test'
import * as core from '../lib/core.js'
import { apply } from '../lib/index.js'

const profile = 'test-desktop'
const required = ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-web-app']
function fixture(t) {
  const home = fs.mkdtempSync(path.join(fs.realpathSync.native(os.tmpdir()), 'dsh-safety-test-'))
  t.after(() => { assert.match(path.basename(home), /^dsh-safety-test-/); fs.rmSync(home, { force:true, recursive:true }) })
  const dir = path.join(home, 'profiles', profile)
  fs.mkdirSync(dir, { recursive:true })
  fs.mkdirSync(path.join(home, 'storages'))
  const patch = path.join(dir, 'cordis.patch.yml')
  fs.writeFileSync(patch, '- insert:\n    - id: test\n      name: test\n')
  fs.writeFileSync(path.join(dir, 'cordis.yml'), 'generated\n')
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({name:'dsh-safety-guard-test',dsh:{profile:{bundles:required}}}))
  fs.writeFileSync(path.join(home, 'AGENTS.md'), '# test\n')
  for (const [unit, table, global] of [['workspace','workspaces',{workspaceIds:[]}],['schedule','tasks',null]]) {
    fs.writeFileSync(path.join(home,'storages',unit+'.json'), JSON.stringify({unit:{name:unit,version:2},global,tables:{[table]:{}}}))
  }
  return { home, dir, patch, profile, files:core.criticalFiles({home,profile:dir}) }
}
function withHome(t, f) {
  const saved = Object.fromEntries(['DSH_HOME','DSH_PROFILE','DSH_PROFILE_DIR'].map(k => [k, process.env[k]]))
  Object.assign(process.env, {DSH_HOME:f.home,DSH_PROFILE:profile,DSH_PROFILE_DIR:f.dir})
  t.after(() => { for (const [k,v] of Object.entries(saved)) if (v === undefined) delete process.env[k]; else process.env[k]=v })
}
function mount(t, f, cfg={}) {
  withHome(t, f)
  const tools = new Map(), routes = new Map(), guards = new Set(), effects = []
  t.after(() => effects.reverse().forEach(cb => cb()))
  const register = (map, key, value) => { assert.ok(!map.has(key)); map.set(key,value); return () => map.delete(key) }
  const ctx = {
    logger:{warn:console.warn},
    effect(cb) { const result = cb(); if (typeof result === 'function') effects.push(result) },
    inject(keys, cb) { assert.deepEqual(keys,['webServer']); cb(this) },
    tools:{register: d=>register(tools,d.name,d), guard: cb=>{ guards.add(cb); return ()=>guards.delete(cb) }},
    webServer:{register: r=>register(routes,r.path,r)},
  }
  const plugin = apply(ctx, {watch:false,...cfg})
  assert.ok(plugin)
  assert.equal(tools.size, 8)
  return { plugin,tools,routes,guards }
}
function renderRoute(route, method) {
  let status, headers, body
  route.handler({method}, {writeHead(s,h) {status=s;headers=h}, end(b) {body=b}})
  return { status,headers,body }
}
function cli(f, action, ...args) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([k])=>!/^NODE_(OPTIONS|PATH)$/i.test(k)))
  return spawnSync(process.execPath, [fileURLToPath(new URL('../maintenance.mjs',import.meta.url)),action,'--home',f.home,'--profile',f.profile,...args],{encoding:'utf8',env})
}

test('rc.5-style mount exposes tools and read-only redacted routes',async t=>{
  const f=fixture(t), {tools,routes}=mount(t,f)
  assert.ok(fs.existsSync(path.join(core.dataDir(f.home,profile),'baseline.json')))
  const s=await tools.get('safety_status').execute({})
  assert.equal(s.ok,true)
  assert.equal(s.health,'green',JSON.stringify(s.status.checks.failed))
  assert.equal(s.status.guard.mode,'warn')
  assert.equal(routes.has('/dsh-safety/action'),false)
  const r=routes.get('/dsh-safety/status')
  const rsp=renderRoute(r,'GET')
  assert.equal(rsp.status,200)
  assert.equal(JSON.parse(rsp.body).health,'green')
  assert.ok(!rsp.body.includes('profileDir'))
  assert.equal(renderRoute(r,'POST').status,405)
  assert.equal(renderRoute(r,'HEAD').body,undefined)
  assert.match(renderRoute(routes.get('/dsh-safety/panel'),'GET').headers['content-security-policy'],/frame-ancestors 'none'/)
})

test('rc.5 invocation arguments guard actual targets, not file text', async t=>{
  const f=fixture(t), {tools,guards}=mount(t,f,{guardMode:'block'})
  const [guard]=guards
  assert.equal(guard({name:'write',arguments:{file_path:path.join(f.home,'other.md'),content:f.patch}}),undefined)
  assert.match(guard({name:'write',arguments:{file_path:f.patch}}),/受保护/)
  assert.match(guard({name:'apply_patch',arguments:{patch:'*** Update File: '+f.patch+'\n'}}),/受保护/)
  assert.equal(guard({name:'write',arguments:{file_path:path.join(f.home,'storages','schedule.json')}}),undefined)
  assert.equal((await tools.get('safety_snap').execute({files:['storage.schedule']})).ok,false)
  const snap=await tools.get('safety_snap').execute({label:'guard test',files:['profile.patch']})
  assert.equal(snap.ok,true,JSON.stringify(snap))
  assert.equal(guard({name:'write',arguments:{file_path:f.patch}}),undefined)
  fs.appendFileSync(f.patch,'# modified\n')
  const preview=await tools.get('safety_restore').execute({state:snap.state,confirm:true})
  assert.equal(preview.dryRun,true)
  assert.match(fs.readFileSync(f.patch,'utf8'),/modified/)
})

test('snapshot restore validates entire backup before changing targets',t=>{
  const f=fixture(t)
  const allowed=f.files.filter(core.isRestorable)
  const snap=core.snapFiles({...f,files:allowed})
  const first=fs.readFileSync(f.patch)
  fs.appendFileSync(f.patch,'# changed\n')
  const badCopy=path.join(snap.dir,snap.state.files.find(x=>x.key==='global.agents').backupRel)
  const data=fs.readFileSync(badCopy)
  fs.writeFileSync(badCopy,'corrupted')
  assert.match(core.restoreState(snap.statePath,f).error,/hash or size/)
  assert.match(fs.readFileSync(f.patch,'utf8'),/changed/)
  fs.writeFileSync(badCopy,data)
  const ret=core.restoreState(snap.statePath,f)
  assert.equal(ret.ok,true,JSON.stringify(ret))
  assert.deepEqual(fs.readFileSync(f.patch),first)
  assert.match(fs.readFileSync(ret.items.find(x=>x.action==='restored').bad,'utf8'),/changed/)
})

test('snapshot stays scoped; absent files are never deleted', t=>{
  const f=fixture(t)
  const a=core.snapFiles({...f,files:f.files.filter(core.isRestorable)})
  const b=core.snapFiles({...f,files:f.files.filter(core.isRestorable)})
  assert.notEqual(a.dir,b.dir)
  assert.match(core.restoreState(a.statePath,{...f,profile:'other-profile'}).error,/this profile/)
  fs.writeFileSync(path.join(f.home,'cordis.patch.yml'),'# added after snap')
  assert.equal(core.restoreState(a.statePath,f).ok,true)
  assert.equal(fs.readFileSync(path.join(f.home,'cordis.patch.yml'),'utf8'),'# added after snap')
})

test('isolated install -> import -> offline restore -> uninstall',async t=>{
  const f=fixture(t), manifest=path.join(f.dir,'package.json')
  const initial=fs.readFileSync(manifest)
  const target=path.join(f.dir,'node_modules',core.TOOL)
  assert.equal(cli(f,'install').status,0)
  assert.deepEqual(fs.readFileSync(manifest),initial)
  assert.ok(!fs.existsSync(target))
  const added=cli(f,'install','--apply')
  assert.equal(added.status,0,added.stderr)
  assert.equal(JSON.parse(fs.readFileSync(manifest)).dsh.profile.bundles.at(-1),core.TOOL)
  assert.notEqual(cli(f,'install','--apply').status,0)
  const module=await import(pathToFileURL(path.join(target,'lib','index.js')).href)
  assert.equal(module.name,core.TOOL)
  const a=core.snapFiles({...f,files:f.files.filter(row=>row.key==='profile.patch')})
  const old=fs.readFileSync(f.patch)
  fs.appendFileSync(f.patch,'# new')
  assert.equal(cli(f,'restore','--state',a.statePath).status,0)
  assert.match(fs.readFileSync(f.patch,'utf8'),/new/)
  const restored=cli(f,'restore','--state',a.statePath,'--apply')
  assert.equal(restored.status,0,restored.stderr || restored.stdout)
  assert.deepEqual(fs.readFileSync(f.patch),old)
  const removed=cli(f,'uninstall','--apply')
  assert.equal(removed.status,0,removed.stderr)
  assert.ok(!fs.existsSync(target))
  assert.deepEqual(JSON.parse(fs.readFileSync(manifest)),JSON.parse(initial))
  assert.ok(fs.existsSync(a.statePath))
})
