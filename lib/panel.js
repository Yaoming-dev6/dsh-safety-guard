const put = (id, value) => { document.getElementById(id).textContent = String(value) }
async function refresh() {
  try {
    const res = await fetch('/dsh-safety/status', { cache: 'no-store', signal: AbortSignal.timeout(4000) })
    if (!res.ok) throw new Error('状态不可用')
    const s = await res.json()
    put('health', ({green:'正常',yellow:'请关注',red:'异常'})[s.health] || '尚未生成')
    put('checks', s.checks ? s.checks.passed + '/' + s.checks.total : '—')
    put('changes', s.changes?.undeclared ?? '—')
    put('guard', s.guard ? s.guard.mode + ' · 提示 ' + s.guard.warned + ' 次 · 拦截 ' + s.guard.blocked + ' 次' : '—')
    put('at', s.at ? new Date(s.at).toLocaleString() : '—')
  } catch { put('health', '状态暂不可用') }
  finally { setTimeout(refresh, 5000) }
}
refresh()
