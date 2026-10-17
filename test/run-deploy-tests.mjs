// ============================================================================
// test/run-deploy-tests.mjs —— 第 4 步（部署链 preinstalled → npx + 预热）测试
// ----------------------------------------------------------------------------
// A 逻辑层：假 engine 覆盖每条分支（不连网、不动远端任何东西）
// B 端到端：连真实 wsl-local 跑只读探测与热缓存路径
// 冷缓存与预热失败两组是破坏性/耗时的，不在本脚本里默认执行 ——
// 由 --cold / --fail 显式触发，避免第 5 步重跑本脚本时把远端缓存清掉。
//   node test/run-deploy-tests.mjs              # A + B
//   node test/run-deploy-tests.mjs --offline    # 只 A
//   node test/run-deploy-tests.mjs --alias=xxx  # 换别名
// ============================================================================

import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import { planRemoteReaDeploy } from '../rea-remote-deploy.js'
import { assertNoPrivilegeEscalation, safeExec } from '../remote-shell-utils.js'

const args = process.argv.slice(2)
const OFFLINE = args.includes('--offline')
const COLD = args.includes('--cold')
const FAIL = args.includes('--fail')
const aliasArg = args.find((a) => a.startsWith('--alias='))
const ALIAS = aliasArg ? aliasArg.slice('--alias='.length) : 'wsl-local'

let pass = 0
let fail = 0
let skip = 0
const failures = []
const ok = (label, cond, detail = '') => {
  if (cond) {
    pass++
    console.log(`  [PASS] ${label}${detail === '' ? '' : '  → ' + detail}`)
  } else {
    fail++
    failures.push(label)
    console.log(`  [FAIL] ${label}${detail === '' ? '' : '  → ' + detail}`)
  }
}
const skipped = (label, why) => {
  skip++
  console.log(`  [SKIP] ${label}  → ${why}`)
}
const info = (label, value) => console.log(`  [INFO] ${label}  → ${value}`)
const section = (t) => console.log(`\n【${t}】`)
const j = (v) => JSON.stringify(v)

// execCommand 的返回形状（见 remote-ssh-core.js:731）：success = exitCode===0；
// 超时给 {success:false, exitCode:null, timedOut:true, error:'command timed out after N ms'}。
function ran(o = {}) {
  const exitCode = o.exitCode ?? 0
  const timedOut = o.timedOut === true
  return {
    success: exitCode === 0 && !timedOut,
    exitCode,
    timedOut,
    stdout: o.stdout ?? '',
    stderr: o.stderr ?? '',
    durationMs: o.durationMs ?? 1234,
    ...(timedOut ? { error: `command timed out after ${o.budget ?? 120000} ms` } : {}),
  }
}

/** 按命令关键字路由的假 engine；同时记录每次下发的命令/超时/attempts。 */
function makeEngine(rules, opts = {}) {
  const calls = []
  return {
    calls,
    async exec(alias, command, timeoutMs, attempts) {
      calls.push({ alias, command, timeoutMs, attempts })
      if (opts.throwOn !== undefined && command.includes(opts.throwOn)) throw new Error(opts.throwMessage ?? 'boom')
      for (const [needle, result] of rules) if (command.includes(needle)) return ran(result)
      return ran({ exitCode: 127, stderr: 'unexpected command' })
    },
  }
}

// 真机抓回来的原文（不是手抄）：
//   npx --yes nonexistent-pkg-xyz-qq@latest --version → exit 1，stderr 437B
//   npx --yes rea-agents@latest --version            → exit 0，stdout 6B "6.5.0\n"
const FIX = join(dirname(fileURLToPath(import.meta.url)), 'fixtures')
const readFixBuf = (name) => readFileSync(join(FIX, name))
const REAL_404_BUF = existsSync(join(FIX, 'npx-registry-404-stderr.txt')) ? readFixBuf('npx-registry-404-stderr.txt') : null
const REAL_404_STDERR = REAL_404_BUF ? REAL_404_BUF.toString('utf8') : ''
const REAL_404_BYTES = REAL_404_BUF ? REAL_404_BUF.length : 0
const REAL_VERSION_OUT = existsSync(join(FIX, 'npx-version-stdout.txt')) ? readFixBuf('npx-version-stdout.txt').toString('utf8') : '6.5.0\n'

const HAS_REA = { stdout: 'HAS' }
const NO_REA = { exitCode: 1, stdout: 'NONE' }
const HAS_NPX = { stdout: 'HAS' }
const NO_NPX = { exitCode: 1, stdout: 'NONE' }
const CACHED_HIT = { stdout: '/home/dev/.npm/_npx/af752b90495482d7/node_modules/rea-agents\n' }
const CACHED_MISS = { exitCode: 2, stdout: '' }
const WARM_OK = { stdout: REAL_VERSION_OUT, durationMs: 76283 }

const CONTRACT_KEYS = ['ok', 'strategy', 'command', 'timeoutMs', 'needsWarmup', 'warmupResult', 'estimatedCost', 'error']

console.log('╔══════════════════════════════════════════════════════════════════════╗')
console.log('║  rea-remote-deploy.js  测试（4：部署链 + 预热）                        ║')
console.log('╚══════════════════════════════════════════════════════════════════════╝')

// ===========================================================================
section('A1 preinstalled 分支')
{
  const e = makeEngine([['command -v rea', HAS_REA], ['rea --version', { stdout: 'rea 6.5.0\n' }]])
  const p = await planRemoteReaDeploy(e, 'h')
  ok('[PRE] strategy/command/timeoutMs 正确', p.strategy === 'preinstalled' && p.command === 'rea' && p.timeoutMs === 30000, `${p.strategy} "${p.command}" ${p.timeoutMs}`)
  ok('[PRE] ok=true 且 error=null', p.ok === true && p.error === null, String(p.error))
  ok('[PRE] 零成本估算', j(p.estimatedCost) === j({ uploadBytes: 0, remoteDownloadBytes: 0 }))
  ok('[PRE] 不预热：needsWarmup=false、warmupResult=null', p.needsWarmup === false && p.warmupResult === null)
  ok('[PRE] 版本取回且只留一行里的号', p.reaVersion === '6.5.0', String(p.reaVersion))
  ok('[PRE] 没有下发任何 npx 命令', !e.calls.some((c) => c.command.includes('npx')), j(e.calls.map((c) => c.command)))
  ok('[PRE] 评估走 assessDeploymentPlan（preinstalled 档）', p.assessment?.strategy === 'preinstalled' && p.assessment?.riskLevel === '无', j(p.assessment?.rationale))
  ok('[PRE] 契约字段齐全', CONTRACT_KEYS.every((k) => k in p), j(Object.keys(p)))
  const versions = e.calls.filter((c) => c.command === 'rea --version')
  ok('[PRE] 版本确认用固定模板、attempts=1', versions.length === 1 && versions[0].attempts === 1, j(versions[0]))
}

// ===========================================================================
section('A2 npx 分支：缓存命中')
{
  const e = makeEngine([
    ['command -v rea', NO_REA],
    ['command -v npx', HAS_NPX],
    ['_npx', CACHED_HIT],
  ])
  const p = await planRemoteReaDeploy(e, 'h')
  ok('[CACHE] strategy=npx、command 前缀、120s 预算', p.strategy === 'npx' && p.command === 'npx --yes rea-agents@latest' && p.timeoutMs === 120000, `${p.strategy} "${p.command}" ${p.timeoutMs}`)
  ok('[CACHE] cached=true → needsWarmup=false 且不下载', p.needsWarmup === false && !e.calls.some((c) => c.command.includes('--version')), j(e.calls.map((c) => c.command)))
  ok('[CACHE] warmupResult 三字段（cached:true）', j(Object.keys(p.warmupResult ?? {})) === j(['ok', 'durationMs', 'cached']) && p.warmupResult.cached === true, j(p.warmupResult))
  ok('[CACHE] ok=true', p.ok === true && p.error === null, String(p.error))
  ok('[CACHE] 估算 160MB（实测隔离缓存 164MB 的量级）', p.estimatedCost.remoteDownloadBytes === 160 * 1024 * 1024 && p.estimatedCost.uploadBytes === 0, `${p.estimatedCost.remoteDownloadBytes / 1048576}MB`)
  ok('[CACHE] 评估文案用的是 npx 档原文', p.assessment?.riskLevel === '低' && p.assessment?.rationale?.includes('160.0MB'), j(p.assessment?.rationale))
  const probe = e.calls.find((c) => c.command.includes('_npx'))
  ok('[CACHE] 缓存探测问的是 rea-agents 在不在（不是 _npx 目录在不在）', probe.command.includes('/node_modules/rea-agents'), probe.command)
  ok('[CACHE] 缓存探测 8s 预算、attempts=1、head -1 限量', probe.timeoutMs === 8000 && probe.attempts === 1 && probe.command.includes('head -1'), `${probe.timeoutMs}ms a=${probe.attempts}`)
}

// 关键差异：_npx 里有「别的包」的 hash 时，naive 的 ls ~/.npm/_npx/ 会说有缓存。
// 我们发的是带 rea-agents 的 glob，所以这类假命中必须判成未命中。
{
  const e = makeEngine([
    ['command -v rea', NO_REA],
    ['command -v npx', HAS_NPX],
    ['_npx', CACHED_MISS],
    ['--version', WARM_OK],
  ])
  const p = await planRemoteReaDeploy(e, 'h')
  ok('[DECOY] 缓存里没有 rea-agents → 判为未命中并预热', p.needsWarmup === true && p.warmupResult?.cached === false, `cached=${p.cacheProbe?.cached}`)
  ok('[DECOY] 预热用的是 --version（不是 doctor --json）', e.calls.some((c) => c.command === 'npx --yes rea-agents@latest --version'), j(e.calls.map((c) => c.command)))
  ok('[DECOY] 探测未命中的 exit=2（ls 无匹配）被如实记下', p.cacheProbe?.exitCode === 2 && p.cacheProbe?.cached === false, `exit=${p.cacheProbe?.exitCode} bytes=${p.cacheProbe?.stdoutBytes}`)
}

// ===========================================================================
section('A3 冷缓存 → 预热')
{
  const e = makeEngine([
    ['command -v rea', NO_REA],
    ['command -v npx', HAS_NPX],
    ['_npx', CACHED_MISS],
    ['--version', WARM_OK],
  ])
  const p = await planRemoteReaDeploy(e, 'h')
  ok('[WARM] ok=true、strategy 仍是 npx', p.ok === true && p.strategy === 'npx')
  ok('[WARM] warmupResult={ok,durationMs,cached:false}（实测冷跑 76s 量级）', j(p.warmupResult) === j({ ok: true, durationMs: 76283, cached: false }), j(p.warmupResult))
  ok('[WARM] needsWarmup 保持 true（如实说明这次确实下了）', p.needsWarmup === true)
  ok('[WARM] 版本从预热输出读出', p.reaVersion === '6.5.0', String(p.reaVersion))
  const warm = e.calls.find((c) => c.command.endsWith('--version'))
  ok('[WARM] 预发热预算 = npxTimeoutMs、attempts=1（不重放，重放会重复下载）', warm.timeoutMs === 120000 && warm.attempts === 1, `${warm.timeoutMs}ms a=${warm.attempts}`)
}

// allowWarmup=false：只给结论不动手
{
  const e = makeEngine([
    ['command -v rea', NO_REA],
    ['command -v npx', HAS_NPX],
    ['_npx', CACHED_MISS],
    ['--version', WARM_OK],
  ])
  const p = await planRemoteReaDeploy(e, 'h', { allowWarmup: false })
  ok('[NOWARM] 没有下发预热命令', !e.calls.some((c) => c.command.includes('--version')), j(e.calls.map((c) => c.command)))
  ok('[NOWARM] needsWarmup=true、warmupResult=null、strategy 仍 npx', p.needsWarmup === true && p.warmupResult === null && p.strategy === 'npx')
  ok('[NOWARM] 计划本身可用（ok=true），error 只作提示', p.ok === true && p.error !== null && p.error.includes('未预热'), String(p.error))
  ok('[NOWARM] 提示里带实测冷跑量级', /75~83s/.test(String(p.error)))
}

// ===========================================================================
section('A4 失败路径')
if (REAL_404_BUF === null) {
  skipped('A4 预热失败（真机 404 原文）', '固件 npx-registry-404-stderr.txt 缺失，不用手抄文本凑数')
} else {
  // 真机 404 原文喂进来（假包不存在于 registry）
  const e = makeEngine([
    ['command -v rea', NO_REA],
    ['command -v npx', HAS_NPX],
    ['_npx', CACHED_MISS],
    ['--version', { exitCode: 1, stderr: REAL_404_STDERR }],
  ])
  const p = await planRemoteReaDeploy(e, 'h')
  ok('[FAIL] 预热失败 → strategy=unavailable、command=null、ok=false', p.strategy === 'unavailable' && p.command === null && p.ok === false)
  ok('[FAIL] error 是一句话', typeof p.error === 'string' && p.error.split('\n').length === 1 && p.error.length < 160, `${p.error.length} 字`)
  ok('[FAIL] 固件字节数与真机实测一致（437B stderr）', REAL_404_BYTES === 437, `${REAL_404_BYTES}B`)
  ok('[FAIL] 失败口径带 exit 与字节量级', /exit=1/.test(p.error) && p.error.includes(`stderr ${REAL_404_BYTES}B`), p.error)
  ok('[FAIL] 不回显远端原文（npm ERR!/E404 都不进 error）', !p.error.includes('npm ERR') && !p.error.includes('E404') && !p.error.includes('registry.npmjs.org'))
  ok('[FAIL] 失败后成本估算归零（不留「还要下 160MB」的误导）', j(p.estimatedCost) === j({ uploadBytes: 0, remoteDownloadBytes: 0 }))
  ok('[FAIL] warmupResult 仍如实记录失败这次', j(p.warmupResult) === j({ ok: false, durationMs: 1234, cached: false }), j(p.warmupResult))
  ok('[FAIL] needsWarmup 仍为 true（确实没缓存）', p.needsWarmup === true)
  ok('[FAIL] 不重试：预热只下发一次', e.calls.filter((c) => c.command.endsWith('--version')).length === 1)
  ok('[FAIL] unavailable 不给「未知策略」这种没信息量的评估', p.assessment === null, j(p.assessment))
}
{
  const e = makeEngine([
    ['command -v rea', NO_REA],
    ['command -v npx', HAS_NPX],
    ['_npx', CACHED_MISS],
    ['--version', { exitCode: null, timedOut: true, budget: 120000, durationMs: 120001 }],
  ])
  const p = await planRemoteReaDeploy(e, 'h')
  ok('[TIMEOUT] 说的是超时而不是通用失败', p.ok === false && p.error.includes('超时') && p.error.includes('120000ms'), p.error)
  ok('[TIMEOUT] 超时口径不谎报 exit code', !/exit=/.test(p.error))
}
{
  const e = makeEngine([
    ['command -v rea', NO_REA],
    ['command -v npx', NO_NPX],
  ])
  const p = await planRemoteReaDeploy(e, 'h')
  ok('[NONPX] 没有 npx → unavailable 并说明怎么修', p.strategy === 'unavailable' && p.error === '远端无 npx，请安装 Node.js 22.19+ 或全局安装 rea', p.error)
  ok('[NONPX] 未下发任何 rea/npx 命令', e.calls.filter((c) => /rea-agents|rea --version|_npx/.test(c.command)).length === 0, j(e.calls.map((c) => c.command)))
  ok('[NONPX] unavailable → 无评估', p.assessment === null)
}
{
  const e = makeEngine([], { throwOn: 'command -v rea', throwMessage: 'connect ECONNREFUSED 127.0.0.1:2222' })
  const p = await planRemoteReaDeploy(e, 'h')
  ok('[DOWN] SSH 抛错被吞：不抛异常、strategy=unavailable', p.ok === false && p.strategy === 'unavailable')
  ok('[DOWN] 口径是「SSH 不可达」而不是「没装 rea」', p.error.includes('SSH 不可达'), p.error)
  ok('[DOWN] 未编造 command/成本', p.command === null && j(p.estimatedCost) === j({ uploadBytes: 0, remoteDownloadBytes: 0 }))
  ok('[DOWN] unavailable → 无评估', p.assessment === null)
}
{
  const e = makeEngine([['command -v rea', HAS_REA], ['rea --version', { exitCode: 1, stdout: '' }]])
  const p = await planRemoteReaDeploy(e, 'h')
  ok('[NOVER] 全局 rea 读不出版本仍给 preinstalled（不谎报 unavailable）', p.strategy === 'preinstalled' && p.ok === true && p.reaVersion === null)
}

// ===========================================================================
section('A5 全局约定')
{
  const e = makeEngine([['command -v rea', NO_REA], ['command -v npx', HAS_NPX], ['_npx', CACHED_MISS], ['--version', WARM_OK]])
  const p = await planRemoteReaDeploy(e, 'h')
  ok('[GUARD] 所有下发 attempts 恒为 1', e.calls.every((c) => c.attempts === 1), j([...new Set(e.calls.map((c) => c.attempts))]))
  const TEMPLATES = [/^command -v (rea|npx) >\/dev\/null 2>&1 && printf HAS \|\| printf NONE$/, /^ls -d ~\/\.npm\/_npx\/\*\/node_modules\/rea-agents 2>\/dev\/null \| head -1$/, /^npx --yes rea-agents@latest --version$/, /^rea --version$/]
  ok('[GUARD] 命令全部落在固定模板内', e.calls.every((c) => TEMPLATES.some((re) => re.test(c.command))), j(e.calls.map((c) => c.command)))
  ok('[GUARD] 每条命令都过提权闸门', e.calls.every((c) => {
    try { return assertNoPrivilegeEscalation(c.command) === true } catch { return false }
  }))
  ok('[GUARD] 无 sudo / --break-system-packages', !e.calls.some((c) => /sudo|break-system-packages/.test(c.command)))
  // 省 token：返回结构里不留任何远端原文
  const blob = j(p)
  ok('[TOKEN] 返回体小（<1.5KB，不含远端原文）', blob.length < 1500, `${blob.length} 字节`)
  ok('[TOKEN] 没有任何字段是长文本', Object.values(p).every((v) => typeof v !== 'string' || v.length <= 200))
  ok('[TOKEN] cacheProbe 只留字节数不留内容', p.cacheProbe !== undefined && typeof p.cacheProbe.stdoutBytes === 'number' && !('stdout' in p.cacheProbe))
  ok('[TOKEN] 不含 stdout 原文特征串', !blob.includes('af752b90495482d7'))
}

// 自定义预算要透传
{
  const e = makeEngine([['command -v rea', NO_REA], ['command -v npx', HAS_NPX], ['_npx', CACHED_HIT]])
  const p = await planRemoteReaDeploy(e, 'h', { npxTimeoutMs: 45000 })
  ok('[CFG] 自定义 npxTimeoutMs 透传到 timeoutMs', p.timeoutMs === 45000, String(p.timeoutMs))
}
{
  const e = makeEngine([['command -v rea', HAS_REA], ['rea --version', { stdout: 'rea 6.5.0\n' }]])
  const p = await planRemoteReaDeploy(e, 'h', { globalTimeoutMs: 5000 })
  ok('[CFG] 自定义 globalTimeoutMs 透传', p.timeoutMs === 5000 && p.assessment?.strategy === 'preinstalled', String(p.timeoutMs))
}

// ===========================================================================
section(`B 端到端（别名 ${ALIAS}）`)
if (OFFLINE) {
  skipped('端到端', '--offline')
} else {
  const storeMod = await import('../remote-ssh-core.js')
  const store = storeMod.createHostStore()
  const entry = store.find(ALIAS)
  if (entry === undefined) {
    skipped('端到端', `主机库无别名 ${ALIAS}（库 ${store.path}）`)
  } else {
    const engine = storeMod.createSshEngine(store)
    // 先做一次连通性预检：WSL 实例可能是冷启动/已退出（portproxy 空转），
    // 那种情况属于环境问题，应 SKIP 并说明，而不是刷一串 FAIL。
    let reachable = true
    try {
      await safeExec(engine, ALIAS, 'true', 15000)
    } catch (error) {
      reachable = false
      skipped('端到端全部断言', `SSH 不可达（${error.message}）—— 远端实例可能已退出，不是代码回归`)
    }
    if (reachable) try {
      info('目标', `${entry.user}@${entry.host}:${entry.port}`)
      const t0 = Date.now()
      const p = await planRemoteReaDeploy(engine, ALIAS)
      const wall = Date.now() - t0
      ok('[LIVE] 出计划且不抛', p.strategy === 'npx' && p.ok === true && p.error === null, `${p.strategy} ok=${p.ok} ${String(p.error)}`)
      ok('[LIVE] 远端确实没有全局 rea（走的是 npx 分支）', p.command === 'npx --yes rea-agents@latest', String(p.command))
      ok('[LIVE] 3b 跑过后缓存应命中 → 不预热', p.cacheProbe?.cached === true && p.needsWarmup === false, `cached=${p.cacheProbe?.cached} 探测 ${p.cacheProbe?.durationMs}ms`)
      ok('[LIVE] 预算与估算落地', p.timeoutMs === 120000 && p.estimatedCost.remoteDownloadBytes === 160 * 1024 * 1024)
      ok('[LIVE] 契约字段齐全', CONTRACT_KEYS.every((k) => k in p))
      info('[LIVE] 总耗时', `${wall}ms`)
      console.log('\n  ── 真实 planRemoteReaDeploy 返回（wsl-local）──')
      console.log(JSON.stringify(p, null, 2).split('\n').map((l) => '  ' + l).join('\n'))

      // 与 3b 的探测结论对齐：缓存命中时不该有任何 npx 下载动作
      ok('[LIVE] 缓存命中路径里没有下发预热', !(p.warmupResult?.cached === true && p.needsWarmup))

      if (COLD) {
        section('B2 冷缓存：清掉 ~/.npm/_npx 再规划（--cold 显式触发）')
        const rm = await safeExec(engine, ALIAS, 'rm -rf ~/.npm/_npx', 15000)
        ok('[COLD] 缓存已清空', rm.success, `exit=${rm.exitCode}`)
        const t1 = Date.now()
        const cold = await planRemoteReaDeploy(engine, ALIAS)
        ok('[COLD] 清空后 needsWarmup=true', cold.needsWarmup === true && cold.cacheProbe?.cached === false, `cached=${cold.cacheProbe?.cached}`)
        ok('[COLD] 预热跑通', cold.warmupResult?.ok === true && cold.ok === true, String(cold.error))
        const d = cold.warmupResult?.durationMs ?? 0
        // 不写死 60~90s：实测冷跑取决于 rea-agents postinstall 里 prebuild-install 下载预编译二进制，
        // 本轮观察到 75s 完成，也观察到 >420s 仍未完成。这里只断言「确实跑完了并如实计时」。
        ok('[COLD] 预热耗时被如实记录（>1s，冷跑必然有量级）', d > 1000, `${d}ms`)
        info('[COLD] 冷跑耗时', `${d}ms（本轮总耗时 ${Date.now() - t1}ms；实测区间 75s ~ >420s，不固定）`)
        // 恢复：再规划一次，此时应命中缓存
        const back = await planRemoteReaDeploy(engine, ALIAS)
        ok('[COLD] 缓存已恢复（第 5 步不会拿到空缓存）', back.cacheProbe?.cached === true && back.needsWarmup === false, `cached=${back.cacheProbe?.cached}`)
      }

      if (FAIL) {
        section('B3 真实预热失败：超时口径（--fail 显式触发，不动缓存）')
        const p3 = await planRemoteReaDeploy(engine, ALIAS, { npxTimeoutMs: 1 })
        // 缓存命中时不会预热；这条只在冷缓存下才有意义，故先判前置条件
        if (p3.needsWarmup) {
          ok('[FAIL-LIVE] 预热超时 → unavailable + 一句话', p3.ok === false && p3.strategy === 'unavailable' && p3.error.includes('超时'), String(p3.error))
        } else {
          skipped('[FAIL-LIVE] 预热超时', `缓存已命中（cached=true），本路径不会下发预热；需配合 --cold`)
        }
      }
    } finally {
      // engine 只有 dispose()（remote-ssh-core.js:1108）；close 是不存在的名字，
      // 空操作会让连接吊住事件循环，脚本打完全绿也不退出。
      engine.dispose()
    }
  }
}

console.log('\n══════════════════════════════════════════════════════════════')
console.log(`结果：${pass} 通过 / ${fail} 失败 / ${skip} 跳过`)
if (fail > 0) {
  console.log('失败项：')
  for (const f of failures) console.log(`  - ${f}`)
  process.exitCode = 1
} else {
  console.log('全部通过')
}
