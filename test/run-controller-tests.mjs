// ============================================================================
// test/run-controller-tests.mjs —— 第 5 步（控制器骨架：定位 + 拉取 + 存档）测试
// ----------------------------------------------------------------------------
// A 段：假 engine，逐分支与全局约定（离线可重复，不碰远端）。
// B 段：连真实 wsl-local（localhost:2222）跑端到端。
//   node test/run-controller-tests.mjs              # A + B
//   node test/run-controller-tests.mjs --offline    # 只 A
//   node test/run-controller-tests.mjs --cold       # 额外跑破坏性冷缓存 + 恢复
//   node test/run-controller-tests.mjs --alias=xxx  # 换别名
// --cold 会清 ~/.npm/_npx，跑完必须恢复缓存（第 6 步要拿热缓存）。
// ============================================================================

import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

import { runFetch, preflightCommand, parsePreflight } from '../rea-controller.js'
import { planRemoteReaDeploy } from '../rea-remote-deploy.js'
import { safeExec } from '../remote-shell-utils.js'

const args = process.argv.slice(2)
const OFFLINE = args.includes('--offline')
const COLD = args.includes('--cold')
const aliasArg = args.find((a) => a.startsWith('--alias='))
const ALIAS = aliasArg ? aliasArg.slice('--alias='.length) : 'wsl-local'
// 临时主机库（默认不传 = 用 DSH 共享库）。portproxy 坏掉时用它连当前 WSL IP，不改共享配置。
const storeArg = args.find((a) => a.startsWith('--store='))
const STORE_PATH = storeArg ? storeArg.slice('--store='.length) : undefined

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

const CONTRACT_KEYS = ['ok', 'alias', 'remotePath', 'localPath', 'metadata', 'deploy', 'reportPath', 'error']

/** 断言里读本地文件大小：路径为 null 时给 null 而不是把整个套件炸掉。 */
const sizeOf = (p) => (typeof p === 'string' && existsSync(p) ? statSync(p).size : null)

// ============================================================================
// 假 engine
// ----------------------------------------------------------------------------
// exec 按命令内容路由；download 真写本地文件（校验路径要真读盘）。
// ============================================================================

const FAKE_TARGET = '/tmp/rea-fake-target.bin'
const FAKE_BODY = Buffer.concat([Buffer.from('dsh-controller-fixture\n'), Buffer.from([0x00, 0x7f, 0x45, 0x4c, 0x01, 0x02])])
const FAKE_SHA = createHash('sha256').update(FAKE_BODY).digest('hex')

function ran(o = {}) {
  const exitCode = o.exitCode ?? 0
  const timedOut = o.timedOut === true
  return {
    success: exitCode === 0 && !timedOut,
    exitCode,
    timedOut,
    stdout: o.stdout ?? '',
    stderr: o.stderr ?? '',
    durationMs: o.durationMs ?? 77,
    ...(timedOut ? { error: `command timed out after ${o.budget ?? 30000} ms` } : {}),
  }
}

function preflightStdout({ exists = true, size = FAKE_BODY.length, type = 'data', sha = FAKE_SHA } = {}) {
  if (!exists) return 'EXISTS=0\n'
  return `EXISTS=1\nSIZE=${size}\nTYPE=${type}\nSHA256=${sha}\n`
}

function fakeEngine(o = {}) {
  const cfg = {
    hasGlobalRea: false,
    hasNpx: true,
    cacheHit: true,
    warmupOk: true,
    warmupMs: 76283,
    preflight: {},
    preflightThrows: null,
    warmupTimeout: false,
    downloadThrows: null,
    downloadFails: false,
    ...o,
  }
  const calls = []
  const downloads = []
  const engine = {
    calls,
    downloads,
    async exec(alias, command, timeoutMs, attempts) {
      calls.push({ alias, command, timeoutMs, attempts })
      if (/command -v rea\b/.test(command)) return ran({ stdout: cfg.hasGlobalRea ? 'HAS' : 'NONE' })
      if (/command -v npx\b/.test(command)) return ran({ stdout: cfg.hasNpx ? 'HAS' : 'NONE' })
      if (command.includes('node_modules/rea-agents')) {
        return cfg.cacheHit ? ran({ stdout: '/home/dev/.npm/_npx/af752b90495482d7/node_modules/rea-agents\n' }) : ran({ stdout: '', exitCode: 2 })
      }
      if (command.includes('rea-agents@latest --version')) {
        if (cfg.warmupOk) return ran({ stdout: '6.5.0\n', durationMs: cfg.warmupMs })
        if (cfg.warmupTimeout) return ran({ timedOut: true, exitCode: null, budget: cfg.warmupMs, durationMs: cfg.warmupMs })
        return ran({ stdout: '', stderr: 'x'.repeat(437), exitCode: 1, durationMs: cfg.warmupMs })
      }
      if (command.includes("printf 'EXISTS=")) {
        if (cfg.preflightThrows !== null) throw cfg.preflightThrows
        return ran(typeof cfg.preflight === 'function' ? cfg.preflight(command) : { stdout: preflightStdout(cfg.preflight), ...cfg.preflight })
      }
      return ran({ stdout: '', exitCode: 127 })
    },
    async download(alias, remotePath, localPath, onProgress) {
      downloads.push({ alias, remotePath, localPath })
      if (cfg.downloadThrows !== null) throw cfg.downloadThrows
      if (cfg.downloadFails) {
        onProgress?.({ phase: 'error', file: remotePath, transferred: 0, total: 0, percent: 0, error: 'No such file' })
        throw Object.assign(new Error("No such file\n    at sftp.stat (/x/node_modules/ssh2/lib/protocol/sftp.js:1)\n"), { code: 2 })
      }
      const body = cfg.downloadBody !== undefined ? cfg.downloadBody : FAKE_BODY
      mkdirSync(dirname(localPath), { recursive: true }) // 与 remote-ssh-core.js:856 的行为一致
      writeFileSync(localPath, body)
      onProgress?.({ phase: 'transferring', file: remotePath, transferred: body.length, total: body.length, percent: 100 })
      onProgress?.({ phase: 'done', file: remotePath, transferred: body.length, total: body.length, percent: 100 })
      return { bytes: body.length }
    },
    dispose() {},
  }
  return engine
}

const scratch = mkdtempSync(join(tmpdir(), 'dsh-ctl-test-'))
const reportsDir = join(scratch, 'reports')
const localDir = join(scratch, 'out')

/** 跑一次并收集进度帧。 */
async function fetchOnce(engine, remotePath = FAKE_TARGET, extra = {}) {
  const frames = []
  const r = await runFetch('fake-host', remotePath, { engine, reportsDir, localDir, onProgress: (f) => frames.push(f), ...extra })
  return { r, frames }
}

console.log('╔══════════════════════════════════════════════════════════════════════╗')
console.log('║  rea-controller.js  测试（5：控制器骨架 + 定位拉取 + 预热前置）      ║')
console.log('╚══════════════════════════════════════════════════════════════════════╝')

// ============================================================================
// A0 预检命令与解析（纯函数）
// ============================================================================
section('A0 预检命令合并 / 解析')
{
  const cmd = preflightCommand('/tmp/rea test/a b.bin')
  ok('[CMD] 一条命令做完四项预检', cmd.includes('[ -f') && cmd.includes('stat -c %s') && cmd.includes('file -b') && cmd.includes('sha256sum'))
  ok('[CMD] 带空格的路径被单引号包住（转义后才拼命令）', cmd.includes("'/tmp/rea test/a b.bin'"), cmd.slice(0, 40) + '…')
  ok('[CMD] 没有 sudo / --break-system-packages', !/\bsudo\b/.test(cmd) && !cmd.includes('--break-system-packages'))
  ok('[CMD] 单行下发（换行只会在 printf 的参数里）', !cmd.includes('\n'))
  const p = parsePreflight(preflightStdout({ type: 'ELF, 64-bit LSB executable, x86-64, version 1 (SYSV)' }))
  ok('[PARSE] 四个字段都对上', p.exists === true && p.sizeBytes === FAKE_BODY.length && p.sha256 === FAKE_SHA, `${p.sizeBytes}B ${String(p.sha256).slice(0, 8)}…`)
  ok('[PARSE] fileType 保留 file -b 的一行原文（含逗号不截断）', p.fileType === 'ELF, 64-bit LSB executable, x86-64, version 1 (SYSV)', p.fileType)
  ok('[PARSE] EXISTS=0 → exists=false 其余留空', j(parsePreflight('EXISTS=0\n')) === j({ exists: false, sizeBytes: null, fileType: null, sha256: null }))
  ok('[PARSE] NA 不当成值', parsePreflight('EXISTS=1\nSIZE=NA\nTYPE=NA\nSHA256=NA\n').sha256 === null)
  ok('[PARSE] 非 64 位十六进制不算 sha', parsePreflight('EXISTS=1\nSHA256=deadbeef\n').sha256 === null)
  ok('[PARSE] 值里再出现 = 不破坏 KEY 切分', parsePreflight('EXISTS=1\nTYPE=data=weird\n').fileType === 'data=weird')
  ok('[PARSE] 空/垃圾输入不抛', j(parsePreflight('')) === j({ exists: false, sizeBytes: null, fileType: null, sha256: null }) && parsePreflight(null).exists === false)

  // 本机真跑一遍：模板语法/KEY 行格式这类问题，只有真的交给 bash 才暴露得出来。
  const hasBash = spawnSync('bash', ['--noediting', '-c', 'true'], { encoding: 'utf8' }).status === 0
  if (!hasBash) {
    skipped('预检命令本机真跑', '本机没有可用的 bash')
  } else {
    const toSh = (p) => p.replace(/\\/g, '/').replace(/^([A-Za-z]):/, (_m, d) => '/' + d.toLowerCase())
    const real = join(scratch, 'preflight-real.bin')
    writeFileSync(real, FAKE_BODY)
    const shCmd = preflightCommand(toSh(real))
    const cmdFile = join(scratch, 'preflight-cmd.sh')
    writeFileSync(cmdFile, shCmd + '\n')
    const syn = spawnSync('bash', ['-n', toSh(cmdFile)], { encoding: 'utf8' })
    ok('[CMD] 生成的命令过了 bash -n（then 后不能再跟分号）', syn.status === 0, String(syn.stderr ?? '').trim().slice(0, 90))
    const ran1 = spawnSync('bash', ['-c', shCmd], { encoding: 'utf8' })
    const p1 = parsePreflight(ran1.stdout)
    ok('[CMD] 本机一条命令真跑：exists / size / sha256 都对得上 node 自己算的', p1.exists === true && p1.sizeBytes === FAKE_BODY.length && p1.sha256 === FAKE_SHA, `exit=${ran1.status} exists=${p1.exists} size=${p1.sizeBytes} type=${String(p1.fileType)}`)
    const ran2 = spawnSync('bash', ['-c', preflightCommand(toSh(real) + '.nope')], { encoding: 'utf8' })
    ok('[CMD] 本机跑不存在的文件：EXISTS=0 且不是语法错', parsePreflight(ran2.stdout).exists === false && ran2.status === 0, `exit=${ran2.status}`)
  }
}

// ============================================================================
// A1 入参闸门（必须在下发之前拦住）
// ============================================================================
section('A1 入参闸门')
{
  const e = fakeEngine()
  const noEngine = await runFetch('h', FAKE_TARGET, { reportsDir, localDir })
  ok('[ARG] engine 缺失即失败，且不碰任何下发', noEngine.error.includes('engine 必传') && e.calls.length === 0, String(noEngine.error))
  const noDirs = await runFetch('h', FAKE_TARGET, { engine: e, reportsDir })
  ok('[ARG] localDir 缺失即失败', noDirs.error.includes('reportsDir 与 localDir 必传'), String(noDirs.error))
  const rel = await runFetch('h', 'tmp/a.bin', { engine: e, reportsDir, localDir })
  ok('[ARG] 相对路径被拦（download 侧没有这个校验）', rel.ok === false && rel.error.includes('绝对路径'), String(rel.error))
  ok('[ARG] 相对路径没有下发过任何命令', e.calls.length === 0, `${e.calls.length} 次`)
  const nl = await runFetch('h', '/tmp/a\nb', { engine: e, reportsDir, localDir })
  ok('[ARG] 含换行的路径被拦（拼命令不安全）', nl.error.includes('换行'), String(nl.error))
  const root = await runFetch('h', '/', { engine: e, reportsDir, localDir })
  ok('[ARG] 纯根路径取不出文件名 → 失败', root.error.includes('不是一个文件名'), String(root.error))
  const empty = await runFetch('h', '', { engine: e, reportsDir, localDir })
  ok('[ARG] 空路径失败而不是抛异常', empty.ok === false && empty.error === '远端路径为空')
}

// ============================================================================
// A2 部署路径不可用 → 直接失败，不下发预检
// ============================================================================
section('A2 部署不可用')
{
  const e = fakeEngine({ hasNpx: false })
  const { r, frames } = await fetchOnce(e)
  ok('[DEPLOY] 没有 rea 也没有 npx → ok=false', r.ok === false && r.deploy.strategy === 'unavailable')
  ok('[DEPLOY] error 用第 4 步的原文，不自己编', r.error === '远端无 npx，请安装 Node.js 22.19+ 或全局安装 rea', String(r.error))
  ok('[DEPLOY] 未下发预检（deploy 阶段就止步）', e.calls.filter((c) => c.command.includes('EXISTS=')).length === 0)
  ok('[DEPLOY] 没有拉取', e.downloads.length === 0)
  ok('[DEPLOY] deploy 字段仍带上（预热信息在这）', r.deploy !== null && 'warmupResult' in r.deploy)
  ok('[DEPLOY] 失败也落一页报告', r.reportPath !== null && existsSync(r.reportPath))
  ok('[DEPLOY] 进度报的是 failed 而不是继续', frames.at(-1).phase === 'failed', frames.map((f) => f.phase).join('>'))
}
{
  const e = fakeEngine({ cacheHit: false, warmupOk: false, warmupTimeout: true, warmupMs: 300005 })
  const { r } = await fetchOnce(e)
  ok('[WARMFAIL] 预热撞穿预算 → 控制器如实失败', r.ok === false && r.deploy.error.includes('超时'), String(r.deploy.error))
  ok('[WARMFAIL] 走的是第 4 步的超时口径而不是自己编', r.error === r.deploy.error)
  ok('[WARMFAIL] 没有继续下发预检', e.calls.filter((c) => c.command.includes('EXISTS=')).length === 0)
}

// ============================================================================
// A3 正常路径（缓存命中，不预热）
// ============================================================================
section('A3 正常路径（缓存命中）')
{
  const e = fakeEngine()
  const { r, frames } = await fetchOnce(e)
  ok('[OK] ok=true、error=null', r.ok === true && r.error === null, String(r.error))
  ok('[OK] 契约字段齐全', CONTRACT_KEYS.every((k) => k in r), CONTRACT_KEYS.join(','))
  ok('[OK] metadata 四项齐全', j(Object.keys(r.metadata).sort()) === j(['exists', 'fileType', 'sha256', 'sizeBytes']))
  ok('[OK] 本地文件真的落盘且大小一致', sizeOf(r.localPath) === FAKE_BODY.length, `${r.localPath} ${sizeOf(r.localPath)}B`)
  ok('[OK] 本地 sha256 == 远端 sha256', r.verification.shaMatches === true && r.verification.localSha256 === FAKE_SHA, String(r.verification.localSha256).slice(0, 12))
  ok('[OK] 缓存命中路径没有预热', r.deploy.needsWarmup === false && r.deploy.warmupResult.cached === true)
  const ctl = frames.filter((f) => f.source === 'controller')
  // 第 6 步：预热帧改由 planRemoteReaDeploy 自己发（source:'warmup'），控制器不再转述
  ok('[OK] 进度帧序列完整（控制器侧不再有预热帧）', j(ctl.map((f) => f.phase)) === j(['planning', 'preflight', 'downloading', 'verifying', 'finished']), ctl.map((f) => f.phase).join('>'))
  ok('[OK] 缓存命中的 warmed 帧来自部署规划（source=warmup、cached=true）', frames.some((f) => f.source === 'warmup' && f.phase === 'warmed' && f.cached === true), j(frames.filter((f) => f.source === 'warmup')))
  const transferring = frames.filter((f) => f.source === undefined && f.phase === 'transferring')
  ok('[OK] download 的进度帧原样透传（无 source，含 transferred/total/percent）', transferring.length === 1 && typeof transferring[0].transferred === 'number' && typeof transferring[0].total === 'number' && typeof transferring[0].percent === 'number', j(transferring[0]))
  ok('[OK] 靠 source 区分两种 done（fastTransfer 那边也发 phase:done）', frames.some((f) => f.source === undefined && f.phase === 'done') && !ctl.some((f) => f.phase === 'done'))
  ok('[OK] 控制器帧用 message 描述在干什么', ctl.length > 0 && ctl.every((f) => typeof f.message === 'string' && f.message !== ''))
  const report = JSON.parse(readFileSync(r.reportPath, 'utf8'))
  ok('[OK] 报告是同一份结论 + 时间戳', report.fetchedAt !== undefined && report.ok === true && report.remotePath === FAKE_TARGET)
  ok('[OK] 报告文件名带别名与时间戳', /fetch-fake-host-\d{8}-\d{6}\.json$/.test(r.reportPath), r.reportPath.split(/[\\/]/).pop())
  ok('[OK] npxTimeoutMs 默认 600000 覆盖第 4 步的 120000', r.deploy.timeoutMs === 600000, String(r.deploy.timeoutMs))
  ok('[OK] 自定义 npxTimeoutMs 透传', (await fetchOnce(fakeEngine(), FAKE_TARGET, { npxTimeoutMs: 45000 })).r.deploy.timeoutMs === 45000)
}

// ============================================================================
// A4 目标不存在
// ============================================================================
section('A4 目标不存在')
{
  const e = fakeEngine({ preflight: { stdout: 'EXISTS=0\n' } })
  const { r, frames } = await fetchOnce(e, '/tmp/nonexistent-xyz')
  ok('[MISS] exists=false、ok=false', r.ok === false && r.metadata.exists === false)
  ok('[MISS] error 一句话', r.error === '远端目标不存在或不是普通文件：/tmp/nonexistent-xyz', String(r.error))
  ok('[MISS] 没有拉取（不存在就不占传输）', e.downloads.length === 0 && r.localPath === null)
  ok('[MISS] metadata 其余字段留空而不是编 0', j([r.metadata.sizeBytes, r.metadata.fileType, r.metadata.sha256]) === j([null, null, null]))
  ok('[MISS] 进度收在 failed', frames.at(-1).phase === 'failed')
  ok('[MISS] 失败也存档（第 6 步要能追溯）', r.reportPath !== null && existsSync(r.reportPath))
}

// ============================================================================
// A5 校验：sha 不一致 / 远端算不出 sha
// ============================================================================
section('A5 完整性校验')
{
  const e = fakeEngine({ preflight: { stdout: preflightStdout({ sha: 'a'.repeat(64) }) } })
  const { r, frames } = await fetchOnce(e)
  ok('[SHA] 远端/本地不一致 → 判失败', r.ok === false && r.verification.shaMatches === false)
  ok('[SHA] 错误口径说清是校验没过而不是传输报错', r.error.includes('本地 sha256 与远端不一致'), String(r.error))
  ok('[SHA] 错误里只放前 12 位，不铺整串', r.error.length < 200 && !r.error.includes('a'.repeat(20)), `${r.error.length} 字`)
  ok('[SHA] 本地文件仍在（失败不偷偷删证据）', existsSync(r.localPath))
  ok('[SHA] 收在 failed', frames.at(-1).phase === 'failed')
}
{
  const e = fakeEngine({ preflight: { stdout: preflightStdout({ sha: 'NA' }) } })
  const { r, frames } = await fetchOnce(e)
  ok('[NOSHA] 远端没有 sha256sum → 拉取仍算成功', r.ok === true && r.metadata.sha256 === null)
  ok('[NOSHA] 但明确报「校验未做」，不假装通过', frames.some((f) => f.phase === 'warn' && f.message.includes('校验未做')), frames.map((f) => f.phase).join('>'))
  ok('[NOSHA] verification.shaMatches 如实为 false', r.verification.shaMatches === false && r.verification.sizeMatches === true)
}
{
  const e = fakeEngine({ downloadBody: Buffer.from('truncated') })
  const { r } = await fetchOnce(e)
  ok('[SIZE] 大小不一致被记下', r.verification.sizeMatches === false && r.verification.localSizeBytes === 9, String(r.verification.localSizeBytes))
}

// ============================================================================
// A6 预检执行细节（合并、闸门、attempts、成败判据）
// ============================================================================
section('A6 预检执行细节')
{
  const e = fakeEngine()
  await fetchOnce(e)
  const pres = e.calls.filter((c) => c.command.includes("printf 'EXISTS="))
  ok('[PRE] 预检只下发一条（不是四条）', pres.length === 1, `${pres.length} 条`)
  ok('[PRE] 固定模板 + attempts=1（不重放）', pres[0].attempts === 1 && pres[0].timeoutMs === 30000, `t=${pres[0].timeoutMs} a=${pres[0].attempts}`)
  ok('[PRE] 所有下发 attempts 恒为 1', e.calls.every((c) => c.attempts === 1), j(e.calls.map((c) => c.attempts)))
  ok('[PRE] 所有下发都无 sudo 痕迹（闸门在 safeExec 内）', e.calls.every((c) => !/\bsudo\b/.test(c.command)))
  const hostile = preflightCommand("/tmp/we;ird name.bin")
  ok('[PRE] 含元字符的路径整体进单引号（不当 shell 语法）', hostile.includes("'/tmp/we;ird name.bin'"), hostile.match(/\[ -f [^]]+\]/)?.[0] ?? '')
  ok('[PRE] 路径里的单引号被转义成反斜杠引号形式', preflightCommand("/tmp/o'uch.bin").includes(String.raw`'\''`))
}
{
  // 退出码没有信息量：bash 只回最后一个 printf 的码。这里给 exit=1 也要解析成功。
  const e = fakeEngine({ preflight: { stdout: preflightStdout(), exitCode: 1 } })
  const { r } = await fetchOnce(e)
  ok('[PRE] 成败看 KEY= 行不看退出码', r.ok === true && r.metadata.exists === true, `exit=1 时仍 ok=${r.ok}`)
}
{
  const e = fakeEngine({ preflight: { stdout: '', exitCode: 0, timedOut: true, budget: 30000 } })
  const { r } = await fetchOnce(e)
  ok('[PRE] 预检超时单独口径', r.ok === false && r.error.includes('目标预检超时'), String(r.error))
  ok('[PRE] 超时不谎报成「目标不存在」', !String(r.error).includes('不存在'))
}
{
  // 命令本身没跑成（对端 shell 不是 bash、模板语法错）→ 不能算成「目标不存在」
  const e = fakeEngine({ preflight: { stdout: '', exitCode: 2, stderr: 'syntax error near unexpected token' } })
  const { r } = await fetchOnce(e)
  ok('[PRE] 一个 KEY 都没回 → 单独口径，不误诊成文件不存在', r.ok === false && r.error.includes('没回 KEY= 行') && !r.error.includes('不存在'), String(r.error))
  ok('[PRE] 口径里带退出码与 stderr 量级', r.error.includes('exit=2') && r.error.includes('B）'), String(r.error))
  ok('[PRE] 没有继续拉取', e.downloads.length === 0 && r.localPath === null)
}

// ============================================================================
// A7 预热前置：needsWarmup 的状态要能被用户看见
// ============================================================================
section('A7 预热前置（needsWarmup）')
{
  const e = fakeEngine({ cacheHit: false })
  const { r, frames } = await fetchOnce(e)
  ok('[WARM] 冷缓存跑通后 ok=true', r.ok === true, String(r.error))
  ok('[WARM] deploy.warmupResult.ok=true、cached=false', r.deploy.warmupResult.ok === true && r.deploy.warmupResult.cached === false, j(r.deploy.warmupResult))
  ok('[WARM] 预热帧由部署规划自己发：下发前有 warming，跑完有 warmed(cached=false, durationMs)', (() => {
    const wf = frames.filter((f) => f.source === 'warmup')
    return wf[0]?.phase === 'warming' && wf[1]?.phase === 'warmed' && wf[1]?.cached === false && typeof wf[1]?.durationMs === 'number'
  })(), j(frames.filter((f) => f.source === 'warmup')))
  ok('[WARM] 控制器没有再转述一遍（没有 controller 的 warmed/ready 帧）', !frames.some((f) => f.source === 'controller' && (f.phase === 'warmed' || f.phase === 'ready')), frames.map((f) => `${f.source}:${f.phase}`).join('>'))
  ok('[WARM] 预热确实下发过一次 --version', e.calls.filter((c) => c.command.includes('rea-agents@latest --version')).length === 1)
  ok('[WARM] 预热的预算是 600000（第 5 步覆盖第 4 步默认）', e.calls.find((c) => c.command.includes('rea-agents@latest --version')).timeoutMs === 600000)
  const planOnly = await runFetch('h', FAKE_TARGET, { engine: fakeEngine({ cacheHit: false }), reportsDir, localDir })
  ok('[WARM] 计划本体不拆走：预热仍由 planRemoteReaDeploy 内部完成', planOnly.deploy.warmupResult.durationMs === 76283, String(planOnly.deploy.warmupResult.durationMs))
}

// ============================================================================
// A8 传输异常
// ============================================================================
section('A8 传输异常')
{
  const e = fakeEngine({ downloadFails: true })
  const { r, frames } = await fetchOnce(e)
  ok('[ERR] download 抛错被吞，ok=false', r.ok === false && r.error.startsWith('拉取失败：'), String(r.error))
  ok('[ERR] 多行堆栈被压成一行且不超长', r.error.split('\n').length === 1 && r.error.length <= 202, `${r.error.length} 字`)
  ok('[ERR] 没有假装校验通过', r.verification === null && r.localPath === null)
  ok('[ERR] 收在 failed', frames.at(-1).phase === 'failed')
}
{
  const e = fakeEngine()
  e.exec = async () => { throw new Error('ssh: connection lost mid-flight') }
  const { r } = await fetchOnce(e)
  ok('[ERR] exec 抛错也不外抛', r.ok === false && r.error !== null, String(r.error))
}

// ============================================================================
// A9 省 token 约定
// ============================================================================
section('A9 省 token')
{
  const e = fakeEngine()
  const { r } = await fetchOnce(e)
  const bytes = Buffer.byteLength(JSON.stringify(r))
  ok('[TOKEN] 返回体小（<1.6KB）', bytes < 1600, `${bytes} 字节，其中两个绝对路径占 ${Buffer.byteLength(String(r.localPath) + String(r.reportPath))}B`)
  ok('[TOKEN] 不含远端原始 stdout（KEY= 行不入盘）', !JSON.stringify(r).includes('EXISTS='))
  ok('[TOKEN] metadata 只有四个约定字段', Object.keys(r.metadata).length === 4)
  ok('[TOKEN] fileType 是一行原文，不是整段 file 输出', !String(r.metadata.fileType).includes('\n'))
  ok('[TOKEN] 报告体积同样受限', Buffer.byteLength(readFileSync(r.reportPath, 'utf8')) < 1600)
}

// ============================================================================
// B 端到端：真实 wsl-local
// ============================================================================
section(`B 端到端（别名 ${ALIAS}）`)
if (OFFLINE) {
  skipped('端到端', '--offline')
} else {
  const storeMod = await import('../remote-ssh-core.js')
  const store = storeMod.createHostStore(STORE_PATH)
  const entry = store.find(ALIAS)
  info('主机库', `${store.path}`)
  if (entry === undefined) {
    skipped('端到端', `主机库无别名 ${ALIAS}（库 ${store.path}）`)
  } else {
    const engine = storeMod.createSshEngine(store)
    let reachable = true
    try {
      await safeExec(engine, ALIAS, 'true', 15000)
    } catch (error) {
      reachable = false
      skipped('端到端全部断言', `SSH 不可达（${error.message}）—— 远端实例可能已退出，不是代码回归`)
    }
    const TARGET = '/tmp/rea-test-target.bin'
    const SPACE_TARGET = '/tmp/rea test target.bin'
    const MISSING = '/tmp/nonexistent-xyz-5b'
    if (reachable) {
      const liveReports = mkdtempSync(join(tmpdir(), 'dsh-ctl-live-'))
      const liveOut = mkdtempSync(join(tmpdir(), 'dsh-ctl-out-'))
      try {
        info('目标', `${entry.user}@${entry.host}:${entry.port}`)
        // 造目标：10KB 随机 + 一个带空格的路径 + 一个真实 ELF（看 file 的输出原文）
        const mk = await safeExec(engine, ALIAS, `dd if=/dev/urandom of=${TARGET} bs=1K count=10 2>/dev/null && printf OK`, 20000)
        ok('[FIXTURE] 远端测试文件已就位', mk.success && mk.stdout.includes('OK'), `exit=${mk.exitCode}`)
        const mk2 = await safeExec(engine, ALIAS, `dd if=/dev/urandom of='${SPACE_TARGET}' bs=1K count=3 2>/dev/null && printf OK`, 20000)
        ok('[FIXTURE] 带空格的路径也能造', mk2.success, `exit=${mk2.exitCode}`)

        // ① 正常路径
        const t0 = Date.now()
        const frames = []
        const r = await runFetch(ALIAS, TARGET, { engine, reportsDir: liveReports, localDir: liveOut, onProgress: (f) => frames.push(f) })
        info('[LIVE] runFetch 总耗时', `${Date.now() - t0}ms（含建连、计划、预检、SFTP 拉取、本地校验、写报告）`)
        console.log('\n  ── 真实 runFetch 返回（wsl-local）──')
        console.log(JSON.stringify(r, null, 2).split('\n').map((l) => '  ' + l).join('\n'))
        ok('[LIVE] 正常路径 ok=true', r.ok === true && r.error === null, String(r.error))
        ok('[LIVE] 走的是 npx 分支且缓存已热', r.deploy.strategy === 'npx' && r.deploy.warmupResult.cached === true, `${r.deploy.strategy} cached=${r.deploy.warmupResult?.cached}`)
        ok('[LIVE] metadata.exists=true', r.metadata.exists === true)
        ok('[LIVE] sizeBytes=10240（dd bs=1K count=10）', r.metadata.sizeBytes === 10240, String(r.metadata.sizeBytes))
        ok('[LIVE] fileType 非空一行', typeof r.metadata.fileType === 'string' && r.metadata.fileType !== '' && !r.metadata.fileType.includes('\n'), String(r.metadata.fileType))
        ok('[LIVE] 本地文件存在且大小一致', sizeOf(r.localPath) === 10240, `${r.localPath} ${sizeOf(r.localPath)}B`)
        const localSha = sizeOf(r.localPath) === null ? null : createHash('sha256').update(readFileSync(r.localPath)).digest('hex')
        ok('[LIVE] 本地独立算的 sha256 == 远端 sha256', localSha === r.metadata.sha256, `${localSha.slice(0, 16)}… vs ${String(r.metadata.sha256).slice(0, 16)}…`)
        ok('[LIVE] 控制器内部的校验也是 true', r.verification.shaMatches === true && r.verification.sizeMatches === true, j(r.verification))
        ok('[LIVE] 拉到的确实是随机数据（不是空文件）', r.metadata.sha256 !== createHash('sha256').update(Buffer.alloc(10240)).digest('hex'))
        ok('[LIVE] reportPath 有文件且能读', r.reportPath !== null && existsSync(r.reportPath) && JSON.parse(readFileSync(r.reportPath, 'utf8')).ok === true, r.reportPath)
        ok('[LIVE] 进度帧顺序（缓存热：planning→warmed(warmup)→preflight→…）', j(frames.filter((f) => f.source === 'controller' || f.source === 'warmup').map((f) => `${f.source}:${f.phase}`)) === j(['controller:planning', 'warmup:warmed', 'controller:preflight', 'controller:downloading', 'controller:verifying', 'controller:finished']), frames.filter((f) => f.source === 'controller' || f.source === 'warmup').map((f) => `${f.source}:${f.phase}`).join('>'))
        ok('[LIVE] 契约字段齐全', CONTRACT_KEYS.every((k) => k in r))

        // ② 预检耗时：合并成一条 vs 拆成四条
        const one = await safeExec(engine, ALIAS, preflightCommand(TARGET), 30000)
        const tSplit = Date.now()
        const parts = []
        for (const c of [`test -f ${TARGET}`, `file -b ${TARGET}`, `stat -c %s ${TARGET}`, `sha256sum ${TARGET}`]) parts.push(await safeExec(engine, ALIAS, c, 30000))
        const splitMs = Date.now() - tSplit
        ok('[COST] 合并后的预检解析成功且只一次往返', one.success && one.stdout.includes('EXISTS=1'), `${one.durationMs}ms`)
        info('[COST] 合并一条', `单命令 ${one.durationMs}ms（往返 1 次）`)
        info('[COST] 拆成四条', `合计 ${splitMs}ms（往返 4 次，逐条 ${parts.map((p) => p.durationMs).join('/')}ms）`)
        ok('[COST] 一条确实比四条快', one.durationMs < splitMs, `${one.durationMs}ms < ${splitMs}ms`)

        // ③ file 的输出原文长什么样（多类目标）
        for (const probe of [TARGET, '/bin/ls', '/etc/hostname']) {
          const p = parsePreflight((await safeExec(engine, ALIAS, preflightCommand(probe), 30000)).stdout)
          info('[FILE] file -b 原文', `${probe} → exists=${p.exists} size=${p.sizeBytes} type=${String(p.fileType)}`)
        }

        // ④ 目标不存在
        const miss = await runFetch(ALIAS, MISSING, { engine, reportsDir: liveReports, localDir: liveOut })
        ok('[LIVE-MISS] exists=false、ok=false', miss.ok === false && miss.metadata.exists === false, `exists=${miss.metadata.exists}`)
        ok('[LIVE-MISS] error 一句话', miss.error === `远端目标不存在或不是普通文件：${MISSING}`, String(miss.error))
        ok('[LIVE-MISS] 没落任何本地文件', miss.localPath === null)
        ok('[LIVE-MISS] 失败也存档', existsSync(miss.reportPath))

        // ⑤ 相对路径 / 目录
        const rel = await runFetch(ALIAS, 'tmp/a.bin', { engine, reportsDir: liveReports, localDir: liveOut })
        ok('[LIVE-ARG] 相对路径被拦在闸门（download 不校验这条）', rel.ok === false && rel.error.includes('绝对路径'), String(rel.error))

        // ⑥ 带空格的路径（shellQuote 真机验证）
        const sp = await runFetch(ALIAS, SPACE_TARGET, { engine, reportsDir: liveReports, localDir: liveOut })
        ok('[LIVE-SPACE] 带空格路径能预检、能拉取', sp.ok === true && sp.metadata.sizeBytes === 3072, `size=${sp.metadata.sizeBytes} ${String(sp.error)}`)
        ok('[LIVE-SPACE] 带空格路径的 sha 也对得上', sp.verification.shaMatches === true)

        // ⑦ 远端目录：预检的 [ -f ] 判假，压根不该走到 SFTP
        const asDir = await runFetch(ALIAS, '/tmp', { engine, reportsDir: liveReports, localDir: liveOut })
        ok('[LIVE-DIR] 目录被预检判为「不是普通文件」', asDir.ok === false && asDir.metadata.exists === false && asDir.error.includes('不是普通文件'), String(asDir.error))
        ok('[LIVE-DIR] 没有尝试拉取目录', asDir.localPath === null)

        // ⑧ 符号链接目标：[ -f ] 跟随链接，stat -c 不跟随（本机 /bin/ls 就是 symlink）
        const link = await runFetch(ALIAS, '/bin/ls', { engine, reportsDir: liveReports, localDir: liveOut })
        info('[LIVE-LINK] 符号链接行为', `exists=${link.metadata.exists} 远端size=${link.metadata.sizeBytes} type=${String(link.metadata.fileType)} ok=${link.ok}`)
        ok('[LIVE-LINK] 内容仍然对得上：sha256sum 与 SFTP 都跟随链接', link.verification !== null && link.verification.shaMatches === true, `远端 ${String(link.metadata.sha256).slice(0, 12)}… 本地 ${String(link.verification?.localSha256).slice(0, 12)}…`)
        ok('[LIVE-LINK] sizeBytes 是链接串长度，与落地大小天生不符 → 按豁免跳过比对（sha 才是权威）', link.verification.sizeMatches === null && link.verification.sizeSkippedForSymlink === true && link.verification.localSizeBytes > link.metadata.sizeBytes, `远端 ${link.metadata.sizeBytes}B / 本地 ${link.verification.localSizeBytes}B sizeMatches=${String(link.verification.sizeMatches)}`)

        if (COLD) {
          section('B2 冷缓存：清 ~/.npm/_npx 后走预热（--cold 显式触发）')
          const rm = await safeExec(engine, ALIAS, 'rm -rf ~/.npm/_npx', 15000)
          ok('[COLD] 缓存已清空', rm.success, `exit=${rm.exitCode}`)
          const coldFrames = []
          const cold = await runFetch(ALIAS, TARGET, { engine, reportsDir: liveReports, localDir: liveOut, onProgress: (f) => coldFrames.push(f) })
          ok('[COLD] 预热跑通、整体 ok', cold.ok === true && cold.deploy.warmupResult.ok === true, String(cold.error))
          ok('[COLD] needsWarmup=true 且 cached=false', cold.deploy.needsWarmup === true && cold.deploy.warmupResult.cached === false)
          ok('[COLD] 预热阶段被报给用户（warming 在 --version 下发之前，warmed 带耗时）', (() => {
            const wf = coldFrames.filter((f) => f.source === 'warmup')
            return wf[0]?.phase === 'warming' && wf.some((f) => f.phase === 'warmed' && f.cached === false)
          })(), coldFrames.map((f) => `${f.source}:${f.phase}`).join('>'))
          ok('[COLD] warming 帧的预算如实带出（用户知道这一步最多等多久）', coldFrames.find((f) => f.source === 'warmup' && f.phase === "warming")?.timeoutMs === 600000, j(coldFrames.find((f) => f.source === 'warmup' && f.phase === 'warming')))
          ok('[COLD] 冷跑期间没有把预检跳过（预热后仍完成拉取）', cold.metadata.exists === true && cold.verification.shaMatches === true)
          const d = cold.deploy.warmupResult.durationMs ?? 0
          ok('[COLD] 耗时如实记录（>1s）', d > 1000, `${d}ms`)
          info('[COLD] 预热耗时', `${d}ms（实测区间 75s ~ >420s；预算 ${cold.deploy.timeoutMs}ms）`)
          const back = await planRemoteReaDeploy(engine, ALIAS, { npxTimeoutMs: 300000 })
          ok('[COLD] 缓存已恢复（第 6 步拿不到空缓存）', back.cacheProbe?.cached === true && back.needsWarmup === false, `cached=${back.cacheProbe?.cached}`)
        } else {
          skipped('B2 冷缓存预热端到端', '破坏性且耗时，需 --cold 显式触发；A7 已用假 engine 覆盖同一分支')
        }
      } catch (error) {
        fail++
        failures.push('端到端异常')
        console.log(`  [FAIL] 端到端异常  → ${error.stack ?? error.message}`)
      } finally {
        const cleanup = await safeExec(engine, ALIAS, `rm -f ${TARGET} '${SPACE_TARGET}' && printf CLEANED`, 15000).catch(() => null)
        info('远端测试文件清理', cleanup?.success === true ? 'done' : '失败（手动清 /tmp/rea-test-target.bin）')
        rmSync(liveReports, { recursive: true, force: true })
        rmSync(liveOut, { recursive: true, force: true })
        engine.dispose()
      }
    }
  }
}

rmSync(scratch, { recursive: true, force: true })

console.log('\n══════════════════════════════════════════════════════════════')
console.log(`结果：${pass} 通过 / ${fail} 失败 / ${skip} 跳过`)
if (fail > 0) {
  console.log('失败项：')
  for (const f of failures) console.log(`  - ${f}`)
  process.exitCode = 1
} else {
  console.log('全部通过')
}
