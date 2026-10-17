// ============================================================================
// test/run-plugin-tests.mjs —— 第 7 步测试（插件契约 / 跨平台补丁 5 条 / A 路 / 超时预算）
// ----------------------------------------------------------------------------
// 全离线：index.js 的三个工具吃假 engine（useEngine 注入口），不建任何 SSH 连接；
// A 路与探测用的是第 3b 步从真机 WSL 抓回的固件（doctor / capabilities 原文）。
// 唯一例外是 B2/B3 的「shell 降级」用例：把 preflightCommand 交给本机 bash 真跑一次，
// 用 shell 函数遮蔽 stat / file 来复现 BSD/macOS 的缺失场景（本机没有 bash 则 SKIP）。
// 落盘一律进临时 $REVERSE_HOME（本文件开头设定，结束时删除）。
//   node test/run-plugin-tests.mjs           # 跑完清临时目录
//   node test/run-plugin-tests.mjs --keep    # 保留临时目录以便复查
// ============================================================================

import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const FIX = join(HERE, 'fixtures')

// 必须在 import index.js 之前定好：三个工具的 reportsDir / targetDir 全部来自 $REVERSE_HOME。
const HOME = join(tmpdir(), `rea-plugin-home-${process.pid}`)
process.env.REVERSE_HOME = HOME
const REPORTS = join(HOME, 'reports')
const TARGETS = join(HOME, 'targets')

const KEEP = process.argv.slice(2).includes('--keep')

let pass = 0
let fail = 0
let skip = 0
const failures = []
const ok = (label, cond, detail = '') => {
  if (cond) { pass++; console.log(`  [PASS] ${label}${detail === '' ? '' : '  → ' + detail}`) }
  else { fail++; failures.push(label); console.log(`  [FAIL] ${label}${detail === '' ? '' : '  → ' + detail}`) }
}
const skipped = (label, why) => { skip++; console.log(`  [SKIP] ${label}  → ${why}`) }
const info = (label, value) => console.log(`  [INFO] ${label}  → ${value}`)
const section = (title) => console.log(`\n【${title}】`)
const j = (v) => JSON.stringify(v)
const arr = (v) => (Array.isArray(v) ? v : [])
const readFix = (name, fallback = '{}') => (existsSync(join(FIX, name)) ? readFileSync(join(FIX, name), 'utf8') : fallback)
const json = (text) => { try { return JSON.parse(text) } catch { return {} } }
const firstLine = (t) => String(t).split('\n')[0]

/** execute() 返回的是「一行结论 + 一段 JSON」；取不出 JSON 就返回 null 让断言自己失败。 */
function payloadOf(text) {
  const i = String(text).indexOf('\n{')
  if (i < 0) return null
  try { return JSON.parse(String(text).slice(i + 1)) } catch { return null }
}

mkdirSync(HOME, { recursive: true })

console.log('╔══════════════════════════════════════════════════════════════════════╗')
console.log('║  第 7 步  插件契约 + 跨平台补丁 5 条 + A 路 + 预算  测试                ║')
console.log('╚══════════════════════════════════════════════════════════════════════╝')
info('临时数据根 $REVERSE_HOME', HOME)
info('本机', `${process.platform} / node ${process.version}`)

// ---------------------------------------------------------------------------
// 共享夹具：一个假目标 + 一个能走完 runFetch 的假 engine
// ---------------------------------------------------------------------------
const TARGET_BYTES = Buffer.concat([Buffer.from('7f454c46', 'hex'), Buffer.alloc(1024, 7)])
const TARGET_SHA = createHash('sha256').update(TARGET_BYTES).digest('hex')
const REMOTE_TARGET = '/tmp/plugin-target.bin'

/**
 * 假 engine：按命令形状分派，只回固定文本，不碰网络。
 * o 的每一项都是一条被测分支的开关（uname / hasRea / hasNpx / nodeVersion / exists / fileType / analyzePayload …）。
 */
function fakeEngine(o = {}) {
  const cfg = {
    uname: 'Linux\n', hasRea: true, hasNpx: false, nodeVersion: 'v22.22.1\n',
    reaVersionText: '6.5.0', doctor: readFix('rea-doctor.json'), capabilities: readFix('rea-capabilities-linux-x64.json'),
    exists: true, fileType: 'ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked',
    sizeBytes: TARGET_BYTES.length, sha256: TARGET_SHA, analyzePayload: null, throwRe: null,
    downloadFails: false, bytes: TARGET_BYTES, store: undefined, ...o,
  }
  const calls = []
  const downloads = []
  const run = (stdout, success = true, exitCode = 0) => ({ success, exitCode, timedOut: false, stdout, stderr: '', durationMs: 1 })
  return {
    cfg, calls, downloads, store: cfg.store,
    async exec(alias, command, timeoutMs, attempts) {
      calls.push({ alias, command, timeoutMs, attempts })
      if (cfg.throwRe !== null && new RegExp(cfg.throwRe).test(command)) throw new Error('connect ECONNREFUSED 127.0.0.1:22')
      if (command === 'uname -s') return cfg.uname === null ? run('', false, 127) : run(cfg.uname)
      if (command.startsWith('command -v rea ')) return run(cfg.hasRea ? 'HAS\n' : 'NONE\n', true, cfg.hasRea ? 0 : 1)
      if (command.startsWith('command -v npx ')) return run(cfg.hasNpx ? 'HAS\n' : 'NONE\n', true, cfg.hasNpx ? 0 : 1)
      if (command === 'node --version') return run(cfg.nodeVersion)
      if (command === 'rea --version') return run(`rea ${cfg.reaVersionText}\n`)
      if (command.startsWith('ls -d ')) return run('')
      if (command.includes('doctor')) return run(cfg.doctor, true, 1)
      if (command.includes('capabilities')) return run(cfg.capabilities)
      if (command.startsWith('if [ -f ')) {
        if (!cfg.exists) return run('EXISTS=0\n')
        return run(`EXISTS=1\nSIZE=${cfg.sizeBytes}\nTYPE=${cfg.fileType ?? 'NA'}\nSHA256=${cfg.sha256}\n`)
      }
      if (/(inspect-artifact|extract-artifact| function| decompile| instructions| xrefs|read-bytes|analyze-javascript-application)/.test(command)) {
        return cfg.analyzePayload === null ? run('', false, 127) : run(cfg.analyzePayload)
      }
      return run('', false, 127)
    },
    async download(alias, remotePath, localPath) {
      downloads.push({ alias, remotePath, localPath })
      if (cfg.downloadFails) throw new Error('sftp open failure')
      mkdirSync(dirname(localPath), { recursive: true })
      writeFileSync(localPath, cfg.bytes)
      return { bytes: cfg.bytes.length }
    },
    dispose() { this.disposed = (this.disposed ?? 0) + 1 },
  }
}

/** remote_hosts 用真 HostStore（脱敏口径得由真存储证明），engine 只是它外面的一层薄壳。 */
function makeHostEngine(store, testResult) {
  const dropped = []
  const tests = []
  return {
    store, dropped, tests,
    list: () => store.list().map((e) => store.summarize(e)),
    find: (alias) => { const e = store.find(alias); return e === undefined ? undefined : store.summarize(e) },
    async test(alias) { tests.push(alias); return testResult(alias) },
    dropAlias: (alias) => dropped.push(alias),
    dispose() {},
  }
}

// ===========================================================================
// P1 插件契约：入口可 import，且三处 id 对得上
// ===========================================================================
section('P1 插件契约（index.js / cordis.patch.yml / package.json）')

const mod = await import('../index.js')
const patchText = readFileSync(join(HERE, '..', 'cordis.patch.yml'), 'utf8').replace(/\r/g, '')
const pkg = json(readFileSync(join(HERE, '..', 'package.json'), 'utf8'))
const patchId = (patchText.match(/^\s*-?\s*id:\s*(\S+)\s*$/m) || [])[1] ?? null
const patchName = (patchText.match(/^\s*name:\s*(\S+)\s*$/m) || [])[1] ?? null

ok('[契约] 导出 name / inject / apply', ['name', 'inject', 'apply'].every((k) => k in mod), j(Object.keys(mod)))
ok('[契约] export const name = remote-rea', mod.name === 'remote-rea', String(mod.name))
ok('[契约] export const inject = ["tools"]', j(mod.inject) === '["tools"]', j(mod.inject))
ok('[契约] apply 是函数', typeof mod.apply === 'function')
ok('[契约] cordis.patch.yml 的 insert[].id 与 name 逐字相等', patchId === mod.name, `yml id=${String(patchId)} ｜ name=${mod.name}`)
ok('[契约] cordis.patch.yml 的 name 是包名', patchName === pkg.name, `yml name=${String(patchName)} ｜ pkg.name=${pkg.name}`)
ok('[契约] patch 文件只有一条 insert（本插件没有多入口）', (patchText.match(/^\s*-?\s*id:/gm) || []).length === 1)
ok('[契约] package.json main/exports 指回 ./index.js', pkg.main === './index.js' && pkg.exports?.['.'] === './index.js', `${pkg.main} / ${pkg.exports?.['.']}`)
ok('[契约] package.json 声明 dsh.bundle.patch', pkg.dsh?.bundle?.patch === './cordis.patch.yml', j(pkg.dsh))
info('patch 正文（去注释）', patchText.split('\n').filter((l) => l.trim() !== '' && !l.trim().startsWith('#')).join(' ⏎ '))

// ===========================================================================
// P2 mock ctx：三个工具注册、生命周期钩子
// ===========================================================================
section('P2 mock ctx 注册三个工具')

const registered = []
const effects = []
mod.apply({
  tools: { register: (t) => registered.push(t) },
  effect: (fn, label) => { effects.push({ fn, label }) },
})
const byName = new Map(registered.map((t) => [t.name, t]))
const fetchTool = byName.get('remote_fetch_binary')
const analyzeTool = byName.get('remote_rea_analyze')
const hostsTool = byName.get('remote_hosts')

ok('[注册] 恰好三个工具', registered.length === 3, j(registered.map((t) => t.name)))
ok('[注册] 工具名齐', ['remote_fetch_binary', 'remote_rea_analyze', 'remote_hosts'].every((t) => byName.has(t)))
ok('[注册] 每个都是 defineTool 产物（有编译后 parameters + execute + render）',
  registered.every((t) => t.parameters?.type === 'object' && typeof t.execute === 'function' && Array.isArray(t.output.render({}, 'x'))))
ok('[注册] ctx.effect 挂了 engine 释放钩子', effects.length === 1 && typeof effects[0].fn === 'function', j(effects.map((e) => e.label)))
ok('[注册] effect 标签带插件 id', effects[0]?.label === 'remote-rea:engine', String(effects[0]?.label))

ok('[schema] fetch 必填 alias+remotePath', j(fetchTool.parameters.required) === '["alias","remotePath"]', j(fetchTool.parameters.required))
ok('[schema] analyze 必填 alias+remotePath 且有可选 provider',
  j(analyzeTool.parameters.required) === '["alias","remotePath"]' && 'provider' in analyzeTool.parameters.properties && !analyzeTool.parameters.required.includes('provider'),
  j(Object.keys(analyzeTool.parameters.properties)))
ok('[schema] provider 不写死枚举（A 路只有 ghidra 有绑定，但不拦未来新 provider）', analyzeTool.parameters.properties.provider.enum === undefined, j(analyzeTool.parameters.properties.provider))
ok('[schema] hosts 必填 action 且七个动作枚举齐',
  j(hostsTool.parameters.required) === '["action"]' && j(hostsTool.parameters.properties.action.enum) === j(['list', 'get', 'add', 'update', 'remove', 'test', 'import']))
ok('[schema] 落盘位置不是工具参数（模型不能把报告写到会话工作区外）',
  registered.every((t) => !Object.keys(t.parameters.properties).some((k) => /^(reportsDir|localDir|dir|outDir|targetDir)$/i.test(k))),
  j(registered.map((t) => Object.keys(t.parameters.properties))))
ok('[schema] 参数里没有口令字段（只有 passwordEnv 这个环境变量名）',
  !Object.keys(hostsTool.parameters.properties).some((k) => /password$|passphrase/i.test(k)), j(Object.keys(hostsTool.parameters.properties)))

/** execute 是 async：schema 违规是 reject，不是同步抛，必须 await 才收得到。 */
const rejects = async (fn) => { try { await fn(); return null } catch (e) { return e } }
ok('[schema] 缺必填参数被宿主 schema 拦下（不静默跑）', await rejects(() => fetchTool.execute({ alias: 'x' }, {})) !== null)
ok('[schema] action 不在枚举内同样被拦', await rejects(() => hostsTool.execute({ action: 'drop-everything' }, {})) !== null)
ok('[schema] engine 不在参数面上（模型无法注入连接）', !('engine' in fetchTool.parameters.properties))

// ===========================================================================
// P3 工具 execute() 真走通到控制器
// ===========================================================================
section('P3 execute() → runFetch / runAnalyze 的接线')

{
  // 远端 rea 与 npx 都没有：runFetch 在部署规划这一步就止步，最便宜地验证「工具真的调了控制器」。
  const eng = fakeEngine({ hasRea: false, hasNpx: false })
  mod.useEngine(eng)
  const text = await fetchTool.execute({ alias: 'fake-host', remotePath: REMOTE_TARGET }, {})
  const p = payloadOf(text)
  ok('[接线] fetch 返回一句话结论 + 一段 JSON 投影', typeof text === 'string' && firstLine(text).startsWith('拉取未完成：'), firstLine(text))
  ok('[接线] 假 engine 真的被调用过', eng.calls.length > 0, `${eng.calls.length} 条命令`)
  ok('[接线] 投影带全部约定字段', p !== null && ['ok', 'error', 'alias', 'remotePath', 'localPath', 'metadata', 'verification', 'deploy', 'stages', 'durationMs', 'reportPath'].every((k) => k in p), p === null ? 'JSON 解析失败' : j(Object.keys(p)))
  ok('[接线] stages 记到止步那一步', p?.stages === 'planning>failed', String(p?.stages))
  ok('[接线] deploy 只留 strategy/command/reaVersion/needsWarmup', j(p?.deploy) === j({ strategy: 'unavailable', command: null, reaVersion: null, needsWarmup: false }), j(p?.deploy))
  ok('[接线] 报告落盘且文件真存在', typeof p?.reportPath === 'string' && existsSync(p.reportPath), String(p?.reportPath))
  ok('[接线] 报告落在 $REVERSE_HOME 下', String(p?.reportPath).startsWith(HOME), String(p?.reportPath).slice(0, HOME.length + 12) + '…')
  ok('[接线] 返回体没有原始 stdout/stderr 字段', !/"(stdout|stderr|rawOutput|raw)"/.test(text))
  ok('[接线] 所有下发 attempts=1', eng.calls.every((c) => c.attempts === 1), j([...new Set(eng.calls.map((c) => c.attempts))]))
}

{
  // 全局 rea 在 → 走完整 runFetch：预检 + 下载 + sha 比对，全部由假 engine 供给。
  const eng = fakeEngine({ hasRea: true })
  mod.useEngine(eng)
  const text = await fetchTool.execute({ alias: 'fake-host', remotePath: REMOTE_TARGET }, {})
  const p = payloadOf(text)
  ok('[拉取通] ok=true 且本地文件落地', p?.ok === true && existsSync(p.localPath), `${p?.ok} / ${String(p?.localPath).slice(-24)}`)
  ok('[拉取通] 落盘目录 = $REVERSE_HOME/targets', String(p?.localPath).startsWith(TARGETS), String(p?.localPath).slice(0, HOME.length + 12) + '…')
  ok('[拉取通] metadata 四项齐', p?.metadata?.exists === true && p?.metadata?.sizeBytes === TARGET_BYTES.length && /ELF/.test(p?.metadata?.fileType) && p?.metadata?.sha256 === TARGET_SHA, j(p?.metadata?.exists) + ' ' + p?.metadata?.sizeBytes)
  ok('[拉取通] sha 校验通过', p?.verification?.shaMatches === true, j(p?.verification?.shaMatches))
  ok('[拉取通] stages 覆盖到 finished', p?.stages === 'planning>ready>preflight>downloading>verifying>finished', String(p?.stages))
  ok('[拉取通] deploy=preinstalled 且版本来自 rea --version', p?.deploy?.strategy === 'preinstalled' && p?.deploy?.reaVersion === '6.5.0', j(p?.deploy))
  ok('[拉取通] 没有下发 sudo / --break-system-packages', !eng.calls.some((c) => /sudo|break-system-packages/.test(c.command)))
}

{
  // provider 透传：工具→控制器→路由；ghidra 不可用时用 REA 原文拒绝，绝不下发深分析命令。
  const eng = fakeEngine({ hasRea: true })
  mod.useEngine(eng)
  const text = await analyzeTool.execute({ alias: 'fake-host', remotePath: REMOTE_TARGET, provider: 'ghidra' }, {})
  const p = payloadOf(text)
  ok('[透传] error 用的是路由给出的原文', p?.ok === false && String(p?.error).startsWith('深分析不可用：ghidra'), firstLine(text))
  ok('[透传] 投影带 surface / marker / routeReason / unavailable', p !== null && ['surface', 'marker', 'routeReason', 'unavailable', 'provider', 'operation', 'subcommand'].every((k) => k in p), p === null ? 'JSON 解析失败' : j(Object.keys(p)))
  ok('[透传] marker 标明 A 路只有 help 证据', p?.marker === 'a-path:help-verified-only', String(p?.marker))
  ok('[透传] unavailable[] 是 provider:code 形式', arr(p?.unavailable).includes('ghidra:not_configured'), j(p?.unavailable))
  ok('[透传] 被拒绝时没下发任何分析子命令', !eng.calls.some((c) => /(inspect-artifact|extract-artifact| function| decompile| instructions| xrefs|read-bytes)/.test(c.command)), j(eng.calls.map((c) => c.command).slice(-1)))
  ok('[禁止] 从没拼过 rea analyze --provider / --operation', !eng.calls.some((c) => /analyze .*--(provider|operation)/.test(c.command)), '两个 flag 都不在 CLI 上')
  ok('[透传] stages 收在 no-route', String(p?.stages).endsWith('routing>no-route'), String(p?.stages).slice(-40))
}

{
  // 自动路由（不点 provider）：广告面 ∩ 已核对绑定 → inspect-artifact，Evidence 当场回收。
  const evidence = {
    evidence_id: 'ev-plugin-fake-1',
    provider: { id: 'rea-native' },
    operation: 'inspect_artifact',
    subject: { format: 'elf', path: REMOTE_TARGET },
    normalized_result: { substeps: [], observations: [{ id: 'o1' }], hypotheses: [], contradictions: [], unexplored_branches: [], next_probes: [] },
  }
  const eng = fakeEngine({ hasRea: true, analyzePayload: j(evidence) })
  mod.useEngine(eng)
  const text = await analyzeTool.execute({ alias: 'fake-host', remotePath: REMOTE_TARGET }, {})
  const p = payloadOf(text)
  ok('[自动路由] 不点 provider 时选到已核对绑定', p?.ok === true && p?.subcommand === 'inspect-artifact', `${p?.subcommand} ｜ err=${String(p?.error)}`)
  ok('[自动路由] 自动选路绝不选 ghidra', p?.provider !== 'ghidra' && p?.surface !== 'a-path', `${p?.provider} / ${p?.surface}`)
  ok('[自动路由] Evidence 只给路径与 ID，正文进磁盘', p?.evidenceId === 'ev-plugin-fake-1' && existsSync(p?.evidencePath ?? '') && !text.includes('normalized_result'), String(p?.evidencePath))
  ok('[自动路由] dialect 计数进了投影', p?.dialect !== null && p.dialect.observations === 1, j(p?.dialect))
  ok('[自动路由] 分析命令是「部署命令 + 已核对子命令 + 转义路径 + --format json」', eng.calls.some((c) => c.command === `rea inspect-artifact ${REMOTE_TARGET} --format json 2>&1`), j(eng.calls.map((c) => c.command).slice(-1)))
  ok('[自动路由] timings 四段都有数', p?.timings !== null && ['fetchMs', 'probeMs', 'analyzeMs', 'mapMs'].every((k) => typeof p.timings[k] === 'number'), j(p?.timings))
  ok('[自动路由] 报告与 analyze 同构且落盘', existsSync(p?.reportPath ?? '') && String(p?.reportPath).includes('analyze'), String(p?.reportPath))
}

// ===========================================================================
// P4 B1：Windows 远端平台闸门
// ===========================================================================
section('P4 B1 平台闸门（uname -s → 拒绝 Windows 远端）')

const { probeRemoteRea, nodeVersionVerdict, collectReadiness } = await import('../rea-remote-probe.js')
const UNSUPPORTED = '不支持的目标平台：Windows 远端，请使用 POSIX shell 目标'

for (const uname of ['MINGW64_NT-10.0-26100', 'MSYS_NT-10.0', 'CYGWIN', 'Windows_NT']) {
  const eng = fakeEngine({ uname: `${uname}\n`, hasRea: true, hasNpx: true })
  const r = await probeRemoteRea(eng, 'fake-host')
  ok(`[B1] uname=${uname} → reachable=false 且文案逐字`, r.reachable === false && r.ok === false && r.error === UNSUPPORTED, String(r.error))
  ok(`[B1] uname=${uname} → 没下发任何 rea/npx 命令`, !eng.calls.some((c) => /rea|npx/.test(c.command)), j(eng.calls.map((c) => c.command)))
  ok(`[B1] uname=${uname} → platform 留原文`, r.platform === uname, String(r.platform))
}
{
  const eng = fakeEngine({ uname: 'Linux\n', hasRea: false, hasNpx: false })
  const r = await probeRemoteRea(eng, 'fake-host')
  ok('[B1] Linux 远端不受闸门影响', !String(r.error).includes('不支持的目标平台') && String(r.error).includes('既没有全局 rea'), firstLine(String(r.error)))
  ok('[B1] 闸门之后探测链照常继续', r.platform === 'Linux', String(r.platform))
}
{
  const eng = fakeEngine({ uname: null, hasRea: false, hasNpx: false })
  const r = await probeRemoteRea(eng, 'fake-host')
  ok('[B1] uname 没输出时不猜平台（读不到 ≠ Windows）', r.platform === null && !String(r.error).includes('不支持的目标平台'), String(r.error).slice(0, 30))
}
{
  const eng = fakeEngine({ uname: 'Linux\n', hasRea: true })
  const r = await probeRemoteRea(eng, 'fake-host')
  const gate = r.commands.find((c) => c.label === 'platform')
  ok('[B1] 闸门命令进审计条目', gate !== undefined && gate.command === 'uname -s' && gate.ok === true, j(gate))
  ok('[B1] 闸门走 safeExec（attempts=1）', eng.calls[0].attempts === 1 && eng.calls[0].command === 'uname -s', j(eng.calls[0]))
  ok('[B1] 平台闸门不影响 ok 判定', r.ok === true && r.reaAvailable === true, `ok=${r.ok} via=${r.via}`)
}
{
  const eng = { async exec() { throw new Error('connect ECONNREFUSED 127.0.0.1:22') } }
  const r = await probeRemoteRea(eng, 'down-host')
  ok('[B1] uname 这一步 SSH 抛错仍归为「SSH 不可达」', r.reachable === false && String(r.error).startsWith('SSH 不可达：'), String(r.error).slice(0, 44))
}

// ===========================================================================
// P5 B2 + P6 B3：预检命令的真实降级（交给本机 bash 跑）
// ===========================================================================
const { preflightCommand, parsePreflight, runFetch } = await import('../rea-controller.js')

section('P5 B2 大小探测：stat -c %s 失败 → wc -c < file')

ok('[B2] 命令模板两条通道都在', /stat -c %s -- /.test(preflightCommand(REMOTE_TARGET)) && /wc -c < /.test(preflightCommand(REMOTE_TARGET)), preflightCommand(REMOTE_TARGET).match(/printf 'SIZE='[^;]*\(.*?\)/)?.[0])
ok('[B2] 兜底顺序是 stat → wc → NA', /stat -c %s --[^\n]*\|\|[^\n]*wc -c <[^\n]*\|\| printf 'NA/.test(preflightCommand(REMOTE_TARGET)))
ok('[B2] NA 不会伪装成数字', parsePreflight('EXISTS=1\nSIZE=NA\nTYPE=NA\nSHA256=NA\n').sizeBytes === null)
ok('[B2] wc 的纯数字照常解析', parsePreflight('EXISTS=1\nSIZE=1028\n').sizeBytes === 1028)

const bashProbe = spawnSync('bash', ['-c', 'command -v wc >/dev/null 2>&1 && echo BASHOK'], { encoding: 'utf8' })
const HAVE_BASH = String(bashProbe.stdout ?? '').includes('BASHOK')

if (!HAVE_BASH) {
  skipped('B2/B3 本机 bash 真跑', `本机取不到 bash（status=${String(bashProbe.status)} ${String(bashProbe.error?.message ?? '')}）`)
  skipped('B3 file 缺失降级（真跑部分）', '同上')
} else {
  const winTarget = join(HOME, 'preflight-target.bin')
  writeFileSync(winTarget, TARGET_BYTES)
  // Git Bash 里的内置命令只认 /c/... 形式；WSL 下 tmpdir 本来就是 POSIX 路径。
  const bashTarget = winTarget.replace(/^([A-Za-z]):\\/, (m, d) => `/${d.toLowerCase()}/`).replace(/\\/g, '/')
  const shellRun = (prefix) => spawnSync('bash', ['-c', `${prefix} ${preflightCommand(bashTarget)}`], { encoding: 'utf8' })
  info('bash 侧目标路径', bashTarget)

  const base = shellRun('')
  const baseParsed = parsePreflight(base.stdout)
  ok('[B2·真跑] 正常环境由 stat 通道给出大小', baseParsed.sizeBytes === TARGET_BYTES.length && baseParsed.exists === true, `SIZE=${baseParsed.sizeBytes} / 期望 ${TARGET_BYTES.length}`)
  const noStat = shellRun("stat() { printf \"stat: illegal option -- c\\n\" >&2; return 1; };")
  const noStatParsed = parsePreflight(noStat.stdout)
  ok('[B2·真跑] stat 失败后 wc -c 兜住同一个大小', noStatParsed.sizeBytes === TARGET_BYTES.length, String(noStat.stdout).trim().replace(/\n/g, ' ⏎ '))
  ok('[B2·真跑] 兜底没有把 exists / sha 带崩', noStatParsed.exists === true && noStatParsed.sha256 === TARGET_SHA, `sha=${String(noStatParsed.sha256).slice(0, 12)}`)
  const bothDead = shellRun("stat() { return 1; }; wc() { return 1; };")
  ok('[B2·真跑] 两条通道都失败时 sizeBytes=null 而不是 0', parsePreflight(bothDead.stdout).sizeBytes === null, String(bothDead.stdout).trim().replace(/\n/g, ' ⏎ '))

  section('P6 B3 file -b 缺失 → fileType=null 后按扩展名降级')
  ok('[B3] 命令模板有 NA 兜底', /printf 'TYPE='; \(file -b --[^\n]*\|\| printf 'NA/.test(preflightCommand(REMOTE_TARGET)))
  ok('[B3] NA 解析成 null', parsePreflight('EXISTS=1\nSIZE=1\nTYPE=NA\n').fileType === null)
  const noFile = shellRun("file() { printf \"bash: file: command not found\\n\" >&2; return 127; };")
  const noFileParsed = parsePreflight(noFile.stdout)
  ok('[B3·真跑] file 不存在时 fileType=null', noFileParsed.fileType === null, String(noFile.stdout).trim().replace(/\n/g, ' ⏎ '))
  ok('[B3·真跑] 其余三项不受影响', noFileParsed.exists === true && noFileParsed.sizeBytes === TARGET_BYTES.length && noFileParsed.sha256 === TARGET_SHA)
  {
    // 同一条降级链路再走一遍工具面：file 缺失的远端 + .exe 目标 → 靠扩展名猜类别。
    const eng = fakeEngine({ hasRea: true, fileType: null, sizeBytes: TARGET_BYTES.length })
    eng.calls.length = 0
    const frames = []
    const r = await runFetch('fake-host', '/tmp/guess.exe', { engine: eng, reportsDir: REPORTS, localDir: TARGETS, onProgress: (f) => frames.push(f) })
    ok('[B3·端到端] file 缺失时拉取仍然成功且 fileType=null', r.ok === true && r.metadata.fileType === null, j(r.metadata))
  }
  const { classifyTarget } = await import('../rea-provider-router.js')
  const { routeProvider: routeForFallback } = await import('../rea-provider-router.js')
  const guess = classifyTarget(noFileParsed.fileType, '/tmp/guess.exe')
  ok('[B3] 降级①按扩展名猜并写进 note', guess.targetClass === 'pe' && guess.note.includes('按扩展名 .exe 猜为 pe') && guess.note.includes('未经格式头证实'), j(guess))
  const blind = classifyTarget(noFileParsed.fileType, '/tmp/blob')
  ok('[B3] 降级②扩展名也认不出时要求点名 provider', blind.targetClass === 'unresolved' && blind.note.includes('深度分析需指定 provider'), j(blind))
  ok('[B3] 有 fileType 原文时根本不进降级', classifyTarget('ELF 64-bit LSB executable', '/tmp/x.exe').targetClass === 'elf')
  const capsForRoute = json(readFix('rea-capabilities-linux-x64.json'))
  const noFileType = routeForFallback({ fileType: null, sizeBytes: 10 }, [], capsForRoute, { remotePath: '/tmp/blob' })
  ok('[B3] 路由把降级 note 带进返回值', noFileType.note.includes('file -b 没有输出'), String(noFileType.note).slice(0, 80))
}

// ===========================================================================
// P7 B4：远端 node 版本闸门
// ===========================================================================
section('P7 B4 远端 node 版本闸门（22.19+ / 24.11+ / 26+，排除 23 与 25）')

const NODE_REQ = 'REA 要求 Node 22.19+ / 24.11+ / 26+（不支持 23 和 25）'
for (const [text, expect] of [['v22.19.0', true], ['v22.22.1', true], ['v22.18.0', false], ['v23.1.0', false], ['v24.10.0', false], ['v24.11.0', true], ['v25.2.0', false], ['v26.0.0', true], ['v18.20.1', false]]) {
  ok(`[B4] ${text} → ${expect ? '放行' : '拦下'}`, nodeVersionVerdict(text).ok === expect, j(nodeVersionVerdict(text)))
}
ok('[B4] 读不出版本号时不拦（「读不到」≠「不满足」）', nodeVersionVerdict('not found').ok === true && nodeVersionVerdict('not found').known === false)
ok('[B4] 空输入同样不拦', nodeVersionVerdict('').known === false && nodeVersionVerdict(null).ok === true)

{
  const eng = fakeEngine({ hasRea: false, hasNpx: true, nodeVersion: 'v23.1.0\n' })
  const r = await probeRemoteRea(eng, 'fake-host')
  ok('[B4·探测] 奇数线 node → 一句话拒绝并附 REA 的要求', r.ok === false && r.error === `远端 Node 23.1 是奇数线，REA 不支持；${NODE_REQ}`, String(r.error))
  ok('[B4·探测] 拦下时不下发 rea 命令（command -v 探测之外没有 rea/npx 拉起）', !eng.calls.some((c) => /rea-agents|rea --version|rea doctor|rea capabilities|npx --yes/.test(c.command)), j(eng.calls.map((c) => c.command)))
  ok('[B4·探测] nodeVersion 进了结果与审计条目', r.nodeVersion === '23.1' && r.commands.some((c) => c.label === 'node-version' && c.ok === true), j(r.commands.map((c) => c.label)))
  ok('[B4·探测] 版本闸门也走 safeExec（attempts=1）', eng.calls.every((c) => c.attempts === 1))
}
{
  const eng = fakeEngine({ hasRea: false, hasNpx: true, nodeVersion: 'v22.22.1\n' })
  const r = await probeRemoteRea(eng, 'fake-host')
  ok('[B4·探测] 达标 node 照常走 npx 分支', r.via === 'npx' && r.nodeVersion === '22.22', `${r.via} / ${r.nodeVersion}`)
}
{
  const eng = fakeEngine({ hasRea: false, hasNpx: true, nodeVersion: '' })
  const r = await probeRemoteRea(eng, 'fake-host')
  ok('[B4·探测] node --version 没输出时继续探测，失败交给 rea 暴露', r.via === 'npx' && r.commands.some((c) => c.label === 'node-version' && c.ok === false), j(r.commands.find((c) => c.label === 'node-version')))
  ok('[B4·探测] 读不到版本时审计条目里带上原因文案', String(r.commands.find((c) => c.label === 'node-version')?.error).includes(NODE_REQ), String(r.commands.find((c) => c.label === 'node-version')?.error))
}
{
  const eng = fakeEngine({ hasRea: true, nodeVersion: 'v23.1.0\n' })
  const r = await probeRemoteRea(eng, 'fake-host')
  ok('[B4·探测] 全局 rea 在就不跑 node 闸门', r.ok === true && r.nodeVersion === null && !eng.calls.some((c) => c.command === 'node --version'), `ok=${r.ok} node=${String(r.nodeVersion)}`)
}

// ===========================================================================
// P8 B5：远端无 npx 的一句话
// ===========================================================================
section('P8 B5 远端无 npx 的部署结论')

const { planRemoteReaDeploy } = await import('../rea-remote-deploy.js')
const NO_NPX_TEXT = '远端无 npx，请安装 Node.js 22.19+ 或全局安装 rea'
{
  const eng = fakeEngine({ hasRea: false, hasNpx: false })
  const plan = await planRemoteReaDeploy(eng, 'fake-host')
  ok('[B5] strategy=unavailable 且文案逐字', plan.strategy === 'unavailable' && plan.error === NO_NPX_TEXT, String(plan.error))
  ok('[B5] 只发了两条 command -v 探测，没碰 npx', j(eng.calls.map((c) => c.command)) === j(['command -v rea >/dev/null 2>&1 && printf HAS || printf NONE', 'command -v npx >/dev/null 2>&1 && printf HAS || printf NONE']), j(eng.calls.map((c) => c.command)))
  ok('[B5] ok=false / needsWarmup=false / 没有半成品命令', plan.ok === false && plan.needsWarmup === false && plan.command === null)
}
{
  const eng = fakeEngine({ hasRea: false, hasNpx: false })
  const r = await probeRemoteRea(eng, 'fake-host')
  ok('[B5·探测侧] 探测链缺 npx 的文案保持原口径', String(r.error).includes('既没有全局 rea，也没有 npx'), String(r.error).slice(0, 40))
}
{
  const eng = fakeEngine({ hasRea: false })
  eng.exec = async (alias, command, timeoutMs, attempts) => {
    if (command.startsWith('command -v npx ')) throw new Error('socket closed')
    return fakeEngine({ hasRea: false }).exec(alias, command, timeoutMs, attempts)
  }
  const plan = await planRemoteReaDeploy(eng, 'fake-host')
  ok('[B5] 探测 npx 时 SSH 断 → 口径是 SSH 失败而不是「没有 npx」', String(plan.error).startsWith('探测 npx 时 SSH 失败：'), String(plan.error).slice(0, 40))
}

// ===========================================================================
// P9 A 路：绑定表 + 不可用时的诊断原文
// ===========================================================================
section('P9 A 路（ghidra 深分析）绑定表与拒绝口径')

const { GHIDRA_BINDINGS, A_PATH_PROVIDER, VERIFIED_CLI_BINDINGS, MANUAL_EXCEPTIONS, diagnosticSummary, ghidraDiagnostics, routeProvider } = await import('../rea-provider-router.js')
const capsJson = json(readFix('rea-capabilities-linux-x64.json'))
const doctorJson = json(readFix('rea-doctor.json'))
const readinessReal = collectReadiness(doctorJson, capsJson)
const META_ELF = { exists: true, sizeBytes: TARGET_BYTES.length, fileType: 'ELF 64-bit LSB executable, x86-64', sha256: TARGET_SHA }

ok('[A路] 深分析入口只开给 ghidra', A_PATH_PROVIDER === 'ghidra')
ok('[A路] 绑定表恰好 5 条', Object.keys(GHIDRA_BINDINGS).length === 5, j(Object.keys(GHIDRA_BINDINGS)))
const BIND_WANT = {
  analyze_function: ['function', 'optional'],
  procedure_pseudo_code: ['decompile', 'optional'],
  procedure_assembly: ['instructions', 'optional'],
  xrefs: ['xrefs', 'optional'],
  read_bytes: ['read-bytes', 'required'],
}
for (const [op, [sub, addr]] of Object.entries(BIND_WANT)) {
  const b = GHIDRA_BINDINGS[op]
  ok(`[A路] ${op} → rea ${sub}（address ${addr}）`, b?.subcommand === sub && b?.address === addr && String(b?.usage).startsWith(`rea ${sub} <path>`), j(b))
}
ok('[A路] 每条绑定都留了 help 原文 usage', Object.values(GHIDRA_BINDINGS).every((b) => /^rea [a-z-]+ <path> (<address>|\[address\])/.test(b.usage)), j(Object.values(GHIDRA_BINDINGS).map((b) => b.usage)))
ok('[A路] 已核对自动绑定表没被 ghidra 污染', j(Object.keys(VERIFIED_CLI_BINDINGS)) === j(['inspect_artifact', 'extract_artifact']))
ok('[A路] 手工例外表仍是 1 条（第 6 步的 JS ASAR）', MANUAL_EXCEPTIONS.length === 1 && MANUAL_EXCEPTIONS[0].marker === 'manual-exception:not-advertised', j(MANUAL_EXCEPTIONS.map((m) => m.operation)))

{
  const route = routeProvider(META_ELF, readinessReal, capsJson, { preferredProvider: 'ghidra', remotePath: REMOTE_TARGET })
  ok('[A路·拒绝] ghidra 不可用时不降级、不选路', route.provider === null && route.subcommand === null && route.operation === null, `${route.provider}/${route.operation}/${route.subcommand}`)
  ok('[A路·拒绝] reason 带状态与 code', String(route.reason).startsWith('深分析不可用：ghidra 判定为 unavailable/not_configured'), String(route.reason).slice(0, 60))
  ok('[A路·拒绝] reason 带 REA remediation 原文', String(route.reason).includes('Set GHIDRA_INSTALL_DIR to an extracted Ghidra 12.1.x release directory.'), String(route.reason).slice(0, 130))
  ok('[A路·拒绝] reason 带诊断原文四个字段', ['install_dir=null', 'analyze_headless_path=null', 'java_command="java"', 'java_home=null'].every((k) => String(route.reason).includes(k)), String(route.reason).slice(-150))
  ok('[A路·拒绝] 诊断原文标了出处', String(route.reason).includes('远端诊断原文：'), '前缀在')
  ok('[A路·拒绝] marker 说明只有 help 证据', route.marker === 'a-path:help-verified-only' && route.surface === null, `${route.surface} / ${route.marker}`)
  ok('[A路·拒绝] unavailable 仍完整交代深分析三件套', ['ghidra', 'hopper', 'ida'].every((p) => arr(route.unavailable).some((u) => u.provider === p)), j(arr(route.unavailable).map((u) => `${u.provider}:${u.availabilityCode}`)))
  ok('[A路] 不点名时 ghidra 永远不进首选', routeProvider(META_ELF, readinessReal, capsJson, { remotePath: REMOTE_TARGET }).provider !== 'ghidra', String(routeProvider(META_ELF, readinessReal, capsJson, {}).provider))
  const diag = ghidraDiagnostics(capsJson)
  ok('[A路] diagnostics 直接取自 capabilities 广告面（零额外下发）', diag !== null && String(diagnosticSummary(diag)).startsWith('install_dir='), diagnosticSummary(diag))
  ok('[A路] diagnostics 拿不到时返回 null 而不是空串', diagnosticSummary(null) === null && ghidraDiagnostics({}) === null)
}

{
  // ghidra「可用」的正路：readiness 合成 ready，广告面仍用真固件（5 个操作都真被 ghidra 广告）。
  const ready = [{ id: 'ghidra', status: 'ready', availabilityCode: null, remediation: null, effects: [], sources: ['test:run-plugin-tests'] }]
  const route = routeProvider(META_ELF, ready, capsJson, { preferredProvider: 'ghidra', remotePath: REMOTE_TARGET })
  ok('[A路·可用] 首选 analyze_function → rea function', route.provider === 'ghidra' && route.operation === 'analyze_function' && route.subcommand === 'function', `${route.operation} → ${route.subcommand}`)
  ok('[A路·可用] surface/marker 如实标成未实跑', route.surface === 'a-path' && route.marker === 'a-path:help-verified-only', `${route.surface} / ${route.marker}`)
  ok('[A路·可用] reason 写明「没有一次实跑证据」', String(route.reason).includes('没有一次实跑证据') && String(route.reason).includes(GHIDRA_BINDINGS.analyze_function.usage), String(route.reason).slice(0, 150))
  ok('[A路·可用] 备选按绑定表顺序 = decompile/instructions/xrefs', j(arr(route.alternatives).map((a) => a.subcommand)) === j(['decompile', 'instructions', 'xrefs']), j(arr(route.alternatives).map((a) => a.subcommand)))
  ok('[A路·可用] 每个备选都带 marker', arr(route.alternatives).every((a) => a.marker === 'a-path:help-verified-only' && a.surface === 'a-path'))
  ok('[A路·可用] read_bytes 因缺 <address> 被跳过并写进 note', String(route.note).includes('read_bytes→rea read-bytes 需要 <address> 实参'), String(route.note).slice(-150))
}
{
  const ready = [{ id: 'ghidra', status: 'ready' }]
  const noAdv = { capabilities: [], analysis_provider_candidates: [{ provider: { id: 'ghidra' }, capabilities: [{ groups: [] }] }] }
  const route = routeProvider(META_ELF, ready, noAdv, { preferredProvider: 'ghidra', remotePath: REMOTE_TARGET })
  ok('[A路·可用但无广告] 不硬发命令，reason 交代跳过了什么', route.provider === null && String(route.reason).includes('未被 ghidra 广告'), String(route.reason).slice(0, 80))
}

// ===========================================================================
// P10 remote_hosts：真 HostStore 上的 CRUD 与口令红线
// ===========================================================================
section('P10 remote_hosts 主机库 CRUD（真 HostStore，零连接）')

const { createHostStore, HostStore } = await import('../remote-ssh-core.js')
const SECRET = 'plug1n-test-secret-42'
process.env.REA_PLUGIN_TEST_PASSWORD = SECRET
process.env.REA_PLUGIN_BLANK_PASSWORD = ''
const storeFile = join(HOME, 'hosts-plugin-tests.json')
const sshCfg = join(HOME, 'ssh_config')
writeFileSync(sshCfg, 'Host imported-one\n  HostName 10.0.0.9\n  User ops\n\nHost *\n  IdentityFile ~/.ssh/id_ed25519\n\nHost no-hostname\n  User x\n', 'utf8')
// createHostStore(path) 只转发第一个参数（第 3 步模块，本步不动），要拿到 sshConfigOverride
// 必须直接 new HostStore(path, override) —— 否则 import 会去读用户真实的 ~/.ssh/config。
const store = new HostStore(storeFile, sshCfg)
ok('[hosts] 工厂函数不转发 sshConfigOverride（改用类的双参构造，测试因此不碰真实 ~/.ssh/config）', createHostStore(storeFile, sshCfg).sshConfigOverride === undefined && store.sshConfigOverride === sshCfg, `factory=${String(createHostStore(storeFile, sshCfg).sshConfigOverride)} ｜ class=${store.sshConfigOverride}`)
const heng = makeHostEngine(store, (alias) => (alias === 'good-host'
  ? { ok: true, alias, latencyMs: 12, error: null }
  : { ok: false, alias, latencyMs: 0, error: 'connect ECONNREFUSED 10.0.0.1:22' }))
mod.useEngine(heng)
const hosts = (a) => hostsTool.execute(a, {})

{
  const first = await hosts({ action: 'add', alias: 'fake-host', host: '10.0.0.1', user: 'analyst', authKind: 'key', keyPath: '~/.ssh/id_ed25519', description: '测试机', tags: ['elf', 'rea'] })
  ok('[hosts] add 回显别名/地址/端口/认证方式', firstLine(first) === '已登记 fake-host（analyst@10.0.0.1:22，auth=key）', firstLine(first))
  const proj = payloadOf(first)
  ok('[hosts] add 附的是 store.summarize 脱敏投影', proj !== null && proj.auth === 'key' && !('password' in proj) && !('passphrase' in proj) && proj.alias === 'fake-host', j(proj === null ? null : Object.keys(proj)))
  ok('[hosts] list 计数正确', (await hosts({ action: 'list' })).startsWith('主机库 1 台'), firstLine(await hosts({ action: 'list' })))
  const got = await hosts({ action: 'get', alias: 'fake-host' })
  ok('[hosts] get 命中的也是投影（没有 password/passphrase 键）', !/password|passphrase/.test(String(got)), String(got).slice(0, 40))
  ok('[hosts] get 未登记别名时一句话', String(await hosts({ action: 'get', alias: 'nope' })).includes('不在主机库里'), String(await hosts({ action: 'get', alias: 'nope' })))
  ok('[hosts] 别名会真的落到存储文件', existsSync(storeFile) && readFileSync(storeFile, 'utf8').includes('fake-host'))
}
{
  const noEnv = await hosts({ action: 'add', alias: 'pw-host', host: '10.0.0.2', user: 'ops', authKind: 'password' })
  ok('[hosts] password 必须走 passwordEnv（口令不作为工具参数）', String(noEnv).includes('passwordEnv') && String(noEnv).startsWith('主机库操作失败：'), firstLine(noEnv))
  const missingEnv = await hosts({ action: 'add', alias: 'pw-host', host: '10.0.0.2', user: 'ops', authKind: 'password', passwordEnv: 'REA_PLUGIN_NO_SUCH_ENV' })
  ok('[hosts] 环境变量不存在时不登记', String(missingEnv).includes('里没有值'), firstLine(missingEnv))
  const blank = await hosts({ action: 'add', alias: 'pw-host', host: '10.0.0.2', user: 'ops', authKind: 'password', passwordEnv: 'REA_PLUGIN_BLANK_PASSWORD' })
  ok('[hosts] 环境变量是空串时同样不登记', String(blank).includes('里没有值'), firstLine(blank))
  const good = await hosts({ action: 'add', alias: 'pw-host', host: '10.0.0.2', user: 'ops', authKind: 'password', passwordEnv: 'REA_PLUGIN_TEST_PASSWORD' })
  ok('[hosts] passwordEnv 有值时登记成功', firstLine(good).startsWith('已登记 pw-host') && String(good).includes('auth=password'), firstLine(good))
  ok('[hosts] 工具返回体里没有口令原文', !String(good).includes(SECRET))
  ok('[hosts] 存储层按既有设计保存口令（红线在工具面，本步不动第 3 步的存储）', readFileSync(storeFile, 'utf8').includes(SECRET))
  const savedSock = process.env.SSH_AUTH_SOCK
  process.env.SSH_AUTH_SOCK = join(HOME, 'fake-agent.sock')
  const agent = await hosts({ action: 'add', alias: 'ag-host', host: '10.0.0.3', user: 'ci', authKind: 'agent' })
  ok('[hosts] agent 默认记号 SSH_AUTH_SOCK 在登记时固化成宿主进程当时的端点', firstLine(agent).includes('auth=agent') && store.find('ag-host').auth.agentPath === process.env.SSH_AUTH_SOCK, String(store.find('ag-host').auth.agentPath))
  if (savedSock === undefined) delete process.env.SSH_AUTH_SOCK
  else process.env.SSH_AUTH_SOCK = savedSock
  const agentPathArg = await hosts({ action: 'add', alias: 'ag-host-2', host: '10.0.0.6', user: 'ci', authKind: 'agent', agentPath: '/run/user/1000/key/sock' })
  ok('[hosts] 显式 agentPath 原样落库', store.find('ag-host-2').auth.agentPath === '/run/user/1000/key/sock', `${String(agentPathArg).split('\n')[0]} ｜ ${String(store.find('ag-host-2').auth.agentPath)}`)
  const badKind = await rejects(() => hostsTool.execute({ action: 'add', alias: 'x', host: '10.0.0.4', user: 'a', authKind: 'bearer' }, {}))
  ok('[hosts] authKind 不在枚举内被 schema 拦下', badKind !== null, String(badKind?.message).slice(0, 60))
}
{
  const upd = await hosts({ action: 'update', alias: 'fake-host', host: '10.0.0.5', port: 2222, tags: ['pe'] })
  const e = store.find('fake-host')
  ok('[hosts] update 只改传了的字段', String(upd) === '已更新 fake-host' && e.host === '10.0.0.5' && e.port === 2222 && j(e.tags) === j(['pe']) && e.user === 'analyst', j({ host: e.host, port: e.port, user: e.user, tags: e.tags, auth: e.auth.kind }))
  ok('[hosts] 不传 authKind 时 auth 原样保留', e.auth.kind === 'key' && e.auth.keyPath !== undefined, j(e.auth.kind))
  ok('[hosts] update 不存在的别名走失败口径', String(await hosts({ action: 'update', alias: 'ghost', host: '1.1.1.1' })).startsWith('主机库操作失败：'), firstLine(await hosts({ action: 'update', alias: 'ghost', host: '1.1.1.1' })))
}
{
  const good = await hosts({ action: 'test', alias: 'good-host' })
  const bad = await hosts({ action: 'test', alias: 'fake-host' })
  ok('[hosts] test 连通带往返毫秒', String(good).startsWith('连通：good-host（往返 12ms）'), String(good))
  ok('[hosts] test 不通带原因', String(bad).startsWith('不通：fake-host —— connect ECONNREFUSED') && heng.tests.length === 2, String(bad))
}
{
  const before = store.list().length
  const imp = await hosts({ action: 'import' })
  ok('[hosts] import 收下有 HostName 的块', String(imp).includes('解析 3 块，新增 1，跳过 2') && store.find('imported-one') !== undefined && store.list().length === before + 1, firstLine(imp))
  ok('[hosts] import 点名跳过通配符块与无 HostName 块', String(imp).includes('no-hostname') && String(imp).includes('*'), firstLine(imp))
  const again = await hosts({ action: 'import' })
  ok('[hosts] 重复 import 不新增', String(again).includes('新增 0') && store.list().length === before + 1, firstLine(again))
}
{
  const removed = await hosts({ action: 'remove', alias: 'ag-host' })
  ok('[hosts] remove 同时丢连接池里的别名', String(removed) === '已删除 ag-host' && store.find('ag-host') === undefined && j(heng.dropped) === j(['ag-host']), j({ msg: String(removed), dropped: heng.dropped }))
  ok('[hosts] 删不存在的别名不抛', String(await hosts({ action: 'remove', alias: 'never-existed' })).startsWith('主机库操作失败：'), firstLine(await hosts({ action: 'remove', alias: 'never-existed' })))
}

// ===========================================================================
// P11 单例生命周期：ctx.effect 的 disposer 真的释放 engine
// ===========================================================================
section('P11 engine 单例与释放')

{
  const a = fakeEngine({ hasRea: false, hasNpx: false })
  ok('[单例] useEngine 注入后原样返回', mod.useEngine(a) === a)
  await fetchTool.execute({ alias: 'h', remotePath: REMOTE_TARGET }, {})
  await fetchTool.execute({ alias: 'h', remotePath: REMOTE_TARGET }, {})
  ok('[单例] 两次工具调用共用同一个 engine', a.calls.length > 2 && mod.useEngine(a) === a, `${a.calls.length} 条命令`)
  ok('[单例] useEngine(null) 清空并 dispose', mod.useEngine(null) === null && a.disposed === 1, `disposed=${String(a.disposed)}`)
}
{
  // 不注入时首次调用会按默认路径自建真 engine（REVERSE_HOME 指向临时根，不会连任何主机）。
  const text = await hostsTool.execute({ action: 'list' }, {})
  ok('[单例] 懒建真 engine 后 list 可用', String(text).startsWith('主机库'), firstLine(text))
  const disposer = effects[0].fn
  let thrown = null
  try { disposer() } catch (e) { thrown = e }
  ok('[单例] effect disposer 调用不抛（真 engine 释放，清扫定时器随之停掉）', thrown === null, String(thrown?.message ?? 'ok'))
  ok('[单例] disposer 重复调用安全', (() => { try { effects[0].fn(); effects[0].fn(); return true } catch { return false } })())
  ok('[单例] disposer 后单例为空', mod.useEngine(null) === null)
}

// ===========================================================================
// P12 D：npx 预热预算 600000 与超时路径口径
// ===========================================================================
section('P12 D 冷 npx 预算与超时路径')

const controllerText = readFileSync(join(HERE, '..', 'rea-controller.js'), 'utf8')
ok('[D] 默认预算常量 = 600000', /const NPX_WARMUP_TIMEOUT_MS = 600000\b/.test(controllerText))
ok('[D] 300000 不再当预算用', !/TIMEOUT_MS = 300000\b/.test(controllerText))
ok('[D] runFetch / runAnalyze 的默认值都用这个常量', (controllerText.match(/npxTimeoutMs = NPX_WARMUP_TIMEOUT_MS/g) || []).length === 2, String((controllerText.match(/npxTimeoutMs = \w+/g) || []).join(', ')))
ok('[D] 工具面不暴露 timeout 参数（预算不由模型调）', [fetchTool, analyzeTool, hostsTool].every((t) => !Object.keys(t.parameters.properties).some((k) => /timeout|budget|ms$/i.test(k))), j(Object.keys(analyzeTool.parameters.properties)))
{
  const frames = []
  const eng = fakeEngine({ hasRea: false, hasNpx: true, nodeVersion: 'v22.22.1\n' })
  await runFetch('fake-host', REMOTE_TARGET, { engine: eng, reportsDir: REPORTS, localDir: TARGETS, onProgress: (f) => frames.push(f) })
  const warming = frames.find((f) => f.source === 'warmup' && f.phase === 'warming')
  ok('[D] 默认预算透传到预热帧', warming?.timeoutMs === 600000, j(warming))
  const frames2 = []
  const eng2 = fakeEngine({ hasRea: false, hasNpx: true, nodeVersion: 'v22.22.1\n' })
  const r2 = await runFetch('fake-host', REMOTE_TARGET, { engine: eng2, reportsDir: REPORTS, localDir: TARGETS, npxTimeoutMs: 2000, onProgress: (f) => frames2.push(f) })
  ok('[D] npxTimeoutMs 可覆盖（超时用例靠这条 plumbing）', frames2.find((f) => f.phase === 'warming')?.timeoutMs === 2000, j(frames2.find((f) => f.phase === 'warming')))
  ok('[D] 预热失败时收口成 unavailable 且预热命令只发一次（不重放）', r2.deploy?.strategy === 'unavailable' && eng2.calls.filter((c) => /rea-agents@latest --version/.test(c.command)).length === 1, `${r2.deploy?.strategy} ｜ err=${String(r2.error).slice(0, 50)}`)
}
ok('[D] 冷缓存超时用例落在 analyze 套件（真机 npx，2000ms 预算断言超时路径）', readFileSync(join(HERE, 'run-analyze-tests.mjs'), 'utf8').includes("npxTimeoutMs: 2000"))

// ===========================================================================
// 收口
// ===========================================================================
console.log('\n════════════════════════════════════════════════════════════════════')
console.log(`通过 ${pass} ｜ 失败 ${fail} ｜ 跳过 ${skip}`)
if (failures.length > 0) console.log(`失败项：\n${failures.map((f) => `  · ${f}`).join('\n')}`)
if (!KEEP) {
  try { rmSync(HOME, { recursive: true, force: true }) } catch {}
  info('临时目录', `${basename(HOME)} 已清理（--keep 可保留）`)
} else info('临时目录', `保留在 ${HOME}`)
process.exitCode = fail === 0 ? 0 : 1
