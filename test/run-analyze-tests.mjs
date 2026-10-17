// ============================================================================
// test/run-analyze-tests.mjs —— 第 6 步（结果映射 + 报告层 + 接 rea 分析）测试
// ----------------------------------------------------------------------------
// A 段：假 engine + 真机抓的固件（rea-doctor.json / rea-capabilities-linux-x64.json /
//        rea-analyze-js-app.jsonl），逐分支与全局约定，离线可重复。
// B 段：连真实 wsl-local 端到端跑 runAnalyze。
//   node test/run-analyze-tests.mjs                    # A + B
//   node test/run-analyze-tests.mjs --offline          # 只 A
//   node test/run-analyze-tests.mjs --cold             # 额外破坏性冷缓存 + 恢复
//   node test/run-analyze-tests.mjs --alias=x --store=y
// 固件就是这台机器（rea 6.5.0 / linux-x64）实跑抓的，所以 A 段的路由判定与真机同源。
// ============================================================================

import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

import { runFetch, runAnalyze, reaFailure, analyzeCommand, dialectCounts } from '../rea-controller.js'
import { routeProvider, classifyTarget, advertisedOperations, VERIFIED_CLI_BINDINGS, MANUAL_EXCEPTIONS } from '../rea-provider-router.js'
import { parseReaOutput, persistEvidence } from '../rea-output-parser.js'
import { probeRemoteRea } from '../rea-remote-probe.js'

const args = process.argv.slice(2)
const OFFLINE = args.includes('--offline')
const COLD = args.includes('--cold')
const ALIAS = (args.find((a) => a.startsWith('--alias=')) ?? '--alias=wsl-local').slice('--alias='.length)
const STORE_PATH = (args.find((a) => a.startsWith('--store=')) ?? '').slice('--store='.length) || undefined

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
    console.log(`  [FAIL] ${label}${detail === '' ? '' : '  → ' + detail}`)
    failures.push(label)
  }
}
const skipped = (label, why) => {
  skip++
  console.log(`  [SKIP] ${label}  → ${why}`)
}
const info = (label, value) => console.log(`  [INFO] ${label}  → ${value}`)
const section = (t) => console.log(`\n【${t}】`)
const j = (v) => JSON.stringify(v)

// 契约要求的 9 个键（第 6 步规格）；timings 是本轮为定位离群耗时加的，另外申报
const CONTRACT_KEYS = ['ok', 'alias', 'remotePath', 'localPath', 'metadata', 'route', 'analysis', 'summary', 'reportPath', 'error']

const FIX = (name) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8')
const DOCTOR = JSON.parse(FIX('rea-doctor.json'))
const CAPS = JSON.parse(FIX('rea-capabilities-linux-x64.json'))
const JS_LINES = FIX('rea-analyze-js-app.jsonl').split('\n').filter((l) => l.trim() !== '')
const JS_EVIDENCE_LINE = JS_LINES[JS_LINES.length - 1] // 最后一行才是完整 Evidence
const JS_EVIDENCE = JSON.parse(JS_EVIDENCE_LINE)

// 真机 file -b 原文（本轮抓的），分类表按这些字符串断言，不按想象的格式
const REAL_FILE_OUTPUTS = [
  ['ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, stripped', 'elf'],
  ['symbolic link to ../lib/cargo/bin/coreutils/ls', 'symlink'],
  ['data', 'data'],
  ['ASCII text', 'source-text'],
  ['JavaScript source, ASCII text', 'source-text'],
  ['directory', 'directory'],
  ['', 'unresolved'],
  ['PE32+ executable (console) x86-64, for MS Windows', 'pe'],
  ['Mach-O 64-bit dynamically linked shared library arm64', 'macho'],
  ['Zip archive data, at least v1.0 to extract', 'archive'],
  ['POSIX tar archive', 'archive'],
  ['Electron ASAR archive, header length: 502 bytes', 'asar'],
]
const ASAR_TYPE = REAL_FILE_OUTPUTS[11][0]

// ============================================================================
// 假 engine：exec 按命令内容路由；doctor/capabilities 直接回放真机固件
// ============================================================================

const FAKE_BODY = Buffer.concat([Buffer.from('\x7fELF'), Buffer.from('dsh-analyze-fixture-'.repeat(40))])
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
    durationMs: o.durationMs ?? 120,
    ...(timedOut ? { error: `command timed out after ${o.budget ?? 180000} ms` } : {}),
  }
}

function fakeEngine(o = {}) {
  const cfg = {
    hasNpx: true,
    cacheHit: true,
    preflightType: 'ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped',
    preflightExists: true,
    preflightSha: FAKE_SHA,
    analyze: null, // null=用 JS Evidence 原文；字符串=直接当 stdout；函数=按命令返回 ran()
    analyzeThrows: null,
    probeFails: false,
    downloadBody: undefined,
    ...o,
  }
  const calls = []
  const engine = {
    calls,
    async exec(alias, command, timeoutMs, attempts) {
      calls.push({ alias, command, timeoutMs, attempts })
      if (/command -v rea\b/.test(command)) return ran({ stdout: 'NONE' })
      if (/command -v npx\b/.test(command)) return ran({ stdout: cfg.hasNpx ? 'HAS' : 'NONE' })
      if (command.includes('node_modules/rea-agents')) {
        return cfg.cacheHit ? ran({ stdout: '/home/dev/.npm/_npx/af752b90495482d7/node_modules/rea-agents\n' }) : ran({ stdout: '', exitCode: 2 })
      }
      if (command.includes('rea-agents@latest --version')) return ran({ stdout: '6.5.0\n', durationMs: 50773 })
      if (command.includes('doctor')) return cfg.probeFails ? ran({ stdout: '抱歉，网络不可达', exitCode: 1 }) : ran({ stdout: JSON.stringify(DOCTOR), exitCode: 1 })
      if (command.includes('capabilities')) return cfg.probeFails ? ran({ stdout: '', exitCode: 1 }) : ran({ stdout: JSON.stringify(CAPS) })
      if (command.includes("printf 'EXISTS=")) {
        if (!cfg.preflightExists) return ran({ stdout: 'EXISTS=0\n' })
        return ran({ stdout: `EXISTS=1\nSIZE=${FAKE_BODY.length}\nTYPE=${cfg.preflightType}\nSHA256=${cfg.preflightSha}\n` })
      }
      if (/inspect-artifact|extract-artifact|analyze-javascript-application/.test(command)) {
        if (cfg.analyzeThrows !== null) throw cfg.analyzeThrows
        if (typeof cfg.analyze === 'function') return cfg.analyze(command)
        if (typeof cfg.analyze === 'string') return ran({ stdout: cfg.analyze })
        // 进度行走 stderr 的真机形态：这里合并后一起进 stdout
        return ran({ stdout: `${JS_LINES[0]}\n${String(cfg.analyze ?? JS_EVIDENCE_LINE)}\n` })
      }
      return ran({ stdout: '', exitCode: 127 })
    },
    async download(alias, remotePath, localPath, onProgress) {
      const body = cfg.downloadBody !== undefined ? cfg.downloadBody : FAKE_BODY
      mkdirSync(dirname(localPath), { recursive: true })
      writeFileSync(localPath, body)
      onProgress?.({ phase: 'transferring', file: remotePath, transferred: body.length, total: body.length, percent: 100 })
      onProgress?.({ phase: 'done', file: remotePath, transferred: body.length, total: body.length, percent: 100 })
      return { bytes: body.length }
    },
    dispose() {},
  }
  return engine
}

const scratch = mkdtempSync(join(tmpdir(), 'dsh-ana-test-'))
const reportsDir = join(scratch, 'reports')
const localDir = join(scratch, 'local')
const evHome = join(scratch, 'home') // Evidence 落盘根
// runAnalyze 内部调 persistEvidence 时读的是 process.env：不在这里改，A7/A8 会把
// Evidence 写进共享的 ~/.reverse/evidence（那是给用户用的，不是测试垃圾场）。
// 已经显式给了 REVERSE_HOME 就沿用（真机跑时留在那儿，报告里给的就是可回查的路径）。
if (typeof process.env.REVERSE_HOME !== 'string' || process.env.REVERSE_HOME.trim() === '') process.env.REVERSE_HOME = evHome
mkdirSync(reportsDir, { recursive: true })
mkdirSync(localDir, { recursive: true })
mkdirSync(evHome, { recursive: true })
const READINESS = [
  { id: 'ghidra', status: 'unavailable', availabilityCode: 'not_configured', remediation: 'Set GHIDRA_INSTALL_DIR to an extracted Ghidra 12.1.x release directory.' },
  { id: 'hopper', status: 'unavailable', availabilityCode: 'executable_missing', remediation: 'Hopper launcher is missing or not executable: /opt/hopper/bin/Hopper' },
  { id: 'ida', status: 'unavailable', availabilityCode: 'not_configured', remediation: 'Set REA_IDA_MCP_CONFIG to an upstream IDA MCP JSON registration' },
  { id: 'jadx', status: 'unavailable', availabilityCode: 'executable_missing', remediation: null },
  { id: 'rea-artifact-graph', status: 'ready', availabilityCode: null, remediation: null },
  { id: 'rea-dotnet-static', status: 'ready', availabilityCode: null, remediation: null },
  { id: 'sqlite', status: 'unavailable', availabilityCode: 'unsupported_version', remediation: 'SQLite inspection requires Node.js 24.x' },
  { id: 'native-macos', status: 'unavailable', availabilityCode: 'unsupported_host', remediation: 'Native macOS utilities require macOS.' },
]
const sizeOf = (p) => (typeof p === 'string' && existsSync(p) ? statSync(p).size : null)
/** runAnalyze 的公共调用封装：Evidence 落在临时 home，不污染共享 ~/.reverse/evidence */
async function analyzeWith(engine, remotePath, opts = {}) {
  const frames = []
  const r = await runAnalyze(ALIAS, remotePath, {
    engine,
    reportsDir,
    localDir,
    onProgress: (f) => frames.push(f),
    ...opts,
  })
  return { r, frames }
}

console.log('╔══════════════════════════════════════════════════════════════')
console.log('║  第 6 步：结果映射 + 报告层 + 接 rea 分析 —— 测试            ║')
console.log('╚══════════════════════════════════════════════════════════════')

// ============================================================================
section('A0 classifyTarget（按真机 file -b 原文）')
for (const [text, expected] of REAL_FILE_OUTPUTS) {
  const got = classifyTarget(text).targetClass
  ok(`classify ${j(text.slice(0, 42))} → ${expected}`, got === expected, got === expected ? '' : `实际 ${got}`)
}
ok('classify 保留 file 原文当 note', classifyTarget('ELF 64-bit LSB pie executable').note.includes('ELF'))
ok('符号链接 note 带出链接目标', classifyTarget('symbolic link to ../lib/x').note.includes('../lib/x'))
ok('data 类别的 note 说明 REA 会拒', /file_format_rejected/.test(classifyTarget('data').note))
// 真机原文里有 "archive" 一词，放到压缩包规则之后会被吞成 archive，手工例外就永远走不到
ok('ASAR 不被 archive 规则吞掉', classifyTarget(ASAR_TYPE).targetClass === 'asar')

section('A1 advertisedOperations（摊平两个广告位）')
const adv = advertisedOperations(CAPS)
ok('摊平出条目且带 provider/operation', adv.length > 50 && adv.every((a) => typeof a.provider === 'string' && typeof a.operation === 'string'), `${adv.length} 条`)
ok('深分析操作来自 candidates 而非顶层 capabilities', adv.some((a) => a.surface === 'candidates' && a.operation === 'analyze_function'))
ok('inspect_artifact 被 artifact-graph 广告且 available', adv.some((a) => a.provider === 'rea-artifact-graph' && a.operation === 'inspect_artifact' && a.available === true))
ok('asset_catalog 组带 availability_code', adv.some((a) => a.operation === 'inspect_asset_catalog' && a.available === false && a.availabilityCode === 'unsupported_host'))
ok('effects 原文带出（不只给 op 名）', j(adv.find((a) => a.operation === 'inspect_artifact').effects).includes('may_write_filesystem'))
ok('空/坏输入不抛', advertisedOperations(null).length === 0 && advertisedOperations({ capabilities: 'x' }).length === 0)

section('A2 routeProvider 正常路径')
const rElf = routeProvider({ fileType: REAL_FILE_OUTPUTS[0][0] }, READINESS, CAPS, {})
ok('ELF → rea-artifact-graph/inspect_artifact', rElf.provider === 'rea-artifact-graph' && rElf.operation === 'inspect_artifact', `${rElf.provider}/${rElf.operation}`)
ok('route 带出已核对的 CLI 子命令', rElf.subcommand === 'inspect-artifact' && VERIFIED_CLI_BINDINGS[rElf.operation] === 'inspect-artifact', String(rElf.subcommand))
ok('reason 说明类别 + 可用性 + 绑定来源', /目标类别 elf/.test(rElf.reason) && /--help 核对/.test(rElf.reason))
ok('reason 如实带出 effects（会起进程/写文件系统）', /effects=\[launches_process, may_write_filesystem\]/.test(rElf.reason))
ok('备选里有 extract_artifact', rElf.alternatives.some((a) => a.operation === 'extract_artifact'))
for (const t of [REAL_FILE_OUTPUTS[7][0], REAL_FILE_OUTPUTS[8][0], REAL_FILE_OUTPUTS[9][0]]) {
  const rr = routeProvider({ fileType: t }, READINESS, CAPS, {})
  ok(`容器类 ${classifyTarget(t).targetClass} 也给到 inspect_artifact`, rr.provider === 'rea-artifact-graph', rr.reason.slice(0, 60))
}
const rLink = routeProvider({ fileType: REAL_FILE_OUTPUTS[1][0] }, READINESS, CAPS, {})
ok('符号链接仍路由（链接串不带类型，交给 REA 判）', rLink.provider === 'rea-artifact-graph' && rLink.route === undefined && rLink.targetClass === 'symlink', rLink.note.slice(0, 40))

section('A2b 手工例外：analyze-javascript-application（广告面查不到，真机跑通过）')
ok('手工例外表只有一条，且限定目标类别', MANUAL_EXCEPTIONS.length === 1 && MANUAL_EXCEPTIONS[0].operation === 'analyze_javascript_application' && j(MANUAL_EXCEPTIONS[0].targetClasses) === '["asar"]')
ok('手工例外不混进 VERIFIED_CLI_BINDINGS（两张表判据不同源）', VERIFIED_CLI_BINDINGS[MANUAL_EXCEPTIONS[0].operation] === undefined)
ok('capabilities 固件里确实查不到 javascript（所以才叫例外）', !/javascript/i.test(JSON.stringify(CAPS)))
const rAsar = routeProvider({ fileType: ASAR_TYPE }, READINESS, CAPS, {})
ok('ASAR → rea-javascript-application/analyze_javascript_application', rAsar.provider === 'rea-javascript-application' && rAsar.operation === 'analyze_javascript_application', `${rAsar.provider}/${rAsar.operation}`)
ok('手工例外给到实跑核对过的子命令', rAsar.subcommand === 'analyze-javascript-application', String(rAsar.subcommand))
ok('路由结果打标记：surface/advertised/marker', rAsar.surface === 'manual-exception' && rAsar.advertised === false && rAsar.marker === 'manual-exception:not-advertised', `${rAsar.surface}/${rAsar.advertised}/${rAsar.marker}`)
ok('reason 自己说清「不在广告面」并给出实测依据', /不在 capabilities\/providers\/doctor 任何广告面/.test(rAsar.reason) && /68876B/.test(rAsar.reason), rAsar.reason.slice(0, 60))
ok('广告面的 inspect_artifact 退为备选且标明 advertised', rAsar.alternatives.some((a) => a.operation === 'inspect_artifact' && a.surface === 'advertised' && a.marker === null))
ok('readiness 没有该 provider 条目时照样放行（没被广告≠不可用）', READINESS.every((r) => r.id !== 'rea-javascript-application') && rAsar.provider === 'rea-javascript-application')
ok('手工例外不依赖广告面：capabilities 为空照样选得出', (() => routeProvider({ fileType: ASAR_TYPE }, READINESS, {}, {}).provider)() === 'rea-javascript-application')
const rAsarPref = routeProvider({ fileType: ASAR_TYPE }, READINESS, CAPS, { preferredProvider: 'inspect_artifact' })
ok('preferredProvider 能让手工例外让位给广告面操作', rAsarPref.provider === 'rea-artifact-graph' && rAsarPref.surface === 'advertised' && rAsarPref.alternatives.some((a) => a.marker === 'manual-exception:not-advertised'), `${rAsarPref.provider}/${rAsarPref.surface}`)
{
  const blocked = [...READINESS, { id: 'rea-javascript-application', status: 'unavailable', availabilityCode: 'not_configured', remediation: 'Set REA_JS_RUNTIME_DIR to a Node runtime.' }]
  const rBlocked = routeProvider({ fileType: ASAR_TYPE }, blocked, CAPS, {})
  ok('readiness 明确判不可用时拦下例外，回落到广告面', rBlocked.provider === 'rea-artifact-graph' && rBlocked.surface === 'advertised', `${rBlocked.provider}/${rBlocked.surface}`)
  ok('被拦的例外进 unavailable[]：reason 用 remediation 原文，靠 marker 字段标明是手工例外', (() => {
    const u = rBlocked.unavailable.find((x) => x.provider === 'rea-javascript-application')
    return u !== undefined && u.reason.startsWith('Set REA_JS_RUNTIME_DIR') && u.marker === 'manual-exception:not-advertised' && u.advertised_operations === 0
  })(), j(rBlocked.unavailable.find((u) => u.provider === 'rea-javascript-application') ?? null))
  ok('被拦时不进 alternatives', !rBlocked.alternatives.some((a) => a.operation === 'analyze_javascript_application'))
}
for (const [text, cls] of REAL_FILE_OUTPUTS) {
  if (cls === 'asar') continue
  const rr = routeProvider({ fileType: text }, READINESS, CAPS, {})
  ok(`类别 ${cls} 不会走到手工例外`, rr.provider !== 'rea-javascript-application', String(rr.provider))
}
ok('单个 .js 不给例外（真机 exit=1：只收目录或 .asar；目录又过不了 runFetch 的普通文件预检）', routeProvider({ fileType: 'JavaScript source, ASCII text' }, READINESS, CAPS, {}).provider === null)

section('A3 routeProvider 不可用与无路可走')
for (const t of ['data', 'directory', 'JavaScript source, ASCII text']) {
  const rr = routeProvider({ fileType: t }, READINESS, CAPS, {})
  ok(`类别 ${classifyTarget(t).targetClass} 本步不给操作（provider=null）`, rr.provider === null && rr.operation === null && rr.subcommand === null, rr.reason.slice(0, 70))
}
const codes = Object.fromEntries(rElf.unavailable.map((u) => [u.provider, u.availabilityCode]))
ok('unavailable[] 有 ghidra/hopper/ida 且各带 availabilityCode', ['ghidra', 'hopper', 'ida'].every((p) => codes[p] !== undefined), j(codes))
ok('reason 用 3b 的 remediation 原文，不自编', rElf.unavailable.find((u) => u.provider === 'ghidra').reason.startsWith('Set GHIDRA_INSTALL_DIR'))
ok('hopper 的 code 是 executable_missing', codes.hopper === 'executable_missing')
ok('dotnet 可用但没有已核对绑定 → 单独口径，reason 不自相矛盾', codes['rea-dotnet-static'] === 'no_verified_cli_binding' && /已核对的 CLI 绑定/.test(rElf.unavailable.find((u) => u.provider === 'rea-dotnet-static').reason), String(codes['rea-dotnet-static']))
ok('unavailable[] 里没有 reason=readiness 状态词这种废话（要么 remediation 原文要么说清为什么）', rElf.unavailable.every((u) => typeof u.reason === 'string' && u.reason.length > 8 && u.reason !== 'ready' && u.reason !== 'unavailable'), j(rElf.unavailable.map((u) => `${u.provider}:${u.availabilityCode}`)))
ok('available 且可用的 provider 不进 unavailable', !rElf.unavailable.some((u) => u.provider === 'rea-artifact-graph'))
const rPref = routeProvider({ fileType: REAL_FILE_OUTPUTS[0][0] }, READINESS, CAPS, { preferredProvider: 'extract_artifact' })
ok('preferredProvider 命中操作时重排到首选', rPref.operation === 'extract_artifact' && rPref.subcommand === 'extract-artifact')
const rBad = routeProvider({ fileType: REAL_FILE_OUTPUTS[0][0] }, READINESS, CAPS, { preferredProvider: 'hopper' })
ok('不可用的 preferred（非 A 路）只记 note，不放宽判定', rBad.provider === 'rea-artifact-graph' && /没有可用且已验证绑定/.test(rBad.note), rBad.note.slice(-40))
// 第 7 步 A 路改了这条口径：点名的 provider 是 ghidra 时不再静默回退浅分析 ——
// 用户要的是深分析结论，换成「广告面选出来的浅分析」等于换结论口径，必须直接拒绝并给诊断原文。
const rGhidra = routeProvider({ fileType: REAL_FILE_OUTPUTS[0][0] }, READINESS, CAPS, { preferredProvider: 'ghidra' })
ok('点名的 provider 是 ghidra 且不可用时拒绝选路（不自动降级到浅分析）', rGhidra.provider === null && String(rGhidra.reason).startsWith('深分析不可用：ghidra'), String(rGhidra.reason).slice(0, 60))
ok('readiness 缺条目时回退 capabilities 的组可用性', (() => {
  const rr = routeProvider({ fileType: REAL_FILE_OUTPUTS[0][0] }, [], CAPS, {})
  return rr.provider === 'rea-artifact-graph'
})())
ok('capabilities 全空 → 选不出路（不放宽到未广告的operation），且不抛', (() => {
  const rr = routeProvider({ fileType: REAL_FILE_OUTPUTS[0][0] }, READINESS, {}, {})
  return rr.provider === null && rr.operation === null && /都不可用/.test(rr.reason) && Array.isArray(rr.unavailable)
})(), routeProvider({ fileType: 'ELF x' }, READINESS, {}, {}).reason.slice(0, 70))
ok('metadata 为 null 也能选路（类别 unresolved）', routeProvider(null, READINESS, CAPS, {}).targetClass === 'unresolved')

section('A4 命令拼装与闸门')
ok('analyzeCommand 走 shellQuote（分号/空格被单引号包住）', analyzeCommand('rea', 'inspect-artifact', "/tmp/a b;c'rm'") === `rea inspect-artifact '/tmp/a b;c'\\''rm'\\''' --format json`, analyzeCommand('rea', 'inspect-artifact', "/tmp/a b;c'rm'"))
ok('analyzeCommand 带 --format json', analyzeCommand('npx --yes rea-agents@latest', 'extract-artifact', '/tmp/x').endsWith('--format json'))
{
  const engine = fakeEngine()
  const { r, frames } = await analyzeWith(engine, '/tmp/x.bin')
  const ana = engine.calls.find((c) => /inspect-artifact/.test(c.command))
  ok('分析命令只下发一次（attempts=1，不重放）', ana !== undefined && engine.calls.filter((c) => /inspect-artifact/.test(c.command)).length === 1, `attempts=${ana?.attempts}`)
  ok('分析命令的超时是 180000ms', ana?.timeoutMs === 180000, String(ana?.timeoutMs))
  ok('下发命令里没有 sudo / --break-system-packages', !/\bsudo\b|--break-system-packages/.test(ana?.command ?? ''))
  ok('runAnalyze 没改写 remotePath（命令里就是原路径，转义交给 shellQuote）', (ana?.command ?? '').includes('/tmp/x.bin --format json'), String(ana?.command))
  ok('预热帧由 planRemoteReaDeploy 发（source=warmup，缓存命中也报 warmed）', r.ok === true && frames.some((f) => f.source === 'warmup' && f.phase === 'warmed' && f.cached === true), j(frames.filter((f) => f.source === 'warmup')))
  ok('控制器不再自己转述预热（没有 source=controller 的 warmed 帧）', !frames.some((f) => f.source === 'controller' && f.phase === 'warmed'), frames.map((f) => `${f.source}:${f.phase}`).join('>'))
}
{
  // 手工例外在控制器侧的可见性：下发例外表里的子命令，进度帧与落盘报告都带标记
  const engine = fakeEngine({ preflightType: ASAR_TYPE })
  const { r, frames } = await analyzeWith(engine, '/tmp/app.asar')
  const ana = engine.calls.find((c) => /analyze-javascript-application/.test(c.command))
  ok('[例外] ASAR 目标下发的是例外表里的子命令', r.ok === true && (ana?.command ?? '').includes('analyze-javascript-application /tmp/app.asar --format json'), String(ana?.command).slice(0, 90))
  ok('[例外] 下发仍然 attempts=1、超时 180000', ana?.attempts === 1 && ana?.timeoutMs === 180000, `attempts=${ana?.attempts} timeout=${ana?.timeoutMs}`)
  ok('[例外] Evidence 的 provider/operation 与路由一致', r.analysis?.provider === 'rea-javascript-application' && r.analysis?.operation === 'analyze_javascript_application', `${r.analysis?.provider}/${r.analysis?.operation}`)
  ok('[例外] routed 帧带 surface 与 marker 文案', frames.some((f) => f.phase === 'routed' && f.surface === 'manual-exception' && /manual-exception:not-advertised/.test(f.message)), j(frames.find((f) => f.phase === 'routed')?.message))
  ok('[例外] 标记随报告落盘（回查看得出这不是广告面选的路）', (() => {
    const rep = JSON.parse(readFileSync(r.reportPath, 'utf8'))
    return rep.route?.marker === 'manual-exception:not-advertised' && rep.route?.advertised === false && rep.route?.surface === 'manual-exception'
  })(), j({ m: JSON.parse(readFileSync(r.reportPath, 'utf8')).route?.marker }))
  ok('[例外] JS 方言有 semantic_graph → findings 不为 0（与 artifact-graph 的零不同源）', r.analysis?.dialect?.has_semantic_graph === true && r.analysis.findingCount > 0, `findings=${r.analysis?.findingCount}`)
}

section('A5 reaFailure：exit=0 的失败信封必须认出来')
const ENVELOPE = '{"error":"Analysis failed","code":"target_unavailable","category":"unsupported_target","message":"Cannot open artifact: unsupported binary format.","retryable":false,"remediation":{"action":"Review the reported file-format reason and select a supported, well-formed target."},"details":{"path":"/tmp/x","reason":"unsupported binary format","constraint":"file_format_rejected"}}'
const fEnv = reaFailure(JSON.parse(ENVELOPE))
ok('失败信封判定出 code/category/constraint', fEnv?.code === 'target_unavailable' && fEnv?.category === 'unsupported_target' && fEnv?.constraint === 'file_format_rejected')
ok('remediation 原文保留', fEnv?.remediation?.startsWith('Review the reported file-format reason'))
ok('真 Evidence 不误判（有 evidence_id 即放行）', reaFailure(JS_EVIDENCE) === null)
ok('缺 evidence_id 的怪对象不误判为失败', reaFailure({ foo: 1 }) === null)
ok('只有 error 没有 code 也判失败', reaFailure({ error: 'Nope' })?.message === 'Nope')
ok('数组/标量输入不抛', reaFailure([1, 2]) === null && reaFailure('x') === null && reaFailure(null) === null)

section('A6 dialectCounts')
const dJs = dialectCounts(JS_EVIDENCE)
ok('JS 方言有 semantic_graph 且带 nodes', dJs.has_semantic_graph === true && dJs.semantic_graph_nodes > 0, `nodes=${dJs.semantic_graph_nodes}`)
const artifactShape = { normalized_result: { substeps: [{}], observations: [{}], hypotheses: [], contradictions: [], unexplored_branches: [{}], next_probes: [{}] } }
const dArt = dialectCounts(artifactShape)
ok('artifact-graph 方言没有 semantic_graph', dArt.has_semantic_graph === false && dArt.semantic_graph_nodes === null)
ok('artifact-graph 方言按原文数组计数', dArt.substeps === 1 && dArt.observations === 1 && dArt.unexplored_branches === 1 && dArt.next_probes === 1)
ok('normalized_result 缺失/非对象返回 null', dialectCounts({}) === null && dialectCounts(null) === null)

section('A7 runAnalyze 正常路径（离线，Evidence 用真机抓的 JS 分析原文）')
{
  const engine = fakeEngine()
  const { r, frames } = await analyzeWith(engine, '/tmp/rea-target.bin')
  ok('ok=true 且 error=null', r.ok === true, String(r.error))
  ok('契约键齐全', CONTRACT_KEYS.every((k) => k in r), CONTRACT_KEYS.filter((k) => !(k in r)).join(','))
  ok('route 选中 available 的 provider', r.route.provider === 'rea-artifact-graph' && r.route.operation === 'inspect_artifact')
  ok('analysis.evidence 解析成功（有 evidence_id）', typeof r.analysis?.evidence?.evidence_id === 'string', String(r.analysis?.evidenceId))
  ok('evidencePath 文件存在且能读', existsSync(r.analysis.evidencePath) && statSync(r.analysis.evidencePath).size > 100, `${r.analysis.evidencePath} ${sizeOf(r.analysis.evidencePath)}B`)
  ok('落盘的是原文（逐字节等于 stdout 里那一行）', readFileSync(r.analysis.evidencePath, 'utf8') === JS_EVIDENCE_LINE)
  ok('summary 结构完整（subject/provider/operation/evidence_id/coverage）', ['subject', 'provider', 'operation', 'evidence_id', 'evidence_path', 'coverage', 'findings_by_kind', 'unknowns', 'statistics', 'limitations', 'truncated'].every((k) => k in (r.summary ?? {})))
  ok('summary 的 evidence_path 指向落盘文件', r.summary?.evidence_path === r.analysis.evidencePath)
  ok('映射真的产出 findings（3a 层对 semantic_graph 有效）', r.analysis.findingCount > 0, `findings=${r.analysis.findingCount} groups=${j(r.summary.group_counts)}`)
  ok('reportPath 有文件', existsSync(r.reportPath ?? '') && statSync(r.reportPath).size > 200, `${r.reportPath} ${sizeOf(r.reportPath)}B`)
  ok('报告里不复制整份 Evidence（只留计数与路径）', (() => {
    const rep = JSON.parse(readFileSync(r.reportPath, 'utf8'))
    return rep.analysis?.evidence === undefined && rep.analysis?.evidencePath === r.analysis.evidencePath
  })())
  ok('报告里 analysis 的字段是全量的（不含 evidence 对象本身）', JSON.parse(readFileSync(r.reportPath, 'utf8')).analysis.stdoutBytes === r.analysis.stdoutBytes)
  ok('进度帧含 fetched/routed/analyzing/evidence/summarized/finished', ['fetching', 'routed', 'analyzing', 'evidence', 'summarized', 'finished'].every((p) => frames.some((f) => f.phase === p)), frames.map((f) => f.phase).join('>'))
  ok('透传的 plan 预热帧带 source=warmup', frames.some((f) => f.source === 'warmup' && f.phase === 'warmed' && f.cached === true))
  ok('透传的传输帧没被改写 source（保持 undefined 原样）', frames.some((f) => f.phase === 'transferring'))
  ok('timings 四段都填了数（假 engine 是 0ms 量级，真机不是）', ['fetchMs', 'probeMs', 'analyzeMs', 'mapMs'].every((k) => typeof r.timings[k] === 'number' && r.timings[k] >= 0) && r.timings.fetchMs + r.timings.probeMs + r.timings.analyzeMs + r.timings.mapMs <= r.durationMs + 5, j({ ...r.timings, total: r.durationMs }))
  ok('返回体不含远端原始 stdout', !JSON.stringify({ ...r, analysis: null }).includes('rea_progress') && r.analysis.stdoutBytes > 0)
  ok('dialect 如实记 semantic_graph 方言', r.analysis.dialect.has_semantic_graph === true && r.analysis.dialect.semantic_graph_nodes > 0)
  ok('localPath 真的落盘且大小对上', r.localPath !== null && statSync(r.localPath).size === FAKE_BODY.length)
}

section('A8 runAnalyze 失败路径（每类都要一句话）')
{
  const mk = (o) => fakeEngine(o)
  const cases = [
    ['目标不存在', mk({ preflightExists: false }), (r) => /不存在或不是普通文件/.test(r.error) && r.analysis === null && r.summary === null],
    ['无可用 provider（readiness 全灭）', mk({ preflightType: 'ELF 64-bit' }), (r) => r.ok === false, { readinessKill: true }],
    ['data 目标无路可走', mk({ preflightType: 'data' }), (r) => r.route?.provider === null && /没有可用的分析路径/.test(r.error) && r.analysis === null],
    ['REA 回失败信封但 exit=0', mk({ analyze: ENVELOPE }), (r) => r.ok === false && /REA 拒绝该目标：target_unavailable\/file_format_rejected/.test(r.error) && r.analysis.failure?.code === 'target_unavailable'],
    ['输出里没有 JSON', mk({ analyze: '抱歉，网络不可达' }), (r) => /分析输出没解析出 JSON/.test(r.error) && r.analysis.evidenceId === null],
    ['解析不出对象（数组也算）', mk({ analyze: '[1,2,3]' }), (r) => /分析输出没解析出 JSON/.test(r.error)],
    ['分析超时', mk({ analyze: () => ran({ timedOut: true, exitCode: null, budget: 180000, stdout: '' }) }), (r) => /分析超时（180000ms 内没返回）/.test(r.error)],
    ['能力面探测失败', mk({ probeFails: true }), (r) => /能力面探测失败，无法路由/.test(r.error) && r.route === null],
    ['exec 直接抛', mk({ analyzeThrows: new Error('SSH packet loop died') }), (r) => /分析失败：SSH packet loop died/.test(r.error)],
  ]
  for (const [label, engine, check, extra] of cases) {
    let r
    if (extra?.readinessKill) {
      // 路由层单独验：所有 provider 都不可用时不选路
      const rr = routeProvider({ fileType: 'ELF 64-bit' }, READINESS.map((x) => ({ ...x, status: 'unavailable' })), CAPS, {})
      ok(`${label}（provider 全不可用）`, rr.provider === null && /都不可用/.test(rr.reason), rr.reason.slice(0, 60))
      continue
    }
    r = (await analyzeWith(engine, '/tmp/rea-target.bin')).r
    ok(label, check(r), String(r.error).slice(0, 90))
    ok(`  ${label} 的 error 是一句话（无换行）`, typeof r.error === 'string' && !/[\r\n]/.test(r.error))
  }
  const noRoute = (await analyzeWith(mk({ preflightType: 'data' }), '/tmp/rea-target.bin')).r
  ok('失败也存档 analyze 报告', existsSync(noRoute.reportPath ?? ''))
  ok('no-route 时 analysis 保持 null（没下发命令）', noRoute.analysis === null)
  const fetchEngine = mk({ preflightExists: false })
  const fetchFail = (await analyzeWith(fetchEngine, '/tmp/rea-missing.bin')).r
  ok('拉取失败时直接引用 fetch 报告（不写空 analyze 报告）', fetchFail.reportPath !== null && /fetch-/.test(String(fetchFail.reportPath)))
  ok('拉取失败时一条分析命令都没下发', fetchEngine.calls.every((c) => !/inspect-artifact|extract-artifact|analyze-javascript-application/.test(c.command)) && fetchFail.route === null, `${fetchEngine.calls.length} 次 exec 里没有分析命令`)
  ok('拉取失败时没探测能力面（省掉那 11s）', fetchEngine.calls.every((c) => !/doctor|capabilities/.test(c.command)), `${fetchEngine.calls.filter((c) => /doctor|capabilities/.test(c.command)).length} 次`)
}

section('A9 Evidence 落盘与解析层的一致性（第 3a 层的契约在这里复核）')
{
  const parsed = parseReaOutput(`${JS_LINES[0]}\n${JS_LINES[3]}\n${JS_EVIDENCE_LINE}\n`)
  ok('进度行被跳过、Evidence 取最后一个对象', parsed.progress.length === 2 && parsed.evidence?.evidence_id === JS_EVIDENCE.evidence_id, `progress=${parsed.progress.length}`)
  ok('evidence_raw 与那一行逐字节相等', parsed.evidence_raw === JS_EVIDENCE_LINE)
  const p = persistEvidence(parsed.evidence, { homeDir: evHome, raw: parsed.evidence_raw })
  ok('persistEvidence 落在 <home>/evidence/<id>.json', p === join(evHome, 'evidence', `${JS_EVIDENCE.evidence_id}.json`) && existsSync(p))
  ok('落盘内容逐字节等于原文', readFileSync(p, 'utf8') === JS_EVIDENCE_LINE)
}

section('A10 符号链接的 size 豁免（第 5 步遗留，本轮收口）')
{
  const engine = fakeEngine({ preflightType: 'symbolic link to ../lib/cargo/bin/coreutils/ls' })
  const fetched = await runFetch(ALIAS, '/bin/ls', { engine, reportsDir, localDir })
  ok('符号链接不比对大小（sizeMatches=null）', fetched.verification?.sizeMatches === null, j(fetched.verification?.sizeMatches))
  ok('豁免原因如实记录', fetched.verification?.sizeSkippedForSymlink === true)
  ok('sha 仍然是权威且判过了', fetched.verification?.shaMatches === true)
  const normal = await runFetch(ALIAS, '/tmp/rea-target.bin', { engine: fakeEngine(), reportsDir, localDir })
  ok('普通文件照常比对大小', normal.verification.sizeMatches === true && normal.verification.sizeSkippedForSymlink === false)
}

// ============================================================================
if (!OFFLINE) {
  section(`B 端到端（别名 ${ALIAS}，真机 rea 6.5.0 via npx）`)
  const core = await import('../remote-ssh-core.js')
  const store = core.createHostStore(STORE_PATH ?? join(process.env.HOME ?? '', '.reverse', 'remote-ssh-hosts.json'))
  const engine = core.createSshEngine(store)
  const NOMAGIC = '/tmp/rea-analyze-nomagic.bin'
  const LEGACY_RAND = '/tmp/rea-analyze-rand.bin'
  const TRUNC = '/tmp/rea-analyze-trunc.elf'
  const ASAR_REMOTE = '/tmp/rea-analyze-app.asar'
  const SMALL_ELF = '/usr/bin/file'
  try {
    // 无格式头样本必须确定性：实测 40 个新鲜 10KB /dev/urandom 里有 2 个被 file 判成
    // 「OpenPGP Public Key」（5% 抖动），于是路由照发、REA 回 file_format_rejected，
    // 断言就假红了。全零 10240 字节稳定判为 data。
    const mk = await engine.exec(ALIAS, `head -c 10240 /dev/zero > ${NOMAGIC}; head -c 4000 ${SMALL_ELF} > ${TRUNC}; file -b ${NOMAGIC}; ls -l ${SMALL_ELF} ${NOMAGIC} ${TRUNC} | awk '{print $5, $9}'`, 30000)
    ok('远端样本就位', mk.exitCode === 0 && /^data$/m.test(String(mk.stdout)), String(mk.stdout).replace(/\n/g, ' | ').slice(0, 120))
    const ft = await engine.exec(ALIAS, `file -b ${TRUNC}`, 30000)
    info('截断 ELF 的 file -b 原文', String(ft.stdout).trim().slice(0, 120))

    const { r, frames } = await analyzeWith(engine, SMALL_ELF)
    console.log('\n  ── 真实 runAnalyze 返回（Evidence 全文只留路径）──')
    console.log('  ' + j({ ...r, analysis: { ...r.analysis, evidence: undefined }, summary: `<${Object.keys(r.summary ?? {}).length} 键>` }).replace(/\n/g, '\n  '))
    ok('[LIVE] ok=true', r.ok === true, String(r.error))
    ok('[LIVE] route 选中 available 的 provider', r.route?.provider === 'rea-artifact-graph' && r.route?.operation === 'inspect_artifact', `${r.route?.provider}/${r.route?.operation} 类别=${r.route?.targetClass}`)
    ok('[LIVE] Evidence 解析成功并落盘', typeof r.analysis?.evidenceId === 'string' && existsSync(r.analysis.evidencePath), `${r.analysis?.evidenceId} → ${r.analysis?.evidencePath}`)
    ok('[LIVE] 落盘是 Evidence 原文（能读回、id 与返回一致、体积 ≤ stdout）', (() => {
      const n = statSync(r.analysis.evidencePath).size
      return n > 0 && n <= r.analysis.stdoutBytes && JSON.parse(readFileSync(r.analysis.evidencePath, 'utf8')).evidence_id === r.analysis.evidenceId
    })(), `落盘=${statSync(r.analysis.evidencePath).size}B stdout=${r.analysis.stdoutBytes}B 差值=${r.analysis.stdoutBytes - statSync(r.analysis.evidencePath).size}B`)
    ok('[LIVE] Evidence 里远端自算的 sha256 == 预检 sha256（两码对账）', r.analysis.evidence?.subject?.digest?.sha256 === r.metadata.sha256, String(r.analysis?.evidence?.subject?.digest?.sha256).slice(0, 16))
    ok('[LIVE] Evidence 的 subject 指向远端落地路径', typeof r.analysis?.evidence?.subject?.local_path === 'string', String(r.analysis?.evidence?.subject?.local_path))
    ok('[LIVE] summary 结构完整', ['subject', 'provider', 'operation', 'evidence_id', 'evidence_path', 'coverage', 'findings_by_kind', 'unknowns'].every((k) => k in (r.summary ?? {})))
    // 实测（本轮）：/usr/bin/file 的报告 5631B、Evidence 5573B —— 「报告一定比 Evidence 小」是巧合，
    // 目标是 5.5KB 这种小文件时它就不成立了（路由留痕本身 2KB）。真正要钉的是：报告不内联 Evidence，
    // 体积随摘要与路由走，不随目标大小长。ASAR 那条（Evidence 74829B）给了量级证据。
    ok('[LIVE] 报告不内联 Evidence：analysis 投影里没有 evidence 字段，回查只靠 evidence_path', (() => {
      const rep = JSON.parse(readFileSync(r.reportPath, 'utf8'))
      return !('evidence' in rep.analysis) && typeof rep.summary?.evidence_path === 'string' && existsSync(rep.summary.evidence_path)
    })(), `${statSync(r.reportPath).size}B 报告 / ${statSync(r.analysis.evidencePath).size}B Evidence`)
    ok('[LIVE] 报告的固定开销与目标大小无关（analysis < 2KB、route < 4KB）', (() => {
      const sizeOf = (v) => Buffer.byteLength(JSON.stringify(v))
      const rep = JSON.parse(readFileSync(r.reportPath, 'utf8'))
      return sizeOf(rep.analysis) < 2048 && sizeOf(rep.route) < 4096
    })(), (() => {
      const sizeOf = (v) => Buffer.byteLength(JSON.stringify(v))
      const rep = JSON.parse(readFileSync(r.reportPath, 'utf8'))
      return `analysis=${sizeOf(rep.analysis)}B route=${sizeOf(rep.route)}B`
    })())
    ok('[LIVE] 帧序：fetch→预热→路由→分析→落盘→摘要→收口', (() => {
      const order = frames.filter((f) => f.source === 'controller' || f.source === 'warmup').map((f) => f.phase)
      const want = ['fetching', 'planning', 'warmed', 'preflight', 'downloading', 'verifying', 'finished', 'routing', 'routed', 'analyzing', 'evidence', 'summarized', 'finished']
      let i = 0
      for (const p of order) if (p === want[i]) i++
      return i === want.length
    })(), frames.map((f) => `${f.source ?? 'x'}:${f.phase}`).join('>'))
    ok('[LIVE] dialect 计数与 Evidence 数组实际长度一致', (() => {
      const nr = r.analysis.evidence?.normalized_result ?? {}
      return r.analysis.dialect.observations === (nr.observations ?? []).length && r.analysis.dialect.substeps === (nr.substeps ?? []).length
    })(), j(r.analysis.dialect))
    ok('[LIVE] artifact-graph 方言没有 semantic_graph → findings 恒为 0（结构性，不是「没问题」）', r.analysis.findingCount === 0 && r.analysis.dialect.has_semantic_graph === false && Array.isArray(r.summary?.limitations) && r.summary.limitations.length > 0, `findings=${r.analysis.findingCount} limitations=${(r.summary?.limitations ?? []).length} 条`)
    info('[LIVE] 分段耗时', `fetch=${r.timings.fetchMs}ms probe=${r.timings.probeMs}ms analyze=${r.timings.analyzeMs}ms map=${r.timings.mapMs}ms 合计=${r.durationMs}ms`)
    info('[LIVE] findings / unknowns', `${r.analysis.findingCount} / ${r.analysis.unknownCount}（该方言没有 semantic_graph，0 是结构决定的）`)

    const nomagic = (await analyzeWith(engine, NOMAGIC)).r
    ok('[LIVE] 无格式头目标 → 路由判 no-path 且一句话', nomagic.ok === false && nomagic.route?.provider === null && /没有可用的分析路径/.test(nomagic.error), String(nomagic.error).slice(0, 80))
    ok('[LIVE] 无格式头目标没有下发分析命令', nomagic.analysis === null)
    ok('[LIVE] 无格式头目标仍存档报告', existsSync(nomagic.reportPath ?? ''))

    const miss = (await analyzeWith(engine, '/tmp/nonexistent-xyz-6c')).r
    ok('[LIVE] 目标不存在 → 一句话、不进分析', miss.ok === false && /不存在或不是普通文件/.test(miss.error) && miss.route === null, String(miss.error).slice(0, 60))

    // 实测（本轮抓的）：截断 ELF（file -b = "… missing section headers at 27288"）在
    // inspect-artifact 这里照样 exit=0 回完整 Evidence、format=elf，Evidence 里没有任何 truncation 告警。
    // 所以「REA 拒绝」只覆盖 file 判不出格式的目标（data），格式对但内容残缺它不管 —— 这条要钉住，
    // 哪天它开始校验了（或哪天我们不再看 unexplored_branches）这里就会红。
    const trunc = (await analyzeWith(engine, TRUNC)).r
    ok('[LIVE] 截断 ELF 仍被判为可分析（格式头是 elf，路由按类别放行）', trunc.route?.provider === 'rea-artifact-graph' && trunc.route?.targetClass === 'elf', `${String(trunc.route?.provider)} 类别=${String(trunc.route?.targetClass)}`)
    ok('[LIVE] REA 不校验 section headers：残缺 ELF 照样回 Evidence 且没有失败信封', trunc.ok === true && trunc.analysis?.failure === null && trunc.analysis?.subjectFormat === 'elf', String(trunc.error))
    ok('[LIVE] 但 Evidence 自己承认没做格式级分析：unexplored_branches → next_probes=open_binary', (() => {
      const nr = trunc.analysis?.evidence?.normalized_result ?? {}
      const ub = nr.unexplored_branches ?? []
      const np = nr.next_probes ?? []
      return ub.length > 0 && np.some((p) => p?.operation === 'open_binary')
    })(), `substeps=${trunc.analysis?.dialect?.substeps} observations=${trunc.analysis?.dialect?.observations} node_count 只有 1（inventory_artifact 一步）`)
    info('[LIVE] 截断 ELF 的 limitations', j(trunc.analysis?.evidence?.limitations ?? []))

    // 手工例外的真机用例：ASAR 是普通文件（过 runFetch 的 [ -f ] 预检），
    // 且 analyze-javascript-application 只收目录或 .asar —— 单个 .js 回 exit=1 unsupported_target。
    const pack = await engine.exec(ALIAS,
      `rm -rf /tmp/rea-analyze-jsapp ${ASAR_REMOTE}; mkdir -p /tmp/rea-analyze-jsapp && ` +
      `printf '%s' '{"name":"dsh-fixture","version":"0.0.0","main":"index.js"}' > /tmp/rea-analyze-jsapp/package.json && ` +
      `printf '%s' 'const fs = require("fs"); function readIt(p) { return fs.readFileSync(p, "utf8"); } module.exports = { readIt };' > /tmp/rea-analyze-jsapp/index.js && ` +
      `npx --yes @electron/asar pack /tmp/rea-analyze-jsapp ${ASAR_REMOTE} && file -b ${ASAR_REMOTE} && wc -c < ${ASAR_REMOTE}`,
      240000)
    if (pack.exitCode === 0 && /Electron ASAR archive/.test(String(pack.stdout))) {
      info('[LIVE] ASAR 固件', String(pack.stdout).trim().replace(/\n/g, ' | '))
      const a = (await analyzeWith(engine, ASAR_REMOTE)).r
      ok('[LIVE] ASAR 路由到手工例外并带回标记', a.ok === true && a.route?.marker === 'manual-exception:not-advertised' && a.route?.surface === 'manual-exception' && a.route?.advertised === false, `${a.route?.provider}/${a.route?.operation} ${String(a.route?.marker)}`)
      ok('[LIVE] 下发的子命令就是实跑核对过的那个', String(a.analysis?.command).includes('analyze-javascript-application /tmp/rea-analyze-app.asar --format json'), String(a.analysis?.command).slice(0, 80))
      ok('[LIVE] Evidence 的 provider 与路由同源（例外不是猜的）', a.analysis?.provider === 'rea-javascript-application' && a.analysis?.operation === 'analyze_javascript_application', `${a.analysis?.provider}/${a.analysis?.operation} format=${a.analysis?.subjectFormat}`)
      ok('[LIVE] 例外路径的 Evidence 当场落盘', typeof a.analysis?.evidenceId === 'string' && existsSync(a.analysis?.evidencePath ?? ''), `${String(a.analysis?.evidenceId).slice(0, 18)}… ${a.analysis?.evidencePath ? statSync(a.analysis.evidencePath).size : 0}B`)
      ok('[LIVE] 标记随报告落盘', JSON.parse(readFileSync(a.reportPath, 'utf8'))?.route?.marker === 'manual-exception:not-advertised')
      ok('[LIVE] 大目标下报告的固定开销仍不随 Evidence 长（analysis < 2KB 而 Evidence 7 万字节级）', (() => {
        const sizeOf = (v) => Buffer.byteLength(JSON.stringify(v))
        const rep = JSON.parse(readFileSync(a.reportPath, 'utf8'))
        return sizeOf(rep.analysis) < 2048 && statSync(a.analysis.evidencePath).size > 10 * sizeOf(rep.analysis)
      })(), `报告=${statSync(a.reportPath).size}B Evidence=${statSync(a.analysis.evidencePath).size}B analysis 段=${Buffer.byteLength(JSON.stringify(JSON.parse(readFileSync(a.reportPath, 'utf8')).analysis))}B`)
      info('[LIVE] 例外路径的方言与发现数', `${j(a.analysis?.dialect)} findings=${a.analysis?.findingCount} unknowns=${a.analysis?.unknownCount}`)
      ok('[LIVE] 例外路径没有失败信封', a.analysis?.failure === null, String(a.error).slice(0, 80))
    } else {
      skipped('[LIVE] ASAR 手工例外', `固件打包没成：exit=${pack.exitCode} ${String(pack.stdout ?? pack.error).slice(0, 100)}`)
    }

    const runs = []
    for (let i = 0; i < 2; i++) {
      const one = (await analyzeWith(engine, SMALL_ELF)).r
      if (one.ok) runs.push(one.timings)
    }
    info('[LIVE] 连跑两次的分段（probe 是最贵的一段）', runs.map((t) => `probe=${t.probeMs}ms analyze=${t.analyzeMs}ms`).join(' / '))
    ok('[LIVE] 两次都成功且 analyzeMs 在 180s 预算内', runs.length === 2 && runs.every((t) => t.analyzeMs < 180000), `${runs.length} 次`)
    // session 生命周期：规格点名要查的一条。inspect-artifact 是单发的，跑完不该留 open target。
    const post = await probeRemoteRea(engine, ALIAS, { npxTimeoutMs: 300000 })
    ok('[LIVE] 连跑多次之后 capabilities.open 仍是 false（artifact-graph 不留 session）', post.ok === true && post.capabilities?.open === false, `open=${String(post.capabilities?.open)}`)
    const sameId = (await analyzeWith(engine, SMALL_ELF)).r
    ok('[LIVE] 同一目标重复分析得到同一个 evidence_id（无状态漂移）', sameId.analysis?.evidenceId === r.analysis.evidenceId, `${String(sameId.analysis?.evidenceId).slice(0, 18)}… vs ${r.analysis.evidenceId.slice(0, 18)}…`)

    if (COLD) {
      section('B2/D 冷缓存：清 ~/.npm/_npx 后用 2000ms 预算断言超时路径')
      const wipe = await engine.exec(ALIAS, 'rm -rf ~/.npm/_npx && echo wiped', 60000)
      ok('[COLD] 缓存已清空', wipe.exitCode === 0 && /wiped/.test(String(wipe.stdout)))
      // 冷下载实测 50~83s（离群 >420s），2000ms 必定走不到 warmed。上一版把「冷跑整链成功」当判据，
      // 在 300000ms 预算下两次擦边失败（300104ms / 300107ms）—— 那是环境耗时不是代码回归，
      // 所以这里断言的是超时收口的口径；冷跑到底能不能成，由下面的默认预算恢复跑顺带证实。
      const cold = await analyzeWith(engine, SMALL_ELF, { npxTimeoutMs: 2000 })
      const wf = cold.frames.filter((f) => f.source === 'warmup')
      ok('[COLD] 收到 source=warmup 的帧', wf.length >= 2, j(wf))
      ok('[COLD] warming 帧在命令下发前就有，且带的就是本次预算 2000ms', wf[0]?.phase === 'warming' && wf[0]?.timeoutMs === 2000, j(wf[0]))
      ok('[COLD] 超时也回一条 warmed（cached=false、ok=false），不是静默消失', wf.some((f) => f.phase === 'warmed' && f.cached === false && f.ok === false), j(wf.find((f) => f.phase === 'warmed')))
      // 冷跑如果预热就没成，整条链路根本走不到 analyzing —— 这里不能拿 -1 下标比大小（会把
      // 「没走到分析」误判成「帧序错了」）。有 analyzing 帧时才比先后。
      const wi = cold.frames.findIndex((f) => f.source === 'warmup' && f.phase === 'warming')
      const ai = cold.frames.findIndex((f) => f.phase === 'analyzing')
      ok('[COLD] warming 帧在任何 analyzing 帧之前（超时路径没有 analyzing 帧，照样成立）', wi >= 0 && (ai < 0 || wi < ai), `warming@${wi} analyzing@${ai}`)
      ok('[COLD] 超时路径：ok=false', cold.r.ok === false, String(cold.r.error).slice(0, 90))
      ok('[COLD] 超时路径：error 是一句含「超时」的话', typeof cold.r.error === 'string' && cold.r.error.includes('超时'), String(cold.r.error))
      // analyze 的返回体里没有 deploy 这一层（① 整体复用 runFetch，deploy 只进 fetch 报告），
      // 止步时 analyze 直接把 fetch 的落盘报告路径引用过来 —— 所以判据从那份 JSON 取。
      const fetchReport = typeof cold.r.reportPath === 'string'
        ? JSON.parse(readFileSync(cold.r.reportPath, 'utf8')) : null
      ok('[COLD] 超时路径：deploy.strategy=unavailable（读 fetch 报告，analyze 返回体不带这层）',
        fetchReport?.deploy?.strategy === 'unavailable',
        `${String(fetchReport?.deploy?.strategy)}｜err=${String(fetchReport?.error).slice(0, 60)}`)
      ok('[COLD] 超时路径：没有预检、没有拉取、没有分析命令（止步在预热）', ai < 0 && cold.frames.every((f) => !['preflight', 'downloading', 'analyzing'].includes(f.phase)), cold.frames.map((f) => `${f.source}:${f.phase}`).join('>'))
      info('[COLD] 预热超时实测耗时', `${wf.find((f) => f.phase === 'warmed')?.durationMs}ms（预算 2000ms）`)
      const restore = await analyzeWith(engine, SMALL_ELF)
      ok('[COLD] 默认预算下冷跑恢复且整链成功（新默认 600000 够用）', restore.r.ok === true, String(restore.r.error).slice(0, 90))
      const rw = restore.frames.find((f) => f.phase === 'warming')
      // 上一次的 npx 进程被超时打断后仍在远端继续装，恢复跑可能直接命中缓存 —— 没有 warming 帧也对。
      ok('[COLD] 恢复跑若要预热，预算用的是新默认 600000', rw === undefined || rw.timeoutMs === 600000, j(rw ?? null))
    } else {
      skipped('B2 冷缓存预热回调', '破坏性且耗时，需 --cold 显式触发；A4/A7 已用假 engine 覆盖帧转发')
    }
  } catch (error) {
    ok('[LIVE] 端到端没有抛异常', false, String(error?.message ?? error))
  } finally {
    const clean = await engine.exec(ALIAS, `rm -f ${NOMAGIC} ${TRUNC} ${LEGACY_RAND}; rm -rf /tmp/rea-analyze-jsapp ${ASAR_REMOTE}; echo done`, 30000).catch(() => null)
    info('远端样本清理', clean === null ? '清理命令本身没跑成（SSH 已断？）' : String(clean.stdout).trim())
    engine.dispose()
  }
} else {
  skipped('B 端到端', '--offline：只跑 A 段')
}

rmSync(scratch, { recursive: true, force: true })
console.log('\n══════════════════════════════════════════════════════════════')
console.log(`结果：${pass} 通过 / ${fail} 失败 / ${skip} 跳过`)
if (failures.length > 0) console.log('失败项:\n  ' + failures.join('\n  '))
process.exit(fail > 0 ? 1 : 0)
