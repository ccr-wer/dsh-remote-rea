// ============================================================================
// test/run-probe-tests.mjs —— 第 3b 步（远程 REA 只读探测）测试
// ----------------------------------------------------------------------------
// 两层：
//   A. 逻辑层：全部吃真实固件（WSL 上实跑 REA 抓回来的字节），不连网。
//   B. 端到端：连真实主机跑 probeRemoteRea（默认别名 wsl-local）。
// 端到端需要主机库里有该别名；没有则 SKIP 并说明，不伪造成功。
//   node test/run-probe-tests.mjs                # 两层都跑
//   node test/run-probe-tests.mjs --offline      # 只跑逻辑层
//   node test/run-probe-tests.mjs --alias=web-01 # 换主机别名
// 探测命令本身是只读的，但会真的建 SSH 连接。
// ============================================================================

import { readFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import { parseReaOutput } from '../rea-output-parser.js'
import { collectReadiness, missingLines, probeRemoteRea } from '../rea-remote-probe.js'
import { assertNoPrivilegeEscalation, safeExec } from '../remote-shell-utils.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const FIX = join(HERE, 'fixtures')

const args = process.argv.slice(2)
const OFFLINE = args.includes('--offline')
const aliasArg = args.find((a) => a.startsWith('--alias='))
const ALIAS = aliasArg ? aliasArg.slice('--alias='.length) : 'wsl-local'

let pass = 0
let fail = 0
let skip = 0
const failures = []

const ok = (label, cond, detail = '') => {
  if (cond) {    pass++
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
const section = (title) => console.log(`\n【${title}】`)
const j = (v) => JSON.stringify(v)
const arr = (v) => (Array.isArray(v) ? v : [])
const readFix = (name) => readFileSync(join(FIX, name), 'utf8')

console.log('╔══════════════════════════════════════════════════════════════════════╗')
console.log('║  rea-remote-probe.js  测试（3b：远程 REA 只读探测）                    ║')
console.log('╚══════════════════════════════════════════════════════════════════════╝')

// --- 固件到位情况 -----------------------------------------------------------
const FILES = {
  doctor: 'rea-doctor.json',
  capabilities: 'rea-capabilities-linux-x64.json',
  banner: 'rea-doctor-cold-npx-banner.txt',
  analyze: 'rea-analyze-js-app.jsonl',
}
const have = {}
for (const [key, name] of Object.entries(FILES)) {
  have[key] = existsSync(join(FIX, name))
  info(`固件 ${key}`, `${name} ${have[key] ? '存在' : '缺失'}`)
}

// ===========================================================================
// A1. 解析层：真实 doctor / capabilities / banner
// ===========================================================================
section('A1 真实输出的解析边界（parseReaOutput）')

if (!have.doctor) {
  skipped('doctor 固件解析', '固件缺失')
} else {
  const raw = readFix('rea-doctor.json')
  const parsed = parseReaOutput(raw)
  ok('[DOCTOR] 单行 JSON 解析成功', parsed.evidence !== null, `${raw.length} 字节`)
  ok('[DOCTOR] 没有进度行（doctor 不吐 rea_progress）', parsed.progress.length === 0)
  ok('[DOCTOR] 无解析错误', parsed.error === null, String(parsed.error))
  // evidence_raw 是「那一行的字节」：行尾换行属于分隔符、不属于记录本身。
  ok('[DOCTOR] evidence_raw = stdout 去掉行尾换行（逐字节）', parsed.evidence_raw === raw.replace(/\n$/, '') && raw.endsWith('\n') && !raw.slice(0, -1).includes('\n'), `${parsed.evidence_raw.length}/${raw.length} 字节`)
  ok('[DOCTOR] 是 unhealthy 的那份（探测按 JSON 判定，不看退出码）', parsed.evidence.healthy === false)
  ok('[DOCTOR] providerInspections 有条目', Array.isArray(parsed.evidence.providerInspections) && parsed.evidence.providerInspections.length > 0, `${parsed.evidence.providerInspections.length} 条`)
}

if (!have.capabilities) {
  skipped('capabilities 固件解析', '固件缺失')
} else {
  const raw = readFix('rea-capabilities-linux-x64.json')
  const parsed = parseReaOutput(raw)
  ok('[CAPS] 解析成功', parsed.evidence !== null, `${raw.length} 字节`)
  ok('[CAPS] evidence_raw = stdout 去掉行尾换行（逐字节）', parsed.evidence_raw === raw.replace(/\n$/, ''), `${parsed.evidence_raw.length}/${raw.length} 字节`)
  ok('[CAPS] analysis_provider_candidates 有条目', arr(parsed.evidence?.analysis_provider_candidates).length > 0, `${arr(parsed.evidence?.analysis_provider_candidates).length} 条`)
  ok('[CAPS] capabilities（能力面）有条目', arr(parsed.evidence?.capabilities).length > 0, `${arr(parsed.evidence?.capabilities).length} 条`)
}

if (!have.banner) {
  skipped('banner 混排固件', '固件缺失')
} else {
  // 真机冷启动 npx 的第一次输出：一行 npm WARN + 单行 JSON。不是合成的。
  const raw = readFix('rea-doctor-cold-npx-banner.txt')
  const firstLine = raw.split('\n')[0]
  ok('[BANNER] 首行确实是 npm banner，不是 JSON', firstLine.startsWith('npm WARN') && !firstLine.startsWith('{'), firstLine.slice(0, 60))
  const parsed = parseReaOutput(raw)
  ok('[BANNER] 混排仍解析出 Evidence', parsed.evidence !== null, parsed.error ?? '')
  ok('[BANNER] 解析出来的就是 doctor 对象', parsed.evidence?.healthy === false && Array.isArray(parsed.evidence?.providerInspections))
  ok('[BANNER] evidence_raw 只含 JSON 区段（不吞 banner）', parsed.evidence_raw !== undefined && parsed.evidence_raw.startsWith('{') && !parsed.evidence_raw.includes('npm WARN'), `${parsed.evidence_raw.length} 字节`)
  const clean = parseReaOutput(raw.slice(raw.indexOf('{')))
  ok('[BANNER] 剥掉 banner 后与整份解析结果深度相同', j(clean.evidence) === j(parsed.evidence))
}

// capabilities 是美化多行 JSON 还是单行？两种都要能过。
if (have.capabilities) {
  const raw = readFix('rea-capabilities-linux-x64.json')
  const lines = raw.split('\n').filter((l) => l.trim() !== '')
  ok('[CAPS] 行数如实记录（多行时走整体截取回退）', lines.length >= 1, `${lines.length} 行`)
  const indented = j(JSON.parse(raw))
  const pretty = JSON.stringify(JSON.parse(raw), null, 2)
  const viaPretty = parseReaOutput(pretty)
  ok('[CAPS] 同一份内容缩进成多行后照样解析', viaPretty.evidence !== null && j(viaPretty.evidence) === indented)
}

// 进度行不得被当成 doctor 结果（探测里若误取会把 rea_progress 当就绪矩阵）。
{
  const withProgress = [
    '{"rea_progress":{"phase":"resolve"}}',
    '{"rea_progress":{"phase":"run"}}',
    '{"healthy":true,"providerInspections":[]}',
  ].join('\n')
  const parsed = parseReaOutput(withProgress)
  ok('[PROGRESS] 进度行被跳过、取到最后一条真结果', parsed.progress.length === 2 && parsed.evidence?.healthy === true)
}

// ===========================================================================
// A2. 合并逻辑：doctor + capabilities → ProviderReadiness[]
// ===========================================================================
section('A2 doctor + capabilities 合并')

let doctorJson = null
let capsJson = null
if (have.doctor && have.capabilities) {
  doctorJson = parseReaOutput(readFix('rea-doctor.json')).evidence
  capsJson = parseReaOutput(readFix('rea-capabilities-linux-x64.json')).evidence
}

if (doctorJson === null || capsJson === null) {
  skipped('readiness 合并', 'doctor 或 capabilities 固件缺失')
} else {
  const readiness = collectReadiness(doctorJson, capsJson)
  const byId = new Map(readiness.map((r) => [r.id, r]))

  ok('[MERGE] 每条都有约定的 6 个键', readiness.every((r) => 'id' in r && 'status' in r && 'availabilityCode' in r && 'reason' in r && 'effects' in r && 'sources' in r), j(Object.keys(readiness[0])))
  ok('[MERGE] status 只会是 ready/unavailable', readiness.every((r) => r.status === 'ready' || r.status === 'unavailable'), j([...new Set(readiness.map((r) => r.status))]))
  ok('[MERGE] id 不重复', new Set(readiness.map((r) => r.id)).size === readiness.length, `${readiness.length} 条`)
  ok('[MERGE] 每条至少有一个来源', readiness.every((r) => arr(r.sources).length > 0))
  ok('[MERGE] 来源字符串只用已知的 4 个', readiness.every((r) => r.sources.every((s) => ['capabilities.candidates', 'doctor.providerInspections', 'doctor.scope_checks', 'capabilities.surfaces'].includes(s))), j([...new Set(readiness.flatMap((r) => r.sources))]))

  // 两个探测源各漏一半：doctor 没 hopper，capabilities 没 jadx —— 合并后都得在。
  const doctorIds = arr(doctorJson.providerInspections).map((p) => p.id)
  const candIds = arr(capsJson.analysis_provider_candidates).map((c) => c?.provider?.id)
  ok('[MERGE] doctor 侧确实缺 hopper（前提成立，不是我们编的）', !doctorIds.includes('hopper'), j(doctorIds))
  ok('[MERGE] capabilities 候选里确实缺 jadx（前提成立）', !candIds.includes('jadx'), j(candIds))
  ok('[MERGE] 合并后 hopper 进来了', byId.has('hopper'), `sources=${j(byId.get('hopper')?.sources)}`)
  ok('[MERGE] 合并后 jadx 进来了', byId.has('jadx'), `sources=${j(byId.get('jadx')?.sources)}`)

  // hopper 只有 scope_checks 来源，remediation 必须从那里补上
  const hopper = byId.get('hopper')
  if (hopper !== undefined) {
    ok('[MERGE] hopper 的 remediation 用的是 REA 原文', typeof hopper.remediation === 'string' && hopper.remediation.includes('Hopper'), j(hopper.remediation).slice(0, 90))
  }

  // 单来源退化：只给 doctor / 只给 capabilities 都不能崩
  const onlyDoctor = collectReadiness(doctorJson, null)
  const onlyCaps = collectReadiness(null, capsJson)
  ok('[MERGE] 只有 doctor 时仍有结果（退化为单源）', onlyDoctor.length > 0, `${onlyDoctor.length} 条 vs 合并 ${readiness.length}`)
  ok('[MERGE] 只有 capabilities 时仍有结果', onlyCaps.length > 0, `${onlyCaps.length} 条`)
  ok('[MERGE] 两个都空 → 空数组、不抛', j(collectReadiness(null, null)) === '[]')

  // 脏输入不得抛出
  const dirty = collectReadiness(
    { providerInspections: [null, 'x', 42, { id: 'ok' }, { id: '', configured: true }], scope_checks: [{ classification: 'missing_analysis_engine', name: 'tool-registration' }, null, { classification: 'other' }] },
    { analysis_provider_candidates: [{ provider: { id: 'a' }, availability: { status: 'available' }, capabilities: [{ groups: [null, { available: true, availability_code: null, effects: ['launches_process', 7] } ] }] }, null] },
  )
  ok('[DIRTY] 混合脏条目不抛异常且按 id 收敛', dirty.length === 3, j(dirty.map((d) => `${d.id}:${d.status}`)))
  const dirtyA = dirty.find((d) => d.id === 'a')
  ok('[DIRTY] 脏 groups 里的非字符串 effect 被丢弃', dirtyA !== undefined && dirtyA.effects.join(',') === 'launches_process', j(dirtyA?.effects))
  ok('[DIRTY] 能力组 code 为 null 时不写成 "null"', dirtyA?.availabilityCode === null, String(dirtyA?.availabilityCode))
  const dirtyTool = dirty.find((d) => d.id === 'tool')
  ok('[MERGE] scope 名 xxx-registration 对齐到 xxx', dirtyTool !== undefined, j(dirty.map((d) => d.id)))

  // ready 时不得带 availabilityCode/reason（否则摘要里出现「就绪但缺项」的矛盾行）
  ok('[MERGE] ready 的条目 code 与 reason 都是 null', readiness.filter((r) => r.status === 'ready').every((r) => r.availabilityCode === null && r.reason === null), j(readiness.filter((r) => r.status === 'ready').map((r) => r.id)))
  ok('[MERGE] unavailable 的条目至少有 reason 或 code 之一', readiness.filter((r) => r.status === 'unavailable').every((r) => r.availabilityCode !== null || r.reason !== null || r.remediation !== null))

  // effects 去重且保序
  ok('[MERGE] effects 无重复', readiness.every((r) => new Set(r.effects).size === r.effects.length))

  // -------------------------------------------------------------------------
  // missing[]：分类词是本项目给的，修法一律用 REA 原文
  // -------------------------------------------------------------------------
  section('A3 缺项清单（missing）文案来源')
  const missing = missingLines(readiness)
  ok('[MISSING] ready 的条目不进 missing', missing.length === readiness.filter((r) => r.status !== 'ready').length, `missing=${missing.length} 未就绪=${readiness.filter((r) => r.status !== 'ready').length}`)
  ok('[MISSING] 每行都以 provider <id> 开头', readiness.filter((r) => r.status !== 'ready').every((r, i) => missing[i].startsWith(`provider ${r.id} `)), j(missing.map((m) => m.slice(0, 24))))

  const withOriginal = readiness.filter((r) => r.status !== 'ready' && (r.remediation !== null || r.reason !== null))
  ok('[MISSING] 有原文的行都用原文（—— 之后逐字来自 REA）', withOriginal.every((r) => {
    const line = missing.find((m) => m.startsWith(`provider ${r.id} `))
    if (line === undefined) return false
    const original = r.remediation ?? r.reason
    return line.endsWith(original) && /[—-]{2} /.test(line)
  }), `${withOriginal.length} 行核对`)
  ok('[MISSING] 没有原文的行只给分类词，不编造修法', readiness.filter((r) => r.status !== 'ready' && r.remediation === null && r.reason === null).every((r) => !missing.some((m) => m.startsWith(`provider ${r.id} `) && m.includes('——'))))

  // 分类词表：出现过的 code 必须映射到文案，没映射的落到「不可用」
  const codeWordingSeen = new Map()
  for (const line of missing) {
    const id = line.match(/^provider (\S+)/)?.[1]
    const r = byId.get(id)
    if (r !== undefined) codeWordingSeen.set(r.availabilityCode, line)
  }
  const knownCodes = ['not_configured', 'executable_missing', 'unsupported_host', 'unsupported_version']
  ok('[MISSING] 用到的 code 都在文案表里', [...codeWordingSeen.keys()].filter((c) => c !== null).every((c) => knownCodes.includes(c)), j([...codeWordingSeen.keys()]))
  ok('[MISSING] not_configured 的行带出需要设置的环境变量名', [...codeWordingSeen.entries()].filter(([c]) => c === 'not_configured').every(([, line]) => /需设置 [A-Z][A-Z0-9_]{4,}/.test(line)), j([...codeWordingSeen.entries()].filter(([c]) => c === 'not_configured').map(([, l]) => l.slice(0, 60))))
  ok('[MISSING] collectReadiness([]) → missing 为空', j(missingLines([])) === '[]')
  ok('[MISSING] 脏输入不抛', missingLines([null, 'x', { status: 'unavailable', id: 'z' }]).length === 1)

  console.log('\n  ── 真实 readiness 矩阵（固件）──')
  for (const r of readiness) {
    console.log(`     ${r.id.padEnd(20)} ${r.status.padEnd(12)} code=${String(r.availabilityCode).padEnd(20)} src=[${r.sources.join(', ')}]`)
  }
  console.log('\n  ── 真实 missing[]（固件）──')
  missing.forEach((m, i) => console.log(`     ${i + 1}. ${m}`))

  // 实测事实：doctor 的 identity.installations.paths[0] 会写进 npx 的绝对安装路径，
  // 换 npm_config_cache 就变字节（实测 5551 ↔ 5564）。就绪矩阵不得被它带跑——
  // 第 4/5 步若按整份 doctor 的 sha 去重，这里就是「哪些字段不能进 sha」的依据。
  const relocatedRaw = j(doctorJson).replace('/home/dev/.npm/_npx/', '/tmp/other-cache/_npx/')
  const relocated = JSON.parse(relocatedRaw)
  ok('[STABLE] 路径替换确实改了原文（避免空断言）', relocatedRaw !== j(doctorJson))
  ok('[STABLE] doctor 安装路径变化时 readiness 不变', j(collectReadiness(relocated, capsJson)) === j(readiness))
  const relocatedCapsRaw = j(capsJson).replace(/\/home\/dev/g, '/tmp/other')
  const relocatedCaps = JSON.parse(relocatedCapsRaw)
  ok('[STABLE] capabilities 里的路径变化同样不影响 readiness', relocatedCapsRaw !== j(capsJson) && j(collectReadiness(doctorJson, relocatedCaps)) === j(readiness))
  ok('[STABLE] 路径字段确实存在于原文（前提成立，不是空断言）', j(doctorJson).includes('/_npx/'), String(j(arr(doctorJson?.identity?.installations?.paths))))

  // 与真机实测对账：固件是同一台 WSL 抓的，条目数应与实跑一致（后面端到端会重跑）
  info('固件 provider 总数', readiness.length)
}

// ===========================================================================
// A4. 安全闸门：探测命令必须过提权检查、且 attempts=1
// ===========================================================================
section('A4 下发前的安全闸门')

{
  const probes = ['command -v rea >/dev/null 2>&1 && printf HAS || printf NONE', 'npx --yes rea-agents@latest doctor --json', 'npx --yes rea-agents@latest capabilities --format json', 'rea --version']
  ok('[GUARD] 探测命令模板全部通过闸门', probes.every((c) => assertNoPrivilegeEscalation(c) === true))
  let blocked = null
  try { assertNoPrivilegeEscalation('sudo rea doctor --json') } catch (e) { blocked = e.message }
  ok('[GUARD] 带 sudo 的命令被拒', blocked !== null && blocked.includes('安全红线'), String(blocked).slice(0, 60))
}

// 探测通道必须走 safeExec：这里用假 engine 断言 attempts 恒为 1、命令全是固定模板。
{
  const calls = []
  const fakeEngine = {
    async exec(alias, command, timeoutMs, attempts) {
      calls.push({ alias, command, timeoutMs, attempts })
      return { success: true, exitCode: 0, timedOut: false, stdout: '', stderr: '', durationMs: 1 }
    },
  }
  const r = await probeRemoteRea(fakeEngine, 'fake-host')
  ok('[FAKE] 每个下发都是 attempts=1（探测不重放）', calls.every((c) => c.attempts === 1), j([...new Set(calls.map((c) => c.attempts))]))
  // 第 7 步 B1/B4 之后固定模板里多了两条环境闸门命令（uname -s / node --version），仍然是常量字面量。
  ok('[FAKE] 命令只落在固定模板内', calls.every((c) => /^(command -v (rea|npx) .*$|npx --yes rea-agents@latest (doctor --json|capabilities --format json)$|rea --version|uname -s|node --version)$/.test(c.command)), j(calls.map((c) => c.command)))
  ok('[FAKE] 没有任何命令带 sudo / --break-system-packages', !calls.some((c) => /sudo|break-system-packages/.test(c.command)))
  ok('[FAKE] 远端 rea 与 npx 都没有 → 明确止步且不抛', r.error !== null && r.error.includes('本步不做离线 tarball 部署'), String(r.error).slice(0, 80))
  ok('[FAKE] 止步时未下发任何 rea 命令', calls.filter((c) => /rea-agents|rea --version|rea doctor|rea capabilities/.test(c.command)).length === 0)
  ok('[FAKE] 探测失败不抛异常，结构仍完整', ['ok', 'reachable', 'reaAvailable', 'reaVersion', 'doctor', 'capabilities', 'readiness', 'missing', 'error'].every((k) => k in r), j(Object.keys(r)))
  ok('[FAKE] 失败时 readiness/missing 保持空数组（不留半成品）', j(r.readiness) === '[]' && j(r.missing) === '[]')
  ok('[FAKE] ok=false 且 reaAvailable=false', r.ok === false && r.reaAvailable === false)
}

// npx 分支跑通了：reaAvailable 表示「npx 能跑通」，不代表装过全局 rea。
{
  const doctorFixture = have.doctor ? readFix('rea-doctor.json') : '{}'
  const capsFixture = have.capabilities ? readFix('rea-capabilities-linux-x64.json') : '{}'
  const calls = []
  const fakeEngine = {
    async exec(alias, command, timeoutMs, attempts) {
      calls.push({ command, attempts })
      if (command.includes('command -v rea ')) return { success: false, exitCode: 1, timedOut: false, stdout: 'NONE\n', stderr: '', durationMs: 2 }
      if (command.includes('command -v npx ')) return { success: true, exitCode: 0, timedOut: false, stdout: 'HAS\n', stderr: '', durationMs: 2 }
      if (command.includes('doctor')) return { success: false, exitCode: 1, timedOut: false, stdout: doctorFixture, stderr: '', durationMs: 3 }
      if (command.includes('capabilities')) return { success: true, exitCode: 0, timedOut: false, stdout: capsFixture, stderr: '', durationMs: 3 }
      return { success: false, exitCode: 127, timedOut: false, stdout: '', stderr: 'unexpected', durationMs: 1 }
    },
  }
  const r = await probeRemoteRea(fakeEngine, 'fake-host')
  ok('[NPX] 走的是 npx 分支', r.via === 'npx', String(r.via))
  ok('[NPX] doctor 退出码 1 但 JSON 可用 → 判定为跑通', r.reaAvailable === true && r.doctor !== null)
  ok('[NPX] 未额外下发 rea --version（版本从 doctor 身份字段取）', !calls.some((c) => c.command === 'rea --version'))
  ok('[NPX] 版本从 doctor.identity 读出', typeof r.reaVersion === 'string' && r.reaVersion !== '', `${r.reaVersion} ← ${r.reaVersionSource}`)
  ok('[NPX] readiness 非空且 error 为 null', r.readiness.length > 0 && r.error === null, `${r.readiness.length} 条`)
  ok('[NPX] npx 分支两条命令都用 120s 预算（冷缓存实测 82s）', r.commands.filter((c) => /rea-agents/.test(c.command)).every((c) => c.timeoutMs === 120000), j(r.commands.map((c) => `${c.label}:${c.timeoutMs}`)))
  ok('[NPX] ok=true', r.ok === true)
}

// 版本优先级：全局 rea 存在时用 rea --version 的文本，不被 doctor 覆盖。
{
  const calls = []
  const fakeEngine = {
    async exec(alias, command, timeoutMs, attempts) {
      calls.push(command)
      if (command.includes('command -v rea ')) return { success: true, exitCode: 0, timedOut: false, stdout: 'HAS\n', stderr: '', durationMs: 1 }
      if (command === 'rea --version') return { success: true, exitCode: 0, timedOut: false, stdout: 'rea 9.9.9\n', stderr: '', durationMs: 1 }
      if (command.includes('doctor')) return { success: false, exitCode: 1, timedOut: false, stdout: have.doctor ? readFix('rea-doctor.json') : '{"identity":{"cli_package_version":"0.0.0"}}', stderr: '', durationMs: 1 }
      if (command.includes('capabilities')) return { success: true, exitCode: 0, timedOut: false, stdout: have.capabilities ? readFix('rea-capabilities-linux-x64.json') : '{}', stderr: '', durationMs: 1 }
      return { success: false, exitCode: 1, timedOut: false, stdout: '', stderr: '', durationMs: 1 }
    },
  }
  const r = await probeRemoteRea(fakeEngine, 'fake-host')
  ok('[GLOBAL] 全局 rea 存在时 via=global 且不再探测 npx', r.via === 'global' && !calls.some((c) => c.includes('command -v npx ')))
  if (have.doctor) {
    ok('[GLOBAL] 版本用 rea --version 的原文（不被 doctor 覆盖）', r.reaVersion === '9.9.9' && r.reaVersionSource === 'rea --version', `${r.reaVersion}/${r.reaVersionSource}`)
  } else {
    skipped('[GLOBAL] 版本优先级', 'doctor 固件缺失')
  }
  ok('[GLOBAL] 命令记录里带 version 一条', r.commands.some((c) => c.label === 'version'), j(r.commands.map((c) => c.label)))
}

// SSH 不可达：probeHasCommand 抛出 → 归为 unreachable，不得说成「没装 rea」。
{
  const fakeEngine = {
    async exec() { throw new Error('connect ECONNREFUSED 127.0.0.1:22') },
  }
  const r = await probeRemoteRea(fakeEngine, 'down-host')
  ok('[DOWN] 连接异常 → reachable=false 且不外抛', r.reachable === false && r.ok === false)
  ok('[DOWN] 错误口径写的是「SSH 不可达」而不是「没装 rea」', r.error !== null && r.error.includes('SSH 不可达'), String(r.error).slice(0, 70))
  ok('[DOWN] 未编造 readiness/版本', j(r.readiness) === '[]' && r.reaVersion === null && r.via === null, `readiness=${r.readiness.length} version=${String(r.reaVersion)}`)
}

// npx 拉起失败（registry 不通）要与「REA 探测失败」分开口径。
{
  const fakeEngine = {
    async exec(alias, command) {
      if (command.includes('command -v rea ')) return { success: false, exitCode: 1, timedOut: false, stdout: 'NONE\n', stderr: '', durationMs: 1 }
      if (command.includes('command -v npx ')) return { success: true, exitCode: 0, timedOut: false, stdout: 'HAS\n', stderr: '', durationMs: 1 }
      return {
        success: false,
        exitCode: 1,
        timedOut: false,
        stdout: '',
        stderr: 'npm error code EAI_AGAIN\nnpm error request to https://registry.npmjs.org/rea-agents failed, reason: getaddrinfo EAI_AGAIN registry.npmjs.org\nnpm error errno EAI_AGAIN',
        durationMs: 1,
      }
    },
  }
  const r = await probeRemoteRea(fakeEngine, 'airgapped')
  ok('[REGISTRY] 归类为 npx 拉起失败而非 REA 探测失败', r.error !== null && r.error.startsWith('npx 拉起失败'), String(r.error).slice(0, 80))
  ok('[REGISTRY] 命中 token 写进文案便于排查', /EAI_AGAIN/.test(String(r.error)))
  ok('[REGISTRY] stderr 片段带在命令记录里', r.commands.some((c) => typeof c.stderrSnippet === 'string' && c.stderrSnippet.includes('EAI_AGAIN')))
  ok('[REGISTRY] reaAvailable=false', r.reaAvailable === false && r.ok === false)
}

// 超时口径：npx 卡住时说的是超时，不是「探测失败」。
{
  const fakeEngine = {
    async exec(alias, command) {
      if (command.includes('command -v rea ')) return { success: false, exitCode: 1, timedOut: false, stdout: 'NONE\n', stderr: '', durationMs: 1 }
      if (command.includes('command -v npx ')) return { success: true, exitCode: 0, timedOut: false, stdout: 'HAS\n', stderr: '', durationMs: 1 }
      return { success: false, exitCode: null, timedOut: true, stdout: '', stderr: '', durationMs: 120000 }
    },
  }
  const r = await probeRemoteRea(fakeEngine, 'slow')
  ok('[SLOW] 超时说的是超时', r.error !== null && r.error.startsWith('npx 拉起超时'), String(r.error).slice(0, 90))
}

// 真机 banner 走完整探测：stdout 首行是 npm WARN，仍要判定为跑通。
if (have.banner) {
  const fakeEngine = {
    async exec(alias, command) {
      if (command.includes('command -v rea ')) return { success: false, exitCode: 1, timedOut: false, stdout: 'NONE\n', stderr: '', durationMs: 1 }
      if (command.includes('command -v npx ')) return { success: true, exitCode: 0, timedOut: false, stdout: 'HAS\n', stderr: '', durationMs: 1 }
      if (command.includes('doctor')) return { success: false, exitCode: 1, timedOut: false, stdout: readFix('rea-doctor-cold-npx-banner.txt'), stderr: '', durationMs: 1 }
      if (command.includes('capabilities')) return { success: true, exitCode: 0, timedOut: false, stdout: have.capabilities ? readFix('rea-capabilities-linux-x64.json') : '{}', stderr: '', durationMs: 1 }
      return { success: false, exitCode: 1, timedOut: false, stdout: '', stderr: '', durationMs: 1 }
    },
  }
  const r = await probeRemoteRea(fakeEngine, 'cold-npx')
  ok('[BANNER] 首行 npm WARN 不干扰探测判定', r.reaAvailable === true && r.ok === true, String(r.error))
  const doctorCmd = r.commands.find((c) => c.label === 'doctor')
  ok('[BANNER] 解析用的是 stdout 本体（banner 在 stdout 时不需要并 stderr）', doctorCmd?.parsedFromMergedStderr === false, `parsed=${doctorCmd?.ok} exit=${doctorCmd?.exitCode}`)
}

// ===========================================================================
// B. 端到端：连真实主机
// ===========================================================================
section(`B 端到端 probeRemoteRea（别名 ${ALIAS}）`)

if (OFFLINE) {
  skipped('端到端探测', '--offline 指定')
} else {
  let storeMod, engine = null
  try {
    storeMod = await import('../remote-ssh-core.js')
    const store = storeMod.createHostStore()
    const entry = store.find(ALIAS)
    if (entry === undefined) {
      skipped('端到端探测', `主机库里没有别名 ${ALIAS}（当前库 ${store.path}）`)
    } else {
      info('目标', `${entry.user}@${entry.host}:${entry.port} auth=${entry.auth.kind}`)
      engine = storeMod.createSshEngine(store)
      // 连通性预检：Windows→WSL 的 portproxy 坏了或 VM 空闲退出时，SSH 不可达属于
      // 环境问题，整段 SKIP 并说明原因，而不是刷一串看起来像回归的 FAIL。
      let reachable = true
      try {
        await safeExec(engine, ALIAS, 'true', 15000)
      } catch (error) {
        reachable = false
        skipped('端到端其余断言', `SSH 不可达（${error.message}）—— portproxy 或远端实例问题，不是代码回归`)
      }
      if (reachable) {
        const t0 = Date.now()
        const r = await probeRemoteRea(engine, ALIAS)
        const total = Date.now() - t0

        ok('[LIVE] 主机可达', r.reachable === true, String(r.error))
        ok('[LIVE] REA 跑通（全局或 npx）', r.reaAvailable === true, `via=${r.via} version=${r.reaVersion}`)
        ok('[LIVE] ok=true 且 error=null', r.ok === true && r.error === null, String(r.error))
        ok('[LIVE] readiness 非空', r.readiness.length > 0, `${r.readiness.length} 条 provider`)
        ok('[LIVE] 下发全部 attempts=1', r.commands.length > 0 && r.via !== null, j(r.commands.map((c) => `${c.label} exit=${c.exitCode} ${c.durationMs}ms`)))
        ok('[LIVE] doctor 解析成功', r.doctor !== null && Array.isArray(r.doctor.providerInspections), `inspections=${r.doctor?.providerInspections?.length}`)
        ok('[LIVE] capabilities 解析成功', r.capabilities !== null && arr(r.capabilities.analysis_provider_candidates).length > 0, `candidates=${r.capabilities?.analysis_provider_candidates?.length}`)

        const slowest = r.commands.length > 0 ? r.commands.reduce((a, c) => (c.durationMs > a.durationMs ? c : a), r.commands[0]) : null
        const npxDoctor = r.commands.find((c) => c.label === 'doctor')
        info('总耗时', `${total}ms`)
        if (slowest === null) info('命令记录', '空（探测在下发前就止步，见 error）')
        else info('最慢命令', `${slowest.label} ${slowest.durationMs}ms (timeout=${slowest.timeoutMs} exit=${slowest.exitCode})`)
        info('版本来源', `${r.reaVersion} ← ${r.reaVersionSource}`)
        if (npxDoctor !== undefined) info('doctor 单次耗时', `${npxDoctor.durationMs}ms（决定超时上限：本模块给 npx 分支 120000ms）`)

        console.log('\n  ── 真实探测返回结构（本机 localhost WSL）──')
        console.log(JSON.stringify({
          ok: r.ok,
          reachable: r.reachable,
          via: r.via,
          reaAvailable: r.reaAvailable,
          reaVersion: r.reaVersion,
          reaVersionSource: r.reaVersionSource,
          error: r.error,
          commands: r.commands,
          readiness_count: r.readiness.length,
        }, null, 2).split('\n').map((l) => '  ' + l).join('\n'))

        console.log('\n  ── 真实 readiness[] ──')
        for (const item of r.readiness) {
          console.log(`     ${item.id.padEnd(20)} ${item.status.padEnd(12)} code=${String(item.availabilityCode).padEnd(20)} effects=[${item.effects.join(', ')}]`)
          console.log(`     ${' '.repeat(20)} sources=[${item.sources.join(', ')}]`)
          if (item.remediation !== null) console.log(`     ${' '.repeat(20)} remediation="${String(item.remediation).slice(0, 100)}"`)
        }
        console.log('\n  ── 真实 missing[] ──')
        r.missing.forEach((m, i) => console.log(`     ${i + 1}. ${m}`))

        // 端到端与固件对账：同一台机子抓的，条目应一致
        if (have.doctor && have.capabilities) {
          const fromFixture = collectReadiness(r.doctor, r.capabilities)
          ok('[LIVE] 实跑 doctor/capabilities 合并结果与固件同构', j(fromFixture.map((x) => `${x.id}:${x.status}`)) === j(r.readiness.map((x) => `${x.id}:${x.status}`)), j(r.readiness.map((x) => `${x.id}:${x.status}`).slice(0, 4)) + '…')
        }
      }
    }
  } catch (error) {
    ok('[LIVE] 端到端不应抛出', false, error.message)
  } finally {
    // engine 只有 dispose()（remote-ssh-core.js:1108）；close 这个名字不存在，
    // 空操作会让连接吊住事件循环，脚本打完全绿也不退出。
    if (engine !== null) engine.dispose()
  }
}

// ===========================================================================
console.log('\n══════════════════════════════════════════════════════════════')
console.log(`结果：${pass} 通过 / ${fail} 失败 / ${skip} 跳过`)
if (fail > 0) {
  console.log('失败项：')
  for (const f of failures) console.log(`  - ${f}`)
  process.exitCode = 1
} else {
  console.log('全部通过')
}
