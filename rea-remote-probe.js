// ============================================================================
// rea-remote-probe.js —— 远程 REA 环境的只读探测（第 3b 步）
// ----------------------------------------------------------------------------
// 只做「连上去 → 下发探测命令 → 解析 → 出就绪矩阵」：不装引擎、不做分析、不写控制器。
// 三条实测出来的铁律：
//   1. 所有命令走 safeExec（内含提权闸门 + attempts=1，探测绝不重放）。
//   2. 成败看「能不能解析出 JSON」，不看退出码：rea doctor --json 在 healthy:false 时
//      exit code 是 1，而 stdout 是完整可用的 JSON。按退出码判会把它当失败。
//   3. 缺什么就报什么，remediation 用 doctor/capabilities 的原文，不自己编「该怎么修」。
// 两个环境闸门先于 rea 探测（第 7 步 B1 / B4）：uname 明确回 Windows 系内核就判「不支持的目标平台」；
// 走 npx 这条路时先核 node --version 是否满足 REA 的要求（22.19+ / 24.11+ / 26+，排除 23 与 25）。
// 探测源有两个，各自覆盖面对不上，必须合并：
//   doctor --json        → providerInspections[]（带 remediation 原文）+ scope_checks[]
//   capabilities --json  → analysis_provider_candidates[]（provider 级 availability + 各组 effects）
//                          + capabilities[]（能力面，如 rea-dotnet-static / sqlite / native-macos）
// 单用 doctor 会漏 hopper（它不在 providerInspections 里），单用 capabilities 会漏 jadx。
// ============================================================================

import { probeHasCommand, safeExec } from './remote-shell-utils.js'
import { parseReaOutput } from './rea-output-parser.js'

const REA_PACKAGE = 'rea-agents@latest'
const GLOBAL_TIMEOUT_MS = 30000
// npx 首跑要从 registry 拉包；实测热缓存 5s，冷缓存远超 30s，这里放宽。
const NPX_TIMEOUT_MS = 120000
const COMMAND_PROBE_TIMEOUT_MS = 15000
const STDERR_SNIPPET_CHARS = 2000

// B1 平台闸门：本插件的探测与预检全靠 POSIX 工具（uname/file/stat/sha256sum、command -v），
// Windows 远端（Git Bash/MSYS/Cygwin 的 uname 会带这些前缀）不在这个支持面里。
// 判据只认「uname 明确回了一个 Windows 系内核」，命令不存在或没输出都不当作 Windows ——
// 从「读不到」推「是 Windows」会把 Linux 上的偶发失败误判成平台不支持。
const WINDOWS_UNAME = /^(MINGW|MSYS|CYGWIN|Windows)/i
const UNSUPPORTED_TARGET_PLATFORM = '不支持的目标平台：Windows 远端，请使用 POSIX shell 目标'

// B4 版本闸门：npx 这条路用的是远端的 node，rea 对它有硬性要求。
const NODE_REQUIREMENT_TEXT = 'REA 要求 Node 22.19+ / 24.11+ / 26+（不支持 23 和 25）'

const obj = (v) => (v !== null && typeof v === 'object' && !Array.isArray(v) ? v : null)
const arr = (v) => (Array.isArray(v) ? v : [])
const str = (v) => (typeof v === 'string' && v.trim() !== '' ? v.trim() : null)

/** availabilityCode → 分类文案（只描述「缺的是哪一类」，不含修法）。 */
const CODE_WORDING = {
  not_configured: '未配置',
  executable_missing: '已配置但可执行文件不在',
  unsupported_host: '不支持当前平台',
  unsupported_version: '需要更高版本运行时',
}

const ENGINE_CLASSIFICATION = 'missing_analysis_engine'

/** 全局装过就直接调 rea，否则走 npx（--yes 免交互确认）。args 是本模块内的固定字面量。 */
function reaCommand(via, args) {
  return via === 'global' ? `rea ${args}` : `npx --yes ${REA_PACKAGE} ${args}`
}

/** doctor 把 ida 的检查命名为 ida-registration；对齐到 provider id，其余原样。 */
const scopeIdOf = (name) => String(name).replace(/-registration$/, '')

/** 从原文里取环境变量名（大写常量），只用于「需设置 X」这半句，后半句仍是 REA 原文。 */
const envTokenOf = (text) => {
  const m = String(text ?? '').match(/[A-Z][A-Z0-9_]{4,}/)
  return m ? m[0] : null
}

const messageOf = (error) => (error instanceof Error ? error.message : String(error))

/**
 * 下发一条探测命令并解析。
 * 先按 stdout 解析；解析不出来才试 stderr+stdout（banner 混排形态）。
 */
async function runProbeCommand(engine, alias, label, command, timeoutMs) {
  const fallbackStart = Date.now()
  const r = await safeExec(engine, alias, command, timeoutMs)
  const stdout = String(r.stdout ?? '')
  const stderr = String(r.stderr ?? '')
  let parsed = parseReaOutput(stdout)
  let merged = false
  if (parsed.evidence === null && stderr.trim() !== '') {
    const attempt = parseReaOutput(`${stderr}\n${stdout}`)
    if (attempt.evidence !== null) {
      parsed = attempt
      merged = true
    }
  }
  return {
    label,
    command,
    timeoutMs,
    ok: parsed.evidence !== null,
    exitCode: r.exitCode ?? null,
    timedOut: r.timedOut === true,
    durationMs: r.durationMs ?? Date.now() - fallbackStart,
    stdoutBytes: Buffer.byteLength(stdout),
    stderrBytes: Buffer.byteLength(stderr),
    // 留给 npx 失败分类用：npm 的报错只在 stderr 里，长度截断以免撑爆返回结构。
    stderrSnippet: stderr.slice(0, STDERR_SNIPPET_CHARS),
    parsedFromMergedStderr: merged,
    json: parsed.evidence,
    error: parsed.error,
  }
}

/** 探测条目的中间累加结构：两个来源的信号在这里对撞，最后才定 status/code。 */
function newEntry(id) {
  return {
    id,
    sources: new Set(),
    providerVersion: null,
    providerStatus: null,
    providerCode: null,
    providerReason: null,
    configured: null,
    available: null,
    remediation: null,
    effects: new Set(),
    groupCodes: new Set(),
    groupAvailable: [],
  }
}

function absorbGroups(entry, capabilityList) {
  for (const raw of arr(capabilityList)) {
    const cap = obj(raw)
    if (cap === null) continue
    for (const rawGroup of arr(cap.groups)) {
      const group = obj(rawGroup)
      if (group === null) continue
      if (typeof group.available === 'boolean') entry.groupAvailable.push(group.available)
      const code = str(group.availability_code)
      if (code !== null) entry.groupCodes.add(code)
      for (const effect of arr(group.effects)) if (typeof effect === 'string') entry.effects.add(effect)
    }
  }
}

/** doctor 与 capabilities 合并成 ProviderReadiness[]。 */
export function collectReadiness(doctor, capabilities) {
  const byId = new Map()
  const touch = (id) => {
    let entry = byId.get(id)
    if (entry === undefined) {
      entry = newEntry(id)
      byId.set(id, entry)
    }
    return entry
  }

  for (const raw of arr(capabilities?.analysis_provider_candidates)) {
    const cand = obj(raw)
    const id = str(obj(cand)?.provider?.id)
    if (id === null) continue
    const entry = touch(id)
    entry.sources.add('capabilities.candidates')
    const availability = obj(cand.availability)
    const status = str(availability?.status)
    if (status !== null) entry.providerStatus = status
    entry.providerCode ??= str(availability?.code)
    entry.providerReason ??= str(availability?.reason)
    entry.providerVersion ??= str(cand.provider?.version)
    absorbGroups(entry, cand.capabilities)
  }

  for (const raw of arr(doctor?.providerInspections)) {
    const inspection = obj(raw)
    const id = str(inspection?.id)
    if (id === null) continue
    const entry = touch(id)
    entry.sources.add('doctor.providerInspections')
    if (typeof inspection.configured === 'boolean') entry.configured = inspection.configured
    if (typeof inspection.available === 'boolean') entry.available = inspection.available
    entry.providerVersion ??= str(inspection.providerVersion)
    if (entry.providerStatus === null) entry.providerStatus = inspection.available === true ? 'available' : 'unavailable'
    for (const rawCheck of arr(inspection.checks)) {
      const check = obj(rawCheck)
      if (check === null || check.ok === true) continue
      entry.providerCode ??= str(check.code)
      entry.providerReason ??= str(check.detail)
      entry.remediation ??= str(check.remediation)
    }
  }

  for (const raw of arr(doctor?.scope_checks)) {
    const check = obj(raw)
    if (check === null || check.classification !== ENGINE_CLASSIFICATION) continue
    const id = scopeIdOf(check.name)
    const entry = touch(id)
    entry.sources.add('doctor.scope_checks')
    entry.remediation ??= str(check.remediation)
    entry.providerReason ??= str(check.detail)
  }

  for (const raw of arr(capabilities?.capabilities)) {
    const cap = obj(raw)
    const id = str(cap?.provider?.id)
    if (id === null) continue
    const entry = touch(id)
    entry.sources.add('capabilities.surfaces')
    entry.providerVersion ??= str(cap.provider?.version)
    absorbGroups(entry, [cap])
  }

  return [...byId.values()].map((entry) => buildReadiness(entry))
}

/**
 * 定 status 与 availabilityCode：
 *   status：有 provider 级状态就用它；只有能力面（按组给可用性）时，任一组可用即 ready。
 *   availabilityCode：回答的是「为什么用不了」——ready 的一律给 null，不要把某个子组的
 *   局部限制（如 rea-artifact-graph 里 macOS 专属那组）当成本 provider 的缺项；
 *   不可用时 provider 级 code 优先，没有再看各组 code 是否同一个（多个则不猜）。
 */
function buildReadiness(entry) {
  let ready
  if (entry.providerStatus !== null) ready = entry.providerStatus === 'available'
  else if (typeof entry.available === 'boolean') ready = entry.available === true
  else ready = entry.groupAvailable.some((available) => available === true)

  const codes = [...entry.groupCodes]
  const uniformCode = codes.length === 1 ? codes[0] : null
  const availabilityCode = ready ? null : entry.providerCode ?? uniformCode
  const reason = ready ? null : entry.providerReason ?? null

  return {
    id: entry.id,
    status: ready ? 'ready' : 'unavailable',
    availabilityCode,
    reason,
    effects: [...entry.effects],
    // 原文照抄，缺则 null；remediation 比 reason 更「怎么办」，优先它进 missing[]
    remediation: entry.remediation,
    providerVersion: entry.providerVersion,
    configured: entry.configured,
    sources: [...entry.sources],
  }
}

/** 就绪矩阵 → 人类可读的缺项清单；分类词是本项目定的，修法一律用 REA 原文。 */
export function missingLines(readiness) {
  const lines = []
  for (const item of arr(readiness)) {
    const entry = obj(item)
    if (entry === null || entry.status === 'ready') continue
    const wording = CODE_WORDING[entry.availabilityCode] ?? '不可用'
    const env = entry.availabilityCode === 'not_configured' ? envTokenOf(entry.remediation ?? entry.reason) : null
    const head = `provider ${entry.id} ${wording}${env !== null ? `，需设置 ${env}` : ''}`
    const original = entry.remediation ?? entry.reason
    lines.push(original ? `${head} —— ${original}` : head)
  }
  return lines
}

/** CLI 版本：全局走 rea --version；npx 路径不额外发命令，直接读 doctor 里的身份字段。 */
const versionFromDoctor = (doctor) =>
  str(obj(doctor)?.identity?.cli_package_version) ?? str(obj(obj(doctor)?.server_identity)?.package?.version) ?? null

const versionFromText = (text) => {
  const line = String(text ?? '').split('\n').map((l) => l.trim()).find((l) => l !== '')
  if (line === undefined) return null
  const m = line.match(/\d+(?:\.\d+){1,3}/)
  return m ? m[0] : line.slice(0, 40)
}

/**
 * 远端 node 版本是否满足 REA 的要求。
 * 读不到版本（没装 node、或 --version 输出不是版本号）时返回 ok=true：
 * 「读不到」不是「不满足」，硬拦会把能跑的远端判死；真正的失败留给后面的 rea 探测暴露。
 */
export function nodeVersionVerdict(text) {
  const m = String(text ?? '').match(/(\d+)\.(\d+)/)
  if (m === null) return { known: false, version: null, ok: true, why: null }
  const major = Number(m[1])
  const minor = Number(m[2])
  const version = `${m[1]}.${m[2]}`
  if (major === 23 || major === 25) return { known: true, version, ok: false, why: `Node ${version} 是奇数线，REA 不支持` }
  if (major < 22) return { known: true, version, ok: false, why: `Node ${version} 低于 REA 支持的最低线` }
  if (major === 22 && minor < 19) return { known: true, version, ok: false, why: `Node ${version} 低于 REA 要求的 22.19` }
  if (major === 24 && minor < 11) return { known: true, version, ok: false, why: `Node ${version} 低于 REA 要求的 24.11` }
  return { known: true, version, ok: true, why: null }
}

/** npx 自身失败（拉包/registry）与 REA 探测失败要分开口径，否则排查方向完全错。 */
function npxFailureReason(command) {
  // npm 大版本改过报错前缀（npm ERR! → npm error），比对统一用小写；
  // 但文案里回显的 token 保持 npm 自己的大写写法，便于直接拿去搜。
  const haystack = `${String(command.stderrSnippet ?? '')}\n${String(command.error ?? '')}`.toLowerCase()
  const markers = [
    ['ENOTFOUND', 'registry 域名解析不通'],
    ['EAI_AGAIN', 'registry 域名解析临时失败'],
    ['ETIMEDOUT', 'registry 连接超时'],
    ['E404', '包在 registry 上找不到'],
    ['ERR_MODULE', 'rea-agents 拉起后模块加载失败'],
    ['npm error', 'npm 报错'],
    ['npm ERR!', 'npm 报错'],
  ]
  for (const [token, why] of markers) {
    if (haystack.includes(token.toLowerCase())) return `npx 拉起失败（${why}，命中 ${token}）`
  }
  if (command.timedOut) return `npx 拉起超时（${command.timeoutMs}ms 内没跑完，多半是下载太慢）`
  return null
}

/**
 * 探测远程 REA 环境，返回就绪矩阵；不抛异常，异常一律进 error 字段。
 * @param {object} engine  remote-ssh-core.js 的 SshEngine
 * @param {string} alias   主机库别名
 */
export async function probeRemoteRea(engine, alias, { timeoutMs = GLOBAL_TIMEOUT_MS, npxTimeoutMs = NPX_TIMEOUT_MS } = {}) {
  const result = {
    ok: false,
    reachable: false,
    reaAvailable: false,
    reaVersion: null,
    reaVersionSource: null,
    // 两个环境闸门各自的读数：platform 是 uname -s 的一行原文，nodeVersion 是解析出的版本号
    platform: null,
    nodeVersion: null,
    doctor: null,
    capabilities: null,
    readiness: [],
    missing: [],
    error: null,
    via: null,
    commands: [],
  }
  const brief = (command) => ({
    label: command.label,
    command: command.command,
    timeoutMs: command.timeoutMs,
    ok: command.ok,
    exitCode: command.exitCode,
    timedOut: command.timedOut,
    durationMs: command.durationMs,
    stdoutBytes: command.stdoutBytes,
    stderrBytes: command.stderrBytes,
    // 正常探测 stderr 是空的；只有失败时才把片段带出来给人看。
    ...(command.stderrSnippet === '' ? {} : { stderrSnippet: command.stderrSnippet }),
    parsedFromMergedStderr: command.parsedFromMergedStderr,
    error: command.error,
  })
  // 环境闸门（uname / node --version）的审计条目：与 rea 探测同形，但没有 JSON 可解析，
  // ok 的含义是「这一眼看出了东西」，由调用方给。
  const gate = (label, command, run, timeoutMs, ok, error = null) => ({
    label,
    command,
    timeoutMs,
    ok,
    exitCode: run.exitCode ?? null,
    timedOut: run.timedOut === true,
    durationMs: run.durationMs ?? null,
    stdoutBytes: Buffer.byteLength(String(run.stdout ?? '')),
    stderrBytes: Buffer.byteLength(String(run.stderr ?? '')),
    parsedFromMergedStderr: false,
    error,
  })

  try {
    // ⓪ 平台闸门（B1）：Windows 远端不是本插件的支持面，先于任何 rea 探测判掉。
    let platform = null
    try {
      const unameRun = await safeExec(engine, alias, 'uname -s', COMMAND_PROBE_TIMEOUT_MS)
      platform = str(unameRun.stdout)
      result.platform = platform
      result.commands.push(gate('platform', 'uname -s', unameRun, COMMAND_PROBE_TIMEOUT_MS, platform !== null))
    } catch (error) {
      result.error = `SSH 不可达：${messageOf(error)}`
      return result
    }
    if (platform !== null && WINDOWS_UNAME.test(platform)) {
      result.error = UNSUPPORTED_TARGET_PLATFORM
      return result
    }

    let via = null
    try {
      if (await probeHasCommand(engine, alias, 'rea', COMMAND_PROBE_TIMEOUT_MS)) via = 'global'
      result.reachable = true
    } catch (error) {
      result.error = `SSH 不可达：${messageOf(error)}`
      return result
    }
    if (via === null) {
      let hasNpx = false
      try {
        hasNpx = await probeHasCommand(engine, alias, 'npx', COMMAND_PROBE_TIMEOUT_MS)
      } catch (error) {
        result.error = `探测 npx 时 SSH 失败：${messageOf(error)}`
        return result
      }
      if (!hasNpx) {
        result.error = `远端既没有全局 rea，也没有 npx —— 本步不做离线 tarball 部署，探测到此为止`
        return result
      }
      // ① 版本闸门（B4）：npx 这条路跑在远端 node 上，版本不达标时 rea 会半途报难懂的错，
      // 所以在这一步按 REA 的版本要求先拦（读不到版本号不拦，见 nodeVersionVerdict）。
      const nodeRun = await safeExec(engine, alias, 'node --version', COMMAND_PROBE_TIMEOUT_MS)
      const verdict = nodeVersionVerdict(nodeRun.stdout)
      result.nodeVersion = verdict.version
      result.commands.push(gate('node-version', 'node --version', nodeRun, COMMAND_PROBE_TIMEOUT_MS, verdict.known,
        verdict.known ? null : `node --version 读不出版本号（${NODE_REQUIREMENT_TEXT}）`))
      if (!verdict.ok) {
        result.error = `远端 ${verdict.why}；${NODE_REQUIREMENT_TEXT}`
        return result
      }
      via = 'npx'
    }
    result.via = via
    const budget = via === 'npx' ? npxTimeoutMs : timeoutMs

    if (via === 'global') {
      const startedAt = Date.now()
      const versionRun = await safeExec(engine, alias, 'rea --version', COMMAND_PROBE_TIMEOUT_MS)
      const text = String(versionRun.stdout ?? '')
      const parsedVersion = versionFromText(text)
      result.commands.push({
        label: 'version',
        command: 'rea --version',
        timeoutMs: COMMAND_PROBE_TIMEOUT_MS,
        ok: parsedVersion !== null,
        exitCode: versionRun.exitCode ?? null,
        timedOut: versionRun.timedOut === true,
        durationMs: versionRun.durationMs ?? Date.now() - startedAt,
        stdoutBytes: Buffer.byteLength(text),
        stderrBytes: Buffer.byteLength(String(versionRun.stderr ?? '')),
        parsedFromMergedStderr: false,
        error: parsedVersion === null ? 'rea --version 没有可读出的版本号' : null,
      })
      if (parsedVersion !== null) {
        result.reaVersion = parsedVersion
        result.reaVersionSource = 'rea --version'
      }
    }

    const doctor = await runProbeCommand(engine, alias, 'doctor', reaCommand(via, 'doctor --json'), budget)
    result.commands.push(brief(doctor))
    result.doctor = doctor.json

    const caps = await runProbeCommand(engine, alias, 'capabilities', reaCommand(via, 'capabilities --format json'), budget)
    result.commands.push(brief(caps))
    result.capabilities = caps.json

    if (result.reaVersion === null) {
      const fromDoctor = versionFromDoctor(result.doctor)
      if (fromDoctor !== null) {
        result.reaVersion = fromDoctor
        result.reaVersionSource = 'doctor.identity.cli_package_version'
      }
    }

    result.reaAvailable = doctor.ok || caps.ok
    if (result.reaAvailable) {
      result.readiness = collectReadiness(result.doctor, result.capabilities)
      result.missing = missingLines(result.readiness)
    }

    result.ok = result.reachable && result.reaAvailable && result.readiness.length > 0
    if (!result.ok && result.error === null) {
      const failed = [doctor, caps].find((command) => !command.ok) ?? caps
      const npxWhy = via === 'npx' ? npxFailureReason(failed) : null
      result.error = npxWhy ?? `REA 探测失败：${failed.error ?? 'doctor 与 capabilities 都没解析出 JSON'}`
    }
    return result
  } catch (error) {
    result.error = `探测异常（已吞掉，不外抛）：${messageOf(error)}`
    return result
  }
}
