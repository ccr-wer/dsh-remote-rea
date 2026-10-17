// ============================================================================
// rea-provider-router.js —— 按目标元数据 + provider 可用性选 provider/operation
// ----------------------------------------------------------------------------
// 本模块纯本地：不连 SSH、不下发命令。输入全部来自 3b 的 probeRemoteRea 返回
// （readiness / capabilities）与第 5 步 runFetch 的 metadata。
//
// 四条真机事实（wsl-local，rea 6.5.0 via npx，2026-10-16 实测）决定了这里的取舍：
//
//  1. capabilities 与 providers 两个面是同一份信封（23663B），广告的 provider id 只有
//     ghidra / hopper / ida / native-macos / rea-artifact-graph / rea-dotnet-static / sqlite。
//     「javascript」在 capabilities 与 doctor 里出现 **0 次**，可 CLI 的 `rea analyze-javascript-application`
//     确实存在且能跑（对一个最小 JS 应用回了 67318B Evidence，provider.id=rea-javascript-application）。
//     → 广告面会漏报。本模块只在「广告面 ∩ 已验证的 CLI 绑定」里选路，绝不因为某个 operation
//       没被广告就断言它不可用，也绝不因为 help 里有就当作可用。
//       唯一例外是 MANUAL_EXCEPTIONS 那张表：真机跑通过、且目标类别对得上的操作允许绕过广告面，
//       但选路结果必须带 surface='manual-exception' + marker，让调用方看得出它不是广告面选出来的。
//
//  2. `rea analyze <path>` 的深度分析只绑 ghidra/hopper/ida：
//     --provider rea-artifact-graph 直接回 code=capability_unavailable /
//     category=unsupported_provider / "Choose one of: ghidra, hopper, ida"。
//     → 这台机器上三个都 unavailable，所以 rea analyze 现在必然失败；B 部分走 inspect-artifact。
//
//  3. operation id 与 CLI 子命令**不是**机械的下划线转连字符：候选面里的 analyze_function
//     没有 `rea analyze-function` 子命令（真机 help 全表 3208B 里没有）。只有核对过的绑定才允许下发。
//     而且 `rea analyze` 没有 --operation（真机：--operation → exit=1、code=UNKNOWN、
//     "Unknown flag: --operation"，66B），所以深分析只能直接下发 rea function / rea decompile
//     这类子命令，绝不拼 `rea analyze --provider ghidra`。
//
//  4. inspect_artifact 所在组的 effects 是 ["launches_process","may_write_filesystem"]，
//     同 provider 的 decode_interface_builder 等组 effects 为空；shared_limitations 里
//     「ASAR files … expanded without bulk extraction」「DMG … read-only native macOS mount」。
//     → 选路时把 effects 如实带进 reason，让调用方看得见「它会起进程/会写文件系统」。
//
// target_support 在没开 target 时是 {status:"unknown", reason:"No target is open."}；
// 但 inspect-artifact 是单发的：跑前跑后 capabilities.open 都是 false，HOME 里也没有新文件，
// 所以 B 部分不受「先开 target」约束（第 2 条里的深分析才受）。
// ============================================================================

/** 已用真机 `--help` 核对过的 operation → 子命令绑定。没在这张表里的 operation 一律不下发。 */
export const VERIFIED_CLI_BINDINGS = Object.freeze({
  inspect_artifact: 'inspect-artifact',
  extract_artifact: 'extract-artifact',
})

/**
 * A 路（深分析）绑定表：operation → `rea <子命令>`，逐条用真机 `--help` 核对过用法
 * （2026-10-17 wsl-local，rea 6.5.0：function 1541B / decompile 1650B / instructions 1552B /
 *  xrefs 1530B / read-bytes 1442B，help 原文里的 Usage 行抄在下面）。
 *
 * 与 VERIFIED_CLI_BINDINGS 分两张表是因为「核对过 help」不等于「真机跑通过」：
 * 这台机器 ghidra 恒 not_configured，这 5 条没有任何一次实跑证据，所以它们
 * **不参与自动选路**，只有调用方显式 provider='ghidra' 且 readiness 判 ghidra 可用时才走。
 *
 * address 一栏记的是 help 的实参形状（可选 / 必填）。本步工具面没有地址入参，
 * 所以 address='required' 的那条（read_bytes）只登记、不下发 —— 缺必填实参的命令必然被
 * CLI 自己的用法校验拒掉，下发它只会产生一条没有信息量的失败。
 */
export const GHIDRA_BINDINGS = Object.freeze({
  analyze_function: Object.freeze({ subcommand: 'function', address: 'optional', usage: 'rea function <path> [address] [options]' }),
  procedure_pseudo_code: Object.freeze({ subcommand: 'decompile', address: 'optional', usage: 'rea decompile <path> [address] [options]' }),
  procedure_assembly: Object.freeze({ subcommand: 'instructions', address: 'optional', usage: 'rea instructions <path> [address] [options]' }),
  xrefs: Object.freeze({ subcommand: 'xrefs', address: 'optional', usage: 'rea xrefs <path> [address] [options]' }),
  read_bytes: Object.freeze({ subcommand: 'read-bytes', address: 'required', usage: 'rea read-bytes <path> <address> [options]' }),
})

/** A 路目前只接 ghidra：hopper/ida 的 CLI 绑定没有逐条核对过，不给入口。 */
export const A_PATH_PROVIDER = 'ghidra'

/**
 * A 路不可用时的「到底缺什么」：capabilities 的 candidate 面自带
 * availability.diagnostics（真机原文含 install_dir / analyze_headless_path /
 * java_command / java_home 等字段），这里只做取用与序列化，不改写、不补文案。
 */
export function ghidraDiagnostics(capabilities) {
  for (const cand of Array.isArray(capabilities?.analysis_provider_candidates) ? capabilities.analysis_provider_candidates : []) {
    if (str(cand?.provider?.id) !== A_PATH_PROVIDER) continue
    const d = cand?.availability?.diagnostics
    if (d !== null && typeof d === 'object' && !Array.isArray(d)) return d
    return null
  }
  return null
}

/** diagnostics 里挑用户最可能要补的几项，原样拼成 `k=v`；值缺失也照写（null 本身就是信息）。 */
const DIAGNOSTIC_KEYS = Object.freeze(['install_dir', 'analyze_headless_path', 'java_command', 'java_home'])

export function diagnosticSummary(diagnostics) {
  if (diagnostics === null) return null
  return DIAGNOSTIC_KEYS.map((k) => `${k}=${JSON.stringify(diagnostics[k] ?? null)}`).join(' ')
}

/**
 * 手工例外：真机跑通过、但 capabilities / providers / doctor 三个广告面都不出现的 CLI 操作。
 * 单独一张表是因为它没有广告可核对 —— 判据只能是一次真实调用，所以使用它必须带标记（marker），
 * 绝不伪装成广告面选出来的结果。
 *
 * 2026-10-16 wsl-local 实测（rea 6.5.0 via npx）：
 *   analyze-javascript-application /tmp/d6-app.asar → exit=0、68876B Evidence、provider.id=rea-javascript-application
 *   analyze-javascript-application 单个 .js        → exit=1、code=unsupported_target、
 *     "JavaScript application analysis accepts only a directory or an .asar file"
 *   目录能分析，但 runFetch 的预检要求普通文件（[ -f ]）拉不下来 → 本插件只有 ASAR 能走到这条路。
 */
export const MANUAL_EXCEPTIONS = Object.freeze([
  Object.freeze({
    provider: 'rea-javascript-application',
    operation: 'analyze_javascript_application',
    subcommand: 'analyze-javascript-application',
    targetClasses: Object.freeze(['asar']),
    marker: 'manual-exception:not-advertised',
    reason: '手工例外：rea-javascript-application 不在 capabilities/providers/doctor 任何广告面里，选路依据是 2026-10-16 真机 ASAR 实跑（exit=0，68876B Evidence）；该 provider 不广告 effects，读文件还是写文件系统未知',
  }),
])

const MANUAL_BY_OPERATION = new Map(MANUAL_EXCEPTIONS.map((m) => [m.operation, m]))

/** 目标类别 → 候选 operation 的优先级。只用已验证绑定，顺序=先只读概览再展开。 */
const CLASS_PREFERENCES = Object.freeze({
  elf: ['inspect_artifact', 'extract_artifact'],
  pe: ['inspect_artifact', 'extract_artifact'],
  macho: ['inspect_artifact', 'extract_artifact'],
  archive: ['inspect_artifact', 'extract_artifact'],
  // ASAR 优先走手工例外：inspect-artifact 对 ASAR 只回清单（真机 dialect 计数 1 条 observation、0 findings），
  // analyze-javascript-application 才是真正展开 JS 应用的那个操作。
  asar: ['analyze_javascript_application', 'inspect_artifact'],
  dylib: ['inspect_artifact', 'trace_dylib_resolution'],
  // 链接串本身不带类型信息（file -b 只回 "symbolic link to <target>"），交给 rea 自己判格式
  symlink: ['inspect_artifact'],
  unresolved: ['inspect_artifact'],
  // 以下类别本步没有可用路径，列出来只为让 reason 说清楚，不是「试着下发看看」
  directory: [],
  'source-text': [],
  data: [],
})

const str = (v) => (typeof v === 'string' && v.trim() !== '' ? v.trim() : null)

/**
 * fileType 拿不到时的降级信号：按扩展名猜类别。
 * 只收「扩展名与格式基本一一对应」的那些，.bin / 无扩展名这种猜不出来的不猜 —— 猜错的类别
 * 会选到能跑但结论无关的操作，比「不知道」更糟。猜出来的结果一定写进 note。
 */
const EXTENSION_CLASSES = Object.freeze({
  elf: 'elf',
  exe: 'pe', dll: 'pe', sys: 'pe', ocx: 'pe', msix: 'pe',
  dylib: 'dylib', so: 'dylib',
  asar: 'asar',
  zip: 'archive', tar: 'archive', gz: 'archive', tgz: 'archive', bz2: 'archive', xz: 'archive', '7z': 'archive', deb: 'archive', dmg: 'archive', jar: 'archive',
  js: 'source-text', json: 'source-text', txt: 'source-text', xml: 'source-text', html: 'source-text', c: 'source-text', py: 'source-text',
})

/** 从路径尾段取小写扩展名；没有扩展名（或以点结尾）返回 null。 */
function extensionOf(remotePath) {
  const name = String(remotePath ?? '').split('/').pop() ?? ''
  const dot = name.lastIndexOf('.')
  if (dot <= 0 || dot === name.length - 1) return null
  return name.slice(dot + 1).toLowerCase()
}

/**
 * 把 file -b 的一行原文归到一个目标类别。
 * 只做识别、不做解析：REA 自己才是格式权威（它拒一个目标会回 constraint=file_format_rejected）。
 * @param {string|null} fileTypeText file -b 的一行原文；远端没有 file 命令时是 null
 * @param {string|null} [remotePath] 只在 fileTypeText 拿不到时用于扩展名降级
 */
export function classifyTarget(fileTypeText, remotePath = null) {
  const t = String(fileTypeText ?? '').trim()
  if (t === '') {
    const ext = extensionOf(remotePath)
    const guess = ext === null ? undefined : EXTENSION_CLASSES[ext]
    if (guess !== undefined) return { targetClass: guess, note: `未知类型：file -b 没有输出，按扩展名 .${ext} 猜为 ${guess}（未经格式头证实）` }
    return { targetClass: 'unresolved', note: '未知类型：file -b 没有输出、扩展名也认不出来；深度分析需指定 provider' }
  }
  if (/^symbolic link\b/i.test(t)) return { targetClass: 'symlink', note: `链接目标：${t.replace(/^symbolic link to\s+/i, '') || '未知'}` }
  if (/^ELF\b/i.test(t)) return { targetClass: 'elf', note: t.slice(0, 120) }
  if (/^(PE32\+?|MS-DOS|MZ)\b/i.test(t) || /\bPE executable\b/i.test(t)) return { targetClass: 'pe', note: t.slice(0, 120) }
  if (/^Mach-O\b/i.test(t)) return { targetClass: 'macho', note: t.slice(0, 120) }
  if (/\bdynamic (link|shared) library\b/i.test(t) || /\.dylib\b/i.test(t)) return { targetClass: 'dylib', note: t.slice(0, 120) }
  if (/\b(directory|folder)\b/i.test(t)) return { targetClass: 'directory', note: t.slice(0, 120) }
  // 必须在 archive 规则之前：真机 `file -b` 原文是 "Electron ASAR archive, header length: 502 bytes"，
  // 含 "archive" 一词，放到下面会被吞成普通压缩包。
  if (/\bElectron ASAR\b/i.test(t)) return { targetClass: 'asar', note: t.slice(0, 120) }
  if (/^(Zip archive|POSIX tar|gzip|bzip2|xz|7-zip|ARJ|Apple disk image|Debian package)\b/i.test(t) || /\barchive\b/i.test(t)) {
    return { targetClass: 'archive', note: t.slice(0, 120) }
  }
  if (/^(JavaScript|JSON|ASCII text|XML|HTML|C source|Python script|UTF-8 Unicode text)\b/i.test(t)) {
    return { targetClass: 'source-text', note: t.slice(0, 120) }
  }
  if (/^data\b/i.test(t)) return { targetClass: 'data', note: 'file 只回 data：无格式头，REA 会按 file_format_rejected 拒' }
  return { targetClass: 'unresolved', note: t.slice(0, 120) }
}

/** capabilities 的两处广告位摊平成 {provider, operation, available, availabilityCode, reason, effects, surface}。 */
export function advertisedOperations(capabilities) {
  const out = []
  const push = (providerId, group, surface) => {
    for (const operation of Array.isArray(group?.operations) ? group.operations : []) {
      if (typeof operation !== 'string') continue
      out.push({
        provider: providerId,
        operation,
        available: group.available === true,
        availabilityCode: group.availability_code ?? group.availabilityCode ?? null,
        reason: str(group.reason),
        effects: Array.isArray(group.effects) ? group.effects : [],
        surface,
      })
    }
  }
  for (const cap of Array.isArray(capabilities?.capabilities) ? capabilities.capabilities : []) {
    const id = str(cap?.provider?.id)
    if (id === null) continue
    for (const group of Array.isArray(cap.groups) ? cap.groups : []) push(id, group, 'capabilities')
  }
  for (const cand of Array.isArray(capabilities?.analysis_provider_candidates) ? capabilities.analysis_provider_candidates : []) {
    const id = str(cand?.provider?.id)
    if (id === null) continue
    // 深分析 provider 的操作挂在 capabilities[0].groups（真机结构），不是顶层 capabilities[]
    for (const surface of Array.isArray(cand.capabilities) ? cand.capabilities : []) {
      for (const group of Array.isArray(surface?.groups) ? surface.groups : []) push(id, group, 'candidates')
    }
  }
  return out
}

/**
 * 3b 的 readiness 条目 → provider 可用性判定。
 * 状态词表以 3b 为准（rea-remote-probe.js:215 只产 'ready' | 'unavailable'），
 * 同时认 capabilities 原文里的 'available'：这里只做归一，不重新发明判定。
 */
function availabilityOf(readiness, advertised) {
  const byProvider = new Map()
  for (const item of Array.isArray(readiness) ? readiness : []) {
    const id = str(item?.id)
    if (id === null) continue
    const raw = str(item.status) ?? 'unknown'
    byProvider.set(id, {
      status: raw,
      usable: raw === 'ready' || raw === 'available',
      availabilityCode: item.availabilityCode ?? null,
      remediation: str(item.remediation),
    })
  }
  return (providerId) => {
    const fromReadiness = byProvider.get(providerId)
    if (fromReadiness !== undefined) return fromReadiness
    const ops = advertised.filter((o) => o.provider === providerId)
    const anyAvailable = ops.some((o) => o.available)
    const firstBlocked = ops.find((o) => o.available === false)
    return {
      status: anyAvailable ? 'ready' : 'unknown',
      usable: anyAvailable,
      availabilityCode: firstBlocked?.availabilityCode ?? null,
      remediation: firstBlocked?.reason ?? null,
      advertised: ops.length,
    }
  }
}

const DEEP_IDS = new Set(['ghidra', 'hopper', 'ida'])

/**
 * 选路。只做「能跑通的那部分」：目标类别 → 已验证绑定 → provider 可用性，三者都过才进首选。
 * 返回 { provider, operation, subcommand, reason, targetClass, alternatives, unavailable, note }
 * 选不出也绝不抛：provider/operation 给 null，reason 说清为什么，unavailable[] 交代没用的那些。
 * @param {object} metadata      第 5 步 runFetch 的 metadata（fileType 可能是 null）
 * @param {Array}  readiness     3b probeRemoteRea 的就绪矩阵
 * @param {object} capabilities  3b 的 capabilities 原文（A 路的 diagnostics 也来自这里）
 * @param {object} [options]
 * @param {string|null} [options.preferredProvider] 传 'ghidra' 走 A 路；其它值只做重排
 * @param {string|null} [options.remotePath]       fileType 拿不到时用于扩展名降级
 */
export function routeProvider(metadata, readiness, capabilities, { preferredProvider = null, remotePath = null } = {}) {
  const advertised = advertisedOperations(capabilities)
  const availability = availabilityOf(readiness, advertised)
  const readinessIds = new Set(
    (Array.isArray(readiness) ? readiness : [])
      .map((item) => str(item?.id))
      .filter((id) => id !== null),
  )
  const targetClassInfo = classifyTarget(metadata?.fileType, remotePath)
  const targetClass = targetClassInfo.targetClass
  const preferred = str(preferredProvider)

  // 不可用清单：深分析三件套 + 任何被 readiness 判为不可用/未就绪的 provider，都如实列出
  const seen = new Set()
  const unavailable = []
  for (const providerId of [...DEEP_IDS, ...advertised.map((o) => o.provider)]) {
    if (seen.has(providerId)) continue
    seen.add(providerId)
    const av = availability(providerId)
    const usableOps = advertised.filter((o) => o.provider === providerId && o.available && VERIFIED_CLI_BINDINGS[o.operation] !== undefined)
    if (av.usable && usableOps.length > 0) continue
    // reason 优先用 3b 的 remediation 原文（那是「怎么才能用」的权威说法）；
    // 没有 remediation 时不能说「reason: ready」这种自相矛盾的话，按不可用的真实原因写。
    const reason = av.remediation ?? (av.usable
      ? `provider 本身可用，但它广告的 ${advertised.filter((o) => o.provider === providerId).length} 个操作里没有一个有已核对的 CLI 绑定（本步不下发未核对的子命令）`
      : `readiness 判定为 ${av.status}（3b 没给 remediation）`)
    unavailable.push({
      provider: providerId,
      availabilityCode: av.availabilityCode ?? (av.usable ? 'no_verified_cli_binding' : av.status),
      reason,
      advertised_operations: advertised.filter((o) => o.provider === providerId).length,
    })
  }

  // A 路：只有调用方点名 provider='ghidra' 才进这条分支，且要同时过「readiness 可用 +
  // 广告面有此操作 + 实参凑得齐」三道。GHIDRA_BINDINGS 不参与下面的自动选路 ——
  // 这 5 条只有 help 证据、没有一次实跑证据，让它跟 inspect-artifact 竞争首选等于拿未验证的
  // 东西去覆盖已验证的东西。
  // 不可用时也不自动降级到 B 路：用户点名要深分析，静默换成浅分析会把结论口径换掉，
  // 错误信息必须用 REA 自己的 remediation + diagnostics 原文。
  if (preferred === A_PATH_PROVIDER) {
    const av = availability(A_PATH_PROVIDER)
    const diagText = diagnosticSummary(ghidraDiagnostics(capabilities))
    if (!av.usable) {
      return {
        provider: null,
        operation: null,
        subcommand: null,
        reason: `深分析不可用：${A_PATH_PROVIDER} 判定为 ${av.status}${av.availabilityCode === null ? '' : `/${av.availabilityCode}`} —— ${av.remediation ?? 'REA 没给 remediation'}${diagText === null ? '' : ` ｜ 远端诊断原文：${diagText}`}`,
        targetClass,
        surface: null,
        advertised: null,
        marker: 'a-path:help-verified-only',
        alternatives: [],
        unavailable,
        note: targetClassInfo.note,
      }
    }
    const aCandidates = []
    const aSkipped = []
    for (const [operation, binding] of Object.entries(GHIDRA_BINDINGS)) {
      const entry = advertised.find((o) => o.provider === A_PATH_PROVIDER && o.operation === operation && o.available)
      if (entry === undefined) {
        aSkipped.push(`${operation} 未被 ${A_PATH_PROVIDER} 广告`)
        continue
      }
      if (binding.address === 'required') {
        aSkipped.push(`${operation}→rea ${binding.subcommand} 需要 <address> 实参（help 原文：${binding.usage}），本步工具面没有地址入参`)
        continue
      }
      aCandidates.push({
        provider: A_PATH_PROVIDER,
        operation,
        subcommand: binding.subcommand,
        effects: entry.effects,
        surface: 'a-path',
        advertised: true,
        marker: 'a-path:help-verified-only',
        reason: `目标类别 ${targetClass}；显式点名 ${A_PATH_PROVIDER} 且 readiness 判定可用；CLI 绑定按 help 核对过（${binding.usage}），但没有一次实跑证据；effects=[${entry.effects.join(', ')}]`,
      })
    }
    if (aCandidates.length === 0) {
      return {
        provider: null,
        operation: null,
        subcommand: null,
        reason: `${A_PATH_PROVIDER} 可用，但这一步没法下发：${aSkipped.join('；') || '没有已核对的绑定'}`,
        targetClass,
        surface: null,
        advertised: null,
        marker: 'a-path:help-verified-only',
        alternatives: [],
        unavailable,
        note: targetClassInfo.note,
      }
    }
    const chosen = aCandidates[0]
    return {
      provider: chosen.provider,
      operation: chosen.operation,
      subcommand: chosen.subcommand,
      reason: chosen.reason,
      targetClass,
      surface: chosen.surface,
      advertised: chosen.advertised,
      marker: chosen.marker,
      alternatives: aCandidates.slice(1).map((c) => ({ provider: c.provider, operation: c.operation, subcommand: c.subcommand, reason: c.reason, surface: c.surface, marker: c.marker })),
      unavailable,
      note: `${targetClassInfo.note}${aSkipped.length === 0 ? '' : `；A 路跳过的操作：${aSkipped.join('；')}`}`,
    }
  }

  const ordered = CLASS_PREFERENCES[targetClass] ?? []
  const candidates = []
  for (const operation of ordered) {
    const manual = MANUAL_BY_OPERATION.get(operation)
    if (manual !== undefined) {
      // 手工例外只在「目标类别对得上」时参与，且只有 readiness 明确说这个 provider 不可用才拦 ——
      // 它本来就不在广告面里，「没被广告」不构成拒绝理由（第 1 条实测：广告面会漏报）。
      if (!manual.targetClasses.includes(targetClass)) continue
      const av = availability(manual.provider)
      if (readinessIds.has(manual.provider) && !av.usable) {
        unavailable.push({
          provider: manual.provider,
          availabilityCode: av.availabilityCode ?? av.status,
          reason: av.remediation ?? `readiness 判定为 ${av.status}（3b 没给 remediation）`,
          advertised_operations: 0,
          marker: manual.marker,
        })
        continue
      }
      candidates.push({
        provider: manual.provider,
        operation,
        subcommand: manual.subcommand,
        effects: [],
        surface: 'manual-exception',
        advertised: false,
        marker: manual.marker,
        reason: `目标类别 ${targetClass}；${manual.reason}`,
      })
      continue
    }
    const binding = VERIFIED_CLI_BINDINGS[operation]
    if (binding === undefined) continue
    for (const entry of advertised.filter((o) => o.operation === operation)) {
      if (!entry.available) continue
      const av = availability(entry.provider)
      if (!av.usable) continue
      candidates.push({
        provider: entry.provider,
        operation,
        subcommand: binding,
        effects: entry.effects,
        surface: 'advertised',
        advertised: true,
        marker: null,
        reason: `目标类别 ${targetClass}；${entry.provider}/${operation} 已广告且 available（CLI 绑定 ${binding} 已用 --help 核对）；effects=[${entry.effects.join(', ')}]`,
      })
    }
  }

  // preferredProvider 只重排，不放宽：它不可用时照样不进首选，理由写进 note。
  let note = targetClassInfo.note
  if (preferred !== null) {
    const hit = candidates.findIndex((c) => c.provider === preferred || c.operation === preferred)
    if (hit > 0) candidates.unshift(candidates.splice(hit, 1)[0])
    else if (hit < 0) note = `${note}；指定的 preferredProvider=${preferred} 当前没有可用且已验证绑定的操作，回退自动选择`
  }

  if (candidates.length === 0) {
    const why = ordered.length === 0
      ? `目标类别 ${targetClass} 在本步没有可用操作（深分析 provider 全不可用，广告面里也没有能处理它的操作）`
      : ordered.map((o) => `${o}→${VERIFIED_CLI_BINDINGS[o] ?? MANUAL_BY_OPERATION.get(o)?.subcommand ?? '未核对绑定'}`).join(', ') + ' 这些候选在这台机器上都不可用'
    return {
      provider: null,
      operation: null,
      subcommand: null,
      reason: `没有可用的分析路径：${why}`,
      targetClass,
      surface: null,
      advertised: null,
      marker: null,
      alternatives: [],
      unavailable,
      note,
    }
  }

  const chosen = candidates[0]
  return {
    provider: chosen.provider,
    operation: chosen.operation,
    subcommand: chosen.subcommand,
    reason: chosen.reason,
    targetClass,
    surface: chosen.surface,
    advertised: chosen.advertised,
    marker: chosen.marker,
    alternatives: candidates.slice(1).map((c) => ({
      provider: c.provider,
      operation: c.operation,
      subcommand: c.subcommand,
      reason: c.reason,
      surface: c.surface,
      marker: c.marker,
    })),
    unavailable,
    note,
  }
}
