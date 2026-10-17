// ============================================================================
// rea-controller.js —— 控制器：定位 → 拉取 → 存档 → 分析 → 摘要（第 5+6 步）
// ----------------------------------------------------------------------------
// runFetch 只做「把远端那个文件取回本地并留下可审计的一页」；
// runAnalyze 在它之后接 routeProvider → rea 子命令 → Evidence 落盘 → Summary。
// 部署路径与预热全部委托给第 4 步的 planRemoteReaDeploy，本文件不重复实现。
// 四条实测/源码依据：
//   * remote-ssh-core.js:847 的 download() 没有绝对路径校验（只有 upload():819 有），
//     相对路径会被 sftp-server 按它的 cwd 解析 —— 所以这里必须自己拦。
//   * download() 也不收 timeoutMs：传输没有硬超时，只能靠 sftp 自己报错。
//   * fastTransfer 的进度帧是 {phase:'transferring'|'done'|'error', file, transferred,
//     total, percent, speedBps}（remote-ssh-core.js:937），本模块直接透传，不加工。
//   * 预检合并成一条命令时，退出码没有信息量（bash 只给最后一个 printf 的码），
//     所以成败看 KEY=VALUE 行，不看 exit code；但「一个 KEY 都没回」是命令没跑成，
//     必须单独开口径 —— 否则模板语法错会被误报成「目标不存在」（本轮真机踩过）。
// 约定：所有下发走 safeExec（内含提权闸门 + attempts=1，预检绝不重放）；
//       返回体不留远端原始 stdout，fileType 用 file -b 的一行原文、不解析；
//       错误信息一句话，不回显远端输出。
// ============================================================================

import { createHash } from 'node:crypto'
import { createReadStream, existsSync, statSync } from 'node:fs'
import { basename, join, resolve } from 'node:path'

import { planRemoteReaDeploy } from './rea-remote-deploy.js'
import { probeRemoteRea } from './rea-remote-probe.js'
import { routeProvider } from './rea-provider-router.js'
import { parseReaOutput, persistEvidence } from './rea-output-parser.js'
import { extractFindings } from './rea-finding-extractor.js'
import { buildSummary } from './rea-summary.js'
import { safeExec, shellQuote, timestamp, writeJsonReport } from './remote-shell-utils.js'

const PREFLIGHT_TIMEOUT_MS = 30000
const REPORT_PREFIX = 'fetch'
const ANALYZE_PREFIX = 'analyze'
// 真机实测：npx 缓存热时单发 inspect-artifact / analyze 都是 3.3~4.2s（含 node 起进程），
// 帮助类 2.9~9.4s。这里给 180s 是给大文件与冷 npx 留量，不是猜的默认值。
const ANALYZE_TIMEOUT_MS = 180000
// 冷 npx 预热的预算。上一版 300000 在真机连续两次擦边失败（实测 300104ms / 300107ms，
// 根因是 prebuild-install 下预编译二进制没有超时上界），抬到 600000 留一倍余量。
const NPX_WARMUP_TIMEOUT_MS = 600000

const messageOf = (error) => (error instanceof Error ? error.message : String(error))

/** 一句话错误：压掉换行、截断，避免把远端多行输出带进返回体。 */
function oneLine(text, maxChars = 200) {
  const s = String(text ?? '').replace(/\s+/g, ' ').trim()
  return s.length > maxChars ? s.slice(0, maxChars) + '…' : s
}

/**
 * 一条命令做完四项预检（存在性 / 大小 / 类型 / 远端 sha256）。
 * KEY= 前缀让解析不必猜行号；file/sha256sum 缺失时该项落 NA，不影响 exists 判定。
 * 注意 then 后面不能再跟分号（`then; printf` 是 bash 语法错误），所以 then 体整体拼一次。
 * SIZE 有两条通道：`stat -c %s` 是 GNU 写法，BSD/macOS 的 stat 不认 %s（打印 usage、退出非 0），
 * 所以再用 `wc -c <` 兜底。注意 wc -c 走的是重定向、会跟随符号链接（拿到的是目标长度），
 * 而 stat -c %s 给的是链接串长度 —— 两者的差异由符号链接豁免统一处理（见 runFetch ④）。
 */
export function preflightCommand(remotePath) {
  const q = shellQuote(remotePath)
  const thenBody = [
    `printf 'EXISTS=1\\n'`,
    `printf 'SIZE='; (stat -c %s -- ${q} 2>/dev/null || wc -c < ${q} 2>/dev/null || printf 'NA\\n')`,
    `printf 'TYPE='; (file -b -- ${q} 2>/dev/null || printf 'NA\\n')`,
    `printf 'SHA256='; (sha256sum -- ${q} 2>/dev/null | cut -d' ' -f1 || printf 'NA\\n')`,
  ].join('; ')
  return `if [ -f ${q} ]; then ${thenBody}; else printf 'EXISTS=0\\n'; fi`
}

/** 只认四个已知 KEY，值里再出现 = 也不影响（按首个 = 切分）。 */
export function parsePreflight(stdout) {
  const fields = {}
  for (const line of String(stdout ?? '').split('\n')) {
    const eq = line.indexOf('=')
    if (eq <= 0) continue
    const key = line.slice(0, eq)
    if (key === 'EXISTS' || key === 'SIZE' || key === 'TYPE' || key === 'SHA256') {
      if (fields[key] === undefined) fields[key] = line.slice(eq + 1).trim()
    }
  }
  const size = fields.SIZE
  const sha = fields.SHA256
  return {
    exists: fields.EXISTS === '1',
    sizeBytes: typeof size === 'string' && /^\d+$/.test(size) ? Number(size) : null,
    fileType: typeof fields.TYPE === 'string' && fields.TYPE !== '' && fields.TYPE !== 'NA' ? fields.TYPE : null,
    sha256: typeof sha === 'string' && /^[0-9a-f]{64}$/.test(sha) ? sha : null,
  }
}

/** 流式算本地 sha256 —— 目标可能是几百 MB 的镜像，不能读进内存。 */
function sha256Local(path) {
  return new Promise((resolvePromise, reject) => {
    const hash = createHash('sha256')
    const stream = createReadStream(path)
    stream.on('error', reject)
    stream.on('data', (chunk) => hash.update(chunk))
    stream.on('end', () => resolvePromise(hash.digest('hex')))
  })
}

/**
 * 定位 + 预检 + 拉取 + 校验 + 存档。不抛异常：任何失败都进 error 字段。
 * @param {string} alias      主机库别名
 * @param {string} remotePath 远端绝对路径
 * @param {object} options
 * @param {object} options.engine      remote-ssh-core.js 的 SshEngine（必传）
 * @param {string} options.reportsDir  报告目录（必传）
 * @param {string} options.localDir    拉取落盘目录（必传）
 * @param {number} [options.npxTimeoutMs=600000] 冷缓存预热预算（300000 在真机擦边失败过两次）
 * @param {(frame:object)=>void} [options.onProgress] 进度回调
 */
export async function runFetch(alias, remotePath, { engine, reportsDir, localDir, npxTimeoutMs = NPX_WARMUP_TIMEOUT_MS, onProgress } = {}) {
  const started = Date.now()
  const result = {
    ok: false,
    alias: String(alias ?? ''),
    remotePath: typeof remotePath === 'string' ? remotePath : null,
    localPath: null,
    metadata: { exists: false, sizeBytes: null, fileType: null, sha256: null },
    deploy: null,
    reportPath: null,
    error: null,
    // 传输后再算一次本地 sha256 比对：分析结论的可信度取决于「拿到的就是那个文件」
    verification: null,
    durationMs: 0,
  }
  // source 用来和 fastTransfer 透传的帧区分：那边也有 phase:'done'（传输完成），
  // 与本模块的收口帧不是一回事（remote-ssh-core.js:968）。
  const report = (phase, message, extra = {}) => {
    if (typeof onProgress === 'function') onProgress({ source: 'controller', phase, message, ...extra })
  }
  const finish = () => {
    result.durationMs = Date.now() - started
    try {
      result.reportPath = writeJsonReport(reportsDir, `${REPORT_PREFIX}-${alias}-${timestamp()}.json`, {
        fetchedAt: new Date().toISOString(),
        ...result,
      })
    } catch (error) {
      result.error = `报告落盘失败：${oneLine(messageOf(error))}`
    }
    return result
  }

  // ⓪ 入参闸门：engine 单例、两个目录、以及 download 不校验的绝对路径
  if (engine === undefined || engine === null || typeof engine.exec !== 'function' || typeof engine.download !== 'function') {
    result.error = 'engine 必传（remote-ssh-core.js 的 SshEngine 单例）'
    return result
  }
  if (typeof reportsDir !== 'string' || reportsDir === '' || typeof localDir !== 'string' || localDir === '') {
    result.error = 'reportsDir 与 localDir 必传（落盘位置不由控制器猜）'
    return result
  }
  if (typeof remotePath !== 'string' || remotePath === '') {
    result.error = '远端路径为空'
    return result
  }
  if (!remotePath.startsWith('/')) {
    result.error = `远端路径必须是绝对路径（download 侧不校验，相对路径会按 sftp-server 的 cwd 解析）：${remotePath}`
    return result
  }
  if (/[\r\n]/.test(remotePath)) {
    result.error = '远端路径含换行，无法安全拼进预检命令'
    return result
  }
  const name = basename(remotePath)
  if (name === '' || name === '.' || name === '..') {
    result.error = `远端路径不是一个文件名：${remotePath}`
    return result
  }

  try {
    // ① 部署计划。预热由 planRemoteReaDeploy 内部完成，它自己发 source:'warmup' 的
    // warming/warmed 帧（冷跑 50~83s、离群 >420s，所以「开始时提醒」必须在那边下发前发出）。
    report('planning', '规划远端 REA 部署路径（缓存冷的话这一步会下载，可能要几分钟）')
    const deploy = await planRemoteReaDeploy(engine, alias, { npxTimeoutMs, onProgress })
    result.deploy = deploy
    if (deploy.strategy === 'unavailable') {
      result.error = deploy.error ?? '远端没有可用的 REA 部署路径'
      report('failed', result.error)
      return finish()
    }
    if (deploy.strategy === 'preinstalled') {
      report('ready', `远端已有全局 rea${deploy.reaVersion === null ? '' : ` ${deploy.reaVersion}`}，无需预热`)
    }

    // ② 目标预检（一条命令，走 safeExec：提权闸门 + attempts=1）
    report('preflight', `预检远端目标：${remotePath}`)
    const pre = await safeExec(engine, alias, preflightCommand(remotePath), PREFLIGHT_TIMEOUT_MS)
    result.metadata = parsePreflight(pre.stdout)
    if (pre.timedOut === true) {
      result.error = `目标预检超时（${PREFLIGHT_TIMEOUT_MS}ms 内没返回）`
      report('failed', result.error)
      return finish()
    }
    if (!String(pre.stdout ?? '').includes('EXISTS=')) {
      // 一个 KEY 都没有 ≠ 目标不存在：多半是命令本身没跑成（语法、shell 不是 bash），
      // 混进「不存在」会把排查方向彻底带偏。
      result.error = `目标预检没回 KEY= 行（命令没跑成：exit=${pre.exitCode}，stderr ${Buffer.byteLength(String(pre.stderr ?? ''))}B）`
      report('failed', result.error)
      return finish()
    }
    if (!result.metadata.exists) {
      result.error = `远端目标不存在或不是普通文件：${remotePath}`
      report('failed', result.error)
      return finish()
    }

    // ③ 拉取（进度帧原样透传，另补一个本模块自己的 start 帧）
    const localPath = resolve(join(localDir, name))
    report('downloading', `开始拉取 → ${localPath}`, { totalBytes: result.metadata.sizeBytes })
    const transferred = await engine.download(alias, remotePath, localPath, onProgress)
    result.localPath = localPath

    // ④ 校验：大小与 sha256 都要对上。
    // 符号链接例外：stat -c %s 给的是链接串长度（实测 /bin/ls → 29B），SFTP 与 sha256sum 都跟随目标
    // （落地 11352352B），所以这里的大小天生对不上，sha 才是权威。
    const isSymlink = /^symbolic link\b/.test(String(result.metadata.fileType ?? ''))
    report('verifying', '比对本地与远端的 sha256')
    const localSize = existsSync(localPath) ? statSync(localPath).size : null
    const localSha = existsSync(localPath) ? await sha256Local(localPath) : null
    result.verification = {
      localSizeBytes: localSize,
      localSha256: localSha,
      sizeMatches: isSymlink ? null : result.metadata.sizeBytes !== null && localSize === result.metadata.sizeBytes,
      sizeSkippedForSymlink: isSymlink,
      shaMatches: result.metadata.sha256 !== null && localSha !== null && localSha === result.metadata.sha256,
      downloadBytes: transferred?.bytes ?? null,
    }
    if (localSize === null) {
      result.error = '拉取后本地文件不在（传输未落盘）'
      report('failed', result.error)
      return finish()
    }
    if (result.metadata.sha256 === null) {
      // 远端 sha256sum 缺失或被拒：不能假装校验通过，如实说明校验没做成
      report('warn', '远端没给出 sha256（sha256sum 不可用），完整性校验未做')
    } else if (!result.verification.shaMatches) {
      result.error = `本地 sha256 与远端不一致（传输截断或落地即被改写）：远端 ${result.metadata.sha256.slice(0, 12)}… / 本地 ${String(localSha).slice(0, 12)}…`
      report('failed', result.error)
      return finish()
    }

    result.ok = true
    report('finished', `拉取完成：${localSize} 字节`, { localPath })
    return finish()
  } catch (error) {
    // download / 远端 IO 的异常在这里收口，一句话口径
    result.error = `拉取失败：${oneLine(messageOf(error))}`
    report('failed', result.error)
    return finish()
  }
}

/**
 * rea 的失败信封与正常结果同形（都是单个 JSON 对象），而且 exit code 是 0
 * —— 真机：`rea inspect-artifact` 吃 10KB 随机数据回 {"error":"Analysis failed",
 * "code":"target_unavailable","category":"unsupported_target",…} 且 exit=0。
 * 所以判据只能是「没有 evidence_id 却有 error/code」，不能看退出码。
 * 返回 null 表示这不是失败信封；否则带回原文字段，remediation.action 不改写。
 */
export function reaFailure(evidence) {
  if (evidence === null || typeof evidence !== 'object' || Array.isArray(evidence)) return null
  if (typeof evidence.evidence_id === 'string' && evidence.evidence_id.trim() !== '') return null
  if (typeof evidence.error !== 'string' && evidence.code === undefined) return null
  return {
    code: typeof evidence.code === 'string' ? evidence.code : null,
    category: typeof evidence.category === 'string' ? evidence.category : null,
    message: typeof evidence.message === 'string' ? evidence.message : oneLine(evidence.error),
    retryable: typeof evidence.retryable === 'boolean' ? evidence.retryable : null,
    remediation: typeof evidence.remediation?.action === 'string' ? evidence.remediation.action : null,
    constraint: typeof evidence.details?.constraint === 'string' ? evidence.details.constraint : null,
  }
}

/** 拼出下发用的分析命令：部署命令 + 已核对的子命令 + 转义后的远端路径。 */
export function analyzeCommand(deployCommand, subcommand, remotePath) {
  return `${deployCommand} ${subcommand} ${shellQuote(remotePath)} --format json`
}

/**
 * Evidence 的「方言计数」：只数 rea 自己数组的长度，不解读内容。
 * 为什么要这个字段：真机 inspect_artifact 的 normalized_result 是
 * {substeps, observations, hypotheses, contradictions, unexplored_branches, next_probes, coverage}，
 * 而不是 3a 映射层认的 semantic_graph —— 于是 findings 恒为 0。
 * 报告若只有「0 条发现」会被读成「这个文件没问题」，这些计数是区分两种「零」的唯一证据。
 */
export function dialectCounts(evidence) {
  const nr = evidence?.normalized_result
  if (nr === null || typeof nr !== 'object' || Array.isArray(nr)) return null
  const len = (v) => (Array.isArray(v) ? v.length : null)
  const sg = nr.semantic_graph
  return {
    has_semantic_graph: sg !== undefined && sg !== null,
    semantic_graph_nodes: len(sg?.nodes),
    semantic_graph_unknowns: len(sg?.unknowns),
    substeps: len(nr.substeps),
    observations: len(nr.observations),
    hypotheses: len(nr.hypotheses),
    contradictions: len(nr.contradictions),
    unexplored_branches: len(nr.unexplored_branches),
    next_probes: len(nr.next_probes),
  }
}

/**
 * 端到端分析：拉取（复用 runFetch）→ 探测能力面 → 路由 → 下发分析 → Evidence 当场落盘 → 摘要 → 报告。
 *
 * 三条真机依据决定了顺序与口径：
 *   1. 分析在远端跑、吃的是 remotePath：rea 装在远端，本地那份只是存档（runFetch 的产物）。
 *   2. 进度行 {"rea_progress":…} 走 stderr、Evidence 走 stdout（真机 JS 分析：stderr 2419B 全是进度行）。
 *      这里合并 2>&1，交给 parseReaOutput 按 key 跳进度行、取最后一个对象当 Evidence。
 *   3. Ghidra 的 session 是 ephemeral，所以 Evidence 一解析出来立刻 persistEvidence，
 *      报告只留摘要与 evidence_path —— 事后回查靠落盘那份，不靠内存。
 *      （rea-artifact-graph 实测无此约束：跑前跑后 capabilities.open 都是 false，HOME 里没有新文件。）
 * 错误一律一句话；不返回远端原始 stdout。
 * provider 传 'ghidra' 时走 A 路（见 rea-provider-router.js 的 GHIDRA_BINDINGS）：
 * 只有 readiness 判定 ghidra 可用才下发已核对的子命令，不可用时把 REA 自己的
 * details.diagnostics 原文带进错误，不自己编「缺什么」。
 */
export async function runAnalyze(alias, remotePath, { engine, reportsDir, localDir, npxTimeoutMs = NPX_WARMUP_TIMEOUT_MS, onProgress, provider = null } = {}) {
  const started = Date.now()
  const result = {
    ok: false,
    alias: String(alias ?? ''),
    remotePath: typeof remotePath === 'string' ? remotePath : null,
    localPath: null,
    metadata: { exists: false, sizeBytes: null, fileType: null, sha256: null },
    route: null,
    analysis: null,
    summary: null,
    reportPath: null,
    error: null,
    durationMs: 0,
    // 分段计时：smoke 实测同一条链路里 probe 稳定 11s、但出现过一次 86s 的离群，
    // 没有分段数字就分不清是传输、探测还是分析慢。
    timings: { fetchMs: null, probeMs: null, analyzeMs: null, mapMs: null },
  }
  const report = (phase, message, extra = {}) => {
    if (typeof onProgress === 'function') onProgress({ source: 'controller', phase, message, ...extra })
  }
  // 报告与 runFetch 的同构：失败也要存档，但全量 Evidence 只进 evidence_path
  const finish = () => {
    result.durationMs = Date.now() - started
    try {
      result.reportPath = writeJsonReport(reportsDir, `${ANALYZE_PREFIX}-${alias}-${timestamp()}.json`, {
        analyzedAt: new Date().toISOString(),
        ...result,
        // 报告里不复制整份 Evidence（真机 /bin/ls 5612B、JS 应用 67318B），只留摘要需要的字段
        analysis: result.analysis === null ? null : {
          command: result.analysis.command,
          exitCode: result.analysis.exitCode,
          timedOut: result.analysis.timedOut,
          durationMs: result.analysis.durationMs,
          stdoutBytes: result.analysis.stdoutBytes,
          progressRecords: result.analysis.progressRecords,
          evidenceId: result.analysis.evidenceId,
          evidencePath: result.analysis.evidencePath,
          provider: result.analysis.provider,
          operation: result.analysis.operation,
          subjectFormat: result.analysis.subjectFormat,
          dialect: result.analysis.dialect,
          findingCount: result.analysis.findingCount,
          unknownCount: result.analysis.unknownCount,
          failure: result.analysis.failure,
        },
      })
    } catch (error) {
      result.error = `报告落盘失败：${oneLine(messageOf(error))}`
    }
    return result
  }

  try {
    // ① 拉取阶段整体复用 runFetch（含部署计划、预热帧、预检、传输、sha 校验、fetch 报告）
    report('fetching', `先定位并拉取远端目标：${remotePath}`)
    const fetchAt = Date.now()
    const timings = result.timings
    const fetch = await runFetch(alias, remotePath, { engine, reportsDir, localDir, npxTimeoutMs, onProgress })
    timings.fetchMs = Date.now() - fetchAt
    result.metadata = fetch.metadata
    result.localPath = fetch.localPath
    if (!fetch.ok) {
      result.error = fetch.error ?? '拉取阶段失败，未进入分析'
      report('failed', `拉取阶段就失败：${result.error}`)
      // fetch 自己已经落了一页报告，直接引用它，不再写一份空的 analyze 报告
      result.reportPath = fetch.reportPath
      result.durationMs = Date.now() - started
      return result
    }

    // ② 能力面：路由要的是 readiness + capabilities 原文，都来自 3b 的探测
    // 这一步是整条链路里最贵的（真机两次实测 11.2s / 10.9s：doctor 6s + capabilities 4s），
    // 而 analyze 本身只要 4.5s —— 分段计时就是为了不把这笔开销算到分析头上。
    report('routing', '探测远端能力面并选择 provider/operation')
    const probeAt = Date.now()
    const probe = await probeRemoteRea(engine, alias, { npxTimeoutMs })
    timings.probeMs = Date.now() - probeAt
    if (probe.ok !== true) {
      result.error = `能力面探测失败，无法路由：${oneLine(probe.error ?? '未知原因')}`
      report('failed', result.error)
      return finish()
    }
    const route = routeProvider(fetch.metadata, probe.readiness, probe.capabilities, { preferredProvider: provider, remotePath })
    result.route = route
    if (route.provider === null || route.subcommand === null) {
      result.error = route.reason
      report('no-route', result.error)
      return finish()
    }
    report('routed', `${route.provider}/${route.operation} → ${route.subcommand}${route.marker === null || route.marker === undefined ? '' : `（${route.marker}）`}`, {
      targetClass: route.targetClass,
      surface: route.surface ?? 'advertised',
      effects: route.reason.match(/effects=\[([^\]]*)\]/)?.[1] ?? '',
    })

    // ③ 下发分析（safeExec：提权闸门 + attempts=1，分析不重放）
    const command = `${analyzeCommand(fetch.deploy.command, route.subcommand, remotePath)} 2>&1`
    report('analyzing', `远端执行 ${route.subcommand}（${route.provider}/${route.operation}）`)
    const analyzeAt = Date.now()
    const run = await safeExec(engine, alias, command, ANALYZE_TIMEOUT_MS)
    timings.analyzeMs = Date.now() - analyzeAt
    const stdout = String(run.stdout ?? '')
    result.analysis = {
      command,
      exitCode: run.exitCode ?? null,
      timedOut: run.timedOut === true,
      durationMs: run.durationMs ?? null,
      stdoutBytes: Buffer.byteLength(stdout),
      progressRecords: 0,
      evidenceId: null,
      evidencePath: null,
      provider: null,
      operation: null,
      subjectFormat: null,
      dialect: null,
      findingCount: 0,
      unknownCount: 0,
      failure: null,
      evidence: null,
    }
    if (run.timedOut === true) {
      result.error = `分析超时（${ANALYZE_TIMEOUT_MS}ms 内没返回）：${route.subcommand}`
      report('failed', result.error)
      return finish()
    }

    // ④ 解析 + 当场回收
    const mapAt = Date.now()
    const parsed = parseReaOutput(stdout)
    result.analysis.progressRecords = parsed.progress.length
    if (parsed.error !== null) {
      result.error = `分析输出没解析出 JSON：${oneLine(parsed.error)}`
      report('failed', result.error)
      return finish()
    }
    const failure = reaFailure(parsed.evidence)
    if (failure !== null) {
      // 真机 exit=0 但回的是失败信封：这里按原文口径报错，remediation 不自己编
      result.analysis.failure = failure
      result.error = `REA 拒绝该目标：${failure.code ?? 'unknown'}${failure.constraint ? `/${failure.constraint}` : ''} —— ${oneLine(failure.message)}`
      report('failed', result.error)
      return finish()
    }
    const evidence = parsed.evidence
    result.analysis.evidence = evidence
    result.analysis.evidenceId = evidence.evidence_id
    result.analysis.provider = evidence?.provider?.id ?? null
    result.analysis.operation = evidence?.operation ?? null
    result.analysis.subjectFormat = evidence?.subject?.format ?? null
    result.analysis.dialect = dialectCounts(evidence)
    report('evidence', `Evidence ${evidence.evidence_id} 落盘`, { stdoutBytes: result.analysis.stdoutBytes })
    result.analysis.evidencePath = persistEvidence(evidence, { raw: parsed.evidence_raw })

    // ⑤ 映射 + 摘要（纯本地，第 3a 步的层）
    const findings = extractFindings(evidence, { host: String(alias ?? ''), artifact: remotePath })
    result.summary = buildSummary(findings, evidence, { evidencePath: result.analysis.evidencePath })
    result.analysis.findingCount = findings.length
    result.analysis.unknownCount = Array.isArray(result.summary.unknowns) ? result.summary.unknowns.length : 0
    timings.mapMs = Date.now() - mapAt
    report('summarized', `findings ${findings.length} 条 / unknowns ${result.analysis.unknownCount} 条`)

    result.ok = true
    report('finished', `分析完成：${result.analysis.provider}/${result.analysis.operation}，Evidence 已落盘`)
    return finish()
  } catch (error) {
    result.error = `分析失败：${oneLine(messageOf(error))}`
    report('failed', result.error)
    return finish()
  }
}
