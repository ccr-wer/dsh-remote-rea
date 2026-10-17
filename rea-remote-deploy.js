// ============================================================================
// rea-remote-deploy.js —— 远端 REA 的部署链决策（第 4 步：preinstalled → npx）
// ----------------------------------------------------------------------------
// 只到这两级，不做离线 tarball。产出的是「计划 + 预热结论」，不是实际分析：
// 后续步骤拿 command 当前缀、拿 timeoutMs 当预算即可。
// 三条实测依据（写在注释里省得再猜）：
//   * 冷缓存跑 npx：实测 75.0s / 76.3s / 82.6s 三个数，量级 1~2 分钟；热缓存 3.3s。
//   * 预热用 `--version` 而不是 `doctor --json`：stdout 6 字节（"6.5.0\\n"）、stderr 0。
//   * 缓存目录里只要有任何一个 hash（哪怕不是 rea-agents 的），
//     `ls ~/.npm/_npx/ | head -1` 就会说有缓存 —— 于是首次真跑静默付 76s。
//     因此这里探测的是 rea-agents 本身在不在，而不是 _npx 目录在不在。
// 约定：所有下发走 safeExec（内含提权闸门 + attempts=1，探测与预热都不重放）；
//       返回结构里不留任何原始 stdout/stderr 文本，错误信息一句话、不回显远端输出。
// 进度：可选 onProgress 回调，帧统一带 source:'warmup'（与 fastTransfer 的 done/error 区分）。
//       冷跑要 50~83s（离群 >420s），所以 warming 帧必须在 --version 下发之前发，
//       调用方不能事后转述 —— 转述就等于用户干等两分钟不知道在等什么。
// ============================================================================

import { assessDeploymentPlan, probeHasCommand, safeExec } from './remote-shell-utils.js'

const REA_PACKAGE = 'rea-agents@latest'
const GLOBAL_COMMAND = 'rea'
const NPX_COMMAND = `npx --yes ${REA_PACKAGE}`
// 探 rea-agents 是否已在 npx 缓存树里；空目录 / 不存在 / 无匹配都落到「没输出」。
const NPX_CACHE_PROBE = `ls -d ~/.npm/_npx/*/node_modules/rea-agents 2>/dev/null | head -1`

const GLOBAL_TIMEOUT_MS = 30000
const NPX_TIMEOUT_MS = 120000
const CACHE_PROBE_TIMEOUT_MS = 8000
const VERSION_PROBE_TIMEOUT_MS = 15000

// 量级估算（不求精确，回答的是「这策略大概要下多少」）：
// 实测隔离缓存跑一次后总占用 164MB（_npx 安装树 116MB + _cacache 增量）。
const NPX_DOWNLOAD_BYTES = 160 * 1024 * 1024

const str = (v) => (typeof v === 'string' && v.trim() !== '' ? v.trim() : null)

const messageOf = (error) => (error instanceof Error ? error.message : String(error))

const byteLen = (text) => Buffer.byteLength(String(text ?? ''))

/** 只取首个非空行里的版本号；整段输出不留。 */
function versionFromText(text) {
  const line = String(text ?? '').split('\n').map((l) => l.trim()).find((l) => l !== '')
  if (line === undefined) return null
  const m = line.match(/\d+(?:\.\d+){1,3}/)
  return m ? m[0] : line.slice(0, 40)
}

/** 预热失败的一句话：只报口径与量级，不回显远端输出。 */
function warmupFailure(errorPrefix, run, timeoutMs) {
  if (run.timedOut === true) return `${errorPrefix}超时（${timeoutMs}ms 内没跑完，多半是 registry 下载太慢）`
  if (run.exitCode === null || run.exitCode === undefined) return `${errorPrefix}失败（没有退出码，可能被信号杀掉或通道异常）`
  return `${errorPrefix}失败（exit=${run.exitCode}，stdout ${byteLen(run.stdout)}B / stderr ${byteLen(run.stderr)}B）`
}

/**
 * 规划远端 REA 的部署路径：preinstalled → npx → unavailable。
 * allowWarmup=false 时只出结论不动手（needsWarmup 仍为 true，首跑由调用方自己担预算）。
 * 不抛异常：任何失败都落到 error 字段，strategy 收成 'unavailable'。
 */
export async function planRemoteReaDeploy(engine, alias, { globalTimeoutMs = GLOBAL_TIMEOUT_MS, npxTimeoutMs = NPX_TIMEOUT_MS, allowWarmup = true, onProgress = () => {} } = {}) {
  const plan = {
    ok: false,
    strategy: 'unavailable',
    command: null,
    timeoutMs: globalTimeoutMs,
    needsWarmup: false,
    warmupResult: null,
    estimatedCost: { uploadBytes: 0, remoteDownloadBytes: 0 },
    error: null,
    // 附带的取证字段：都是计数或单值，不含远端原文
    reaVersion: null,
    cacheProbe: null,
    assessment: null,
  }
  const finish = () => {
    // unavailable 没有成本可评估；硬套 assessDeploymentPlan 只会得出「未知策略」这种没信息量的文案。
    if (plan.strategy === 'preinstalled' || plan.strategy === 'npx') {
      plan.assessment = assessDeploymentPlan(plan.strategy, plan.estimatedCost)
    }
    return plan
  }

  try {
    // ① 全局 rea 在不在
    let hasGlobal = false
    try {
      hasGlobal = await probeHasCommand(engine, alias, GLOBAL_COMMAND, CACHE_PROBE_TIMEOUT_MS)
    } catch (error) {
      plan.error = `SSH 不可达：${messageOf(error)}`
      return finish()
    }

    if (hasGlobal) {
      plan.strategy = 'preinstalled'
      plan.command = GLOBAL_COMMAND
      plan.timeoutMs = globalTimeoutMs
      plan.estimatedCost = { uploadBytes: 0, remoteDownloadBytes: 0 }
      // 确认版本：只取一行文本，不作为成败判据（跑不通由后续 doctor/capabilities 那步暴露）
      const run = await safeExec(engine, alias, `${GLOBAL_COMMAND} --version`, VERSION_PROBE_TIMEOUT_MS)
      plan.reaVersion = versionFromText(run.stdout)
      plan.ok = true
      return finish()
    }

    // ② npx 本身在不在 —— 没有 npx 就没有这两级里的任何一条路
    let hasNpx = false
    try {
      hasNpx = await probeHasCommand(engine, alias, 'npx', CACHE_PROBE_TIMEOUT_MS)
    } catch (error) {
      plan.error = `探测 npx 时 SSH 失败：${messageOf(error)}`
      return finish()
    }
    if (!hasNpx) {
      // 一句话给「怎么才能往下走」，不复述探测过程：这两级路都要求远端至少有一个能跑的 node 工具链。
      plan.error = '远端无 npx，请安装 Node.js 22.19+ 或全局安装 rea'
      return finish()
    }

    plan.strategy = 'npx'
    plan.command = NPX_COMMAND
    plan.timeoutMs = npxTimeoutMs
    plan.estimatedCost = { uploadBytes: 0, remoteDownloadBytes: NPX_DOWNLOAD_BYTES }

    // ③ 缓存探测：问的是 rea-agents 在不在缓存树里，不是 _npx 目录在不在
    const cache = await safeExec(engine, alias, NPX_CACHE_PROBE, CACHE_PROBE_TIMEOUT_MS)
    const cached = cache.success && cache.timedOut !== true && str(cache.stdout) !== null
    plan.cacheProbe = {
      command: NPX_CACHE_PROBE,
      cached,
      exitCode: cache.exitCode ?? null,
      timedOut: cache.timedOut === true,
      durationMs: cache.durationMs ?? null,
      stdoutBytes: byteLen(cache.stdout),
    }
    plan.needsWarmup = !cached
    if (cached) {
      plan.warmupResult = { ok: true, durationMs: cache.durationMs ?? 0, cached: true }
      onProgress({ source: 'warmup', phase: 'warmed', durationMs: cache.durationMs ?? 0, cached: true })
      plan.ok = true
      return finish()
    }

    // ④ 需要预热：allowWarmup=false 就止步于结论
    if (allowWarmup !== true) {
      plan.error = `未预热：远端没有 rea-agents 的 npx 缓存，首跑要付冷下载（实测 75~83s，预算 ${npxTimeoutMs}ms）`
      plan.ok = true
      return finish()
    }

    // 预热用 --version（6 字节输出），不用 doctor --json（5.5KB）
    // warming 必须在下发之前发：冷跑要 50~83s（离群 >420s），事后转述等于用户干等。
    onProgress({ source: 'warmup', phase: 'warming', timeoutMs: npxTimeoutMs })
    const warm = await safeExec(engine, alias, `${NPX_COMMAND} --version`, npxTimeoutMs)
    const warmOk = warm.success && warm.timedOut !== true
    plan.warmupResult = { ok: warmOk, durationMs: warm.durationMs ?? null, cached: false }
    onProgress({ source: 'warmup', phase: 'warmed', durationMs: warm.durationMs ?? null, cached: false, ok: warmOk })
    plan.reaVersion = versionFromText(warm.stdout)
    if (!warmOk) {
      // 预热失败直接失败，不再往下走
      plan.strategy = 'unavailable'
      plan.command = null
      plan.timeoutMs = globalTimeoutMs
      plan.estimatedCost = { uploadBytes: 0, remoteDownloadBytes: 0 }
      plan.error = warmupFailure('npx 预热', warm, npxTimeoutMs)
      return finish()
    }
    plan.ok = true
    return finish()
  } catch (error) {
    plan.strategy = 'unavailable'
    plan.error = `部署规划异常（已吞掉，不外抛）：${messageOf(error)}`
    return finish()
  }
}
