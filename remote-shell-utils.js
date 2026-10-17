// ============================================================================
// remote-shell-utils.js —— 远程 shell 的通用小工具
// ----------------------------------------------------------------------------
// 逻辑摘自 dsh-dolphin-security 的 dolphin-patrol.js 与 dolphin-core.js，
// 逐函数搬运、行为零改动，只做以下中性化：
//   * 模块内常量 PROBE_TIMEOUT → 本文件的 PROBE_TIMEOUT_MS，并可由调用方传参覆盖
//   * 注释中的具体业务示例改为通用的远程文件上传/引用场景
//   * assessDeploymentPlan 的策略名与 rationale 文案改写为本项目场景
//   * writeJsonReport 的 reportsDir 由参数传入（默认在调用时解析数据根），
//     不在 import 期求值任何目录常量
// engine 由调用方传入（见 remote-ssh-core.js 的 createSshEngine）。
// ============================================================================

import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { resolveReverseHome } from './remote-ssh-core.js'

// 探测类命令的默认时间预算（毫秒）。安装类命令由调用方传更大的预算。
const PROBE_TIMEOUT_MS = 8000

/**
 * POSIX shell 单引号转义。
 * 用户可控值在拼进远程命令字符串前必须转义，否则空格、$()、; 会注入命令。
 */
export function shellQuote(value) {
  const s = String(value)
  if (s === '') return "''"
  // 只含安全字符（路径 / 冒号 / 等号 / @ 等）时原样返回，可读性更好
  if (/^[A-Za-z0-9_./:=@%+,-]+$/.test(s)) return s
  return "'" + s.replace(/'/g, "'\\''") + "'"
}

/**
 * 报告落盘：统一「建目录 → 序列化 → 写文件」三步。
 * reportsDir 每次调用时解析（默认 <数据根>/reports），不依赖 import 期常量。
 */
export function writeJsonReport(reportsDir = defaultReportsDir(), fileName, payload) {
  const reportFile = join(reportsDir, fileName)
  mkdirSync(reportsDir, { recursive: true })
  writeFileSync(reportFile, JSON.stringify(payload, null, 2), 'utf8')
  return reportFile
}

/** 默认报告目录：$REVERSE_HOME（回退见 remote-ssh-core.js 的 resolveReverseHome）下的 reports。 */
export function defaultReportsDir(env = process.env) {
  return join(resolveReverseHome(env), 'reports')
}

// ============================================================================
// 远端临时目录探测 —— 统一 exec 与 SFTP 两条通道路径
// ----------------------------------------------------------------------------
// 背景（Windows 主机坑）：若远端默认 shell 是 Git Bash/MSYS，exec 通道的
// /tmp 映射到 C:\Users\<u>\AppData\Local\Temp（$TEMP），而 SFTP 走
// sftp-server.exe，其 /tmp 映射到 C:\tmp（/ 根 = 驱动器根 C:\）。两通道错位
// 会导致远程文件「上传到 C:\tmp、执行侧却去 TEMP 找」。实测（远端 Windows:22，
// Git Bash 默认 shell）：
//   exec(Git Bash) cygpath -w /tmp        → C:\Users\<user>\AppData\Local\Temp
//   sftp put /tmp/xx.txt                  → C:\tmp\xx.txt
//   sftp put /Users/<user>/.../Temp/xx.txt→ C:\Users\<user>\...\Temp\xx.txt（正确）
//   sftp put C:/Users/...                 → 失败（拼成 /C:/Users/<user>/C:/...）
//   sftp put /c/Users/...                 → 失败（MSYS 形式 sftp-server 不认）
// 因此 Windows 上：exec 用 /tmp（其映射即 TEMP），SFTP 用「去盘符 + 正斜杠」的
// Windows 原生路径（/Users/.../Temp）。Linux/macOS 上两者都用 /tmp，行为不变。
// ============================================================================
export async function detectRemoteTempBase(engine, alias, timeoutMs = PROBE_TIMEOUT_MS) {
  // cygpath 是 MSYS/Git Bash 的标志；无 cygpath 即 POSIX 环境
  const cyg = await engine.exec(
    alias,
    'command -v cygpath >/dev/null 2>&1 && printf MSYS || printf POSIX',
    timeoutMs,
    1,
  )
  const isMsys = cyg.success && cyg.stdout.includes('MSYS')
  if (!isMsys) return { execBase: '/tmp', sftpBase: '/tmp', platform: 'posix' }
  // 拿 Windows 原生临时目录，转成 sftp-server 能解析的形式（去盘符 + 正斜杠）
  let sftpBase = '/tmp'
  try {
    const w = await engine.exec(alias, 'cygpath -w /tmp', timeoutMs, 1)
    const winPath = (w.stdout || '').trim()
    if (winPath && /^[A-Za-z]:/.test(winPath)) {
      sftpBase = winPath.replace(/^[A-Za-z]:/, '').replace(/\\/g, '/')
    }
  } catch {
    // 探测失败退回 /tmp（行为与旧版一致，至少不崩）
  }
  return { execBase: '/tmp', sftpBase, platform: 'windows' }
}

// ============================================================================
// 远端能力探测 + 安全下发闸门
// ============================================================================

// 硬闸门：任何含提权/系统污染语义的命令一律拦截。
export function assertNoPrivilegeEscalation(command) {
  const s = String(command)
  if (/\bsudo\b/.test(s)) {
    throw new Error(`安全红线：检测到 sudo，已阻止下发 —— ${s.slice(0, 120)}`)
  }
  if (s.includes('--break-system-packages')) {
    throw new Error(`安全红线：检测到 --break-system-packages，已阻止下发 —— ${s.slice(0, 120)}`)
  }
  return true
}

// 统一的安全下发通道：所有部署类命令都必须走这里。
// attempts 固定为 1：下发前无法确认命令幂等，重试可能重复执行副作用。
export async function safeExec(engine, alias, command, timeoutMs) {
  assertNoPrivilegeEscalation(command)
  return engine.exec(alias, command, timeoutMs, 1)
}

// 探测远端某个能力是否存在（command -v 的探测命令，固定模板防注入）。
export async function probeHasCommand(engine, alias, bin, timeoutMs = PROBE_TIMEOUT_MS) {
  if (!/^[A-Za-z0-9_.-]+$/.test(bin)) throw new Error(`非法探测目标：${bin}`)
  const r = await safeExec(engine, alias, `command -v ${bin} >/dev/null 2>&1 && printf HAS || printf NONE`, timeoutMs)
  return r.success && r.stdout.includes('HAS')
}

// 风险/收益评估（纯函数）：在真正下发部署命令之前给出可读的预检结论。
export function assessDeploymentPlan(strategy, { uploadBytes = 0, remoteDownloadBytes = 0 } = {}) {
  const mb = (n) => `${(n / 1024 / 1024).toFixed(1)}MB`
  const base = { strategy, uploadBytes, remoteDownloadBytes }
  switch (strategy) {
    case 'preinstalled':
      return { ...base, riskLevel: '无', rationale: '远端已有目标命令，零部署成本' }
    case 'npx':
      return { ...base, riskLevel: '低', rationale: `上传 0 字节；远端从 npm registry 拉取 ≈${mb(remoteDownloadBytes)} 进 npx 用户级缓存，可复用、不碰全局包` }
    case 'npm-prefix':
      return { ...base, riskLevel: '低', rationale: `上传 0 字节；远端拉取 ≈${mb(remoteDownloadBytes)} 装入用户级 npm prefix，不写系统 site 目录` }
    case 'offline-tarball':
      return { ...base, riskLevel: '中（有上传流量）', rationale: `SFTP 上传 ≈${mb(uploadBytes)} 的离线包；远端仅解包到临时隔离目录引用，任务结束自动清理` }
    default:
      return { ...base, riskLevel: '未知', rationale: '未知策略' }
  }
}

// 时间戳（本地时区，YYYYMMDD-HHmmss）
export function timestamp() {
  const d = new Date()
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`
}
