// ============================================================================
// rea-output-parser.js —— REA 输出的本地解析层（纯函数，不连 SSH、不调 REA）
// ----------------------------------------------------------------------------
// REA 的 stdout 有两类已知形态，都要能处理：
//   1. analyze 类：N 条 {"rea_progress":...} 行 + 最后一行才是完整 Evidence
//   2. doctor 类：npm 的 banner 文本混在 JSON 前面（单个 JSON 对象，可能多行）
// 进度行本身是合法 JSON，不能靠「解析失败就跳过」区分——按 key 显式跳过。
// Evidence 原文落盘到 <homeDir>/evidence/<evidence_id>.json，供用户追问细节时回查。
// 落盘优先用解析时顺手保留的原文行（evidence_raw），与 REA stdout 那一行逐字节相等——
// 重新 stringify 会丢掉 REA 自己的键序与数字写法，对账时无法证明「这就是它吐的那一行」。
// ============================================================================

import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { resolveReverseHome } from './remote-ssh-core.js'

const PROGRESS_KEY = 'rea_progress'

/** 顶层出现 rea_progress 这个 key（或其值/类型字段等于它）即视为进度行。 */
export function isProgressRecord(record) {
  if (record === null || typeof record !== 'object' || Array.isArray(record)) return false
  if (PROGRESS_KEY in record) return true
  const t = record.type ?? record.event ?? record.kind
  return t === PROGRESS_KEY
}

/**
 * 逐行解析 JSONL：跳过空行与进度行，取最后一个完整 JSON 对象作为 Evidence。
 * 若整段里没有一行能独立解析（多行美化 JSON / banner 混排），回退到
 * extractJsonFromMixedText 的「第一个 { 到最后一个 }」整体截取。
 * evidence_raw = 该结果对象在 stdout 里的原始字节（去掉行尾 \n，其余一字不改）。
 */
export function parseReaOutput(stdout) {
  const text = String(stdout ?? '')
  const progress = []
  let evidence = null
  let evidenceRaw = null
  let unparsed = 0
  // 按 \n 而非 \r?\n 切：CRLF 输入下留在行尾的 \r 属于那一行的字节，逐字节落盘时要带着它。
  for (const line of text.split('\n')) {
    const trimmed = line.trim()
    if (trimmed === '') continue
    let record
    try {
      record = JSON.parse(trimmed)
    } catch {
      unparsed++
      continue
    }
    if (record === null || typeof record !== 'object' || Array.isArray(record)) {
      unparsed++
      continue
    }
    if (isProgressRecord(record)) {
      progress.push(record)
      continue
    }
    evidence = record
    evidenceRaw = line
  }
  if (evidence === null && unparsed > 0) {
    const slice = jsonSliceOf(text)
    if (slice !== null) {
      evidence = slice.value
      evidenceRaw = slice.raw
    }
  }
  let error = null
  if (evidence === null) {
    error = text.includes('{')
      ? `未解析到结果 JSON：进度行 ${progress.length} 条，无法解析的行 ${unparsed} 条`
      : '输出中没有任何 JSON 对象（未出现 {）'
  }
  return { evidence, evidence_raw: evidenceRaw, progress, error }
}

/** banner 混排文本里的 JSON 区间：第一个 { 到最后一个 }，连同原始切片一起返回。截不出合法 JSON 返回 null。 */
function jsonSliceOf(text) {
  const start = text.indexOf('{')
  const end = text.lastIndexOf('}')
  if (start < 0 || end < start) return null
  const raw = text.slice(start, end + 1)
  try {
    return { raw, value: JSON.parse(raw) }
  } catch {
    return null
  }
}

/** 从 banner 混排的文本里截取 JSON 并解析，失败返回 null。 */
export function extractJsonFromMixedText(stdout) {
  return jsonSliceOf(String(stdout ?? ''))?.value ?? null
}

/**
 * 落盘原始 Evidence，返回落盘后的绝对路径。
 * 缺 evidence_id 直接抛错：绝不替 Evidence 编一个 ID（编出来的文件名无法回查）。
 * ID 还要过白名单——它来自外部工具输出，直接拼路径可被 ../ 或分隔符穿越目录。
 * raw（= parseReaOutput 的 evidence_raw）给出时按原始字节落盘，与 stdout 里那一行逐字节相等、
 * 不补行尾换行；raw 与 evidence 对不上则拒绝落盘——存进去一段「不是这份 Evidence 的原文」，
 * 比重新格式化更糟，因为它看起来像原件。没有 raw（程序内构造的 Evidence）才回退规范化 JSON。
 */
export function persistEvidence(evidence, { homeDir = resolveReverseHome(), env = process.env, raw = null } = {}) {
  if (evidence === null || typeof evidence !== 'object' || Array.isArray(evidence)) {
    throw new Error('persistEvidence：Evidence 必须是非数组对象')
  }
  const id = evidence.evidence_id
  if (typeof id !== 'string' || id.trim() === '') {
    throw new Error('persistEvidence：Evidence 缺少 evidence_id，拒绝落盘（不生成占位 ID）')
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(id)) {
    throw new Error(`persistEvidence：evidence_id 含非法字符，拒绝落盘 —— ${id.slice(0, 120)}`)
  }
  let content = JSON.stringify(evidence, null, 2)
  if (raw !== null && raw !== undefined) {
    const mismatch = rawMismatchReason(evidence, raw)
    if (mismatch !== null) throw new Error(`persistEvidence：${mismatch}，拒绝落盘`)
    content = raw
  }
  const dir = join(homeDir ?? resolveReverseHome(env), 'evidence')
  mkdirSync(dir, { recursive: true })
  const file = join(dir, `${id}.json`)
  writeFileSync(file, content, 'utf8')
  return file
}

/** raw 能不能代表这份 Evidence；能则返回 null。 */
function rawMismatchReason(evidence, raw) {
  if (typeof raw !== 'string') return 'raw 必须是字符串'
  let parsed
  try {
    parsed = JSON.parse(raw)
  } catch {
    return 'raw 不是合法 JSON，无法与 Evidence 对账'
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return 'raw 不是 JSON 对象'
  if (parsed.evidence_id !== evidence.evidence_id) {
    return `raw 的 evidence_id（${String(parsed.evidence_id).slice(0, 120)}）与 Evidence（${evidence.evidence_id}）不一致`
  }
  return null
}
