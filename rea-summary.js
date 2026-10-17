// ============================================================================
// rea-summary.js —— AnalysisFinding[] → 结构化摘要（纯函数）
// ----------------------------------------------------------------------------
// 设计约定：默认只给摘要，细节不主动塞。
//   * coverage / unknowns / statistics / summary / limitations 原文透传，
//     不改写、不翻译、不压缩——REA 自己怎么说就怎么给。
//   * findings_by_kind 按 kind 分组，每组最多 maxFindingsPerGroup 条，
//     超出只计数（group_counts），不展开。
//   * 用户追问细节时凭 evidence_id + evidence_path 回到落盘的原始 Evidence。
// ============================================================================

import { readEvidenceMeta } from './rea-finding-extractor.js'

const DEFAULT_MAX_FINDINGS_PER_GROUP = 50

const obj = (v) => (v !== null && typeof v === 'object' && !Array.isArray(v) ? v : null)
const arr = (v) => (Array.isArray(v) ? v : [])
const str = (v) => (typeof v === 'string' && v.trim() !== '' ? v : null)

/**
 * AnalysisFinding[] → Summary。
 * evidencePath 由调用方传入（persistEvidence 的返回值）；本模块不做任何 I/O。
 */
export function buildSummary(findings, evidence, { maxFindingsPerGroup = DEFAULT_MAX_FINDINGS_PER_GROUP, evidencePath = null } = {}) {
  const meta = readEvidenceMeta(evidence)
  const limit = Number.isInteger(maxFindingsPerGroup) && maxFindingsPerGroup > 0 ? maxFindingsPerGroup : DEFAULT_MAX_FINDINGS_PER_GROUP

  const findingsByKind = {}
  const groupCounts = {}
  let truncatedFindings = false
  for (const finding of arr(findings)) {
    const entry = obj(finding)
    if (entry === null) continue
    const kind = str(entry.kind) ?? 'unknown'
    const group = (findingsByKind[kind] ??= [])
    groupCounts[kind] = (groupCounts[kind] ?? 0) + 1
    if (group.length < limit) group.push(entry)
    else truncatedFindings = true
  }

  const unknowns = []
  let truncatedUnknowns = false
  for (const raw of meta.unknowns) {
    const entry = obj(raw)
    if (entry === null) continue
    if (unknowns.length >= limit) {
      truncatedUnknowns = true
      continue
    }
    // 先展开原始条目：REA 多给的字段一律保留，再补齐摘要约定要用的键。
    unknowns.push({
      ...entry,
      family: str(entry.family) ?? '',
      reason: str(entry.reason) ?? '',
      detail: str(entry.detail) ?? '',
      node_id: str(entry.node_id ?? entry.id) ?? null,
      candidate_node_ids: arr(entry.candidate_node_ids),
    })
  }

  return {
    subject: {
      name: meta.subject.name,
      format: meta.subject.format,
      sha256: meta.subject.sha256,
      local_path: meta.subject.local_path,
    },
    provider: { id: meta.provider.id, name: meta.provider.name, version: meta.provider.version },
    operation: meta.operation,
    evidence_id: meta.evidence_id,
    evidence_path: str(evidencePath),
    // coverage 原文（status/truncated/omitted_*）一并保留，families 另补约定键。
    // 这里是 coverage 的唯一出处——extractFindings 不再为 family 生成占位 finding，摘要里不重复。
    coverage: {
      ...obj(meta.coverage),
      families: meta.coverageFamilies.map((raw) => ({
        ...obj(raw),
        family: str(raw?.family) ?? '',
        status: raw?.status ?? null,
        retained_relations: raw?.retained_relations ?? null,
        unknown_ids: arr(raw?.unknown_ids),
      })),
    },
    findings_by_kind: findingsByKind,
    // 每组的原始条数（截断前后都记这个），供「还有 N 条没展开」的追问。
    group_counts: groupCounts,
    unknowns,
    unknown_count: meta.unknowns.length,
    statistics: meta.statistics,
    summary: meta.summary,
    // Evidence 级限制（原文）；其余层级原文放在 limitations_by_scope，不合并、不改写。
    limitations: meta.limitations.evidence,
    limitations_by_scope: meta.limitations,
    truncated: { findings_by_kind: truncatedFindings, unknowns: truncatedUnknowns },
  }
}
