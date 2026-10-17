// ============================================================================
// rea-finding-extractor.js —— Evidence → AnalysisFinding[]（纯函数）
// ----------------------------------------------------------------------------
// REA 的真实结构（据 test/fixtures/rea-analyze-js-app.jsonl 核对）：
//   normalized_result.semantic_graph.{nodes,unknowns,fingerprints,relations,
//                                    evidence_contexts,coverage,limitations}
//   —— 注意是 semantic_graph（jsrg_*），不是 normalized_result.graph（jag_*，应用图）。
// 三条提取来源：
//   nodes[]        → 每个节点一条 finding
//   unknowns[]     → kind: 'unknown'，带 family/reason/detail/candidate_node_ids
//   fingerprints[] → 不单独成条，把 effects 与它自己的 context 合并回 function_node_id 那个节点
// coverage.families[] 不产出 finding：它是对「分析覆盖度」的整体陈述而非某处的发现，
// 原文只在 Summary.coverage.families 出现一次，不再在 finding 列表里重复一遍。
// 可信度三层（authority/state/confidence）不在节点上，而在 semantic_graph.evidence_contexts[]，
// 由节点的 evidence.context_id 反查；一个节点可能对应多个 context（自身 + 指纹），取最权威的。
// limitations 一律原文透传，不翻译、不改写。
// ============================================================================

const UNKNOWN = 'unknown'
const STATE_RANK = { observed: 0, inferred: 1, [UNKNOWN]: 2 }
const AUTHORITY_RANK = { 'artifact-bytes': 0, 'ast-static-analysis': 1, 'static-relationship-inference': 2, [UNKNOWN]: 3 }
const CONFIDENCE_RANK = { exact: 0, high: 1, [UNKNOWN]: 2 }
const RANK_FLOOR = 99

const obj = (v) => (v !== null && typeof v === 'object' && !Array.isArray(v) ? v : null)
const arr = (v) => (Array.isArray(v) ? v : [])
const str = (v) => (typeof v === 'string' && v.trim() !== '' ? v : null)
const rank = (table, value) => table[String(value)] ?? RANK_FLOOR

/** Evidence 里会被读到的各处元信息，一次抽干净，供提取与摘要共用。 */
export function readEvidenceMeta(evidence) {
  const ev = obj(evidence) ?? {}
  const nr = obj(ev.normalized_result) ?? {}
  const sg = obj(nr.semantic_graph) ?? obj(ev.semantic_graph) ?? {}
  const subject = obj(ev.subject) ?? obj(nr.subject) ?? {}
  const digest = obj(subject.digest) ?? {}
  const provider = obj(ev.provider) ?? obj(nr.provider) ?? {}
  return {
    evidence_id: str(ev.evidence_id) ?? null,
    operation: str(ev.operation ?? ev.operation_id ?? nr.operation) ?? null,
    subject: {
      name: str(subject.name) ?? null,
      format: str(subject.format ?? subject.type ?? ev.input_format) ?? null,
      sha256: str(digest.sha256 ?? subject.sha256) ?? null,
      local_path: str(subject.local_path ?? subject.path ?? ev.input_path ?? nr.input_path) ?? null,
    },
    provider: { id: str(provider.id) ?? null, name: str(provider.name) ?? null, version: str(provider.version) ?? null },
    nodes: arr(sg.nodes),
    unknowns: arr(sg.unknowns),
    fingerprints: arr(sg.fingerprints),
    relations: arr(sg.relations),
    coverage: sg.coverage ?? null,
    coverageFamilies: arr(sg.coverage?.families ?? obj(nr.coverage)?.families ?? obj(ev.coverage)?.families),
    contexts: arr(sg.evidence_contexts ?? ev.evidence_contexts ?? nr.evidence_contexts),
    statistics: obj(nr.statistics ?? ev.statistics) ?? {},
    summary: obj(nr.summary ?? ev.summary) ?? {},
    // 三个层级的 limitations 各自原文保存，取用规则见 findingLimitations()
    limitations: {
      evidence: arr(ev.limitations),
      normalized_result: arr(nr.limitations),
      semantic_graph: arr(sg.limitations),
    },
  }
}

/** context_id → evidence_contexts 条目。id 既可能是数组下标，也可能是字符串标识。 */
export function findContext(contexts, contextId) {
  const list = arr(contexts)
  if (typeof contextId === 'number') return obj(list[contextId])
  const id = str(contextId)
  if (id === null) return null
  for (const item of list) {
    const entry = obj(item)
    if (entry === null) continue
    if (str(entry.context_id) === id || str(entry.id) === id) return entry
  }
  return null
}

function trustOf(context) {
  const entry = obj(context)
  if (entry === null) return { authority: UNKNOWN, state: UNKNOWN, confidence: UNKNOWN }
  return {
    authority: str(entry.authority) ?? UNKNOWN,
    state: str(entry.state) ?? UNKNOWN,
    confidence: str(entry.confidence) ?? UNKNOWN,
  }
}

function compareTrust(a, b) {
  return (rank(STATE_RANK, a.state) - rank(STATE_RANK, b.state))
    || (rank(AUTHORITY_RANK, a.authority) - rank(AUTHORITY_RANK, b.authority))
    || (rank(CONFIDENCE_RANK, a.confidence) - rank(CONFIDENCE_RANK, b.confidence))
}

/**
 * 多个 context 条目里取最权威：先比 state（observed>inferred>unknown），再比 authority，最后比 confidence。
 * 表外取值一律记 RANK_FLOOR，避免 REA 将来加的新状态被当成最高。
 */
export function pickMostAuthoritative(contexts) {
  let best = null
  for (const entry of arr(contexts)) {
    if (obj(entry) === null) continue
    if (best === null || compareTrust(trustOf(entry), trustOf(best)) < 0) best = entry
  }
  return best
}

const trustOrUnknown = (context) => trustOf(context) ?? { authority: UNKNOWN, state: UNKNOWN, confidence: UNKNOWN }

/** 条目自己的证据引用：REA 放在 evidence.{context_id,location} 里，不是顶层 context_id。 */
const evidenceRefOf = (entry) => obj(entry?.evidence) ?? {}

/**
 * location：REA 用 {available, value} 信封，value.kind 有 source-range / artifact-path 两种，
 * available:false 一律按「无位置」出 null，不猜。
 */
function readLocation(entry, fallbackSource) {
  const envelope = obj(evidenceRefOf(entry).location)
  const direct = obj(entry.location) ?? obj(entry.span) ?? obj(entry.source_range) ?? obj(obj(entry.identity)?.source_range)
  const raw = envelope !== null ? (envelope.available === true ? obj(envelope.value) : null) : direct
  if (raw === null) return null
  const source = str(raw.source ?? raw.path ?? raw.file ?? raw.uri) ?? (str(obj(entry.identity)?.module_path) ?? fallbackSource)
  return { source, start: raw.start ?? raw.start_line ?? raw.from ?? null, end: raw.end ?? raw.end_line ?? raw.to ?? null }
}

const nodeIdOf = (node) => str(node.node_id ?? node.id) ?? null

/**
 * 节点级原文 sha：identity.artifact_sha256 是「这个节点所在那个文件」的 blob sha，
 * 与 baseFinding.artifact_sha256（根 subject.digest.sha256，整个产物目录）粒度不同，两者都要留。
 */
const artifactShaOf = (entry) => str(obj(entry?.identity)?.artifact_sha256 ?? entry?.artifact_sha256) ?? null

/** 指纹回指函数节点用的是 function_node_id；保留几种历史写法做兜底。 */
function fingerprintNodeId(fp) {
  return str(fp.function_node_id ?? fp.node_id ?? fp.subject_node_id ?? obj(fp.subject)?.node_id) ?? null
}

const fingerprintEffects = (fp) => arr(obj(fp.components)?.effects ?? fp.effects)

/**
 * 取用哪一层 limitations：条目自带（节点/指纹/unknown 常有）→ 其 context 的 limitations → 空。
 * 不回退到 Evidence 级数组：那是全局声明，逐条复制 12 遍会淹掉摘要，Summary 里原文单放一份。
 */
function findingLimitations(entry, context) {
  const own = arr(entry?.limitations)
  if (own.length > 0) return own
  return arr(obj(context)?.limitations)
}

function baseFinding(meta, host, artifact) {
  return {
    host,
    artifact,
    artifact_sha256: meta.subject.sha256 ?? '',
    // 节点级原文 sha：节点没有 identity 时保持 null，不拿根 sha 冒充。
    source_artifact_sha256: null,
    kind: '',
    name: '',
    provider: meta.provider.id ?? '',
    operation: meta.operation ?? '',
    location: null,
    authority: UNKNOWN,
    state: UNKNOWN,
    confidence: UNKNOWN,
    evidence_id: meta.evidence_id ?? '',
    node_id: null,
    effects: [],
    limitations: [],
  }
}

/**
 * Evidence → AnalysisFinding[]。
 * host 是 SSH alias（远程维度），artifact 省略时回退 subject.name → local_path → input_path。
 */
export function extractFindings(evidence, { host = '', artifact = null } = {}) {
  const meta = readEvidenceMeta(evidence)
  const resolvedArtifact = str(artifact) ?? meta.subject.name ?? meta.subject.local_path ?? ''
  const fallbackSource = meta.subject.local_path ?? resolvedArtifact
  const findings = []

  // 指纹先按目标节点归堆：effects 与指纹自带的 context 都要合并回那个节点。
  const byNode = new Map()
  // 节点 id → 该节点的原文 sha；unknown 条目自己没有 identity，靠它回指宿主节点。
  const shaByNodeId = new Map()
  for (const raw of meta.fingerprints) {
    const fp = obj(raw)
    if (fp === null) continue
    const id = fingerprintNodeId(fp)
    if (id === null) continue
    const bucket = byNode.get(id) ?? { effects: [], contexts: [] }
    bucket.effects.push(...fingerprintEffects(fp))
    const fpContext = findContext(meta.contexts, evidenceRefOf(fp).context_id ?? fp.context_id)
    if (fpContext !== null) bucket.contexts.push(fpContext)
    byNode.set(id, bucket)
  }

  for (const raw of meta.nodes) {
    const node = obj(raw)
    if (node === null) continue
    const id = nodeIdOf(node)
    const nodeSha = artifactShaOf(node)
    if (id !== null && nodeSha !== null) shaByNodeId.set(id, nodeSha)
    const bucket = (id !== null ? byNode.get(id) : undefined) ?? { effects: [], contexts: [] }
    const ownContext = findContext(meta.contexts, evidenceRefOf(node).context_id ?? node.context_id)
    const chosen = pickMostAuthoritative([...bucket.contexts, ...(ownContext === null ? [] : [ownContext])])
    const trust = trustOrUnknown(chosen)
    findings.push({
      ...baseFinding(meta, host, resolvedArtifact),
      kind: str(node.kind ?? node.type) ?? 'node',
      name: str(node.label ?? node.name ?? obj(node.properties)?.name) ?? '',
      location: readLocation(node, fallbackSource),
      authority: trust.authority,
      state: trust.state,
      confidence: trust.confidence,
      node_id: id,
      source_artifact_sha256: nodeSha,
      effects: [...new Set(bucket.effects)],
      limitations: findingLimitations(node, chosen),
    })
  }

  for (const raw of meta.unknowns) {
    const unknown = obj(raw)
    if (unknown === null) continue
    const chosen = pickMostAuthoritative([findContext(meta.contexts, evidenceRefOf(unknown).context_id ?? unknown.context_id)])
    const trust = trustOrUnknown(chosen)
    findings.push({
      ...baseFinding(meta, host, resolvedArtifact),
      kind: 'unknown',
      name: str(unknown.label ?? unknown.name) ?? str(unknown.family) ?? '',
      location: readLocation(unknown, fallbackSource),
      authority: trust.authority,
      state: trust.state,
      confidence: trust.confidence,
      node_id: nodeIdOf(unknown),
      // unknown 挂在哪个节点上，就沿用那个节点的原文 sha（追问时要能定位到具体那份文件）
      source_artifact_sha256: shaByNodeId.get(nodeIdOf(unknown) ?? '') ?? artifactShaOf(unknown),
      // coverage.families[].unknown_ids 指的就是这个 id，追问时要靠它串起「家族 → 未知项 → 候选节点」
      unknown_id: str(unknown.unknown_id ?? unknown.id) ?? null,
      limitations: findingLimitations(unknown, chosen),
      family: str(unknown.family) ?? '',
      reason: str(unknown.reason) ?? '',
      detail: str(unknown.detail) ?? '',
      relation_kinds: arr(unknown.relation_kinds),
      // 引用关系要留住：REA 没分析出来的东西常指向已分析出来的节点，是追问的入口。
      candidate_node_ids: arr(unknown.candidate_node_ids),
    })
  }

  return findings
}
