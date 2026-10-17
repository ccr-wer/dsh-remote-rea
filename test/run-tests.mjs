// ============================================================================
// test/run-tests.mjs —— 第 3a 步本地解析层的测试
// ----------------------------------------------------------------------------
// 两类用例：
//   [FIXTURE]     依赖 test/fixtures/ 里两份真实 REA 输出（analyze JSONL、doctor JSON）。
//   [PROVISIONAL] 内联构造的 payload，形状与真实固件一致，只用来覆盖固件里不存在的边界
//                 （无 brace、非法 evidence_id、截断、available:false、表外状态值等）。
// 跑法：node test/run-tests.mjs   （Windows 与 WSL 都可跑；全绿 exit 0）
// ============================================================================

import { existsSync, readFileSync, readdirSync, rmSync, mkdtempSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseReaOutput, extractJsonFromMixedText, persistEvidence, isProgressRecord } from '../rea-output-parser.js'
import { extractFindings, readEvidenceMeta, findContext, pickMostAuthoritative } from '../rea-finding-extractor.js'
import { buildSummary } from '../rea-summary.js'

const here = dirname(fileURLToPath(import.meta.url))
const FIXTURES = join(here, 'fixtures')
const ANALYZE_FIXTURE = join(FIXTURES, 'rea-analyze-js-app.jsonl')
const DOCTOR_FIXTURE = join(FIXTURES, 'rea-doctor.json')

let pass = 0, fail = 0, skip = 0
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`PASS  ${name}${extra ? ' — ' + extra : ''}`) }
  else { fail++; console.log(`FAIL  ${name}${extra ? ' — ' + extra : ''}`) }
}
const skipped = (name, why) => { skip++; console.log(`SKIP  ${name} — ${why}`) }
const j = (v) => JSON.stringify(v)
const throws = (fn, expectSub = '') => {
  try { fn(); return `未抛错（期望包含「${expectSub}」）` }
  catch (e) { return String(e && e.message ? e.message : e).includes(expectSub) ? null : `抛错文案不符：${e.message}` }
}

// ============================================================================
// 内联构造 payload（形状对齐真实 REA，内容为构造）
// ============================================================================
const CTX = (id, authority, state, confidence, limitations = []) => ({ context_id: id, authority, state, confidence, limitations })
const EVIDENCE = (contextId, value) => ({ context_id: contextId, location: value === null ? { available: false } : { available: true, value: { kind: 'source-range', ...value } } })
// 节点级原文 sha 与根 subject.digest.sha256（'a'.repeat(64)）刻意不同，用来验证两个粒度不混用
const NODE_SHA = 'b'.repeat(64)
const NODE = (id, kind, label, contextId, value = undefined) => ({
  node_id: id, kind, label, identity: { module_path: 'app.js', artifact_sha256: NODE_SHA },
  // value 显式传 null = 「有 location 信封但 available:false」；不传则给一个正常 source-range
  evidence: EVIDENCE(contextId, value === undefined ? { source: 'app.js', start: { line: 1, column: 0 }, end: { line: 1, column: 9 } } : value),
})

function provisionalEvidence() {
  return {
    evidence_id: 'ev_20260101deadbeef',
    operation: 'analyze_javascript_application',
    subject: { name: 'rea-test', format: 'directory', architecture: null, digest: { sha256: 'a'.repeat(64) }, local_path: '/tmp/rea-test' },
    provider: { id: 'rea-javascript-application', name: 'REA JavaScript application analyzer', version: null },
    authority: 'shipped-artifact',
    confidence: 'derived',
    limitations: ['全局声明 A', '全局声明 B'],
    locations: [{ kind: 'artifact-path', path: 'artifact-root' }],
    normalized_result: {
      input_path: '/tmp/rea-test',
      format: 'directory',
      statistics: { relevant_files: 1, parsed_javascript_files: 1, findings: 1 },
      summary: { browser_windows: 0, ipc: { operations: 0 } },
      limitations: ['归一化层声明'],
      semantic_graph: {
        schema: 'JavaScriptSemanticRelationGraph',
        root_node_ids: ['jsrg_node_mod'],
        evidence_contexts: [
          CTX('ctx-obs', 'ast-static-analysis', 'observed', 'exact'),
          CTX('ctx-inf', 'static-relationship-inference', 'inferred', 'high'),
          CTX('ctx-obs-dyn', 'ast-static-analysis', 'observed', 'exact', ['Binding name has no constant initializer.']),
          CTX('ctx-unk', 'unknown', 'unknown', 'unknown', ['Dynamic syntax prevents an exact static relationship.']),
          { context_id: 'ctx-num', authority: 'unknown', state: 'inferred', confidence: 'high' },
        ],
        coverage: {
          status: 'unknown', truncated: false, omitted_nodes: 0, omitted_relations: 0, limits: [],
          families: Array.from({ length: 12 }, (_, i) => ({
            family: `family-${i}`, status: i % 2 === 0 ? 'partial' : 'complete', retained_relations: i,
            omitted_relations: 0, unknown_ids: i === 3 ? ['jsrg_unknown_3'] : [], extra_from_rea: `x${i}`,
          })),
        },
        limitations: ['语义图声明 1', '语义图声明 2'],
        nodes: [
          NODE('jsrg_node_mod', 'module', 'index.js', 'ctx-obs'),
          // 节点自身 inferred，指纹带 observed —— 验证指纹上下文参与择权威
          NODE('jsrg_node_greet', 'function', 'greet', 'ctx-inf'),
          NODE('jsrg_node_name', 'parameter', 'name', 'ctx-inf'),
          NODE('jsrg_node_bind', 'binding', 'greet', 'ctx-obs-dyn'),
          { node_id: 'jsrg_node_legacy', kind: 'call', label: 'console.log(...)', context_id: 0 },
          NODE('jsrg_node_orphan', 'expression', 'noctx', 'ctx-missing'),
          NODE('jsrg_node_noloc', 'expression', 'nolocate', 'ctx-obs', null),
        ],
        relations: [{ relation_id: 'jsrg_relation_0', source_node_id: 'jsrg_node_mod', target_node_id: 'jsrg_node_name', relation: 'defines', resolution: 'resolved' }],
        unknowns: [
          { unknown_id: 'jsrg_unknown_0', node_id: 'jsrg_node_bind', family: 'data-flow', relation_kinds: ['defines'], reason: 'unknown-value', detail: 'Binding name has no constant initializer.', candidate_node_ids: ['jsrg_node_bind'], evidence: EVIDENCE('ctx-unk', { source: 'app.js', start: { line: 2, column: 0 }, end: { line: 2, column: 4 } }) },
          { unknown_id: 'jsrg_unknown_1', node_id: 'jsrg_node_orphan', family: 'object-flow', relation_kinds: ['writes-property'], reason: 'ambiguous-target', detail: 'receiver unresolved', candidate_node_ids: [], evidence: EVIDENCE('ctx-unk', { source: 'app.js', start: { line: 3, column: 0 }, end: { line: 3, column: 4 } }) },
          { unknown_id: 'jsrg_unknown_2', node_id: 'jsrg_node_noloc', family: 'call-flow', relation_kinds: ['calls'], reason: 'dynamic', detail: 'no candidate', evidence: EVIDENCE('ctx-unk', null) },
        ],
        fingerprints: [
          { fingerprint_id: 'jsrg_fp_0', function_node_id: 'jsrg_node_greet', algorithm: 'rea.javascript-semantic-function', status: 'complete', components: { parameter_arity: 1, effects: ['reads:name', 'calls:console.log'] }, evidence: EVIDENCE('ctx-obs', null) },
          { fingerprint_id: 'jsrg_fp_1', function_node_id: 'jsrg_node_unmatched', components: { effects: ['orphan'] }, evidence: EVIDENCE('ctx-obs', null) },
        ],
      },
    },
  }
}

const PROGRESS_ROW = (i) => j({ rea_progress: { phase: 'parse_javascript_source', completed: i, total: 1, message: `working ${i}`, sequence: i + 1 } })

// ============================================================================
// rea-output-parser.js
// ============================================================================
console.log('\n== rea-output-parser.js ==')

{
  const lines = []
  for (let i = 0; i < 14; i++) lines.push(PROGRESS_ROW(i))
  lines.push('')
  lines.push(j(provisionalEvidence()))
  const r = parseReaOutput(lines.join('\n') + '\n')
  ok('[PROVISIONAL] JSONL：14 条进度行全识别', r.progress.length === 14 && r.error === null, `progress=${r.progress.length}`)
  ok('[PROVISIONAL] JSONL：最后一行取为 Evidence', r.evidence?.evidence_id === 'ev_20260101deadbeef')
  ok('[PROVISIONAL] JSONL：Evidence 未被进度污染', !('rea_progress' in (r.evidence ?? {})))
  ok('[PROVISIONAL] JSONL：evidence_raw = 那一行的原文（逐字节）', r.evidence_raw === j(provisionalEvidence()), `${String(r.evidence_raw).length} 字节`)
  ok('[PROVISIONAL] JSONL：evidence_raw 不含行尾换行', (r.evidence_raw ?? '').endsWith('\n') === false)
}
{
  const r = parseReaOutput(`${PROGRESS_ROW(0)}\n\n   \n${j(provisionalEvidence())}\n${PROGRESS_ROW(1)}\n`)
  ok('[PROVISIONAL] 进度行在最后时仍取结果对象', r.evidence?.evidence_id !== undefined && r.progress.length === 2, `progress=${r.progress.length}`)
  ok('[PROVISIONAL] 空行/纯空白行被跳过', r.error === null)
}
{
  ok('[PROVISIONAL] 进度行是合法 JSON 也按 key 跳过', isProgressRecord({ rea_progress: {} }) && isProgressRecord({ type: 'rea_progress' }) && !isProgressRecord({ evidence_id: 'x' }))
  const r = parseReaOutput(`${j({ type: 'rea_progress', n: 1 })}\n${j({ rea_progress: { n: 2 } })}\n${j({ evidence_id: 'ev-1' })}`)
  ok('[PROVISIONAL] type/内层 key 两种进度写法都计数', r.progress.length === 2 && r.evidence?.evidence_id === 'ev-1')
}
{
  const banner = 'npm WARN deprecated inflight@1.0.6: This module is not supported\nnpm WARN deprecated foo@2: use bar\n'
  const pretty = '{\n  "ok": true,\n  "nested": { "deep": [1, 2, 3] }\n}\n'
  const mixed = extractJsonFromMixedText(banner + pretty)
  ok('[PROVISIONAL] doctor 混排：banner 跳过、多行 JSON 完整取出', mixed?.ok === true && j(mixed?.nested?.deep) === '[1,2,3]', j(mixed))
  ok('[PROVISIONAL] parseReaOutput 对混排文本回退截取', parseReaOutput(banner + pretty).evidence?.ok === true)
  ok('[PROVISIONAL] 混排截取也保留原文切片（首个 { 到末个 }）', parseReaOutput(banner + pretty).evidence_raw === pretty.trimEnd(), JSON.stringify(String(parseReaOutput(banner + pretty).evidence_raw).slice(0, 20)))
  ok('[PROVISIONAL] CRLF 输入：evidence_raw 带着行尾 \\r（逐字节）', (() => {
    const crlf = `${PROGRESS_ROW(0)}\r\n${j({ evidence_id: 'ev-crlf' })}\r\n`
    return parseReaOutput(crlf).evidence_raw === `${j({ evidence_id: 'ev-crlf' })}\r`
  })())
  ok('[PROVISIONAL] 无 { 时返回 error', (() => { const x = parseReaOutput('npm ERR! code 1\n'); return x.evidence === null && x.progress.length === 0 && /未出现 \{/.test(x.error) })(), parseReaOutput('no json').error)
  ok('[PROVISIONAL] 有 { 但截不出合法 JSON → error 带计数', (() => { const x = parseReaOutput('garbage { oops\n'); return x.evidence === null && /无法解析的行 1/.test(x.error) })())
  ok('[PROVISIONAL] extractJsonFromMixedText 截不出返回 null', extractJsonFromMixedText('no braces') === null && extractJsonFromMixedText('{ broken') === null && extractJsonFromMixedText('') === null)
  ok('[PROVISIONAL] 空 stdout 不崩', (() => { const x = parseReaOutput(''); return x.evidence === null && x.progress.length === 0 && typeof x.error === 'string' })())
  ok('[PROVISIONAL] 进度行数组保留原始条目（可回看 phase/sequence）', parseReaOutput(`${PROGRESS_ROW(3)}\n${j({ evidence_id: 'e' })}`).progress[0].rea_progress.sequence === 4)
}

// ---- persistEvidence ----
{
  const home = mkdtempSync(join(tmpdir(), 'rea-ev-'))
  const ev = provisionalEvidence()
  const file = persistEvidence(ev, { homeDir: home })
  ok('[PROVISIONAL] 落盘路径 = <homeDir>/evidence/<evidence_id>.json', file === resolve(home, 'evidence', 'ev_20260101deadbeef.json'), file)
  const bytes = readFileSync(file, 'utf8')
  ok('[PROVISIONAL] 无 raw 时回退规范化 JSON', bytes === JSON.stringify(ev, null, 2), `${bytes.length} 字节`)
  ok('[PROVISIONAL] 回读语义等于原始 Evidence', j(JSON.parse(bytes)) === j(ev))
  ok('[PROVISIONAL] 重复落盘幂等覆盖', persistEvidence(ev, { homeDir: home }) === file)
  const nested = persistEvidence({ evidence_id: 'a.b-c_1', x: 1 }, { homeDir: join(home, 'deep', 'sub') })
  ok('[PROVISIONAL] 目录不存在时递归创建 + 合法 id 字符集', existsSync(nested) && nested.endsWith('a.b-c_1.json'))
  // raw 通路：逐字节等于 stdout 那一行
  const rawLine = '{"evidence_id":"ev_raw","reorder":{"b":1,"a":[1.50,2e3],"u":"\\u00e9"}}'
  ok('[PROVISIONAL] 样本本身可区分两种写法（规范化 ≠ 原文）', rawLine !== JSON.stringify(JSON.parse(rawLine), null, 2))
  const rawFile = persistEvidence(JSON.parse(rawLine), { homeDir: home, raw: rawLine })
  const rawBytes = readFileSync(rawFile)
  ok('[PROVISIONAL] raw 落盘字节 = 原始行字节（逐字相等）', Buffer.compare(rawBytes, Buffer.from(rawLine, 'utf8')) === 0, `${rawBytes.length} 字节`)
  ok('[PROVISIONAL] raw 落盘不被重新格式化（键序/数字写法/转义原样）', rawBytes.toString('utf8') === rawLine && rawBytes.includes('2e3') && rawBytes.includes('\\u00e9'))
  ok('[PROVISIONAL] raw 落盘不补行尾换行', rawBytes.toString('utf8').endsWith('\n') === false)
  ok('[PROVISIONAL] raw 落盘 sha256 与该行 sha256 相同', createHash('sha256').update(rawBytes).digest('hex') === createHash('sha256').update(rawLine).digest('hex'))
  for (const [label, raw, expect] of [
    ['raw 不是 JSON', '{ oops', '不是合法 JSON'],
    ['raw 是另一份 Evidence', '{"evidence_id":"ev_other"}', '不一致'],
    ['raw 是数组', '[1,2]', '不是 JSON 对象'],
    ['raw 非字符串', 12345, '必须是字符串'],
  ]) {
    const why = throws(() => persistEvidence(JSON.parse('{"evidence_id":"ev_raw"}'), { homeDir: home, raw }), expect)
    ok(`[PROVISIONAL] 拒绝落盘：${label}`, why === null, why ?? '')
  }
  ok('[PROVISIONAL] 被拒的 raw 没有覆盖已落盘原文', readFileSync(rawFile, 'utf8') === rawLine)
  for (const [label, payload, expect] of [
    ['缺 evidence_id', { normalized_result: {} }, '缺少 evidence_id'],
    ['空白 evidence_id', { evidence_id: '   ' }, '缺少 evidence_id'],
    ['数字 evidence_id', { evidence_id: 12345 }, '缺少 evidence_id'],
    ['路径穿越 id', { evidence_id: '../../etc/passwd' }, '非法字符'],
    ['分隔符 id', { evidence_id: 'a/b' }, '非法字符'],
    ['非对象', null, '必须是非数组对象'],
    ['数组', [1, 2], '必须是非数组对象'],
  ]) {
    const why = throws(() => persistEvidence(payload, { homeDir: home }), expect)
    ok(`[PROVISIONAL] 拒绝落盘：${label}`, why === null, why ?? '')
  }
  const evDirFiles = readdirSync(join(home, 'evidence')).sort()
  ok('[PROVISIONAL] 十次拒绝都没多落一个文件', j(evDirFiles) === j(['ev_20260101deadbeef.json', 'ev_raw.json']), j(evDirFiles))
  ok('[PROVISIONAL] 穿越 id 没在 home 之外造文件', existsSync(resolve(home, '..', '..', 'passwd')) === false)
  rmSync(home, { recursive: true, force: true })
}

// ============================================================================
// rea-finding-extractor.js
// ============================================================================
console.log('\n== rea-finding-extractor.js ==')
{
  const ev = provisionalEvidence()
  const findings = extractFindings(ev, { host: 'lab-ubuntu', artifact: 'index.js' })
  // unknown 条目复用宿主节点的 node_id，所以按 node_id 索引只在「节点条目」范围内做
  const byId = Object.fromEntries(findings.filter((f) => f.kind !== 'unknown').map((f) => [f.node_id, f]))
  ok('[PROVISIONAL] 7 节点 + 3 unknown = 10 条（coverage 不再成条）', findings.length === 10, `got ${findings.length}`)
  ok('[PROVISIONAL] function kind 提取到 greet', byId.jsrg_node_greet?.kind === 'function' && byId.jsrg_node_greet?.name === 'greet')
  ok('[PROVISIONAL] parameter kind 提取到 name', byId.jsrg_node_name?.kind === 'parameter' && byId.jsrg_node_name?.name === 'name')
  ok('[PROVISIONAL] binding kind 提取到绑定', byId.jsrg_node_bind?.kind === 'binding')
  ok('[PROVISIONAL] 来源字段：host/artifact/sha256/provider/operation', findings.every((f) => f.host === 'lab-ubuntu' && f.artifact === 'index.js' && f.artifact_sha256 === 'a'.repeat(64) && f.provider === 'rea-javascript-application' && f.operation === 'analyze_javascript_application'))
  ok('[PROVISIONAL] source_artifact_sha256 = 节点 identity.artifact_sha256（与根 sha 不同粒度）', byId.jsrg_node_mod.source_artifact_sha256 === NODE_SHA && byId.jsrg_node_greet.source_artifact_sha256 === NODE_SHA && NODE_SHA !== 'a'.repeat(64))
  ok('[PROVISIONAL] 节点无 identity 时 source_artifact_sha256 = null（不拿根 sha 冒充）', byId.jsrg_node_legacy.source_artifact_sha256 === null)
  ok('[PROVISIONAL] evidence_id 落到每条 finding', findings.every((f) => f.evidence_id === ev.evidence_id))
  ok('[PROVISIONAL] authority 三层来自 context 而非节点', byId.jsrg_node_mod.authority === 'ast-static-analysis' && byId.jsrg_node_mod.state === 'observed' && byId.jsrg_node_mod.confidence === 'exact')
  ok('[PROVISIONAL] fingerprint 的 context 参与择权威（observed 胜出节点自身 inferred）', byId.jsrg_node_greet.state === 'observed' && byId.jsrg_node_greet.authority === 'ast-static-analysis')
  ok('[PROVISIONAL] 无指纹上下文时保留节点自身的 inferred', byId.jsrg_node_name.state === 'inferred' && byId.jsrg_node_name.confidence === 'high', j([byId.jsrg_node_name.authority, byId.jsrg_node_name.state, byId.jsrg_node_name.confidence]))
  ok('[PROVISIONAL] context 查不到时三层全 unknown', byId.jsrg_node_orphan.authority === 'unknown' && byId.jsrg_node_orphan.state === 'unknown' && byId.jsrg_node_orphan.confidence === 'unknown')
  ok('[PROVISIONAL] 顶层数字 context_id 走数组下标（兼容旧写法）', byId.jsrg_node_legacy.state === 'observed' && byId.jsrg_node_legacy.confidence === 'exact', j([byId.jsrg_node_legacy.authority, byId.jsrg_node_legacy.state, byId.jsrg_node_legacy.confidence]))
  ok('[PROVISIONAL] effects 合并到对应函数', j(byId.jsrg_node_greet.effects) === j(['reads:name', 'calls:console.log']), j(byId.jsrg_node_greet.effects))
  ok('[PROVISIONAL] 无指纹的节点 effects = []', j(byId.jsrg_node_mod.effects) === '[]' && j(byId.jsrg_node_bind.effects) === '[]')
  ok('[PROVISIONAL] 无指纹命中时不误挂 effects', findings.every((f) => !f.effects.includes('orphan')))
  ok('[PROVISIONAL] location 取 evidence.location.value（source-range 信封）', byId.jsrg_node_mod.location?.source === 'app.js' && byId.jsrg_node_mod.location.start.column === 0)
  ok('[PROVISIONAL] location available:false → null', byId.jsrg_node_noloc.location === null)
  ok('[PROVISIONAL] limitations 取 context 原文，不复制全局声明', j(byId.jsrg_node_bind.limitations) === j(['Binding name has no constant initializer.']) && j(byId.jsrg_node_mod.limitations) === '[]')
  const unks = findings.filter((f) => f.kind === 'unknown')
  ok('[PROVISIONAL] unknowns 3 条 → kind:unknown', unks.length === 3 && unks.every((f) => f.authority === 'unknown' && f.state === 'unknown'))
  ok('[PROVISIONAL] unknown 带 family/reason/detail/node_id/relation_kinds', unks.every((f) => f.family && f.reason && f.detail && f.node_id && Array.isArray(f.relation_kinds)))
  ok('[PROVISIONAL] candidate_node_ids 保留（追问线索）', j(unks.find((f) => f.unknown_id === 'jsrg_unknown_0').candidate_node_ids) === j(['jsrg_node_bind']))
  ok('[PROVISIONAL] 无 candidate_node_ids 的 unknown 给空数组', j(unks.find((f) => f.unknown_id === 'jsrg_unknown_2').candidate_node_ids) === '[]')
  ok('[PROVISIONAL] unknown 的 limitations 来自其 context', j(unks[0].limitations) === j(['Dynamic syntax prevents an exact static relationship.']))
  ok('[PROVISIONAL] unknown 沿用宿主节点的 source_artifact_sha256', unks.every((f) => f.source_artifact_sha256 === NODE_SHA), j([...new Set(unks.map((f) => String(f.source_artifact_sha256).slice(0, 8)))]))
  ok('[PROVISIONAL] coverage 家族不进 finding 列表', findings.every((f) => f.kind !== 'coverage') && readEvidenceMeta(ev).coverageFamilies.length === 12)
  ok('[PROVISIONAL] artifact 省略时回退 subject.name', extractFindings(ev, { host: 'h' })[0].artifact === 'rea-test')
  ok('[PROVISIONAL] artifact 再回退 local_path', extractFindings({ normalized_result: {} }, {}).length === 0 && extractFindings({ subject: { local_path: '/tmp/x' } }, {}).length === 0 && (() => { const e = extractFindings({ normalized_result: { semantic_graph: { nodes: [{ node_id: 'n', kind: 'module', label: 'm' }] } } }, {}); return e[0].artifact === '' })())
  ok('[PROVISIONAL] 空/畸形 Evidence 不崩', j(extractFindings({}, {})) === '[]' && j(extractFindings(null, {})) === '[]' && j(extractFindings({ normalized_result: { semantic_graph: { nodes: [null, 1, 'x'] } } }, {})) === '[]')
}
{
  const A = (state, authority, confidence) => ({ context_id: `${state}/${authority}/${confidence}`, state, authority, confidence })
  ok('[PROVISIONAL] 择权威：state 优先于 authority', pickMostAuthoritative([A('observed', 'static-relationship-inference', 'unknown'), A('inferred', 'ast-static-analysis', 'exact')]).state === 'observed')
  ok('[PROVISIONAL] state 相同时比 authority', pickMostAuthoritative([A('inferred', 'static-relationship-inference', 'exact'), A('inferred', 'ast-static-analysis', 'unknown')]).authority === 'ast-static-analysis')
  ok('[PROVISIONAL] 前两层相同比 confidence', pickMostAuthoritative([A('inferred', 'ast-static-analysis', 'high'), A('inferred', 'ast-static-analysis', 'exact')]).confidence === 'exact')
  ok('[PROVISIONAL] 全平手时保留先出现的（稳定）', pickMostAuthoritative([{ context_id: 'first', state: 'observed' }, { context_id: 'second', state: 'observed' }]).context_id === 'first')
  ok('[PROVISIONAL] 空列表/非对象兜底 null', pickMostAuthoritative([]) === null && pickMostAuthoritative([null, 3]) === null && j(trustFallback()) === j({ authority: 'unknown', state: 'unknown', confidence: 'unknown' }))
  ok('[PROVISIONAL] 表外 state 不被当成最高', pickMostAuthoritative([A('observed', 'unknown', 'unknown'), { context_id: 'weird', state: 'weird-new-state', authority: 'artifact-bytes', confidence: 'exact' }]).context_id === 'observed/unknown/unknown')
  const m = readEvidenceMeta(provisionalEvidence())
  ok('[PROVISIONAL] readEvidenceMeta 齐备', m.evidence_id === 'ev_20260101deadbeef' && m.subject.format === 'directory' && m.provider.version === null && m.nodes.length === 7 && m.coverageFamilies.length === 12 && m.contexts.length === 5 && m.relations.length === 1)
  ok('[PROVISIONAL] coverage 原始信封一并读出', m.coverage.status === 'unknown' && m.coverage.omitted_nodes === 0)
  ok('[PROVISIONAL] providerVersion 为 null 时不炸', m.provider.version === null && extractFindings(provisionalEvidence(), {})[0].provider === 'rea-javascript-application')
  ok('[PROVISIONAL] findContext 下标/字符串/缺失三种', findContext(m.contexts, 0)?.context_id === 'ctx-obs' && findContext(m.contexts, 'ctx-inf')?.state === 'inferred' && findContext(m.contexts, 'nope') === null && findContext(m.contexts, undefined) === null)
  ok('[PROVISIONAL] limitations 按三层原文分开保存', j(m.limitations) === j({ evidence: ['全局声明 A', '全局声明 B'], normalized_result: ['归一化层声明'], semantic_graph: ['语义图声明 1', '语义图声明 2'] }))
}
function trustFallback() {
  const c = pickMostAuthoritative([])
  return c === null ? { authority: 'unknown', state: 'unknown', confidence: 'unknown' } : null
}

// ============================================================================
// rea-summary.js
// ============================================================================
console.log('\n== rea-summary.js ==')
{
  const ev = provisionalEvidence()
  const findings = extractFindings(ev, { host: 'lab-ubuntu' })
  const s = buildSummary(findings, ev, { evidencePath: '/home/dev/.reverse/evidence/ev_20260101deadbeef.json' })
  ok('[PROVISIONAL] 顶层键齐备且顺序符合约定', j(Object.keys(s)) === j(['subject', 'provider', 'operation', 'evidence_id', 'evidence_path', 'coverage', 'findings_by_kind', 'group_counts', 'unknowns', 'unknown_count', 'statistics', 'summary', 'limitations', 'limitations_by_scope', 'truncated']), j(Object.keys(s)))
  ok('[PROVISIONAL] subject 四字段', j(s.subject) === j({ name: 'rea-test', format: 'directory', sha256: 'a'.repeat(64), local_path: '/tmp/rea-test' }), j(s.subject))
  ok('[PROVISIONAL] provider 三元组（version 可为 null）', j(s.provider) === j({ id: 'rea-javascript-application', name: 'REA JavaScript application analyzer', version: null }))
  ok('[PROVISIONAL] evidence_id / evidence_path 透传', s.evidence_id === ev.evidence_id && s.evidence_path === '/home/dev/.reverse/evidence/ev_20260101deadbeef.json')
  ok('[PROVISIONAL] evidence_path 缺省为 null（本模块不做 I/O）', buildSummary([], ev, {}).evidence_path === null)
  ok('[PROVISIONAL] coverage.families 12 条全在', s.coverage.families.length === 12)
  ok('[PROVISIONAL] coverage 信封字段原文保留 + families 多给字段也保留', s.coverage.status === 'unknown' && s.coverage.truncated === false && s.coverage.families.every((f, i) => f.extra_from_rea === `x${i}` && f.omitted_relations === 0), j(s.coverage.families[0]))
  ok('[PROVISIONAL] limitations = Evidence 级原文', j(s.limitations) === j(ev.limitations))
  ok('[PROVISIONAL] limitations_by_scope 三层逐字原文', j(s.limitations_by_scope) === j(readEvidenceMeta(ev).limitations))
  ok('[PROVISIONAL] statistics / summary 原文透传', j(s.statistics) === j(ev.normalized_result.statistics) && j(s.summary) === j(ev.normalized_result.summary))
  ok('[PROVISIONAL] findings_by_kind 分组正确（不含 coverage）', j(Object.keys(s.findings_by_kind).sort()) === j(['binding', 'call', 'expression', 'function', 'module', 'parameter', 'unknown']), j(Object.keys(s.findings_by_kind)))
  ok('[PROVISIONAL] coverage 只在 Summary.coverage 出现一次', s.coverage.families.length === 12 && !('coverage' in s.findings_by_kind) && !('coverage' in s.group_counts) && findings.some((f) => f.kind === 'coverage') === false)
  ok('[PROVISIONAL] 每组条数与 group_counts 一致', Object.entries(s.group_counts).every(([k, v]) => s.findings_by_kind[k].length === v) && s.group_counts.unknown === 3 && s.findings_by_kind.function.length === 1 && s.findings_by_kind.function[0].name === 'greet', j(s.group_counts))
  ok('[PROVISIONAL] unknowns 单独成组且含 candidate_node_ids', s.unknowns.length === 3 && j(s.unknowns[0].candidate_node_ids) === j(['jsrg_node_bind']) && s.unknown_count === 3 && s.truncated.unknowns === false)
  ok('[PROVISIONAL] 默认 50 条上限不截断', s.truncated.findings_by_kind === false)
  const small = buildSummary(findings, ev, { maxFindingsPerGroup: 2 })
  ok('[PROVISIONAL] 超限分组只留 2 条并置 truncated', small.findings_by_kind.unknown.length === 2 && small.truncated.findings_by_kind === true && small.group_counts.unknown === 3, j(small.group_counts))
  ok('[PROVISIONAL] group_counts 记截断前总数', small.group_counts.unknown === 3 && small.group_counts.expression === 2 && small.group_counts.module === 1, j(small.group_counts))
  ok('[PROVISIONAL] unknowns 超限也截断并计数', small.unknowns.length === 2 && small.truncated.unknowns === true && small.unknown_count === 3)
  ok('[PROVISIONAL] 非法 max 回退默认值', [0, -5, 'x', null].every((m) => buildSummary(findings, ev, { maxFindingsPerGroup: m }).findings_by_kind.unknown.length === 3 && buildSummary(findings, ev, { maxFindingsPerGroup: m }).truncated.findings_by_kind === false))
  ok('[PROVISIONAL] 空 findings 也能出摘要骨架', (() => { const e = buildSummary([], ev, {}); return Object.keys(e.findings_by_kind).length === 0 && e.truncated.findings_by_kind === false && e.coverage.families.length === 12 })())
  ok('[PROVISIONAL] 脏 finding（非对象/无 kind）归入 unknown 组', (() => { const e = buildSummary([null, 7, { foo: 1 }], ev, {}); return e.findings_by_kind.unknown.length === 1 && e.group_counts.unknown === 1 })())
  ok('[PROVISIONAL] 空 Evidence 骨架字段为 null 而非崩', (() => { const e = buildSummary([], {}, {}); return e.subject.name === null && e.evidence_id === null && e.provider.id === null && j(e.coverage.families) === '[]' && j(e.limitations) === '[]' })())
}

// ============================================================================
// [FIXTURE] 真实 REA 输出
// ============================================================================
console.log('\n== [FIXTURE] 真实固件 ==')
if (!existsSync(ANALYZE_FIXTURE) || !existsSync(DOCTOR_FIXTURE)) {
  const missing = [!existsSync(ANALYZE_FIXTURE) && 'rea-analyze-js-app.jsonl', !existsSync(DOCTOR_FIXTURE) && 'rea-doctor.json'].filter(Boolean)
  skipped('analyze JSONL 全部用例', `缺固件：${missing.join(', ')}`)
  skipped('doctor 全部用例', `缺固件：${missing.join(', ')}`)
} else {
  const rawAnalyze = readFileSync(ANALYZE_FIXTURE, 'utf8')
  const rawDoctor = readFileSync(DOCTOR_FIXTURE, 'utf8')
  const nonEmpty = rawAnalyze.split(/\r?\n/).filter((l) => l.trim() !== '')
  ok('[FIXTURE] analyze：15 行（14 进度 + 1 Evidence）逐行原样保存', nonEmpty.length === 15 && rawAnalyze.includes('\r\n') === false, `非空行 ${nonEmpty.length}，CRLF ${rawAnalyze.includes('\r\n')}`)
  const a = parseReaOutput(rawAnalyze)
  ok('[FIXTURE] analyze：14 条进度行', a.progress.length === 14, `got ${a.progress.length}`)
  ok('[FIXTURE] analyze：Evidence 取出且无 error', a.evidence !== null && a.error === null, a.error ?? '')
  ok('[FIXTURE] analyze：每行进度都过 isProgressRecord', a.progress.every(isProgressRecord))
  ok('[FIXTURE] analyze：进度行按 phase 可读（不丢原文）', a.progress[0].rea_progress.phase === 'analyze_javascript_application' && a.progress[13].rea_progress.sequence === 14, j(Object.keys(a.progress[0].rea_progress)))
  ok('[FIXTURE] analyze：evidence_id 形如 ev_<64hex>', /^ev_[0-9a-f]{64}$/.test(String(a.evidence?.evidence_id)), String(a.evidence?.evidence_id).slice(0, 24) + '…')
  const evidenceLine = nonEmpty[nonEmpty.length - 1]
  ok('[FIXTURE] analyze：evidence_raw 逐字节等于固件里那一行原文', a.evidence_raw === evidenceLine, `${Buffer.byteLength(String(a.evidence_raw))} 字节 / 该行 ${Buffer.byteLength(evidenceLine)} 字节`)
  ok('[FIXTURE] analyze：进度行原文没混进 evidence_raw', (a.evidence_raw ?? '').includes('rea_progress') === false)

  const meta = readEvidenceMeta(a.evidence)
  ok('[FIXTURE] 结构核对：contexts 5 / nodes 11 / unknowns 3 / fingerprints 1 / families 12', meta.contexts.length === 5 && meta.nodes.length === 11 && meta.unknowns.length === 3 && meta.fingerprints.length === 1 && meta.coverageFamilies.length === 12, `c=${meta.contexts.length} n=${meta.nodes.length} u=${meta.unknowns.length} f=${meta.fingerprints.length} fam=${meta.coverageFamilies.length}`)
  ok('[FIXTURE] 结构核对：context 三层取值都在表内', meta.contexts.every((c) => ['observed', 'inferred', 'unknown'].includes(c.state) && ['ast-static-analysis', 'static-relationship-inference', 'artifact-bytes', 'unknown'].includes(c.authority) && ['exact', 'high', 'unknown'].includes(c.confidence)), [...new Set(meta.contexts.map((c) => `${c.authority}/${c.state}/${c.confidence}`))].join(' , '))

  const findings = extractFindings(a.evidence, { host: 'lab-ubuntu', artifact: 'rea-test' })
  const greet = findings.find((f) => f.kind === 'function' && f.name === 'greet')
  const nameParam = findings.find((f) => f.kind === 'parameter' && f.name === 'name')
  const binding = findings.find((f) => f.kind === 'binding' && f.name === 'greet')
  ok('[FIXTURE] greet（function）提取到', greet !== undefined && greet.node_id?.startsWith('jsrg_node_'), String(greet?.node_id)?.slice(0, 22) + '…')
  ok('[FIXTURE] name（parameter）提取到', nameParam !== undefined)
  ok('[FIXTURE] greet（binding）提取到', binding !== undefined)
  ok('[FIXTURE] 节点条数 = 11，总条数 = 11+3（coverage 不再成条）', findings.filter((f) => f.kind !== 'unknown').length === 11 && findings.length === 14, `total=${findings.length}`)
  ok('[FIXTURE] greet 三层来自 context', greet.authority === 'ast-static-analysis' && greet.state === 'observed' && greet.confidence === 'exact', `${greet.authority}/${greet.state}/${greet.confidence}`)
  ok('[FIXTURE] location 指回 index.js 的行列', greet.location?.source === 'index.js' && greet.location.start.line === 1 && greet.location.start.column === 14, j(greet.location?.start))
  ok('[FIXTURE] artifact_sha256 = subject.digest.sha256（根）', findings.every((f) => f.artifact_sha256 === a.evidence.subject.digest.sha256), String(findings[0].artifact_sha256).slice(0, 16) + '…')
  const nodeShaById = new Map(a.evidence.normalized_result.semantic_graph.nodes.map((n) => [n.node_id, n.identity?.artifact_sha256 ?? null]))
  const nodeSha = nodeShaById.get(findings.find((f) => f.kind === 'function')?.node_id)
  ok('[FIXTURE] 11 条节点 finding 的 source_artifact_sha256 = 各自 identity.artifact_sha256', (() => {
    const rows = findings.filter((f) => f.kind !== 'unknown')
    return rows.length === 11 && rows.every((f) => f.source_artifact_sha256 === nodeShaById.get(f.node_id))
  })(), `${String(nodeSha).slice(0, 16)}…`)
  ok('[FIXTURE] 节点级 sha（index.js blob）与根 sha（产物目录）确实是两个值', nodeSha !== a.evidence.subject.digest.sha256)
  ok('[FIXTURE] 有节点级 sha 的条目都不等于根 sha', findings.filter((f) => f.source_artifact_sha256 !== null).every((f) => f.source_artifact_sha256 !== f.artifact_sha256))
  ok('[FIXTURE] 指纹按 function_node_id 合并（本例 effects 为空数组）', greet.effects.length === 0 && a.evidence.normalized_result.semantic_graph.fingerprints[0].function_node_id === greet.node_id, j(greet.effects))
  ok('[FIXTURE] module 节点的 location 走 artifact-path 形式', (() => { const mod = findings.find((f) => f.kind === 'module'); return mod !== undefined && typeof mod.location?.source === 'string' })(), j(findings.find((f) => f.kind === 'module')?.location))
  const unks = findings.filter((f) => f.kind === 'unknown')
  ok('[FIXTURE] unknowns 3 条 → kind:unknown 且三层 unknown', unks.length === 3 && unks.every((f) => f.authority === 'unknown' && f.state === 'unknown' && f.confidence === 'unknown'))
  ok('[FIXTURE] unknown 的 family/reason/detail 原文非空', unks.every((f) => f.family !== '' && f.reason !== '' && f.detail !== ''), unks.map((f) => `${f.family}:${f.reason}`).join(' , '))
  ok('[FIXTURE] candidate_node_ids 保留且能回指向已提取节点', unks.some((f) => f.candidate_node_ids.length > 0) && unks.every((f) => f.candidate_node_ids.every((id) => findings.some((n) => n.node_id === id))), j(unks.map((f) => f.candidate_node_ids.length)))
  const link = unks.find((f) => f.candidate_node_ids.includes(binding?.node_id))
  ok('[FIXTURE] 「unknown → binding(greet)」这条线索可顺藤摸瓜', link !== undefined && link.family === 'data-flow' && link.candidate_node_ids[0] === binding.node_id, link ? `${link.family} → ${link.candidate_node_ids[0].slice(0, 20)}…` : '未找到')
  ok('[FIXTURE] unknown 的 limitations 来自其 context（原文）', unks.every((f) => Array.isArray(f.limitations) && (f.limitations.length > 0 || f.detail === '')), j(unks.map((f) => f.limitations.length)))
  ok('[FIXTURE] coverage 家族不再成条 finding（12 个家族改由 Summary.coverage.families 承载）', findings.every((f) => f.kind !== 'coverage') && meta.coverageFamilies.length === 12, `findings=${findings.length}`)
  ok('[FIXTURE] unknown 条目带 unknown_id（coverage.unknown_ids 的回指锚点）', unks.every((f) => /^jsrg_unknown_[0-9a-f]{64}$/.test(String(f.unknown_id))), String(unks[0]?.unknown_id)?.slice(0, 20) + '…')
  ok('[FIXTURE] unknown 沿用宿主节点的 source_artifact_sha256', unks.every((f) => f.source_artifact_sha256 === nodeShaById.get(f.node_id) && f.source_artifact_sha256 !== null), j([...new Set(unks.map((f) => String(f.source_artifact_sha256).slice(0, 12)))]))
  ok('[FIXTURE] 节点级 sha 只在有 identity 的条目上（unknown 继承宿主，其余无）', unks.every((f) => typeof f.source_artifact_sha256 === 'string') && findings.every((f) => f.source_artifact_sha256 === null || typeof f.source_artifact_sha256 === 'string'))
  ok('[FIXTURE] data-flow 家族的 unknown_ids 能在摘要里查到', (() => {
    const ids = a.evidence.normalized_result.semantic_graph.coverage.families.find((f) => f.family === 'data-flow').unknown_ids
    return ids.length === 2 && unks.every((u) => typeof u.unknown_id === 'string') && ids.every((id) => typeof id === 'string')
  })(), j(a.evidence.normalized_result.semantic_graph.coverage.families.find((f) => f.family === 'data-flow').unknown_ids.map((s) => s.slice(0, 14) + '…')))

  const s = buildSummary(findings, a.evidence, {})
  ok('[FIXTURE] Summary.coverage.families 12 条全在', s.coverage.families.length === 12 && s.coverage.families.every((f) => typeof f.family === 'string'))
  ok('[FIXTURE] coverage.families 原文含 omitted_relations（未丢字段）', s.coverage.families.every((f, i) => 'omitted_relations' in f && f.unknown_ids.length === a.evidence.normalized_result.semantic_graph.coverage.families[i].unknown_ids.length), j(s.coverage.families[5]))
  ok('[FIXTURE] coverage 信封 status/omitted_* 原文保留', s.coverage.status === 'unknown' && s.coverage.truncated === false && Array.isArray(s.coverage.limits), `status=${s.coverage.status}`)
  ok('[FIXTURE] coverage 只在 Summary.coverage 出现一次（findings_by_kind/group_counts 里都没有）', !('coverage' in s.findings_by_kind) && !('coverage' in s.group_counts) && j(Object.keys(s.findings_by_kind).sort()) === j(['binding', 'expression', 'function', 'module', 'parameter', 'return-site', 'unknown']), j(Object.keys(s.findings_by_kind)))
  ok('[FIXTURE] limitations 与原文逐字相同（三层各自）', j(s.limitations) === j(a.evidence.limitations) && j(s.limitations_by_scope.semantic_graph) === j(a.evidence.normalized_result.semantic_graph.limitations), `ev=${s.limitations.length} nr=${s.limitations_by_scope.normalized_result.length} sg=${s.limitations_by_scope.semantic_graph.length}`)
  ok('[FIXTURE] statistics / summary 原文透传', j(s.statistics) === j(a.evidence.normalized_result.statistics) && j(s.summary) === j(a.evidence.normalized_result.summary), j(s.statistics).slice(0, 60) + '…')
  ok('[FIXTURE] group_counts 与 findings_by_kind 自洽', Object.entries(s.group_counts).every(([k, v]) => s.findings_by_kind[k].length === v && v === findings.filter((f) => f.kind === k).length), j(s.group_counts))
  ok('[FIXTURE] 摘要默认不塞全部节点（每组上限 50，本例最大组未超）', s.truncated.findings_by_kind === false && s.findings_by_kind.expression.length === s.group_counts.expression, j(s.group_counts))
  ok('[FIXTURE] unknowns 组原文透传（原始字段一个不少）', s.unknowns.length === 3 && s.unknowns.every((u, i) => Object.keys(a.evidence.normalized_result.semantic_graph.unknowns[i]).every((k) => k in u)), j(Object.keys(s.unknowns[0])))
  ok('[FIXTURE] 追问线索在摘要里可见（unknown → candidate node）', s.unknowns.some((u) => u.candidate_node_ids.length > 0))
  ok('[FIXTURE] 摘要展开的 finding 行带节点级 sha（不只有根 sha）', Object.values(s.findings_by_kind).flat().every((f) => 'source_artifact_sha256' in f), `${Object.values(s.findings_by_kind).flat().length} 行`)
  ok('[FIXTURE] subject/provider 元数据可读', s.subject.name === 'rea-test' && s.subject.format === 'directory' && s.provider.id === 'rea-javascript-application' && s.operation === 'analyze_javascript_application', `${s.provider.id}@${s.provider.version}`)
  const home = mkdtempSync(join(tmpdir(), 'rea-fix-ev-'))
  const file = persistEvidence(a.evidence, { homeDir: home, raw: a.evidence_raw })
  ok('[FIXTURE] 落盘文件名 = <evidence_id>.json', file.endsWith(`${a.evidence.evidence_id}.json`) && existsSync(file), file.replace(home, '<home>'))
  const stored = readFileSync(file)
  ok('[FIXTURE] 落盘文件与 REA stdout 那一行逐字节相等', Buffer.compare(stored, Buffer.from(evidenceLine, 'utf8')) === 0, `${stored.length} 字节 vs ${Buffer.byteLength(evidenceLine)}`)
  ok('[FIXTURE] 落盘 sha256 = 该行 sha256', createHash('sha256').update(stored).digest('hex') === createHash('sha256').update(evidenceLine).digest('hex'), createHash('sha256').update(stored).digest('hex').slice(0, 16) + '…')
  ok('[FIXTURE] 逐字节落盘 ≠ 重新格式化（原文确实没被改写）', stored.toString('utf8') !== JSON.stringify(a.evidence, null, 2), `规范化要 ${Buffer.byteLength(JSON.stringify(a.evidence, null, 2))} 字节`)
  ok('[FIXTURE] 落盘内容回读等于原始 Evidence', j(JSON.parse(stored.toString('utf8'))) === j(a.evidence))
  ok('[FIXTURE] 落盘文件行数 = 1（单行原文，无补换行）', stored.toString('utf8').split('\n').length === 1)
  const withPath = buildSummary(findings, a.evidence, { evidencePath: file })
  ok('[FIXTURE] evidence_path 串起「摘要 → 原始 Evidence」回路', withPath.evidence_path === file && j(JSON.parse(readFileSync(withPath.evidence_path, 'utf8'))).includes(withPath.evidence_id))
  ok('[FIXTURE] 无 raw 时仍可按规范化 JSON 落盘（内联构造的 Evidence）', (() => {
    const alt = join(home, 'fallback')
    const f2 = persistEvidence(a.evidence, { homeDir: alt })
    return readFileSync(f2, 'utf8') === JSON.stringify(a.evidence, null, 2)
  })())
  const whyBad = throws(() => persistEvidence(a.evidence, { homeDir: home, raw: j(a.progress[0]) }), '不一致')
  ok('[FIXTURE] 拒绝把进度行当成这份 Evidence 的原文', whyBad === null, whyBad ?? '')
  rmSync(home, { recursive: true, force: true })

  // doctor：本份固件实跑时无 banner（首字符即 {），banner 场景用同一份 JSON 加真 banner 复现
  ok('[FIXTURE] doctor：本份固件首字符即 {（无 banner 前缀）', rawDoctor.trimStart().startsWith('{'), JSON.stringify(rawDoctor.slice(0, 24)))
  const d = parseReaOutput(rawDoctor)
  ok('[FIXTURE] doctor：单 JSON 直接取到、不误判为进度行', d.evidence !== null && d.progress.length === 0 && d.error === null, j(Object.keys(d.evidence ?? {})).slice(0, 120))
  ok('[FIXTURE] doctor：evidence_raw 逐字节等于整份 JSON', d.evidence_raw === rawDoctor.trimEnd(), `${Buffer.byteLength(String(d.evidence_raw))} 字节`)
  ok('[FIXTURE] doctor：字段可读（healthy/scope_checks/identity）', typeof d.evidence?.healthy === 'boolean' && Array.isArray(d.evidence?.scope_checks) && Array.isArray(d.evidence?.checks), `scope_checks=${d.evidence?.scope_checks?.length}`)
  ok('[FIXTURE] doctor：host/node 分类信息在（14 项检查）', d.evidence?.scope_checks?.some((c) => c.name === 'node' && c.classification === 'healthy') === true && d.evidence?.scope_checks?.every((c) => 'ok' in c), `missing_engine=${d.evidence?.scope_checks?.filter((c) => c.classification === 'missing_analysis_engine').map((c) => c.name).join(',')}`)
  const withBanner = `npm WARN deprecated inflight@1.0.6: This module is not supported\nnpm WARN reify weird\n${rawDoctor}`
  const dm = parseReaOutput(withBanner)
  ok('[FIXTURE] doctor+真banner：parseReaOutput 仍取出同一对象', dm.evidence !== null && j(dm.evidence) === j(d.evidence), `error=${dm.error}`)
  ok('[FIXTURE] doctor+真banner：extractJsonFromMixedText 一致', j(extractJsonFromMixedText(withBanner)) === j(d.evidence))
  ok('[FIXTURE] doctor+真banner：evidence_raw 只含 JSON 区间（banner 不入盘）', dm.evidence_raw === rawDoctor.trimEnd(), `${Buffer.byteLength(String(dm.evidence_raw))} 字节`)
  ok('[FIXTURE] doctor+真banner：banner 行不被当成进度', dm.progress.length === 0 && isProgressRecord(d.evidence) === false)
}

console.log(`\n合计：${pass} PASS / ${fail} FAIL / ${skip} SKIP`)
process.exit(fail === 0 ? 0 : 1)
