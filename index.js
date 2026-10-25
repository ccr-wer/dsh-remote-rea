// dsh-remote-rea 插件入口（Cordis 宿主侧适配层）。
// ---------------------------------------------------------------------------
// 定位：纯功能型插件 —— 只向 Agent 注册 remote_fetch_binary / remote_rea_analyze /
// remote_hosts 三个工具，没有 UI / client 半区。
//
// 架构约定：
//   * 本文件是唯一依赖 Cordis 运行时的地方；rea-*.js / remote-*.js 全部保持零 DSH 依赖，
//     既能被这层调用，也能被外部脚本直接 import（双形态并存，与 dolphin 一致）。
//   * 工具逻辑全部委托给 rea-controller.js，这层不做任何 SSH / 解析实现；
//     runFetch 与 runAnalyze 只接受注入进来的 engine，自己从不建连接。
//   * engine 是模块级单例：连接池与主机库在一轮会话里反复要用，每个工具各建一次会
//     把 SSH 握手与空闲定时器复制三遍。首次工具调用时创建，释放挂在 ctx.effect 上
//     （fiber 卸载时宿主反过来调用它）。
//   * 落盘位置一律来自 $REVERSE_HOME（回退见 remote-ssh-core.js:127 的 resolveReverseHome），
//     不接受模型传目录 —— 工具参数面越窄，越不可能把报告写到会话工作区之外。
// ---------------------------------------------------------------------------

import { join } from 'node:path'

import { defineTool } from '@deepseek-ai/dsh-tools'

import { createHostStore, createSshEngine, resolveReverseHome } from './remote-ssh-core.js'
import { defaultReportsDir } from './remote-shell-utils.js'
import { runAnalyze, runFetch } from './rea-controller.js'

// 与 cordis.patch.yml 的 insert[].id 对齐：宿主按该 id 在配置树中挂载本插件。
export const name = 'remote-rea'

// 依赖 tools 服务：Cordis 会等 tools 就绪后再调用 apply。
export const inject = ['tools']

const renderText = (_args, value) => [{ type: 'text', text: String(value) }]

let engineSingleton = null

/** 首次调用时建 engine（主机库用默认路径），之后所有工具复用同一个实例。 */
function engine() {
  if (engineSingleton === null) engineSingleton = createSshEngine(createHostStore())
  return engineSingleton
}

/** 释放单例：dispose 会关掉连接池并停掉清扫定时器（SshEngine 没有 close()）。 */
function releaseEngine() {
  if (engineSingleton !== null) {
    engineSingleton.dispose()
    engineSingleton = null
  }
}

/**
 * 单例注入口：宿主不会调用它，给本仓库的测试与脚本换掉真实 SSH 用。
 * 传 null 表示清掉当前实例（下一次工具调用再按默认路径重建）。
 */
export function useEngine(replacement) {
  if (replacement === null) releaseEngine()
  else engineSingleton = replacement
  return engineSingleton
}

function targetDir() {
  return join(resolveReverseHome(), 'targets')
}

/** 长链路（预热 50s+ / 分析 4s+）失败时，阶段序列往往比最后一句话更能指路。 */
function stages(frames) {
  return frames.map((f) => (f.source === 'warmup' ? `warmup:${f.phase}` : f.phase)).join('>')
}

function projectFetch(r, frames) {
  return {
    ok: r.ok,
    error: r.error,
    alias: r.alias,
    remotePath: r.remotePath,
    localPath: r.localPath,
    metadata: r.metadata,
    verification: r.verification,
    deploy: r.deploy === null ? null : { strategy: r.deploy.strategy, command: r.deploy.command, reaVersion: r.deploy.reaVersion, needsWarmup: r.deploy.needsWarmup },
    stages: stages(frames),
    durationMs: r.durationMs,
    reportPath: r.reportPath,
  }
}

function projectAnalyze(r, frames) {
  const route = r.route
  return {
    ok: r.ok,
    error: r.error,
    alias: r.alias,
    remotePath: r.remotePath,
    localPath: r.localPath,
    targetClass: route?.targetClass ?? null,
    provider: r.analysis?.provider ?? route?.provider ?? null,
    operation: r.analysis?.operation ?? route?.operation ?? null,
    subcommand: route?.subcommand ?? null,
    // surface / marker 是选路口径的诚实记录：manual-exception 与 a-path 都不是广告面选出来的
    surface: route?.surface ?? null,
    marker: route?.marker ?? null,
    routeReason: route?.reason ?? null,
    unavailable: Array.isArray(route?.unavailable) ? route.unavailable.map((u) => `${u.provider}:${u.availabilityCode}`) : [],
    evidenceId: r.analysis?.evidenceId ?? null,
    // 全量 Evidence 只在这里给路径，不进返回体（真机 5.6KB ~ 7.5万B，塞进会话记录没有意义）
    evidencePath: r.analysis?.evidencePath ?? null,
    dialect: r.analysis?.dialect ?? null,
    findingCount: r.analysis?.findingCount ?? 0,
    unknownCount: r.analysis?.unknownCount ?? 0,
    failure: r.analysis?.failure ?? null,
    timings: r.timings,
    stages: stages(frames),
    durationMs: r.durationMs,
    reportPath: r.reportPath,
  }
}

function outcome(header, projection) {
  return `${header}\n${JSON.stringify(projection, null, 2)}`
}

/** 工具参数 → HostStore 的 auth 载荷。口令只从宿主进程的环境变量取，不作为工具参数进会话记录。 */
function authPayload(args) {
  const kind = args.authKind ?? 'key'
  if (kind === 'key') return { kind, keyPath: args.keyPath }
  if (kind === 'agent') return { kind, agentPath: args.agentPath ?? 'SSH_AUTH_SOCK' }
  if (kind === 'password') {
    const envName = args.passwordEnv
    if (typeof envName !== 'string' || envName.trim() === '') {
      throw new Error('口令认证请用 passwordEnv 传宿主进程的环境变量名（口令本身不作为工具参数，否则会进会话记录）')
    }
    const password = process.env[envName.trim()]
    if (password === undefined || password === '') throw new Error(`宿主环境变量 ${envName.trim()} 里没有值，未登记口令`)
    return { kind, password }
  }
  throw new Error(`authKind 只能是 key / agent / password，收到 ${kind}`)
}

export function apply(ctx) {
  // cordis 的 effect(execute) 注册期立即执行 execute，返回值是函数才被登记为卸载 disposer
  // （@deepseek-ai/cordis lib/index.js:1141-1143）。所以传 () => releaseEngine 把函数引用交出去，
  // releaseEngine 本体在 fiber 卸载时才跑；直接传 releaseEngine 会在注册期空跑一次且永不登记。
  ctx.effect(() => releaseEngine, 'remote-rea:engine')

  ctx.tools.register(defineTool({
    name: 'remote_fetch_binary',
    description: '定位并拉取远程主机上的一个目标文件（绝对路径），做存在性/大小/类型/sha256 预检后落地本地存档目录，并写一页 JSON 报告。远端没有 REA 时这一步会先规划部署路径（缓存冷的话首跑要从 registry 下载，实测 50~83s）。只读远端、只写本地存档目录。',
    parameters: {
      alias: { type: 'string', required: true, description: '已登记的主机别名（先用 remote_hosts 确认它存在）。' },
      remotePath: { type: 'string', required: true, description: '远端目标文件的绝对路径，必须是普通文件（符号链接可以，sha 才是权威）。' },
    },
    output: { schema: { type: 'string' }, render: renderText },
    async execute(args) {
      const frames = []
      try {
        const r = await runFetch(args.alias, args.remotePath, {
          engine: engine(),
          reportsDir: defaultReportsDir(),
          localDir: targetDir(),
          onProgress: (frame) => frames.push(frame),
        })
        return outcome(r.ok ? `拉取完成：${r.localPath}` : `拉取未完成：${r.error}`, projectFetch(r, frames))
      } catch (error) {
        return `拉取执行异常：${error?.message ?? error}`
      }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'remote_rea_analyze',
    description: '在远程主机上调用 REA 对目标文件做静态分析（内部先做拉取与预检，再探测能力面、选 provider/operation、下发子命令、把 Evidence 落盘并出摘要）。不指定 provider 时只在「REA 广告面 ∩ 已核对 CLI 绑定」里自动选路；provider=ghidra 走深分析，本机未配置 Ghidra 时会直接用 REA 的诊断原文说明缺什么。只分析、不利用：本工具不执行目标、不做任何植入。',
    parameters: {
      alias: { type: 'string', required: true, description: '已登记的主机别名。' },
      remotePath: { type: 'string', required: true, description: '远端目标文件的绝对路径。' },
      provider: {
        type: 'string',
        description: '可选，点名 provider。目前只有 ghidra 有已核对的 CLI 绑定（rea function / decompile / instructions / xrefs）；留空则自动路由。',
      },
    },
    output: { schema: { type: 'string' }, render: renderText },
    async execute(args) {
      const frames = []
      try {
        const r = await runAnalyze(args.alias, args.remotePath, {
          engine: engine(),
          reportsDir: defaultReportsDir(),
          localDir: targetDir(),
          provider: args.provider ?? null,
          onProgress: (frame) => frames.push(frame),
        })
        return outcome(
          r.ok ? `分析完成：${r.analysis?.provider}/${r.analysis?.operation}，findings ${r.analysis?.findingCount} 条` : `分析未完成：${r.error}`,
          projectAnalyze(r, frames),
        )
      } catch (error) {
        return `分析执行异常：${error?.message ?? error}`
      }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'remote_hosts',
    description: '登记与查看远程主机库（这是拉取/分析的前置条件，Dolphin 没有对应工具，必须先在这里有别名）。列表与详情是脱敏投影，永不回显口令或私钥内容。add/update 只改传了的字段；test 会真的连一次（执行 echo ok）。',
    parameters: {
      action: {
        type: 'string',
        required: true,
        enum: ['list', 'get', 'add', 'update', 'remove', 'test', 'import'],
        description: 'list 列出全部；get 看一台；add 登记；update 改一台；remove 删一台；test 连通性探测；import 从 ~/.ssh/config 导入（跳过通配符块与已存在的别名）。',
      },
      alias: { type: 'string', description: '主机别名（除 list/import 外都要传）。字母数字开头，可含 . _ -。' },
      host: { type: 'string', description: 'add/update：主机地址。' },
      user: { type: 'string', description: 'add/update：登录用户。' },
      port: { type: 'integer', description: 'add/update：SSH 端口，默认 22。' },
      authKind: { type: 'string', enum: ['key', 'agent', 'password'], description: 'add 必填：认证方式。' },
      keyPath: { type: 'string', description: 'authKind=key：私钥文件路径（可用 ~ 前缀）。' },
      agentPath: { type: 'string', description: 'authKind=agent：ssh-agent 端点，填 SSH_AUTH_SOCK 表示取宿主进程的环境变量。' },
      passwordEnv: { type: 'string', description: 'authKind=password：存放口令的「宿主进程环境变量名」。口令本身不能作为工具参数传，否则会进会话记录。' },
      description: { type: 'string', description: 'add/update：这台机器是干什么的。' },
      tags: { type: 'array', items: { type: 'string' }, description: 'add/update：标签数组。' },
    },
    output: { schema: { type: 'string' }, render: renderText },
    async execute(args) {
      const store = engine().store
      const action = args.action
      try {
        if (action === 'list') {
          const hosts = engine().list()
          return `主机库 ${hosts.length} 台：\n${JSON.stringify(hosts, null, 2)}`
        }
        if (action === 'get') {
          const one = engine().find(String(args.alias))
          return one === undefined ? `别名 ${args.alias} 不在主机库里` : JSON.stringify(one, null, 2)
        }
        if (action === 'add') {
          const entry = store.create({
            alias: args.alias,
            host: args.host,
            user: args.user,
            port: args.port,
            auth: authPayload(args),
            description: args.description,
            tags: args.tags,
          })
          // 只回显 auth.kind：create 的返回值里可能含口令，summarize 才是脱敏投影。
          return `已登记 ${entry.alias}（${entry.user}@${entry.host}:${entry.port}，auth=${entry.auth.kind}）\n${JSON.stringify(store.summarize(entry), null, 2)}`
        }
        if (action === 'update') {
          const patch = {}
          for (const key of ['host', 'user', 'description']) if (args[key] !== undefined) patch[key] = args[key]
          if (args.port !== undefined) patch.port = args.port
          if (args.tags !== undefined) patch.tags = args.tags
          if (args.authKind !== undefined) patch.auth = authPayload(args)
          store.update(String(args.alias), patch)
          return `已更新 ${args.alias}`
        }
        if (action === 'remove') {
          store.delete(String(args.alias))
          // 连接池里可能还留着这条别名的活动连接，删了配置也得让它断开。
          engine().dropAlias(String(args.alias))
          return `已删除 ${args.alias}`
        }
        if (action === 'test') {
          const t = await engine().test(String(args.alias))
          return t.ok ? `连通：${args.alias}（往返 ${t.latencyMs}ms）` : `不通：${args.alias} —— ${t.error}`
        }
        if (action === 'import') {
          const r = store.importFromSshConfig()
          return `~/.ssh/config 导入：解析 ${r.parsed} 块，新增 ${r.added}，跳过 ${r.skipped}（已存在或无 HostName）${r.skippedNames.length === 0 ? '' : `：${r.skippedNames.join(', ')}`}`
        }
        return `不支持的动作：${action}（可用 list / get / add / update / remove / test / import）`
      } catch (error) {
        return `主机库操作失败：${error?.message ?? error}`
      }
    },
  }))
}
