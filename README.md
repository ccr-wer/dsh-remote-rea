# dsh-remote-rea

DSH（DeepSeek Harness）生态插件：**远程连接 + 逆向分析** —— 连上远程主机，定位/拉取目标文件，
调用 REA（及其背后的 Ghidra / Hopper / IDA）做静态分析并回收结构化结果。

**只分析、不利用**：本插件不执行目标、不注入、不改写工件、不做任何利用动作。所有远端命令都先过
提权闸门（见「安全边界」）。

## 三个工具

| 工具 | 作用 | 关键入参 |
|---|---|---|
| `remote_hosts` | 主机库 CRUD：登记别名、认证方式、连通性 `test`、从 `~/.ssh/config` 导入 | `action` + `alias` … |
| `remote_fetch_binary` | 预检（存在 / 大小 / 类型 / sha256）→ 拉取 → 本地复算 sha 比对 → 写 JSON 报告 | `alias`、`remotePath`（绝对路径） |
| `remote_rea_analyze` | 拉取之后探测能力面、选 provider/operation、下发分析子命令、Evidence 落盘并出摘要 | `alias`、`remotePath`、可选 `provider` |

用之前必须先在 `remote_hosts` 里有别名 —— 主机库是这两个分析工具的前置条件，本插件不读任何外部口令。

`remote_rea_analyze` 不指定 `provider` 时自动路由，选路范围是
「REA 广告面 ∩ 已用 `--help` 核对过绑定的子命令」，两者取交集，缺一个就不下发。

## 支持范围

| 层面 | 支持 | 不支持时的行为 |
|---|---|---|
| 宿主 OS | Windows / macOS / Linux | 不可能不支持（`ssh2` 是纯 JS 实现，原生加速模块可选） |
| 宿主 Node | `>=18`（建议 20+） | 由 `package.json` 的 `engines.node` 声明；安装器告警，本插件自身不做版本检查 |
| 远程 OS | POSIX shell（Linux / macOS） | 运行时探测 `uname -s`，命中 `MINGW*`/`MSYS*`/`CYGWIN*`/`Windows*` 直接拒：`不支持的目标平台：Windows 远端，请使用 POSIX shell 目标` |
| 远程 Node | 22.19+ / 24.11+ / 26+（不支持 23 和 25） | 走 npx 前先探 `node --version`，不达标报一句话：`远端 <版本>；REA 要求 Node 22.19+ / 24.11+ / 26+（不支持 23 和 25）`，且**不下发任何 rea 命令** |
| 远程工具 | GNU coreutils，或可降级的子集 | 见下面「预检的降级路径」，每条都有兜底而不是直接失败 |

> 宿主 Node 的 `>=18` 是声明值，未在 18 上实测：本项目的开发/回归环境只有 Windows 侧 node 24.x
> 与 WSL 侧 node 22.22.1。用到的语法（ESM、可选链、空值合并、`node:` 前缀内置模块）都在 18 以内。

### 预检的降级路径

- `stat -c %s` 拿不到大小（BSD/macOS 的 `stat` 不认 `%s`）→ 退回 `wc -c <`；两条都失败 → `sizeBytes=null`。
- `file -b` 失败 → `fileType=null`，路由降级为「按扩展名猜类别」，note 里写明「未经格式头证实」；
  扩展名也认不出来就报 `未知类型：file -b 没有输出、扩展名也认不出来；深度分析需指定 provider`。
- 远端既没有全局 `rea` 也没有 `npx` → `远端无 npx，请安装 Node.js 22.19+ 或全局安装 rea`。
- 符号链接：`file -b` 回的是 `symbolic link to …`，而 `stat -c %s` 给的是链接字符串长度、
  `sha256sum`/SFTP 跟随目标 —— 所以链接目标的 `sizeMatches=null` + `sizeSkippedForSymlink=true`，**sha 才是权威**。

## 已知限制

- **Ghidra 路径已接，未实装验证。** 绑定表见 `rea-provider-router.js` 的 `GHIDRA_BINDINGS`（5 条，
  只有 `--help` 证据、没有任何一次真机跑通），因此**不参与自动选路**，只在调用方显式
  `provider:"ghidra"` 且 REA readiness 判它可用时才走。要实装需自备 **Ghidra 12.1.x** 解包目录并把
  `GHIDRA_INSTALL_DIR` 指过去，外加 **JDK 21**（便携 JDK 也行，只要 PATH 上有 `java`）。
- **`analyze-javascript-application` 不在 capabilities 广告面**（providers / capabilities / doctor 三处都没有它），
  作为带标记的**手工例外**接入：`surface='manual-exception'`、`marker='manual-exception:not-advertised'`。
  它的 effects 是空的 —— 也就是「读文件还是写文件系统」REA 自己没说，本项目也不替它猜。
- **`rea-artifact-graph` 只做 inventory，`findings=0` 是结构性的**，不是「这个二进制很干净」：它的 Evidence
  方言里没有 `semantic_graph`，摘要层的 `dialect` 计数会把 `unexplored_branches` / `next_probes` 原样透传，
  深度要靠 Ghidra 那一条路。
- **冷缓存预热可能 50s 到 10 分钟不等**，取决于网络。实测区间 50–83s，但同一条路出现过 120s、420s，
  以及 2026-10-17 在 WSL 上实测的 **534s**（清缓存后用默认预算跑通整链）。`npxTimeoutMs` 因此定为 600000，
  可按调用覆盖。
- **`doctor` 原文不是字节稳定的**：`identity.installations.paths[0]` 会随 npx 缓存位置变化，所以本项目
  不对 doctor 原文做逐字节断言，只按 evidence_id / 字段取用。
- **`@latest` 可能漂移**：`npx --yes rea-agents@latest` 每次解析到的版本可能不同。遇到缓存或行为对不上，
  可把远端命令手动锁成 `rea-agents@<版本>`。
- **`pnpm peers check` 的 missing peer 是静态误报**：DSH profile 的 `pnpm-workspace.yaml` 设了
  `autoInstallPeers: false`，pnpm 只看 profile 自己的 `package.json`，看不到上层
  `profiles/node_modules/@deepseek-ai/`，于是报 `@deepseek-ai/dsh-tools` / `@deepseek-ai/cordis` 缺失。
  实测：那两个 peer 由 DSH 运行时自带 —— `profiles/node_modules/@deepseek-ai/{cordis,dsh-tools}`
  是指向全局 `@deepseek-ai/dsh` 内嵌依赖的符号链接（本机解析到 cordis 4.0.2、dsh-tools 0.1.5-rc.2）。
  插件是从 tarball 解出来的**真实目录**，从它内部 `import.meta.resolve()` 向上走就能命中；
  已装的 dsh-dolphin-security 报的是同一类误报。**只要实际版本落在 peer 范围内，这条警告可以忽略。**

## 跨平台说明

- 开发环境用 **WSL 做真机测试**：Windows → WSL2 的 2222 portproxy 需要管理员权限才能修，本机没修，
  所以 Windows 侧只跑离线套件（逻辑层 + 假 engine），真机套件在 WSL 内部跑。
- `cpu-features` 构建失败**不影响功能**：`ssh2` 把它列为可选加速模块，装不上就退回纯 JS 实现，只是性能略降。
  （这条是 ssh2 上游行为 + 本项目 `loadSsh2`/`isSsh2Available` 的容错设计；我们没有专门实测过构建失败的安装。）
- `REVERSE_HOME` 用**当前 OS 的路径风格**：Windows 上是 `D:\...`，POSIX 上是 `/...`，本项目不做路径翻译。

## 安全边界

- **只分析、不利用**：没有执行目标、注入、patch、改写工件的任何入口。
- **提权硬闸门**：每条远端命令下发前过 `assertNoPrivilegeEscalation`，命中 `sudo` 或
  `--break-system-packages` 直接抛错、不下发（`remote-shell-utils.js`）。探测类命令 `attempts` 固定为 1，
  不做重放 —— 下发前无法确认幂等。
- **`mutates_artifact` 的操作不会被选中**，机制要说准：REA 广告面里确实有带它的组
  （`annotate_native_function`、`set_address_name(s)`、`set_bookmark` / `set_comment` / `set_inline_comment` /
  `unset_bookmark`），但选路的必要条件是「该操作有已核对的 CLI 绑定」，而绑定表里一条写类操作都没有。
  也就是说这是**靠白名单实现的，不是运行期按 effects 拦截**；`effects` 只如实透传进 `route.reason` 给你看。
- **口令不进工具参数**：`authKind=password` 只接受一个环境变量名 `passwordEnv`，口令本体留在宿主进程环境里 ——
  作为参数传会进会话记录。列表/详情回的是脱敏投影（`auth.kind`），不回显口令或私钥内容。

## A 路（Ghidra 深分析）绑定表

| operation | 子命令（`--help` 原文形状） | address |
|---|---|---|
| `analyze_function` | `rea function <path> [address] [options]` | 可选 |
| `procedure_pseudo_code` | `rea decompile <path> [address] [options]` | 可选 |
| `procedure_assembly` | `rea instructions <path> [address] [options]` | 可选 |
| `xrefs` | `rea xrefs <path> [address] [options]` | 可选 |
| `read_bytes` | `rea read-bytes <path> <address> [options]` | **必填 → 只登记不下发** |

Ghidra 不可用时，错误信息用的是 REA 自己的原文（`Set GHIDRA_INSTALL_DIR to an extracted Ghidra 12.1.x
release directory.` ＋ `install_dir / analyze_headless_path / java_command / java_home` 的诊断原值），
本项目不自己编修法。深分析 provider 的 session 是 ephemeral（导入的 Program 与临时工程在 close 时删除），
所以 Evidence 一解析出来就当场落盘。

## 落盘位置

数据根 = `$REVERSE_HOME`（回退 `$DSH_HOME`，再回退 `~/.reverse`）：

- 报告：`<数据根>/reports/fetch-<alias>-<ts>.json`、`analyze-<alias>-<ts>.json`
- 拉取的目标：`<数据根>/targets/<文件名>`
- Evidence：按 `evidence_id` 落盘（`<数据根>/evidence/<evidence_id>.json`），路径写在报告的
  `analysis.evidencePath`；落的是 stdout 里那一行**原始字节**，不重新格式化。

工具返回体里不放远端原始 stdout，也不放全量 Evidence（真机 5.6KB ~ 75KB），只放摘要与路径。

## 安装与挂载

```bash
cd <DSH home> && DSH_HOME=<DSH home> dsh plugin --profile web add dsh-remote-rea
cd <项目根> && DSH_HOME=<DSH home> dsh --profile web --host 127.0.0.1 --no-open
```

`ssh2` / `cpu-features` 需要构建许可：pnpm 11 的门禁会拦依赖的构建脚本
（`ERR_PNPM_IGNORED_BUILDS`，退出码 1），要在 profile 的 `pnpm-workspace.yaml` 里加上

```yaml
allowBuilds:
  cpu-features: true
  ssh2: true
```

装完要重启 `dsh web` 并强制刷新浏览器。桌面端（`desktop` profile）由 Electron 独占管理，
命令行装插件会被拒（`profile "desktop" is managed exclusively by the Electron application`），
入口是应用内的插件管理器。

## 测试

```bash
node test/run-tests.mjs              # 3a 本地解析层
node test/run-probe-tests.mjs        # 3b 远端能力面探测（--offline 只跑逻辑层）
node test/run-deploy-tests.mjs       # 第 4 步 部署链
node test/run-controller-tests.mjs   # 第 5 步 runFetch
node test/run-analyze-tests.mjs      # 第 6 步 runAnalyze（--cold 额外跑破坏性冷缓存）
node test/run-plugin-tests.mjs       # 第 7 步 插件契约 + 跨平台补丁 + A 路
```

需要真机的套件走 `--alias=<别名> --store=<主机库路径>`，别名先用 `remote_hosts` 或主机库脚本登记。

## 许可与第三方声明

本项目以 MIT 发布（`LICENSE`）。`remote-ssh-core.js` 派生自 dsh-web 的 `dsh-ssh`（Apache-2.0），
`remote-shell-utils.js` 派生自 dsh-dolphin-security（MIT，同作者）—— 逐函数的来源位置、修改内容与
许可证原文见 `THIRD_PARTY_NOTICES.md` 与 `THIRD_PARTY_LICENSES/`。

技术债与已知限制的单子在同目录 `TECH_DEBT.md`。
