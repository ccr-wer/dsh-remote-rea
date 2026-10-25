# Changelog

遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 风格，版本号遵循语义化版本。

## 0.1.2 (2026-10-25)

### 修复

- **engine 释放钩子从未生效**：`ctx.effect(releaseEngine, …)` 直接传函数 —— cordis 的契约是
  注册期立即执行 `execute`、把**返回值**登记为卸载 disposer（`@deepseek-ai/cordis` lib/index.js:1141-1143），
  而 `releaseEngine` 无返回值，disposer 从未注册：进程内重载/停用插件时 SSH 池与清扫定时器不会被释放
  （进程整体退出不受影响）。现改为 `ctx.effect(() => releaseEngine, 'remote-rea:engine')`。
- 0.1.0 条目「engine 单例经 `ctx.effect()` 在插件 dispose 时释放」当时不成立，以本条为准。

### 测试

- 插件套件的 `ctx.effect` mock 对齐真 cordis 契约（注册期调 fn、返回值当 disposer）；
  P11 改为经登记的 disposer 走卸载路径。
- 新增 P11b 真 cordis 对照锚点：修复后形状卸载时 disposer 被调；修复前形状卸载零动作
  （证明测试有抓住该缺陷的能力）。cordis 不可解析时 SKIP。插件套件 181 → 184。
- 迷你宿主实证（真 cordis 4.0.2 + 真 index.js，句柄探针）：懒建 1 个清扫 interval → fiber 卸载后
  `clearInterval` 恰 1 次且落在该句柄 → 再次调用工具按默认路径重建。

## 0.1.0 (2026-10-17)

首个可安装版本。DSH 生态插件：远程连接 + 逆向分析。**只分析、不利用。**

### 功能

- 三个工具：`remote_hosts`（主机库 CRUD、从 `~/.ssh/config` 导入、连通性 test）、
  `remote_fetch_binary`（预检 → SFTP 拉取 → sha256 校验 → JSON 报告）、
  `remote_rea_analyze`（拉取后探测能力面、选 provider/operation、下发分析、Evidence 落盘并出摘要）。
- 自动选路范围 = REA 广告面 ∩ 已用 `--help` 核对过绑定的子命令：`inspect-artifact`、`extract-artifact`。
  `analyze-javascript-application`（Electron ASAR）不在任何广告面里，作为带标记的手工例外参与
  （`surface=manual-exception`、`marker=manual-exception:not-advertised`）。
- A 路（Ghidra）绑定表已写入代码：`analyze_function` / `procedure_pseudo_code` / `procedure_assembly`
  / `xrefs` / `read_bytes` 五条，只在显式 `provider:"ghidra"` 且 REA readiness 判可用时才走。
- 跨平台预检降级：BSD/macOS 的 `stat` / `file` / `wc` 差异已补丁（5 条）；`file` 缺失时按扩展名猜类型；
  符号链接上 `stat -c %s` 给链接字符串长度，故大小判定豁免、以 sha256 为权威。
- 落盘：数据根 `$REVERSE_HOME`（回退 `$DSH_HOME`，再回退 `~/.reverse`）下的
  `reports/`、`targets/`、`evidence/`。工具返回体只放摘要与路径，不放远端原始 stdout、不放全量 Evidence。
- 部署策略两级：远端已有 `rea`（preinstalled）或走 `npx`；`npxTimeoutMs` 默认 600000，可按调用覆盖。
- 插件挂载契约：`cordis.patch.yml` 插入 id `remote-rea`，`inject: ['tools']`，engine 单例经
  `ctx.effect()` 在插件 dispose 时释放。

### 安全边界

- 只做静态分析：不执行目标、不注入、不做任何利用动作；代码里没有利用链下发路径。
- 提权闸门 `assertNoPrivilegeEscalation()`：远端命令里出现 `sudo`、`--break-system-packages` 等
  形态直接拒绝。这是**命令形状白名单**，不是「效果过滤」——它不判断命令是否安全，只判断它是否
  试图提权。
- 平台闸门：`uname -s` 回 `MINGW*` / `MSYS*` / `CYGWIN*` / `Windows*` 一律拒绝，只支持 POSIX shell 目标。
- 口令走 `passwordEnv`（环境变量名），不写进主机库、不进返回体。
- 远端 Node 版本闸门：走 npx 时要求 22.19+ / 24.11+ / 26+（不支持 23 和 25）。

### 已知限制

与 README 的「已知限制」一致，原文口径、不美化：

1. **Ghidra 路径已接，未实装验证**：5 条绑定只有 `--help` 证据、没有任何一次真机跑通，故不参与自动选路。
   实装需自备 Ghidra 12.1.x 解包目录 + `GHIDRA_INSTALL_DIR` + JDK 21。
2. **`analyze-javascript-application` 不在 capabilities 广告面**（providers / capabilities / doctor 三处都没有），
   只作为带标记的手工例外接入，其 effects 为空。
3. **`rea-artifact-graph` 只做 inventory，`findings=0` 是结构性的**：Evidence 方言里没有 `semantic_graph`，
   `unexplored_branches` / `next_probes` 原样透传，深度要靠 Ghidra 那一条路。
4. **冷缓存预热 50s 到 10 分钟不等**：实测区间 50–83s，同一条路出现过 120s、420s，以及 2026-10-17 在
   WSL 实测的 534s。`npxTimeoutMs` 因此定为 600000。
5. **`doctor` 原文不是字节稳定的**：`identity.installations.paths[0]` 随 npx 缓存位置变化，故不对原文做逐字节断言。
6. **`@latest` 可能漂移**：`npx --yes rea-agents@latest` 每次解析到的版本可能不同。
7. **`pnpm peers check` 的 missing peer 是静态误报**：profile 设了 `autoInstallPeers: false`，
   peer 由 DSH 运行时在 `profiles/node_modules/@deepseek-ai/` 提供，实际能解析。

另：**离线 tarball 部署未实现**（只支持 preinstalled / npx 两级，隔离内网需人工预装），留待未来版本迭代；
其余技术债见 `TECH_DEBT.md`。
