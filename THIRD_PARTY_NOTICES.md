# Third-Party Notices

`dsh-remote-rea` 包含或派生自以下开源项目。依据各自许可证的要求，其原始版权声明与
许可条款在此保留。完整许可证原文见 `THIRD_PARTY_LICENSES/` 目录。

本项目自身代码以 MIT 许可证发布，完整条款见同目录 `LICENSE`（标准 MIT 模板，21 行）。

---

## 1. dsh-web / dsh-ssh（经 dsh-dolphin-security 中转）

- **本项目文件**：`remote-ssh-core.js`
- **上游来源**：https://github.com/zhu1090093659/dsh-web 的 `packages/dsh-ssh/src`
  （npm 包 `@linxin666/dsh-ssh`）
- **许可证**：Apache License 2.0
- **版权**：Copyright (c) dsh-web contributors
- **完整原文**：`THIRD_PARTY_LICENSES/dsh-web-Apache-2.0.txt`
- **派生链**：`dsh-ssh`（Apache-2.0, TypeScript 多文件）
  → `dsh-dolphin-security/dolphin-ssh-core.js`（MIT, 裁剪为单文件 ESM）
  → `dsh-remote-rea/remote-ssh-core.js`（本文件）
  两个上游均以宽松许可证发布，本项目的再分发满足 Apache-2.0 §4 的要求。
- **保留的上游模块**：`engine.ts`、`engine/connection-pool.ts`、`engine/sftp.ts`、
  `engine/cluster.ts`、`store.ts`、`protocol.ts`（类型契约以 JSDoc 形式保留）
- **上游适配（由 dsh-dolphin-security 完成，本项目继承）**：移除 cordis、
  `@deepseek-ai/dsh-settings`、`@deepseek-ai/dsh-tools`、`schemastery` 等宿主专属上下文，
  移除面向 Web 界面的 `client/` 半区（含 dsh-market 遥测心跳）、`engine/pty.ts`、
  `engine/tunnel.ts`、`routes.ts`、`loopback.ts`；运行时唯一三方依赖为 `ssh2`（MIT）。

### 本项目相对 `dolphin-ssh-core.js` 的修改痕迹

Apache-2.0 §4(b) 要求注明修改。本项目**只做了标识符与文案的机械改名，逻辑改动为 0 行**
（连接池、建连参数、exec 语义、SFTP、cluster、HostStore、自检断言一律未变）：

| 原标识符 | 新标识符 | 类型 | 位置 |
|---|---|---|---|
| `DOLPHIN_HOME` | `REVERSE_HOME` | 环境变量 | `resolveReverseHome()` 读取处 |
| `DOLPHIN_SSH2_MODULE` | `REVERSE_SSH2_MODULE` | 环境变量 | `loadSsh2()` 覆盖项与错误提示 |
| `resolveDolphinHome` | `resolveReverseHome` | 导出函数名 | 定义处、`storePath()` 调用处 |
| `dolphin-ssh-hosts.json` | `remote-ssh-hosts.json` | 主机库文件名 | `storePath()`、`HostStore` 文档注释 |
| `~/.dolphin` | `~/.reverse` | 数据根回退路径 | `resolveReverseHome()` 返回值、文档注释 |
| `dolphin-ssh-selftest-*` | `remote-ssh-selftest-*` | 自检临时文件名 | `selfTest()` |
| `dolphin-ssh-core.js` / `Project Dolphin` 等文案 | `remote-ssh-core.js` / 中性表述 | 注释与自检横幅 | 文件头、各节标题、`selfTest()` |

未改名的中性标识符（保持原样）：`isSsh2Available`、`loadSsh2`、`expandHome`、`storePath`、
`sshConfigPath`、`validateAlias`、`validateHostPayload`、`normalizeAgentPath`、`HostStore`、
`createHostStore`、`DEFAULTS`、`buildConnectConfig`、`resolveAgentPath`、`connectClient`、
`appendOutput`、`connectChain`、`acquire`、`disposeRecord`、`endRecordChain`、`sweepPool`、
`withClient`、`execCommand`、`walkLocalDir`、`upload`、`download`、`ls`、`cluster`、
`SshEngine`、`createSshEngine`。

数据根解析优先级 `$REVERSE_HOME > $DSH_HOME > ~/.reverse` 中的 `DSH_HOME` 是 DSH 生态的
统一数据根变量，非上游项目私有标识，原样保留。

---

## 2. dsh-dolphin-security（`remote-shell-utils.js`）

- **本项目文件**：`remote-shell-utils.js`
- **上游来源**：https://github.com/ccr-wer/dsh-dolphin-security
- **许可证**：MIT
- **版权**：Copyright (c) 2026 Dolphin Contributors
- **完整原文**：`THIRD_PARTY_LICENSES/dsh-dolphin-security-MIT.txt`
- **派生自（逐函数搬运，行为零改动）**：
  `dolphin-patrol.js:69` `shellQuote`、`dolphin-patrol.js:79` `writeJsonReport`、
  `dolphin-patrol.js:186` `assertNoPrivilegeEscalation`、`dolphin-patrol.js:211`
  `assessDeploymentPlan`、`dolphin-core.js:220-224` `timestamp`
  （本项目第 2 步的搬运编号为 A12–A16，指的就是上面这五个函数。）
- **修改**：注释中性化（去掉 semgrep 专属的业务示例与理由文案）、超时常量参数化
  （`PROBE_TIMEOUT` → `PROBE_TIMEOUT_MS`，调用方可覆盖）、`writeJsonReport` 的
  `reportsDir` 改为参数传入且不在 import 期求值、`assessDeploymentPlan` 的策略名与
  rationale 文案改写到本项目场景。新增导出 `defaultReportsDir`（本项目自写，非派生）。
- 两个上游（dsh-web Apache-2.0、dsh-dolphin-security MIT）均为宽松许可证；本文件与
  `THIRD_PARTY_LICENSES/` 满足各自的归属与原文随附要求。

---

## 3. ssh2

- **来源**：https://github.com/mscdex/ssh2
- **许可证**：MIT
- **用途**：底层 SSH/SFTP 协议实现（本项目唯一的运行时三方依赖，不随源码派生）

---

## Apache-2.0 合规说明

对于上述以 Apache License 2.0 授权的部分，本项目：

- 保留原始版权、专利、商标与归属声明（见 `THIRD_PARTY_LICENSES/` 内各文件与本文件）；
- 在 `THIRD_PARTY_LICENSES/` 中随附完整许可证原文；
- 未使用上游商标，未以原作者名义背书；
- 对上表所列的修改已在「修改痕迹」小节中逐条记录变更内容。
