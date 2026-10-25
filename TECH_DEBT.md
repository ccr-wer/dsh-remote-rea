# 技术债

## 待修

1. `createHostStore(path)` 丢弃第二个参数 `sshConfigOverride`（第 3 步模块）。
   当前绕过：测试用 `new HostStore(path, sshCfg)`。
   影响：`createHostStore` 的调用方无法覆盖 ssh config 路径。
   修法：转发所有参数给 `HostStore` 构造器。

## 已知限制（不修）

1. Windows 远端不支持（POSIX shell 才支持）。
2. A 路 Ghidra 未实装验证（下载受限）。
3. `@latest` 可能漂移。
4. `read_bytes` → `rea read-bytes` 的 `<address>` 是必填实参，而工具面没有地址入参，
   所以这条绑定只登记、不下发（`rea-provider-router.js` 的 `address:'required'`）。
5. 离线 tarball 部署未实现：当前只支持 preinstalled / npx 两级，隔离内网（远端无 registry 出口）
   场景要人工预装。留待未来版本迭代。

## 已修（记录教训）

### mock 契约漂移（2026-10-25）

`ctx.effect` 的 mock 假设「注册的就是 disposer」，真 cordis 契约是「注册的是 body，返回值才是 disposer」。
181 条测试全绿，但 disposer 从未注册 —— 测试验证的是我们自己发明的契约。
修法：mock 改成 `(fn, label) => { const disposer = fn(); effects.push({ disposer, label }) }`，
并加一条用真 `@deepseek-ai/cordis` 跑的对照测试作为锚点（P11b：C 组 disposer 被调、A 组不被调）。
教训：mock 宿主 API 时，要么用真实现跑一次对照，要么在 mock 里注明契约来源（包名 + 版本 + 源码行号）。
