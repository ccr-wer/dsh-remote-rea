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
