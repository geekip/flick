# 源码组织

当前 P01–P09 已实现结构化结果与构建、基础类型与资源、Typed Config/Feature Plan、私有 libev loop、Linux Socket Policy、Runtime/Router、Stream/relay、最小 Resolver、Session/DIRECT 和 SOCKS5 TCP 入站。已建立 Stream 可完成 `SOCKS5 → Session → DIRECT → relay`；进程级 listener 与 CLI 在 P11 接入。依赖方向：配置输入 → Typed Config → Compiler/Planner → Runtime；入站 → Session → Router → 出站 → transport。事件与 Linux 细节封装在 net/platform，Core 不访问 libyaml AST、libev watcher 或平台私有 API。

`core` 管所有权与资源；`config` 含 Planner；`router` 管保序决策；`dns` 管 Resolver/Listener；`state` 管跨代身份与持久恢复；`group` 与 `health` 分开选择和测量；`protocol` 与 `tls` 分开 wire 和加密适配；`cli/control` 不进入 relay 快路径。具体职责见各子目录 README。

模块按 Core、配置、网络、协议、平台和运行入口拆分。health/state/tls 目录保留后续版本边界，不表示相关功能已经交付。
