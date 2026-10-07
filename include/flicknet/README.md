# include/flicknet

跨模块自有声明；接口按所有权拆分，不暴露 libev watcher、裸 Linux fd 或 TLS 对象。P01–P06 已实现构建、基础类型、配置、loop/platform、Runtime/Router、socket Stream、共享 buffer pool 与双向 relay。当前 API/ABI 尚未稳定，也没有复制聚合设计头冒充完整实现。

P07 已加入最小 Resolver；P08 已加入 DIRECT connector 和 Session manager；P09 已加入 SOCKS5 入站 parser、已建立 Stream 的握手驱动、统一 inbound request、异步协议回复门和预读移交；P10 已加入 SOCKS5 出站 manager、节点 bootstrap、凭据协商、DOMAIN 转交及上游 BND/REP 传递。P11 已加入严格 CLI、实际构建能力查询、日志构造前门控和 loop counter 快照。接口覆盖接纳后延迟终结、取消优先、候选串行拨号、回调内所有权转移，以及成功回复完整写完后才启动 relay。

关联任务：C01 / C02 / C03 / C04 / P01–P11。后续模块按对应契约逐项加入头文件。
