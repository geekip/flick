# src/core

Core、Session、异步 operation、预算与准入；owning loop 管理可变状态，Runtime 引用保护旧代。

P01 已提供 `fn_result_t` 值对象和 build 清单。P02 已提供 active/candidate/retained/cleanup 分类账本、总/子预算原子准入、按需有界 pool 与路由/拨号/诊断元数据分离；它们不创建业务 fd、timer 或 worker。P05 增加 Runtime manager、candidate build/prepare/commit/rollback、旧代引用保活及有界 lazy acquire。P08 增加 owner-only Session，保留接纳时 Runtime，并驱动路由、解析、DIRECT 建连、relay、取消和最终回收。P11 使 build 清单发布实际 V0.1 TCP/Resolver 能力，并增加在级别判断后才构造记录的 logger；结构化错误与诊断不依赖日志开启。P12 通过内部替换和故障注入验证 A/B Session 代际隔离、prepare 回滚、active/candidate/retained 峰值与无需求资源。

关联任务：P01 / P02 / P05 / P08 / P11 / P12。
