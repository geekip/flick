# tests/unit

纯逻辑、边界、资源计账及异步所有权的真实单元测试。

P01 已加入结构化结果/依赖生命周期和能力 Manifest 检查；P02 已加入基础类型与资源测试；P03 已加入配置与 Feature Plan 测试；P04 已加入 loop/platform；P05 已加入 Runtime/Router；P06 已加入真实 socketpair 的双向 relay、half-close、慢接收者水位、公平额度、资源等待/drain 超时、取消与同步 admission 测试。P07 覆盖 DNS wire fixtures、重试/合并/失败缓存时间线，并用 loopback UDP/TCP server 验证 TC fallback 与 partial TCP frame。P08 用真实 loopback DNS、TCP echo 和 socketpair 验证 Session 的 IPv4/DOMAIN 路由、候选拒绝后继续、双向转发、half-close、取消与资源归零。P09 覆盖 C04 入站 fixtures、认证、部分输入输出、失败映射、deadline、取消和预读资源上限。

关联任务：P01–P11。
