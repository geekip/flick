# tests/integration

本地 SOCKS→DIRECT 与 SOCKS 链、DOMAIN、认证、内部 Runtime 替换和关闭。

关联任务：P08–P14。P08 已验证 Session→DIRECT；P09 已用真实 socketpair 客户端与 loopback TCP 目标验证 SOCKS5→Session→DIRECT、合包预读、成功/拒绝回复、取消、Session admission 失败回复、half-close 和最终资源归零。SOCKS 出站双代理链在 P10 加入。P14 增加 benchmark driver 的固定 workload、plan、未知 target、deadline 与进程组终止合同测试。
