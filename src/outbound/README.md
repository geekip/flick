# src/outbound

DIRECT、REJECT、SOCKS 与 AnyTLS 分派；完成协议成功条件才回复，失败不隐式 DIRECT。

P08 已实现 DIRECT IPv4 非阻塞 connect、DOMAIN 解析候选串行拨号、共享总 deadline、实际 bound endpoint、fd admission 与 Stream 所有权转移。P10 已实现 SOCKS5 TCP 出站、no-auth/用户名密码、节点 DOMAIN bootstrap、IPv4/DOMAIN CONNECT、上游 BND/REP 映射和 Session 分派；业务 DOMAIN 原样交给代理，候选只在 SOCKS 协商前重试。

关联任务：P08 / P10 / C13。
