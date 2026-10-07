# src/inbound

SOCKS、TPROXY、AnyTLS 和 Mixed 适配器；统一移交 Session，不直接绑定出站。

关联任务：P09 / C07 / C08 / C13 / C17。P09 已实现 SOCKS5 TCP CONNECT 入站的增量握手、no-auth/用户名密码认证、IPv4/DOMAIN、失败回复、16 KiB 有界预读，以及已建立 Stream 到统一 Session 的异步移交。BIND、UDP、IPv6、GSSAPI 和进程级 listener 不在 P09 范围。
