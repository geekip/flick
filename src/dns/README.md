# src/dns

V0.1 最小 Resolver 和失败缓存；V0.2 Listener 与响应缓存；DNS UDP 不等于业务 UDP。

P07 已实现独立 A/IN query builder 与 A/CNAME response parser，固定压缩名称、RR、CNAME hop 和地址数量边界。owner-only Resolver 合并相同 key 的在途请求，每个 waiter 保留独立 deadline/取消/terminal reservation；UDP、TCP fallback、bare CNAME 和候选上游共享 attempts 与 policy deadline，同 tuple 最多发送三次。

Linux transport 使用随机 ID、系统临时源端口、源端点与本地目的关联，TCP frame 支持 partial I/O。失败缓存按需分配，只抑制最终上游失败；NXDOMAIN、NODATA、短 deadline、取消与本地资源限制不写入。

关联任务：P07 / C09。DNS Listener、EDNS、普通响应缓存、FakeDNS 和业务 UDP 仍属后续版本。
