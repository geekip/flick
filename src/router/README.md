# src/router

首条命中的顺序参照与后续索引；解析挂起保序，DNS 投影独立，FakeIP 仅恢复身份。

关联任务：P05 / C09。P05 已实现 V0.1 末尾 MATCH 的同步 Router：DIRECT 域名返回 NEED_RESOLVE，数字地址或已有解析结果返回 READY，SOCKS5 保留原目标，REJECT 返回 DENY；所有对象引用先校验 generation 和类型。V0.2 的非 Geo 规则与 V0.3 的 Geo/组仍未实现。
