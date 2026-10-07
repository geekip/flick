# tests/fixtures

合法/非法配置、报文、数据与状态恢复输入；每组注明来源、许可、版本及预期行为。

关联任务：C03–C19。`config/v1/manifest.json` 是 C03 的 V0.1 Schema 正反样例清单，固定每个输入的首要错误 code/path，可直接作为 P03 CLI/parser 测试数据。`socks5/v0_1/manifest.json` 是 C04 的 SOCKS5 增量 wire 向量，要求 whole feed、逐字节和声明边界得到相同结果，可供 P09/P10 测试驱动使用。`dns/v0_1/manifest.json` 是 C05 的 DNS message/TCP frame/attempt 时间线，供 P07 的 parser、关联、CNAME、fallback、deadline 和 failure-cache 测试使用。`evidence/v0_1/` 是 C06 的统一结果 Schema 和显式标记为 example 的正反记录，不能用作产品通过证据。

这些 fixtures 是项目自行编写的合同输入，不是从参考实现复制的代码，也不证明 parser、协议 adapter 或产品测试已经实现/运行。
