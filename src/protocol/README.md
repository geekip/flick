# src/protocol

有界协议编解码和状态机；协议 Session 与业务 Session 分开，无平台规则写入。

关联任务：C04 / C05 / C13 / C17 / C18。P09 的 SOCKS5 wire 状态机当前与入站适配器同置于 `src/inbound/socks5.c`，以固定 workspace、显式 cursor 和结构化结果实现；后续仅在多个适配器共享时再拆分公共 codec，避免提前建立无调用者抽象。
