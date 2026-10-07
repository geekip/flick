# src/net

事件适配、Stream/Datagram、relay、deadline 与后台 completion 交回 loop；不暴露 watcher 到 Core。

P04 已实现私有 libev loop、跨线程 `ev_async` 唤醒、terminal/post 双通道、绝对 deadline 单次 timer 和借用 socket 的 I/O watcher。terminal 在操作接纳前取得 cleanup reservation，普通 post 满载不能挤占；每轮 dispatch 有配额。

P06 已实现拥有 socket 的非阻塞 Stream、按需共享 block pool 与双向 relay。relay 用高低水位传播背压，每个 callback 受字节/I/O 次数额度限制；单向 EOF 在排空后执行 peer 写半关闭，反向仍可继续。buffer 耗尽进入有界 FIFO 资源等待，取消、资源等待超时与 drain 超时均通过预留 terminal 恰好终结一次。

关联任务：P04 / P06 / P07 / P08。
