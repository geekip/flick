# src/cli

V0.1 run/check/test/version；后续在线命令走 Control，进程前台运行。

P11 已实现严格 CLI 解析、配置装载与结构化输出，并把 Config、Runtime、SOCKS listener、Session、Resolver、DIRECT/SOCKS 出站和 relay 组成 `flick` 主程序。`check` 保持离线，`test` 只 prepare 本机 listener 并报告 lazy 依赖状态，`run` 在 owning loop 接纳连接；SIGTERM/SIGINT 通过非阻塞唤醒 fd 进入 loop，支持有限 drain 和第二信号强制取消。V0.1 不 daemonize，也不提供公开 stop/reload/status 控制面。

关联任务：P11 / C03 / C14。
