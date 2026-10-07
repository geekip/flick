# src/platform/linux

Linux socket、防回环、原目标、文件与系统能力；主进程只设置自身 Socket Policy，不修改系统规则。

P04 已实现可移植 socket 句柄的 partial read/write/幂等 close，以及 Linux nonblocking、Route Guard `SO_MARK`、TCP_NODELAY、KEEPALIVE 策略。必需项失败返回带 POSIX 原始码的结构化错误；可选项失败保存在 report。mark 与系统规则的组合验证仍属于 V0.2。

关联任务：P04 / C08。
