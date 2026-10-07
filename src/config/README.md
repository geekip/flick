# src/config

有界 libyaml 输入、Typed Config、无副作用校验及 Compiler/Planner；配置 AST 不进入业务层。

P03 已实现 V0.1 的 1 MiB 输入、深度/节点/scalar 上限、单文档 event AST、完整 Typed Config、稳定错误目录、定义全量校验、可达依赖闭包和静态 Feature Plan。解析与 Planner 不读取文件、不绑定端口、不解析域名，也不创建 Runtime 资源；prepare/lazy 激活由后续任务实现。

关联任务：C03 / P03。
