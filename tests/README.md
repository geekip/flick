# 验证目录

当前有 P01–P14 的真实 unit/integration：除构建、基础类型与配置外，已验证 libev loop、Socket Policy、Runtime/Router、带背压和 half-close 的双向 relay、最小 Resolver、DIRECT、SOCKS5 入站/出站、本地双代理完整链，以及 `flick` CLI、listener、日志门控、loop counter、信号退出和内部 Runtime A/B 替换。fault/resource、fuzz、soak、benchmark 与 platform/linux 工具覆盖正常、边界、失败、取消与回收路径；fixtures 保存可重复输入和预期结果。

V0.1 使用本地受控服务验证两条 TCP 链、DNS fixture、旧代保活和资源上限；P13 提供 ASan/UBSan、parser fuzz、泄漏与受控长稳运行工具，每次运行的实际时长必须单独记录。V0.2 才加入 namespace/veth 透明网络拓扑。没有目标时不注册空 CTest，不把没有测试记为通过。

构建后使用 `ctest --preset <preset> --output-on-failure` 执行对应测试矩阵。
