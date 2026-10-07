# cmake

受测构建组合、依赖发现、编译告警、hardening、sanitizer 与 coverage。P01 已建立 `dev`、`release`、`release-minimal`、`asan`、`ubsan`、`coverage`、`fuzz` preset；当前只构建核心结果/能力骨架和 P01 测试，fuzz/benchmark 产品目标仍由 P13/P14 交付。

关联任务：P01 / C06。真实能力以 build-local `flick-capabilities.json` 为准，未实现能力全部为 false。
