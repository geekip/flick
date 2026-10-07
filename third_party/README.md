# third_party

依赖与数据来源登记；不复制上游实现，不替项目所有者选择主项目许可证。

关联任务：F07 / ENV-01 / C06。[V0.1 依赖锁定](dependencies-v0.1.json)记录 Debian 13 基准环境中的 libev/libyaml 源包、二进制版本、发现方式、文件摘要与许可证路径。它是当前受测环境输入，不代表已完成主项目发布许可审查，也不证明产品已构建。

[V0.1 Submodule 策略](submodule-policy-v0.1.json)记录用户提出的七个仓库及其当前用途。项目允许后续增加显式 `system`/`vendored` 两种模式，但默认继续使用已验证的系统包，configure 阶段不得联网或自动回退。Submodule 只用于已经存在真实调用者的直接依赖，并固定 commit；参考实现和未来版本候选不预先引入。

当前结论：

- `libyaml` 是 V0.1 直接依赖，可从 canonical Git 仓库作为可选 Submodule 引入；
- `libev` 是 V0.1 直接依赖，但 `libev-cn/libev` 只作为候选镜像，完成来源与维护状态审阅前继续使用 Debian 包；
- `json-parser`、`uthash`、`xxHash`、`c-ares`、`lwIP` 没有 V0.1 链接需求，不加入 Submodule；其中 `c-ares` 仅作 resolver 行为参考，`xxHash` 与 `lwIP` 留到产生对应版本契约和调用者时再评估。
