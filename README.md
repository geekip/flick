# FlickNet

**轻量、按需运行的网络代理内核。**

FlickNet 面向 Linux 路由器、网络网关和代理服务器，将代理转发、规则分流、DNS 与 FakeIP 纳入统一配置。主程序名为 **`flick`**。

> V0.1 本地源码里程碑已通过验收，源码构建可生成 `flick` 前台程序，支持 SOCKS5 TCP 入站、DIRECT 与 SOCKS5 TCP 出站、最小 Resolver、配置检查和启动环境检查。当前仍无可安装的发行版，也未发布、推送或部署；其他功能以表中的版本规划为准。

## 适合哪些场景

- **局域网代理**：为浏览器、应用和其他设备提供 SOCKS5 或 HTTP 代理入口。
- **路由器透明代理**：在网关统一处理需要代理的流量，减少终端逐台配置。
- **按规则分流**：根据域名、IP、端口、来源或 Geo 数据选择直连、代理或拒绝。
- **轻量代理服务**：在 Linux 设备上运行服务，查看连接状态并定位网络故障。

## 当前功能与规划

| 能力 | 内容 | 交付安排 |
|---|---|---|
| SOCKS5 代理 | TCP CONNECT、用户名密码认证、直连及 SOCKS5 上游 | V0.1 本地源码验收已通过，尚未发布 |
| 透明代理与 UDP | Linux IPv4 TPROXY、SOCKS5 UDP、按目标隔离的数据报转发 | V0.2 |
| DNS 与 FakeIP | DNS 转发、缓存、选择性 FakeIP、映射持久化与恢复 | V0.2 |
| 规则分流 | 域名、IP、来源、端口和入站规则，按配置顺序首条命中 | V0.2；首版先提供 MATCH |
| Geo 与代理组 | GeoIP/GeoSite、手动选择、按探测结果选择代理 | V0.3 |
| AnyTLS | 入站与出站、TCP/UDP、TLS 验证、连接复用 | V0.4 |
| 运行管理 | 状态、诊断、规则追踪、配置更新与公开热重载 | V0.5 |
| HTTP 与识别 | Mixed 入口、HTTP CONNECT/普通代理、可选 SNI/Host 识别 | V1 完整版本 |

首个发布目标平台是 **Linux amd64**。ARM、OpenWrt、Padavan 及其他平台按后续版本推进；Windows、macOS 和 TUN 不在 V1 范围内。

## 设计特点

- **按需使用资源**：未使用的功能不启动无关监听、探测或连接池；缓冲按需分配并设定上限。
- **统一管理**：通过 YAML 描述代理、DNS 与路由规则，减少多个独立组件之间的配置协调。
- **行为清晰**：规则按顺序执行；代理失败明确报告，不自动改成直连。
- **更新可恢复**：配置准备失败保留旧配置，已建立连接继续使用原有配置；FakeIP 身份单独持久化。
- **便于诊断**：计划提供连接状态、分阶段错误和按需追踪，帮助区分解析、认证、连接和路由问题。

低 CPU、低内存与高吞吐是设计目标。V0.1 已完成可重复的 Debian amd64 本地
loopback 基准与六预设验证矩阵；这些结果用于源码回归，不代表路由器或其他硬件平台，
也不构成发布性能承诺。基准工作负载和运行入口位于 [`bench/`](bench/)。

## 从源码使用当前实现

在 Debian amd64 开发环境安装 CMake、C11 编译器、libev 和 libyaml 后，可构建开发预设：

```sh
cmake --preset dev
cmake --build --preset dev --parallel
```

将配置保存为 `config.yaml`：

```yaml
schema-version: 1
mode: rule
ipv6: false
log-level: warn

dns:
  enable: false
  direct:
    - udp://192.0.2.53:53

inbounds:
  - name: local-socks
    type: socks5
    listen: 127.0.0.1
    port: 10808
    udp: false

rules:
  - MATCH,DIRECT
```

`192.0.2.53` 是文档示例地址，使用时须替换为可达的 IPv4 DNS 服务器。此配置提供本机 SOCKS5 入口并直连目标；`dns.enable: false` 关闭的是 DNS 服务监听，域名连接仍使用所配置的解析上游。

当前构建提供：

```sh
build/dev/flick -c ./config.yaml check
build/dev/flick -c ./config.yaml test
build/dev/flick -c ./config.yaml run
build/dev/flick version --features
```

`check` 离线检查配置和 Feature Plan；`test` 检查启动所需的本机条件，并明确标记尚未验证的 lazy 外部依赖；`run` 在前台运行。服务启动后，应用的 SOCKS5 地址设为 `127.0.0.1:10808`。SIGTERM 或 SIGINT 会停止接纳并有限排空，第二次信号会强制取消。首次安装与下载方法将在首个发行版提供。

## 项目结构

- [`include/flicknet/`](include/flicknet/)：公开 C 接口。
- [`src/`](src/)：Core、配置、网络、Resolver 与 SOCKS5 实现。
- [`tests/`](tests/)：单元、集成、模糊和长稳测试工具。
- [`bench/`](bench/)：固定工作负载与本地 loopback 基准。

项目许可证将在首次发布前确定。
