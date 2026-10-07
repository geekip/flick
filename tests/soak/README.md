# tests/soak

P13 在 loopback 上运行 V0.1 的 24 小时受控混合流量。正式入口：

```sh
python3 tests/soak/run_v0_1.py \
  --preset release --duration 86400 --seed 104729 \
  --sample-interval 10 \
  --output build/release/results/soak-v0.1.json
```

驱动启动 echo、DNS、无认证/认证参考 SOCKS 服务和六个 `flick`
A/B 进程，建立固定的 64 条长连接并产生短连接、DNS、故障与 Runtime
替换负载。带测试的构建通过继承 fd 和 `SIGUSR1` 取得 owning loop 的真实资源
快照；`release-minimal` 不包含该测试钩子。`theil_sen.c` 对 warm-up 后全部
RSS 样本对计算中位斜率。

短 smoke 必须显式使用 `--development-smoke`，其记录为 `example`，不能关闭
V0.1 的 24 小时门禁。

关联任务：P13 / C06。
