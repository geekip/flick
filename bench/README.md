# bench

`bench_rule`、`bench_socks`、`bench_dns` 与 `bench_relay` 测量正式 C 产品路径；
`run.py` 负责固定输入、真实 loopback 产品链、容量阶梯、环境快照、结果复算与统一
证据。正式合同为 5 次预热、30 个样本、seed 104729，共 28 个 case 和 105 组指标。

正式命令：

```sh
python3 bench/run.py --preset release --targets rule,socks,dns,relay \
  --warmup 5 --samples 30 --seed 104729 \
  --output build/release/results/benchmark-v0.1.json
```

所有网络流量仅使用本地 loopback。关联任务：P14 / C06 / D14。
