#!/usr/bin/env python3
"""核验 P14 benchmark driver 的固定输入与 deadline 失败合同。"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile


def load_driver(root: Path):
  """load_driver 从当前源码树加载被测脚本。"""
  path = root / "bench/run.py"
  spec = importlib.util.spec_from_file_location("flick_p14_bench", path)
  if spec is None or spec.loader is None:
    raise AssertionError("cannot load bench/run.py")
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


def expect_driver_error(module, code: str, callback) -> None:
  """expect_driver_error 核对稳定失败码。"""
  try:
    callback()
  except module.DriverError as error:
    if error.code != code:
      raise AssertionError(f"expected {code}, got {error.code}") from error
  else:
    raise AssertionError(f"expected DriverError {code}")


def test_workload_and_targets(module) -> None:
  """test_workload_and_targets 拒绝输入漂移、缺失和未知 target。"""
  workload, digest = module.validate_workload(module.WORKLOAD_PATH)
  assert len(digest) == 64
  assert len(module.expected_cases(workload)) == 28
  assert module.parse_targets("rule,socks,dns,relay") == module.TARGET_ORDER
  for value in ("rule,socks,dns", "rule,socks,dns,relay,unknown",
                "relay,dns,socks,rule", "rule,rule,dns,relay"):
    try:
      module.parse_targets(value)
    except argparse.ArgumentTypeError:
      pass
    else:
      raise AssertionError(f"invalid target set accepted: {value}")

  with tempfile.TemporaryDirectory(prefix="flick-p14-workload-") as name:
    path = Path(name) / "workload.json"
    changed = json.loads(module.WORKLOAD_PATH.read_text(encoding="utf-8"))
    changed["fixture_inputs"]["config"]["sha256"] = "0" * 64
    path.write_text(json.dumps(changed), encoding="utf-8")
    expect_driver_error(
      module, "P14_FIXTURE_HASH", lambda: module.validate_workload(path))


def test_plan_materialization(module) -> None:
  """test_plan_materialization 核对 FNBENCH1 header 与四类 target。"""
  workload, digest = module.validate_workload(module.WORKLOAD_PATH)
  original = module.FIXTURE_DIR
  with tempfile.TemporaryDirectory(
      dir=module.ROOT / "build", prefix="flick-p14-plan-") as name:
    module.FIXTURE_DIR = Path(name)
    plans = module.materialize_plans(workload, digest)
    assert tuple(plans) == module.TARGET_ORDER
    for target, target_id in module.TARGET_IDS.items():
      path = module.ROOT / plans[target]["path"]
      data = path.read_bytes()
      header = struct.unpack("<8sII32sQIIII", data[:72])
      assert header[0] == b"FNBENCH1"
      assert header[1] == 1
      assert header[2] == target_id
      assert header[3].hex() == digest
      assert header[4:7] == (104729, 5, 30)
      assert header[7] == len(workload[target]["cases"])
      assert header[8] == 0
      assert len(data) == 72 + 32 * header[7]
  module.FIXTURE_DIR = original


def test_deadline_terminates_group(module) -> None:
  """test_deadline_terminates_group 保留日志并终止整组子进程。"""
  with tempfile.TemporaryDirectory(
      dir=module.ROOT / "build", prefix="p14-timeout-") as name:
    output = Path(name)
    script = (
      "import subprocess,sys,time; "
      "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']); "
      "print(p.pid,flush=True); time.sleep(30)")
    try:
      module.run_owned(
        [sys.executable, "-c", script], "timeout-contract", 0.1,
        output, 1)
    except module.DriverError as error:
      assert error.code == "P14_STAGE_TIMEOUT"
      assert error.details["termination"]["sigterm"] is True
      stdout = module.ROOT / error.details["stdout"]["path"]
      stderr = module.ROOT / error.details["stderr"]["path"]
      assert stdout.is_file() and stdout.read_text().strip().isdigit()
      assert stderr.is_file()
    else:
      raise AssertionError("deadline command unexpectedly passed")


def main() -> int:
  """main 执行无外网、短时 driver 合同测试。"""
  parser = argparse.ArgumentParser()
  parser.add_argument("--root", required=True, type=Path)
  args = parser.parse_args()
  module = load_driver(args.root.resolve())
  test_workload_and_targets(module)
  test_plan_materialization(module)
  test_deadline_terminates_group(module)
  print("P14 benchmark driver checks passed")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
