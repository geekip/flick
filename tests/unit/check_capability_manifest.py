#!/usr/bin/env python3
"""核验 P01 生成的能力清单，不把构建工具状态当作产品能力。"""

import argparse
import json
from pathlib import Path
import re


def main():
  """main 校验身份、profile、依赖和全部未实现能力。"""
  parser = argparse.ArgumentParser(description="Validate the FlickNet build capability manifest.")
  parser.add_argument("--path", required=True, type=Path)
  parser.add_argument("--profile", required=True)
  args = parser.parse_args()

  data = json.loads(args.path.read_text())
  if data.get("schema") != "flick.build-capabilities/v1":
    raise SystemExit("Invalid capability schema.")
  if data.get("program") != "flick" or data.get("software_release") is not None:
    raise SystemExit("Invalid product identity or release claim.")
  if data.get("profile") != args.profile:
    raise SystemExit("Build profile mismatch.")
  if data.get("compiled_feature_bits") != "0x000000900002b004":
    raise SystemExit("Compiled feature bitset does not match P11.")

  features = data.get("compiled_features")
  if not isinstance(features, dict) or not features:
    raise SystemExit("Compiled feature map is missing.")
  expected_enabled = {
    "direct_tcp", "dns_failure_cache", "dns_resolver",
    "dns_upstream_tcp", "dns_upstream_udp", "socks_in_tcp",
    "socks_out_tcp",
  }
  enabled = {name for name, value in features.items() if value is True}
  invalid_values = sorted(name for name, value in features.items()
                          if not isinstance(value, bool))
  if invalid_values or enabled != expected_enabled:
    raise SystemExit("Compiled capability map does not match P11.")

  dependencies = data.get("dependencies", {})
  if dependencies.get("libev") != "4.33" or dependencies.get("libyaml") != "0.2.5":
    raise SystemExit("Dependency version mismatch.")
  source = data.get("source", {})
  revision = source.get("revision")
  if revision is not None and not re.fullmatch(r"[0-9a-f]{7,64}", revision):
    raise SystemExit("Invalid Git revision.")
  if not isinstance(source.get("dirty"), bool):
    raise SystemExit("Git dirty state must be a boolean.")

  instrumentation = data.get("instrumentation", {})
  expected = {
    "tests_built": args.profile != "release-minimal",
    "benchmarks_requested": args.profile == "release",
    "benchmark_targets_present": args.profile == "release",
    "fuzzers_requested": False,
    "fuzz_targets_present": False,
    "profiling": args.profile == "dev",
    "coverage": args.profile == "coverage",
    "sanitizer": {
      "asan": "address",
      "ubsan": "undefined",
    }.get(args.profile, "none"),
  }
  if instrumentation != expected:
    raise SystemExit(
      f"Instrumentation capability mismatch: {instrumentation!r}")
  print("Capability manifest check passed.")


if __name__ == "__main__":
  main()
