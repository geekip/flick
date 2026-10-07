#!/usr/bin/env python3
"""运行 P11 受测组合，并写入统一 product-validation 记录。"""

import argparse
import json
import os
from pathlib import Path
import shutil
import time
import xml.etree.ElementTree as ET

from run_p01_validation import (
  artifact,
  git_state,
  relative,
  run_command,
  sha256,
  utc_now,
)


ROOT = Path(__file__).resolve().parents[1]
TESTED_PRESETS = {"dev", "release", "asan", "ubsan"}
BUILD_TYPES = {
  "dev": "Debug",
  "release": "Release",
  "asan": "RelWithDebInfo",
  "ubsan": "RelWithDebInfo",
}
EXPECTED_BITS = "0x000000900002b004"
EXPECTED_FEATURES = {
  "direct_tcp",
  "dns_failure_cache",
  "dns_resolver",
  "dns_upstream_tcp",
  "dns_upstream_udp",
  "socks_in_tcp",
  "socks_out_tcp",
}


def source_paths():
  """source_paths 枚举 P11 实现、测试和直接合同输入。"""
  paths = [
    "CMakeLists.txt",
    "CMakePresets.json",
    "cmake/FlickBuildMetadata.cmake",
    "cmake/FlickDependencies.cmake",
    "cmake/FlickProjectOptions.cmake",
    "cmake/flick-capabilities.json.in",
    "include/flicknet/address.h",
    "include/flicknet/build.h",
    "include/flicknet/cli.h",
    "include/flicknet/config.h",
    "include/flicknet/direct.h",
    "include/flicknet/loop.h",
    "include/flicknet/metadata.h",
    "include/flicknet/observability.h",
    "include/flicknet/platform.h",
    "include/flicknet/pool.h",
    "include/flicknet/resolver.h",
    "include/flicknet/resource.h",
    "include/flicknet/result.h",
    "include/flicknet/router.h",
    "include/flicknet/runtime.h",
    "include/flicknet/session.h",
    "include/flicknet/socks5.h",
    "include/flicknet/socks5_outbound.h",
    "include/flicknet/stream.h",
    "src/cli/app.c",
    "src/cli/app_internal.h",
    "src/cli/cli.c",
    "src/cli/main.c",
    "src/config/config.c",
    "src/core/build.c",
    "src/core/metadata.c",
    "src/core/observability.c",
    "src/core/operation.c",
    "src/core/operation_internal.h",
    "src/core/pool.c",
    "src/core/resource.c",
    "src/core/result.c",
    "src/core/runtime.c",
    "src/core/session.c",
    "src/dns/dns_wire.c",
    "src/dns/resolver.c",
    "src/dns/resolver_internal.h",
    "src/dns/resolver_linux.c",
    "src/inbound/socks5.c",
    "src/net/loop.c",
    "src/net/stream.c",
    "src/outbound/direct.c",
    "src/outbound/socks5.c",
    "src/platform/linux/platform.c",
    "src/router/router.c",
    "src/util/address.c",
    "src/util/clock.c",
    "tests/integration/test_p11_cli.py",
    "tests/unit/check_capability_manifest.py",
    "tests/unit/test_p01_contract.c",
    "tests/unit/test_p11_cli_observability.c",
    "tests/run_p01_validation.py",
    "tests/run_p11_validation.py",
    "references/p11-cli-lifecycle-notes.md",
    "third_party/dependencies-v0.1.json",
    "third_party/submodule-policy-v0.1.json",
    "tests/fixtures/evidence/v0_1/validation-result.schema.json",
    "document/FlickNet-Technical-Baseline-V1.0.md",
    "document/FlickNet-Background-and-References-V1.0.md",
    "document/FlickNet-Requirements-Freeze-Audit-V0.1.md",
    "document/FlickNet-Core-and-Session-Design-V0.1.md",
    "document/FlickNet-Configuration-Schema-V0.1.md",
    "document/FlickNet-V0.1-Engineering-Plan.md",
  ]
  return sorted((ROOT / path for path in paths),
                key=lambda path: relative(path).encode("utf-8"))


def write_source_manifest(path):
  """write_source_manifest 使用 C06 固定的 sha256 双空格格式。"""
  lines = [f"{sha256(item)}  {relative(item)}\n" for item in source_paths()]
  path.write_bytes("".join(lines).encode("utf-8"))
  return sha256(path)


def reference_analysis():
  """reference_analysis 记录 P11 实际阅读的固定上游源码。"""
  note = ROOT / "references/p11-cli-lifecycle-notes.md"
  common = {
    "path": relative(note),
    "sha256": sha256(note),
    "copied_code": False,
  }
  return {
    "background_reviewed": True,
    "records": [relative(note)],
    "details": [
      common | {
        "upstream": "https://github.com/shadowsocks/shadowsocks-libev.git",
        "revision": "8285e5a7de093b8ae5a2ca68f7108e6f273092b1",
        "license": "GPL-3.0-or-later",
      },
      common | {
        "upstream": "https://github.com/zfl9/ipt2socks.git",
        "revision": "b2f1461976817417ebf0c9c14210a9f199a22438",
        "license": "AGPL-3.0-only",
      },
    ],
  }


def instrumentation_for(preset):
  """instrumentation_for 返回实际启用的受测插桩。"""
  return {
    "dev": ["profiling"],
    "release": [],
    "asan": ["asan"],
    "ubsan": ["ubsan"],
  }[preset]


def capability_matches(capability):
  """capability_matches 核对 bitset 与所有 true feature 完全一致。"""
  actual = {
    name for name, enabled in capability["compiled_features"].items()
    if enabled
  }
  return (capability["compiled_feature_bits"] == EXPECTED_BITS and
          actual == EXPECTED_FEATURES)


def main():
  """main 构建并只运行 P11 测试，失败时仍保留完整日志。"""
  parser = argparse.ArgumentParser(description="Run FlickNet P11 validation.")
  parser.add_argument("--preset", choices=sorted(TESTED_PRESETS), required=True)
  parser.add_argument("--output", type=Path, required=True)
  args = parser.parse_args()

  preset = args.preset
  output_path = args.output if args.output.is_absolute() else ROOT / args.output
  result_dir = ROOT / "build/validation/p11" / preset
  build_dir = ROOT / "build" / preset
  shutil.rmtree(result_dir, ignore_errors=True)
  result_dir.mkdir(parents=True)
  source_manifest_path = result_dir / "source-manifest.txt"
  source_manifest_hash = write_source_manifest(source_manifest_path)
  junit_path = result_dir / "ctest.junit.xml"
  started_at = utc_now()
  started_ns = time.monotonic_ns()
  commands = []
  test_env = None
  if preset == "asan":
    test_env = os.environ.copy()
    test_env["ASAN_OPTIONS"] = (
      "detect_leaks=1:halt_on_error=1:strict_string_checks=1")
  elif preset == "ubsan":
    test_env = os.environ.copy()
    test_env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"

  command_specs = [
    (["cmake", "--preset", preset], None),
    (["cmake", "--build", "--preset", preset, "--parallel"], None),
    (["ctest", "--preset", preset, "-R", "^p11\\.",
      "--output-on-failure", "--output-junit", str(junit_path)], test_env),
  ]
  if preset == "dev":
    command_specs.append(
      (["ctest", "--preset", preset, "-R", "^p11\\.",
        "--repeat", "until-fail:100", "--output-on-failure"], test_env))
  for index, (argv, environment) in enumerate(command_specs, start=1):
    command = run_command(argv, index, result_dir, environment, [0])
    commands.append(command)
    if command["exit_code"] != 0:
      break

  result = "pass" if len(commands) == len(command_specs) and all(
    command["exit_code"] == 0 for command in commands) else "fail"
  defects = [] if result == "pass" else ["P11_COMMAND_FAILED"]
  test_count = 0
  if result == "pass" and junit_path.is_file():
    suite = ET.parse(junit_path).getroot()
    test_count = int(suite.attrib.get("tests", "0"))
    if test_count != 2:
      result = "fail"
      defects = ["P11_TEST_COUNT_MISMATCH"]

  capability_path = build_dir / "flick-capabilities.json"
  if not capability_path.is_file():
    raise SystemExit("Capability manifest was not generated.")
  capability = json.loads(capability_path.read_text())
  if not capability_matches(capability):
    result = "fail"
    defects = ["P11_CAPABILITY_MISMATCH"]

  inputs = [
    artifact(ROOT / ".harness/reviews/environment.json",
             "environment", "application/json"),
    artifact(ROOT / "third_party/dependencies-v0.1.json",
             "dependency-lock", "application/json"),
    artifact(ROOT / "third_party/submodule-policy-v0.1.json",
             "dependency-policy", "application/json"),
  ]
  inputs.extend(artifact(ROOT / path, "task-source", "text/markdown")
                for path in [
                  "document/FlickNet-Technical-Baseline-V1.0.md",
                  "document/FlickNet-Background-and-References-V1.0.md",
                  "document/FlickNet-Requirements-Freeze-Audit-V0.1.md",
                  "document/FlickNet-Core-and-Session-Design-V0.1.md",
                  "document/FlickNet-Configuration-Schema-V0.1.md",
                  "document/FlickNet-V0.1-Engineering-Plan.md",
                ])
  inputs.extend([
    artifact(ROOT / "references/p11-cli-lifecycle-notes.md",
             "reference-analysis", "text/markdown"),
    artifact(ROOT / "tests/fixtures/evidence/v0_1/validation-result.schema.json",
             "result-schema", "application/schema+json"),
    artifact(source_manifest_path, "source-manifest", "text/plain"),
  ])
  artifacts = [
    artifact(capability_path, "capability-manifest", "application/json"),
    artifact(source_manifest_path, "source-manifest", "text/plain"),
  ]
  if junit_path.is_file():
    artifacts.append(artifact(junit_path, "ctest-junit", "application/xml"))

  revision, dirty = git_state()
  dependencies = capability["dependencies"]
  record = {
    "schema": "flick.validation-result/v1",
    "record_status": "evidence",
    "scope": "product-validation",
    "task": "P11",
    "kind": "integration",
    "result": result,
    "started_at": started_at,
    "finished_at": utc_now(),
    "duration_ms": (time.monotonic_ns() - started_ns) // 1_000_000,
    "source": {
      "revision": revision,
      "dirty": dirty,
      "manifest_sha256": source_manifest_hash,
      "manifest": artifact(source_manifest_path, "source-manifest",
                           "text/plain"),
    },
    "environment": {
      "snapshot_path": ".harness/reviews/environment.json",
      "snapshot_sha256": sha256(ROOT / ".harness/reviews/environment.json"),
    },
    "build": {
      "preset": preset,
      "build_type": BUILD_TYPES[preset],
      "compiler": capability["compiler"],
      "dependencies": [
        {"name": "libev", "version": dependencies["libev"]},
        {"name": "libyaml", "version": dependencies["libyaml"]},
      ],
      "capability_manifest": artifact(
        capability_path, "capability-manifest", "application/json"),
      "instrumentation": instrumentation_for(preset),
    },
    "commands": commands,
    "inputs": inputs,
    "input_hashes": {item["path"]: item["sha256"] for item in inputs},
    "artifacts": artifacts,
    "counts": {
      "planned": len(command_specs),
      "executed": len(commands),
      "passed": sum(command["exit_code"] == 0 for command in commands),
      "failed": sum(command["exit_code"] != 0 for command in commands),
      "skipped": len(command_specs) - len(commands),
    },
    "reference_analysis": reference_analysis(),
    "defects": defects,
    "limitations": [
      "P11 covers the foreground V0.1 process and private signal shutdown; public control and reload remain outside V0.1.",
      "Listener, target, DNS and reference SOCKS services run on loopback; this is lifecycle and interoperability evidence, not external-network or performance evidence.",
      "Exit codes 0, 2, 3, 4, 5 and 8 are fault-induced at process level; codes 6, 7 and 70 retain explicit implementation mappings but are not injected by this task.",
    ],
  }
  output_path.parent.mkdir(parents=True, exist_ok=True)
  output_path.write_text(json.dumps(record, indent=2,
                                    ensure_ascii=False) + "\n")
  print(f"P11 {preset} validation: {result}; tests={test_count}.")
  print(f"Evidence: {relative(output_path)}")
  raise SystemExit(0 if result == "pass" else 1)


if __name__ == "__main__":
  main()
