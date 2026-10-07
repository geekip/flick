#!/usr/bin/env python3
"""运行 P06 受测组合，并写入统一 product-validation 记录。"""

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


def source_paths():
  """source_paths 枚举 P06 实现、测试和直接合同输入。"""
  paths = [
    ROOT / "CMakeLists.txt",
    ROOT / "CMakePresets.json",
    ROOT / "cmake/FlickDependencies.cmake",
    ROOT / "cmake/FlickProjectOptions.cmake",
    ROOT / "include/flicknet/clock.h",
    ROOT / "include/flicknet/loop.h",
    ROOT / "include/flicknet/platform.h",
    ROOT / "include/flicknet/pool.h",
    ROOT / "include/flicknet/resource.h",
    ROOT / "include/flicknet/result.h",
    ROOT / "include/flicknet/stream.h",
    ROOT / "src/core/pool.c",
    ROOT / "src/core/resource.c",
    ROOT / "src/net/loop.c",
    ROOT / "src/net/stream.c",
    ROOT / "src/platform/linux/platform.c",
    ROOT / "tests/unit/test_p06_stream_relay.c",
    ROOT / "tests/run_p01_validation.py",
    ROOT / "tests/run_p06_validation.py",
    ROOT / "references/p06-stream-relay-notes.md",
    ROOT / "third_party/dependencies-v0.1.json",
    ROOT / "third_party/submodule-policy-v0.1.json",
    ROOT / "tests/fixtures/evidence/v0_1/validation-result.schema.json",
    ROOT / "document/FlickNet-Technical-Baseline-V1.0.md",
    ROOT / "document/FlickNet-Background-and-References-V1.0.md",
    ROOT / "document/FlickNet-Requirements-Freeze-Audit-V0.1.md",
    ROOT / "document/FlickNet-Core-and-Session-Design-V0.1.md",
    ROOT / "document/FlickNet-V0.1-Engineering-Plan.md",
  ]
  return sorted(paths, key=lambda path: relative(path).encode("utf-8"))


def write_source_manifest(path):
  """write_source_manifest 使用 C06 固定的 sha256 双空格格式。"""
  lines = [f"{sha256(item)}  {relative(item)}\n" for item in source_paths()]
  path.write_bytes("".join(lines).encode("utf-8"))
  return sha256(path)


def reference_analysis():
  """reference_analysis 记录 P06 实际阅读的固定上游源码。"""
  note = ROOT / "references/p06-stream-relay-notes.md"
  note_hash = sha256(note)
  return {
    "background_reviewed": True,
    "records": [relative(note)],
    "details": [
      {
        "path": relative(note),
        "sha256": note_hash,
        "upstream": "https://github.com/zfl9/ipt2socks.git",
        "revision": "b2f1461976817417ebf0c9c14210a9f199a22438",
        "license": "AGPL-3.0",
        "copied_code": False,
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


def main():
  """main 构建并只运行 P06 测试，失败时仍保留完整日志。"""
  parser = argparse.ArgumentParser(description="Run FlickNet P06 validation.")
  parser.add_argument("--preset", choices=sorted(TESTED_PRESETS), required=True)
  parser.add_argument("--output", type=Path, required=True)
  args = parser.parse_args()

  preset = args.preset
  output_path = args.output if args.output.is_absolute() else ROOT / args.output
  result_dir = ROOT / "build/validation/p06" / preset
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
    (["ctest", "--preset", preset, "-R", "^p06\\.",
      "--output-on-failure", "--output-junit", str(junit_path)], test_env),
  ]
  for index, (argv, environment) in enumerate(command_specs, start=1):
    command = run_command(argv, index, result_dir, environment, [0])
    commands.append(command)
    if command["exit_code"] != 0:
      break

  result = "pass" if len(commands) == len(command_specs) and all(
    command["exit_code"] == 0 for command in commands) else "fail"
  defects = [] if result == "pass" else ["P06_COMMAND_FAILED"]
  test_count = 0
  if result == "pass" and junit_path.is_file():
    test_suite = ET.parse(junit_path).getroot()
    test_count = int(test_suite.attrib.get("tests", "0"))
    if test_count != 1:
      result = "fail"
      defects = ["P06_TEST_COUNT_MISMATCH"]

  capability_path = build_dir / "flick-capabilities.json"
  if not capability_path.is_file():
    raise SystemExit("Capability manifest was not generated.")
  capability = json.loads(capability_path.read_text())
  if any(capability["compiled_features"].values()):
    result = "fail"
    defects = ["P06_RUNTIME_CAPABILITY_REPORTED_EARLY"]

  inputs = [
    artifact(ROOT / ".harness/reviews/environment.json",
             "environment", "application/json"),
    artifact(ROOT / "third_party/dependencies-v0.1.json",
             "dependency-lock", "application/json"),
    artifact(ROOT / "third_party/submodule-policy-v0.1.json",
             "dependency-policy", "application/json"),
  ]
  inputs.extend(artifact(path, "task-source", "text/markdown") for path in [
    ROOT / "document/FlickNet-Technical-Baseline-V1.0.md",
    ROOT / "document/FlickNet-Background-and-References-V1.0.md",
    ROOT / "document/FlickNet-Requirements-Freeze-Audit-V0.1.md",
    ROOT / "document/FlickNet-Core-and-Session-Design-V0.1.md",
    ROOT / "document/FlickNet-V0.1-Engineering-Plan.md",
  ])
  inputs.extend([
    artifact(ROOT / "references/p06-stream-relay-notes.md",
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
    "task": "P06",
    "kind": "resource" if preset == "dev" else "unit",
    "result": result,
    "started_at": started_at,
    "finished_at": utc_now(),
    "duration_ms": (time.monotonic_ns() - started_ns) // 1_000_000,
    "source": {
      "revision": revision,
      "dirty": dirty,
      "manifest_sha256": source_manifest_hash,
      "manifest": artifact(source_manifest_path, "source-manifest", "text/plain"),
    },
    "environment": {
      "snapshot_path": ".harness/reviews/environment.json",
      "snapshot_sha256": sha256(ROOT / ".harness/reviews/environment.json"),
    },
    "build": {
      "preset": preset,
      "build_type": BUILD_TYPES[preset],
      "compiler": {
        "name": capability["compiler"]["name"],
        "version": capability["compiler"]["version"],
      },
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
      "P06 validates socket Stream, bounded user-space buffering, backpressure, half-close and terminal lifecycle in isolation.",
      "splice and adaptive buffer sizing remain excluded until P14 measurement; protocol adapters join the Stream boundary in later tasks.",
      "Socket creation/fd admission remains the responsibility of the later platform factory; P06 takes ownership of already admitted sockets.",
    ],
  }
  output_path.parent.mkdir(parents=True, exist_ok=True)
  output_path.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n")
  print(f"P06 {preset} validation: {result}; tests={test_count}.")
  print(f"Evidence: {relative(output_path)}")
  raise SystemExit(0 if result == "pass" else 1)


if __name__ == "__main__":
  main()
