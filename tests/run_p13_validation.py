#!/usr/bin/env python3
"""运行 P13 全量 sanitizer 回归，并写统一验证记录。"""

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
TESTED_PRESETS = {"asan", "ubsan"}


def source_paths():
  """source_paths 枚举 P13 sanitizer 受测源码、测试和合同输入。"""
  paths = [
    ROOT / "CMakeLists.txt",
    ROOT / "CMakePresets.json",
    ROOT / "document/FlickNet-Technical-Baseline-V1.0.md",
    ROOT / "document/FlickNet-Background-and-References-V1.0.md",
    ROOT / "document/FlickNet-Requirements-Freeze-Audit-V0.1.md",
    ROOT / "document/FlickNet-Core-and-Session-Design-V0.1.md",
    ROOT / "document/FlickNet-DNS-and-FakeDNS-Design-V0.1.md",
    ROOT / "document/FlickNet-Configuration-Schema-V0.1.md",
    ROOT / "document/FlickNet-V0.1-Engineering-Plan.md",
    ROOT / "references/p13-fuzz-soak-notes.md",
    ROOT / "third_party/dependencies-v0.1.json",
    ROOT / "third_party/submodule-policy-v0.1.json",
    ROOT / "tests/run_p01_validation.py",
    ROOT / "tests/run_p13_validation.py",
    ROOT / "tests/soak/run_v0_1.py",
    ROOT / "tests/soak/test_theil_sen.py",
    ROOT / "tests/soak/theil_sen.c",
    ROOT / "tests/fixtures/evidence/v0_1/validation-result.schema.json",
  ]
  for directory in ("cmake", "include", "src", "tests/unit",
                    "tests/integration"):
    paths.extend(path for path in (ROOT / directory).rglob("*")
                 if path.is_file() and "__pycache__" not in path.parts and
                 path.suffix != ".pyc")
  return sorted(set(paths), key=lambda path: relative(path).encode("utf-8"))


def write_source_manifest(path):
  """write_source_manifest 使用 C06 固定的 SHA-256 双空格格式。"""
  lines = [f"{sha256(item)}  {relative(item)}\n" for item in source_paths()]
  path.write_bytes("".join(lines).encode("utf-8"))
  return sha256(path)


def reference_analysis():
  """reference_analysis 固定 P13 已审阅 parser 与长稳上游。"""
  note = ROOT / "references/p13-fuzz-soak-notes.md"
  note_hash = sha256(note)
  return {
    "background_reviewed": True,
    "records": [relative(note)],
    "details": [
      {
        "path": relative(note),
        "sha256": note_hash,
        "upstream": "https://github.com/c-ares/c-ares.git",
        "revision": "c7a3138dcfe3bb0eaaf10c0c24c36dc66dc790ab",
        "license": "MIT",
        "copied_code": False,
      },
      {
        "path": relative(note),
        "sha256": note_hash,
        "upstream": "https://github.com/yaml/libyaml.git",
        "revision": "2c891fc7a770e8ba2fec34fc6b545c672beb37e6",
        "license": "MIT",
        "copied_code": False,
      },
    ],
  }


def sanitizer_finding(paths):
  """sanitizer_finding 防止退出码处理异常时遗漏 sanitizer 报告。"""
  needles = (
    "ERROR: AddressSanitizer",
    "ERROR: LeakSanitizer",
    "UndefinedBehaviorSanitizer:",
    "runtime error:",
    "SUMMARY: AddressSanitizer",
  )
  for path in paths:
    text = path.read_text(errors="replace")
    if any(needle in text for needle in needles):
      return True
  return False


def capability_matches(capability, preset):
  """capability_matches 核对受测 profile、测试目标和 sanitizer 类型。"""
  instrumentation = capability.get("instrumentation", {})
  sanitizer = {"asan": "address", "ubsan": "undefined"}[preset]
  return (
    capability.get("profile") == preset and
    instrumentation.get("tests_built") is True and
    instrumentation.get("sanitizer") == sanitizer
  )


def main():
  """main 配置、构建并在独立 sanitizer 环境运行全量 CTest。"""
  parser = argparse.ArgumentParser(description="Run FlickNet P13 sanitizers.")
  parser.add_argument("--preset", choices=sorted(TESTED_PRESETS), required=True)
  parser.add_argument("--output", type=Path, required=True)
  args = parser.parse_args()
  preset = args.preset
  output_path = args.output if args.output.is_absolute() else ROOT / args.output
  result_dir = ROOT / "build/validation/p13" / preset
  build_dir = ROOT / "build" / preset
  shutil.rmtree(result_dir, ignore_errors=True)
  result_dir.mkdir(parents=True)
  source_manifest = result_dir / "source-manifest.txt"
  source_hash = write_source_manifest(source_manifest)
  junit_path = result_dir / "ctest.junit.xml"
  started_at = utc_now()
  started_ns = time.monotonic_ns()
  environment = os.environ.copy()
  if preset == "asan":
    environment["ASAN_OPTIONS"] = (
      "detect_leaks=1:halt_on_error=1:strict_string_checks=1")
  else:
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
  command_specs = [
    (["cmake", "--preset", preset], None),
    (["cmake", "--build", "--preset", preset, "--parallel"], None),
    (["ctest", "--preset", preset, "--output-on-failure",
      "--output-junit", str(junit_path)], environment),
    (["python3", "tests/soak/test_theil_sen.py", "--binary",
      relative(build_dir / "fn_p13_theil_sen"), "--work-directory",
      relative(result_dir / "theil-sen-test")], environment),
  ]
  commands = []
  for index, (argv, command_environment) in enumerate(command_specs, start=1):
    command = run_command(
      argv, index, result_dir, command_environment, [0])
    commands.append(command)
    if command["exit_code"] != 0:
      break

  defects = []
  if len(commands) != len(command_specs) or any(
      command["exit_code"] != 0 for command in commands):
    defects.append("P13_SANITIZER_COMMAND_FAILED")
  test_count = 0
  if junit_path.is_file():
    suite = ET.parse(junit_path).getroot()
    test_count = int(suite.attrib.get("tests", "0"))
    if test_count != 18:
      defects.append("P13_SANITIZER_TEST_COUNT_MISMATCH")
  else:
    defects.append("P13_SANITIZER_JUNIT_MISSING")
  logs = []
  for command in commands:
    logs.extend((ROOT / command[name]["path"] for name in ("stdout", "stderr")))
  if sanitizer_finding(logs):
    defects.append("P13_SANITIZER_FINDING")

  capability_path = build_dir / "flick-capabilities.json"
  capability = (json.loads(capability_path.read_text())
                if capability_path.is_file() else None)
  if capability is None or not capability_matches(capability, preset):
    defects.append("P13_SANITIZER_CAPABILITY_MISMATCH")
  defects = list(dict.fromkeys(defects))
  result = "pass" if not defects else "fail"

  inputs = [
    artifact(ROOT / ".harness/reviews/environment.json",
             "environment", "application/json"),
    artifact(ROOT / "third_party/dependencies-v0.1.json",
             "dependency-lock", "application/json"),
    artifact(ROOT / "third_party/submodule-policy-v0.1.json",
             "dependency-policy", "application/json"),
    artifact(ROOT / "references/p13-fuzz-soak-notes.md",
             "reference-analysis", "text/markdown"),
    artifact(ROOT / "tests/fixtures/evidence/v0_1/validation-result.schema.json",
             "result-schema", "application/schema+json"),
    artifact(source_manifest, "source-manifest", "text/plain"),
  ]
  artifacts = [artifact(source_manifest, "source-manifest", "text/plain")]
  if capability_path.is_file():
    artifacts.append(artifact(
      capability_path, "capability-manifest", "application/json"))
  if junit_path.is_file():
    artifacts.append(artifact(junit_path, "ctest-junit", "application/xml"))
  revision, dirty = git_state()
  dependencies = capability["dependencies"] if capability else {
    "libev": "unavailable", "libyaml": "unavailable"}
  record = {
    "schema": "flick.validation-result/v1",
    "record_status": "evidence",
    "scope": "product-validation",
    "task": "P13",
    "kind": "resource",
    "result": result,
    "started_at": started_at,
    "finished_at": utc_now(),
    "duration_ms": (time.monotonic_ns() - started_ns) // 1_000_000,
    "source": {
      "revision": revision,
      "dirty": dirty,
      "manifest_sha256": source_hash,
      "manifest": artifact(source_manifest, "source-manifest", "text/plain"),
    },
    "environment": {
      "snapshot_path": ".harness/reviews/environment.json",
      "snapshot_sha256": sha256(ROOT / ".harness/reviews/environment.json"),
    },
    "build": {
      "preset": preset,
      "build_type": "RelWithDebInfo",
      "compiler": (capability["compiler"] if capability else
                   {"name": "unavailable", "version": "unavailable"}),
      "dependencies": [
        {"name": "libev", "version": dependencies["libev"]},
        {"name": "libyaml", "version": dependencies["libyaml"]},
      ],
      "capability_manifest": (
        artifact(capability_path, "capability-manifest", "application/json")
        if capability_path.is_file() else
        artifact(source_manifest, "missing-capability-placeholder", "text/plain")),
      "instrumentation": [preset],
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
      "The sanitizer suites use deterministic local fixtures and loopback integration tests; the separate formal soak supplies duration evidence.",
      "A clean bounded sanitizer run only reports that no finding was observed in the recorded tests.",
    ],
  }
  output_path.parent.mkdir(parents=True, exist_ok=True)
  output_path.write_text(json.dumps(record, indent=2,
                                    ensure_ascii=False) + "\n")
  print(f"P13 {preset} validation: {result}; tests={test_count}.")
  print(f"Evidence: {relative(output_path)}")
  raise SystemExit(0 if result == "pass" else 1)


if __name__ == "__main__":
  main()
