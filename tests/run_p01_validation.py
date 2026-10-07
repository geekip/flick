#!/usr/bin/env python3
"""运行 P01 受测 preset，并写入可追踪的 product-validation 记录。"""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
TESTED_PRESETS = {
  "dev", "release", "release-minimal", "asan", "ubsan", "coverage", "fuzz",
}
BUILD_TYPES = {
  "dev": "Debug",
  "release": "Release",
  "release-minimal": "Release",
  "asan": "RelWithDebInfo",
  "ubsan": "RelWithDebInfo",
  "coverage": "Debug",
  "fuzz": "RelWithDebInfo",
}


def sha256(path):
  """sha256 返回文件原始字节摘要。"""
  return hashlib.sha256(path.read_bytes()).hexdigest()


def relative(path):
  """relative 返回相对项目根的 POSIX 路径。"""
  return path.resolve().relative_to(ROOT).as_posix()


def artifact(path, role, media_type=None):
  """artifact 生成统一文件元数据，不读取或内嵌文件正文。"""
  item = {
    "path": relative(path),
    "role": role,
    "bytes": path.stat().st_size,
    "sha256": sha256(path),
  }
  if media_type is not None:
    item["media_type"] = media_type
  return item


def utc_now():
  """utc_now 生成秒精度 UTC RFC 3339 时间。"""
  return datetime.datetime.now(datetime.timezone.utc).replace(
    microsecond=0).isoformat().replace("+00:00", "Z")


def source_paths():
  """source_paths 枚举 P01 构建和验证实际使用的源输入。"""
  paths = [
    ROOT / "CMakeLists.txt",
    ROOT / "CMakePresets.json",
    ROOT / "document/FlickNet-Technical-Baseline-V1.0.md",
    ROOT / "document/FlickNet-Background-and-References-V1.0.md",
    ROOT / "document/FlickNet-Requirements-Freeze-Audit-V0.1.md",
    ROOT / "document/FlickNet-Core-and-Session-Design-V0.1.md",
    ROOT / "document/FlickNet-V0.1-Engineering-Plan.md",
    ROOT / "references/p01-build-runtime-notes.md",
    ROOT / "third_party/dependencies-v0.1.json",
    ROOT / "tests/run_p01_validation.py",
    ROOT / "tests/fixtures/evidence/v0_1/validation-result.schema.json",
  ]
  for directory in ("cmake", "include", "src", "tests/unit"):
    paths.extend(
      path for path in (ROOT / directory).rglob("*")
      if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    )
  return sorted(set(paths), key=lambda path: relative(path).encode("utf-8"))


def write_source_manifest(path):
  """write_source_manifest 按 C06 的排序和行格式写源清单。"""
  lines = [f"{sha256(item)}  {relative(item)}\n" for item in source_paths()]
  path.write_bytes("".join(lines).encode("utf-8"))
  return sha256(path)


def git_state():
  """git_state 在无首个提交时明确返回 null revision。"""
  revision = subprocess.run(
    ["git", "rev-parse", "--verify", "HEAD"], cwd=ROOT,
    capture_output=True, text=True, check=False)
  status = subprocess.run(
    ["git", "status", "--porcelain"], cwd=ROOT,
    capture_output=True, text=True, check=False)
  return (
    revision.stdout.strip() if revision.returncode == 0 else None,
    status.returncode != 0 or bool(status.stdout.strip()),
  )


def run_command(argv, index, log_dir, extra_env=None, expected_exit_codes=None):
  """run_command 以 argv 直接执行并分别保存 stdout/stderr。"""
  env = None
  if extra_env:
    import os
    env = os.environ.copy()
    env.update(extra_env)
  started = time.monotonic_ns()
  result = subprocess.run(
    argv, cwd=ROOT, env=env, capture_output=True, check=False)
  duration_ms = (time.monotonic_ns() - started) // 1_000_000
  stdout_path = log_dir / f"command-{index:02d}.stdout.txt"
  stderr_path = log_dir / f"command-{index:02d}.stderr.txt"
  stdout_path.write_bytes(result.stdout)
  stderr_path.write_bytes(result.stderr)
  expected = [0] if expected_exit_codes is None else expected_exit_codes
  return {
    "argv": argv,
    "cwd": ".",
    "exit_code": result.returncode,
    "expected_exit_codes": expected,
    "duration_ms": duration_ms,
    "stdout": artifact(stdout_path, "stdout", "text/plain"),
    "stderr": artifact(stderr_path, "stderr", "text/plain"),
  }


def reference_analysis():
  """reference_analysis 固定 P01 已审阅上游和许可边界。"""
  note = ROOT / "references/p01-build-runtime-notes.md"
  note_hash = sha256(note)
  return {
    "background_reviewed": True,
    "records": [relative(note)],
    "details": [
      {
        "path": relative(note),
        "sha256": note_hash,
        "upstream": "https://salsa.debian.org/debian/libev.git",
        "revision": "b0bea514f1aaf80f6361937e057d8deb18d82f05",
        "license": "BSD-2-Clause or GPL-2+",
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
      {
        "path": relative(note),
        "sha256": note_hash,
        "upstream": "https://github.com/c-ares/c-ares.git",
        "revision": "c7a3138dcfe3bb0eaaf10c0c24c36dc66dc790ab",
        "license": "MIT",
        "copied_code": False,
      },
    ],
  }


def instrumentation_for(preset):
  """instrumentation_for 返回当前 preset 的实际编译插桩。"""
  values = {
    "dev": ["profiling"],
    "release": [],
    "release-minimal": [],
    "asan": ["asan"],
    "ubsan": ["ubsan"],
    "coverage": ["coverage"],
    "fuzz": ["asan", "ubsan", "libfuzzer"],
  }
  return values[preset]


def main():
  """main 执行 configure/build/test，并在失败时保留可审阅记录。"""
  parser = argparse.ArgumentParser(description="Run a FlickNet P01 validation preset.")
  parser.add_argument("--preset", choices=sorted(TESTED_PRESETS), required=True)
  parser.add_argument("--output", type=Path, required=True)
  args = parser.parse_args()

  preset = args.preset
  output_path = args.output if args.output.is_absolute() else ROOT / args.output
  result_dir = ROOT / "build/validation/p01" / preset
  build_dir = ROOT / "build" / preset
  shutil.rmtree(result_dir, ignore_errors=True)
  result_dir.mkdir(parents=True)

  source_manifest_path = result_dir / "source-manifest.txt"
  source_manifest_hash = write_source_manifest(source_manifest_path)
  started_at = utc_now()
  started_ns = time.monotonic_ns()
  commands = []

  command_specs = [
    (["cmake", "--preset", preset], None, [0]),
    (["cmake", "--build", "--preset", preset, "--parallel"], None, [0]),
  ]
  junit_path = result_dir / "ctest.junit.xml"
  if preset not in {"release-minimal", "fuzz"}:
    extra_env = None
    if preset == "asan":
      extra_env = {"ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:strict_string_checks=1"}
    elif preset == "ubsan":
      extra_env = {"UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1"}
    command_specs.append(([
      "ctest", "--preset", preset, "--output-on-failure",
      "--output-junit", str(junit_path),
    ], extra_env, [0]))
  if preset == "coverage":
    command_specs.append(([
      "cmake", "--build", "--preset", "coverage", "--target", "coverage",
    ], None, [0]))
  negative_log_index = None
  if preset == "dev":
    negative_build_dir = ROOT / ".cache/builds/p01-missing-pkgconfig"
    shutil.rmtree(negative_build_dir, ignore_errors=True)
    negative_log_index = len(command_specs) + 1
    command_specs.append(([
      "cmake", "-S", ".", "-B", relative(negative_build_dir),
      "-G", "Ninja", "-DCMAKE_C_COMPILER=/usr/bin/gcc",
      "-DCMAKE_BUILD_TYPE=Debug", "-DFN_BUILD_PROFILE=custom",
      "-DFN_BUILD_TESTING=OFF",
      "-DCMAKE_DISABLE_FIND_PACKAGE_PkgConfig=TRUE",
    ], None, [1]))

  for index, (argv, extra_env, expected_exit_codes) in enumerate(command_specs, start=1):
    command = run_command(
      argv, index, result_dir, extra_env, expected_exit_codes)
    commands.append(command)
    if command["exit_code"] not in command["expected_exit_codes"]:
      break

  result = "pass" if len(commands) == len(command_specs) and all(
    command["exit_code"] in command["expected_exit_codes"]
    for command in commands) else "fail"
  defects = [] if result == "pass" else ["P01_COMMAND_FAILED"]

  if result == "pass" and negative_log_index is not None:
    negative_stdout = result_dir / f"command-{negative_log_index:02d}.stdout.txt"
    negative_stderr = result_dir / f"command-{negative_log_index:02d}.stderr.txt"
    negative_output = negative_stdout.read_text() + negative_stderr.read_text()
    negative_flat = " ".join(negative_output.split())
    if "PkgConfig" not in negative_flat or \
       "A REQUIRED package cannot be disabled" not in negative_flat:
      result = "fail"
      defects = ["P01_NEGATIVE_DEPENDENCY_REASON_MISMATCH"]

  if result == "pass" and junit_path.is_file():
    test_suite = ET.parse(junit_path).getroot()
    test_count = int(test_suite.attrib.get("tests", "0"))
    if test_count < 1:
      result = "fail"
      defects = ["P01_EMPTY_TEST_SUITE"]

  capability_path = build_dir / "flick-capabilities.json"
  if not capability_path.is_file():
    raise SystemExit("Capability manifest was not generated.")
  capability = json.loads(capability_path.read_text())

  inputs = [
    artifact(ROOT / ".harness/reviews/environment.json", "environment", "application/json"),
    artifact(ROOT / "third_party/dependencies-v0.1.json", "dependency-lock", "application/json"),
    artifact(ROOT / "document/FlickNet-Technical-Baseline-V1.0.md",
             "task-source", "text/markdown"),
    artifact(ROOT / "document/FlickNet-Background-and-References-V1.0.md",
             "task-source", "text/markdown"),
    artifact(ROOT / "document/FlickNet-Requirements-Freeze-Audit-V0.1.md",
             "task-source", "text/markdown"),
    artifact(ROOT / "document/FlickNet-Core-and-Session-Design-V0.1.md",
             "task-source", "text/markdown"),
    artifact(ROOT / "document/FlickNet-V0.1-Engineering-Plan.md",
             "task-source", "text/markdown"),
    artifact(ROOT / "references/p01-build-runtime-notes.md", "reference-analysis", "text/markdown"),
    artifact(ROOT / "tests/fixtures/evidence/v0_1/validation-result.schema.json",
             "result-schema", "application/schema+json"),
    artifact(source_manifest_path, "source-manifest", "text/plain"),
  ]
  input_hashes = {item["path"]: item["sha256"] for item in inputs}

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
    "task": "P01",
    "kind": "build",
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
    "input_hashes": input_hashes,
    "artifacts": artifacts,
    "counts": {
      "planned": len(command_specs),
      "executed": len(commands),
      "passed": sum(command["exit_code"] in command["expected_exit_codes"]
                    for command in commands),
      "failed": sum(command["exit_code"] not in command["expected_exit_codes"]
                    for command in commands),
      "skipped": len(command_specs) - len(commands),
    },
    "reference_analysis": reference_analysis(),
    "defects": defects,
    "limitations": [
      "P01 validates the build, dependency, result and capability skeleton only.",
      "No flick executable, config parser, event-loop adapter or proxy data path exists yet.",
      "No performance, fuzz-duration, soak or release claim is made by this record.",
    ],
  }
  output_path.parent.mkdir(parents=True, exist_ok=True)
  output_path.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n")
  print(f"P01 {preset} validation: {result}.")
  print(f"Evidence: {relative(output_path)}")
  raise SystemExit(0 if result == "pass" else 1)


if __name__ == "__main__":
  main()
