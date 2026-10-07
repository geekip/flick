#!/usr/bin/env python3
"""运行 P13 单个 parser fuzz target，并写入可追踪验证记录。"""

import argparse
import json
from pathlib import Path
import re
import shutil
import time

from run_p01_validation import (
  artifact,
  git_state,
  relative,
  run_command,
  sha256,
  utc_now,
)


ROOT = Path(__file__).resolve().parents[1]
FORMAL_DURATION_SECONDS = 3600
SEED = 104729
TARGETS = {
  "fuzz_config": {
    "fixture": "tests/fixtures/config/v1",
    "max_len": 1048577,
  },
  "fuzz_socks5": {
    "fixture": "tests/fixtures/socks5/v0_1",
    "max_len": 33024,
  },
  "fuzz_dns": {
    "fixture": "tests/fixtures/dns/v0_1",
    "max_len": 65537,
  },
}


def source_paths():
  """source_paths 枚举 P13 fuzz 的实现、合同和参考输入。"""
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
    ROOT / "tests/run_p13_fuzz.py",
    ROOT / "tests/fixtures/evidence/v0_1/validation-result.schema.json",
  ]
  for directory in ("cmake", "include", "src", "tests/fuzz"):
    paths.extend(path for path in (ROOT / directory).rglob("*")
                 if path.is_file())
  for target in TARGETS.values():
    paths.extend(path for path in (ROOT / target["fixture"]).rglob("*")
                 if path.is_file())
  return sorted(set(paths), key=lambda path: relative(path).encode("utf-8"))


def write_manifest(paths, destination):
  """write_manifest 按 C06 双空格格式写排序 SHA-256 清单。"""
  ordered = sorted(paths, key=lambda path: relative(path).encode("utf-8"))
  lines = [f"{sha256(path)}  {relative(path)}\n" for path in ordered]
  destination.write_bytes("".join(lines).encode("utf-8"))
  return sha256(destination)


def write_source_manifest(destination):
  """write_source_manifest 固定本次受测源码集合。"""
  return write_manifest(source_paths(), destination)


def safe_name(value):
  """safe_name 把合同 case id 转为稳定文件名。"""
  return re.sub(r"[^a-zA-Z0-9_.-]+", "-", value).strip("-")


def decode_seed(data):
  """decode_seed 将项目可审阅的 hex seed 物化为真实 wire bytes。"""
  if data.startswith(b"hex:"):
    return bytes.fromhex(data[4:].decode("ascii").strip())
  return data


def materialize_config_corpus(source, destination):
  """materialize_config_corpus 平铺全部 C03 YAML fixture。"""
  for path in sorted(source.rglob("*.yaml")):
    name = "--".join(path.relative_to(source).parts)
    (destination / name).write_bytes(path.read_bytes())


def materialize_socks_corpus(source, destination):
  """materialize_socks_corpus 拼接每个 C04 case 的入站 wire 输入。"""
  manifest = json.loads((source / "manifest.json").read_text())
  for item in manifest["cases"]:
    chunks = [bytes.fromhex(step["feed_hex"])
              for step in item.get("steps", []) if "feed_hex" in step]
    if chunks:
      (destination / f"case--{safe_name(item['id'])}").write_bytes(
        b"".join(chunks))
  for path in sorted(source.glob("*.seed")):
    (destination / f"seed--{path.name}").write_bytes(
      decode_seed(path.read_bytes()))


def materialize_dns_corpus(source, destination):
  """materialize_dns_corpus 提取 C05 响应和 TCP frame 中的 DNS message。"""
  manifest = json.loads((source / "manifest.json").read_text())
  for item in manifest["parser_cases"]:
    if "response_hex" in item:
      payload = bytes.fromhex(item["response_hex"])
    else:
      frame = bytes.fromhex(item["frame_hex"])
      payload = frame[2:]
    (destination / f"case--{safe_name(item['id'])}").write_bytes(payload)
  for path in sorted(source.glob("*.seed")):
    (destination / f"seed--{path.name}").write_bytes(
      decode_seed(path.read_bytes()))


def prepare_corpus(target, result_dir):
  """prepare_corpus 建立不可变初始 corpus 与独立可写工作副本。"""
  source = ROOT / TARGETS[target]["fixture"]
  initial = ROOT / "build/fuzz/corpus-initial" / target
  working = ROOT / "build/fuzz/corpus" / target
  shutil.rmtree(initial, ignore_errors=True)
  shutil.rmtree(working, ignore_errors=True)
  initial.mkdir(parents=True)
  if target == "fuzz_config":
    materialize_config_corpus(source, initial)
  elif target == "fuzz_socks5":
    materialize_socks_corpus(source, initial)
  else:
    materialize_dns_corpus(source, initial)
  units = sorted(path for path in initial.iterdir() if path.is_file())
  if not units:
    raise RuntimeError("Initial fuzz corpus is empty.")
  manifest = result_dir / "initial-corpus-manifest.txt"
  manifest_hash = write_manifest(units, manifest)
  shutil.copytree(initial, working)
  return source, initial, working, units, manifest, manifest_hash


def write_final_corpus_manifest(working, destination):
  """write_final_corpus_manifest 记录 libFuzzer 运行后可写 corpus。"""
  units = sorted(path for path in working.iterdir() if path.is_file())
  write_manifest(units, destination)
  return units


def reference_analysis():
  """reference_analysis 固定 P13 实际审阅的 parser fuzz 上游。"""
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


def capability_matches(capability):
  """capability_matches 核对 fuzz 请求、目标存在性和插桩模式。"""
  instrumentation = capability["instrumentation"]
  return (
    capability["profile"] == "fuzz" and
    instrumentation["fuzzers_requested"] is True and
    instrumentation["fuzz_targets_present"] is True and
    instrumentation["sanitizer"] == "fuzz"
  )


def executed_inputs(stderr):
  """executed_inputs 从 libFuzzer 最后一个进度行提取执行次数。"""
  matches = re.findall(r"^#(\d+)\s+", stderr, flags=re.MULTILINE)
  return int(matches[-1]) if matches else 0


def sanitizer_finding(stderr):
  """sanitizer_finding 检测即使退出码异常处理失效也不应遗漏的报告。"""
  needles = (
    "ERROR: AddressSanitizer",
    "ERROR: LeakSanitizer",
    "UndefinedBehaviorSanitizer:",
    "runtime error:",
    "SUMMARY: AddressSanitizer",
  )
  return any(needle in stderr for needle in needles)


def main():
  """main 构建并运行一个独立 target；短运行只能生成 example。"""
  parser = argparse.ArgumentParser(description="Run one FlickNet P13 fuzz target.")
  parser.add_argument("--target", choices=sorted(TARGETS), required=True)
  parser.add_argument("--duration", type=int, default=FORMAL_DURATION_SECONDS)
  parser.add_argument("--development-smoke", action="store_true")
  parser.add_argument("--output", type=Path, required=True)
  args = parser.parse_args()
  if args.duration <= 0:
    parser.error("--duration must be positive")
  if args.duration < FORMAL_DURATION_SECONDS and not args.development_smoke:
    parser.error("durations below 3600 require --development-smoke")
  if args.development_smoke and args.duration >= FORMAL_DURATION_SECONDS:
    parser.error("--development-smoke is only valid below 3600 seconds")

  target = args.target
  result_dir = ROOT / "build/validation/p13/fuzz" / target
  artifact_dir = ROOT / "build/fuzz/artifacts" / target
  output_path = args.output if args.output.is_absolute() else ROOT / args.output
  shutil.rmtree(result_dir, ignore_errors=True)
  shutil.rmtree(artifact_dir, ignore_errors=True)
  result_dir.mkdir(parents=True)
  artifact_dir.mkdir(parents=True)

  source_manifest = result_dir / "source-manifest.txt"
  source_hash = write_source_manifest(source_manifest)
  (fixture, initial, working, initial_units,
   corpus_manifest, corpus_hash) = prepare_corpus(target, result_dir)
  started_at = utc_now()
  started_ns = time.monotonic_ns()
  commands = []
  command_specs = [
    ["cmake", "--preset", "fuzz"],
    ["cmake", "--build", "--preset", "fuzz", "--parallel"],
    [
      relative(ROOT / "build/fuzz" / target),
      relative(working),
      f"-seed={SEED}",
      f"-max_len={TARGETS[target]['max_len']}",
      "-timeout=5",
      "-rss_limit_mb=2048",
      "-detect_leaks=1",
      f"-max_total_time={args.duration}",
      f"-artifact_prefix={relative(artifact_dir)}/",
    ],
  ]
  for index, argv in enumerate(command_specs, start=1):
    command = run_command(argv, index, result_dir, None, [0])
    commands.append(command)
    if command["exit_code"] != 0:
      break

  duration_ms = (time.monotonic_ns() - started_ns) // 1_000_000
  fuzz_duration_ms = commands[2]["duration_ms"] if len(commands) == 3 else 0
  stderr = ""
  if len(commands) == 3:
    stderr = (ROOT / commands[2]["stderr"]["path"]).read_text(
      errors="replace")
  runs = executed_inputs(stderr)
  findings = sorted(path for path in artifact_dir.iterdir() if path.is_file())
  final_manifest = result_dir / "final-corpus-manifest.txt"
  final_units = write_final_corpus_manifest(working, final_manifest)

  capability_path = ROOT / "build/fuzz/flick-capabilities.json"
  capability = (json.loads(capability_path.read_text())
                if capability_path.is_file() else None)
  formal_duration_met = (
    args.development_smoke or fuzz_duration_ms >= FORMAL_DURATION_SECONDS * 1000)
  passed = (
    len(commands) == len(command_specs) and
    all(command["exit_code"] == 0 for command in commands) and
    capability is not None and capability_matches(capability) and
    not findings and not sanitizer_finding(stderr) and
    formal_duration_met
  )
  result = "pass" if passed else "fail"
  defects = []
  if not passed:
    if len(commands) != len(command_specs) or any(
        command["exit_code"] != 0 for command in commands):
      defects.append("P13_FUZZ_COMMAND_FAILED")
    if capability is None or not capability_matches(capability):
      defects.append("P13_FUZZ_CAPABILITY_MISMATCH")
    if findings:
      defects.append("P13_FUZZ_ARTIFACT_FOUND")
    if sanitizer_finding(stderr):
      defects.append("P13_FUZZ_SANITIZER_FINDING")
    if not formal_duration_met:
      defects.append("P13_FUZZ_DURATION_SHORT")

  fixture_files = sorted(path for path in fixture.rglob("*") if path.is_file())
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
    artifact(corpus_manifest, "initial-corpus-manifest", "text/plain"),
  ]
  inputs.extend(artifact(path, "contract-fixture") for path in fixture_files)
  inputs.extend(artifact(path, "fuzz-corpus-unit") for path in initial_units)
  artifacts = [
    artifact(source_manifest, "source-manifest", "text/plain"),
    artifact(corpus_manifest, "initial-corpus-manifest", "text/plain"),
    artifact(final_manifest, "final-corpus-manifest", "text/plain"),
  ]
  if capability_path.is_file():
    artifacts.append(artifact(capability_path, "capability-manifest",
                              "application/json"))
  artifacts.extend(artifact(path, "fuzz-finding") for path in findings)

  revision, dirty = git_state()
  dependencies = capability["dependencies"] if capability else {
    "libev": "unavailable", "libyaml": "unavailable"}
  record = {
    "schema": "flick.validation-result/v1",
    "record_status": "example" if args.development_smoke else "evidence",
    "scope": "product-validation",
    "task": "P13",
    "kind": "fuzz",
    "result": result,
    "started_at": started_at,
    "finished_at": utc_now(),
    "duration_ms": duration_ms,
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
      "preset": "fuzz",
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
        artifact(source_manifest, "missing-capability-placeholder", "text/plain")
      ),
      "instrumentation": ["asan", "ubsan", "libfuzzer"],
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
    "metrics": [
      {
        "name": "fuzzer_monotonic_duration",
        "unit": "seconds",
        "samples": [fuzz_duration_ms / 1000.0],
        "value": fuzz_duration_ms / 1000.0,
      },
      {
        "name": "executed_inputs",
        "unit": "inputs",
        "samples": [runs],
        "value": runs,
      },
      {
        "name": "initial_corpus_files",
        "unit": "files",
        "samples": [len(initial_units)],
        "value": len(initial_units),
      },
      {
        "name": "final_corpus_files",
        "unit": "files",
        "samples": [len(final_units)],
        "value": len(final_units),
      },
      {
        "name": "finding_artifacts",
        "unit": "files",
        "samples": [len(findings)],
        "value": len(findings),
      },
    ],
    "reference_analysis": reference_analysis(),
    "defects": defects,
    "limitations": [
      "This bounded fuzz run can only report findings observed for the recorded seed, corpus and duration.",
      "The writable corpus is isolated under build/fuzz; source fixtures remain immutable inputs.",
    ] + ([
      "This development smoke is shorter than 3600 seconds and cannot satisfy the V0.1 fuzz gate.",
    ] if args.development_smoke else []),
  }
  output_path.parent.mkdir(parents=True, exist_ok=True)
  output_path.write_text(json.dumps(record, indent=2,
                                    ensure_ascii=False) + "\n")
  print(f"P13 {target} fuzz: {result}; duration={fuzz_duration_ms / 1000.0:.3f}s; "
        f"runs={runs}; findings={len(findings)}; corpus={corpus_hash}.")
  print(f"Record: {relative(output_path)}")
  raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
  main()
