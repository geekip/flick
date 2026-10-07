#!/usr/bin/env python3
"""执行 FlickNet V0.1 的固定本地 benchmark 与证据汇总。"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import functools
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import resource
import select
import selectors
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Any

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
WORKLOAD_PATH = ROOT / "bench/workloads/v0_1.json"
RESULT_DIR = ROOT / "build/release/benchmark-v0_1"
FIXTURE_DIR = RESULT_DIR / "fixtures"
CAPABILITY_SOURCE = ROOT / "build/release/flick-capabilities.json"
CAPABILITY_SNAPSHOT = (
  ROOT / "build/validation/p14/benchmark/flick-capabilities-at-start.json")
FORMAL_SEED = 104729
FORMAL_WARMUPS = 5
FORMAL_SAMPLES = 30
TARGET_IDS = {"rule": 1, "socks": 2, "dns": 3, "relay": 4}
TARGET_ORDER = tuple(TARGET_IDS)
PLAN_ITERATIONS = 1
PLAN_THROUGHPUT = 2


class DriverError(RuntimeError):
  """DriverError 保存稳定、可测试的 P14 失败原因。"""

  def __init__(self, code: str, message: str, details: dict | None = None):
    super().__init__(message)
    self.code = code
    self.details = details or {}


def utc_now() -> str:
  """utc_now 返回秒精度 UTC 时间。"""
  return dt.datetime.now(dt.timezone.utc).isoformat(
    timespec="seconds").replace("+00:00", "Z")


def sha256(path: Path) -> str:
  """sha256 流式计算文件摘要。"""
  digest = hashlib.sha256()
  with path.open("rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
      digest.update(chunk)
  return digest.hexdigest()


def relative(path: Path) -> str:
  """relative 生成仓库相对路径。"""
  return path.resolve().relative_to(ROOT).as_posix()


def artifact(path: Path, role: str, media_type: str | None = None) -> dict:
  """artifact 固定产物字节数与摘要。"""
  value = {
    "path": relative(path),
    "role": role,
    "bytes": path.stat().st_size,
    "sha256": sha256(path),
  }
  if media_type:
    value["media_type"] = media_type
  return value


def write_json(path: Path, value: Any) -> None:
  """write_json 以稳定格式写 JSON。"""
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(value, indent=2, ensure_ascii=False,
                             sort_keys=True) + "\n", encoding="utf-8")


def load_json(path: Path) -> dict:
  """load_json 读取 JSON object。"""
  value = json.loads(path.read_text(encoding="utf-8"))
  if not isinstance(value, dict):
    raise DriverError("P14_JSON_OBJECT", f"JSON root is not an object: {path}")
  return value


def finite_number(value: Any) -> bool:
  """finite_number 排除 bool、NaN 与无穷值。"""
  return isinstance(value, (int, float)) and not isinstance(value, bool) and \
    math.isfinite(float(value))


def nearest_rank(values: list[float], percentile: float) -> float:
  """nearest_rank 与 C 公共实现使用同一分位数定义。"""
  if not values or not all(finite_number(value) for value in values):
    raise DriverError("P14_NONFINITE_SAMPLE", "samples are empty or nonfinite")
  if percentile <= 0 or percentile > 1:
    raise DriverError("P14_PERCENTILE", "percentile is outside (0, 1]")
  ordered = sorted(float(value) for value in values)
  return ordered[max(1, math.ceil(percentile * len(ordered))) - 1]


def measurement(unit: str, direction: str, values: list[float]) -> dict:
  """measurement 保存原始样本与可复算聚合值。"""
  if len(values) != FORMAL_SAMPLES or not all(
      finite_number(value) for value in values):
    raise DriverError(
      "P14_SAMPLE_COUNT", f"{unit} does not contain 30 finite samples")
  samples = [float(value) for value in values]
  return {
    "unit": unit,
    "direction": direction,
    "samples": samples,
    "minimum": min(samples),
    "maximum": max(samples),
    "p50": nearest_rank(samples, 0.50),
    "p95": nearest_rank(samples, 0.95),
    "p99": nearest_rank(samples, 0.99),
  }


def file_matches(path: Path, expected: str) -> bool:
  """file_matches 核对固定输入摘要。"""
  return path.is_file() and sha256(path) == expected


def validate_workload(path: Path) -> tuple[dict, str]:
  """validate_workload 严格检查正式 workload 与 fixture 绑定。"""
  workload = load_json(path)
  required = {
    "schema", "seed", "warmup_samples", "recorded_samples",
    "percentile_method", "rule", "socks", "dns", "relay", "startup",
    "idle", "capacity", "deadlines", "warnings", "fixture_inputs",
  }
  if set(workload) != required:
    raise DriverError("P14_WORKLOAD_FIELDS", "workload fields are not exact")
  if (workload["schema"] != "flick.benchmark-workload/v1" or
      workload["seed"] != FORMAL_SEED or
      workload["warmup_samples"] != FORMAL_WARMUPS or
      workload["recorded_samples"] != FORMAL_SAMPLES or
      workload["percentile_method"] != "nearest-rank"):
    raise DriverError("P14_WORKLOAD_IDENTITY", "workload identity mismatch")
  expected_counts = {"rule": 5, "socks": 3, "dns": 5, "relay": 4}
  for target, count in expected_counts.items():
    cases = workload[target].get("cases")
    if not isinstance(cases, list) or len(cases) != count:
      raise DriverError("P14_WORKLOAD_CASES", f"{target} case count mismatch")
    ids = [item.get("id") for item in cases]
    if len(ids) != len(set(ids)) or any(not isinstance(value, int)
                                       for value in ids):
      raise DriverError("P14_WORKLOAD_CASE_IDS", f"{target} case IDs invalid")
  fixtures = workload["fixture_inputs"]
  for value in fixtures.values():
    fixture_path = ROOT / value["path"]
    if not file_matches(fixture_path, value["sha256"]):
      raise DriverError(
        "P14_FIXTURE_HASH", f"fixture hash mismatch: {fixture_path}")
  deadlines = workload["deadlines"]
  expected_deadlines = {
    "overall_seconds": 7200,
    "configure_seconds": 600,
    "build_seconds": 600,
    "target_process_seconds": 1800,
    "startup_ready_seconds": 10,
    "product_connect_seconds": 10,
    "throughput_sample_seconds": 60,
    "capacity_batch_seconds": 15,
    "resource_observation_seconds": 10,
    "reclaim_seconds": 60,
    "process_stop_seconds": 70,
  }
  if deadlines != expected_deadlines:
    raise DriverError("P14_DEADLINES", "deadline contract mismatch")
  capacity = workload["capacity"]
  if (capacity.get("connection_counts") != [1, 100, 1000, 10000] or
      capacity.get("open_batch_size") != 128):
    raise DriverError("P14_CAPACITY", "capacity workload mismatch")
  relay = workload["relay"]
  if relay.get("chunk_bytes") != 16384:
    raise DriverError("P14_RELAY_CHUNK", "relay chunk must be 16384 bytes")
  return workload, sha256(path)


def case_by_id(items: list[dict], ident: str) -> dict:
  """case_by_id 返回唯一 fixture case。"""
  matches = [item for item in items if item.get("id") == ident]
  if len(matches) != 1:
    raise DriverError("P14_FIXTURE_CASE", f"fixture case is not unique: {ident}")
  return matches[0]


def materialize_fixtures(workload: dict) -> dict:
  """materialize_fixtures 把已校验 manifest 转成 C target 原始输入。"""
  FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
  mapping: dict[str, dict] = {}
  config_source = ROOT / workload["fixture_inputs"]["config"]["path"]
  config_target = FIXTURE_DIR / "rule-config.yaml"
  shutil.copyfile(config_source, config_target)
  mapping[config_target.name] = {
    "source": relative(config_source), "sha256": sha256(config_target)}

  socks_path = ROOT / workload["fixture_inputs"]["socks_manifest"]["path"]
  socks = load_json(socks_path)
  no_auth = case_by_id(socks["cases"], "inbound-no-auth-ipv4-preread")
  auth = case_by_id(socks["cases"], "inbound-auth-domain-success")
  socks_values = {
    "socks-no-auth-greeting.bin": no_auth["steps"][0]["feed_hex"],
    "socks-no-auth-request.bin": no_auth["steps"][2]["feed_hex"],
    "socks-auth-greeting.bin": auth["steps"][0]["feed_hex"],
    "socks-auth-credentials.bin": auth["steps"][2]["feed_hex"],
    "socks-auth-request.bin": auth["steps"][4]["feed_hex"],
  }
  for name, encoded in socks_values.items():
    if not re.fullmatch(r"(?:[0-9a-f]{2})+", encoded):
      raise DriverError("P14_FIXTURE_HEX", f"invalid SOCKS hex: {name}")
    target = FIXTURE_DIR / name
    target.write_bytes(bytes.fromhex(encoded))
    mapping[name] = {
      "source": relative(socks_path), "case": name,
      "sha256": sha256(target)}

  dns_path = ROOT / workload["fixture_inputs"]["dns_manifest"]["path"]
  dns = load_json(dns_path)
  dns_values = {
    "dns-a-success.bin": "a-success",
    "dns-cname-then-a.bin": "cname-then-a",
    "dns-udp-truncated.bin": "udp-truncated-fallback",
    "dns-nxdomain.bin": "nxdomain-terminal",
  }
  for name, ident in dns_values.items():
    value = case_by_id(dns["parser_cases"], ident)["response_hex"]
    if not re.fullmatch(r"(?:[0-9a-f]{2})+", value):
      raise DriverError("P14_FIXTURE_HEX", f"invalid DNS hex: {name}")
    target = FIXTURE_DIR / name
    target.write_bytes(bytes.fromhex(value))
    mapping[name] = {
      "source": relative(dns_path), "case": ident,
      "sha256": sha256(target)}
  mapping_path = FIXTURE_DIR / "mapping.json"
  write_json(mapping_path, {
    "schema": "flick.benchmark-fixture-map/v1", "files": mapping})
  return mapping


def plan_records(workload: dict, target: str) -> list[tuple[int, int, int, int, int]]:
  """plan_records 把 workload 标量映射到固定二进制 record。"""
  records = []
  for case in workload[target]["cases"]:
    if "iterations_per_sample" in case:
      records.append((case["id"], PLAN_ITERATIONS,
                      case["iterations_per_sample"], 0, 0))
    else:
      tertiary = case.get("receiver_delay_ms", workload["relay"]["chunk_bytes"])
      records.append((case["id"], PLAN_THROUGHPUT,
                      case["payload_bytes_per_sample"],
                      case["directions"], tertiary))
  return records


def materialize_plans(workload: dict, workload_sha: str) -> dict[str, dict]:
  """materialize_plans 写入四个 FNBENCH1 little-endian plan。"""
  result = {}
  digest = bytes.fromhex(workload_sha)
  for target in TARGET_ORDER:
    records = plan_records(workload, target)
    header = struct.pack(
      "<8sII32sQIIII", b"FNBENCH1", 1, TARGET_IDS[target], digest,
      FORMAL_SEED, FORMAL_WARMUPS, FORMAL_SAMPLES, len(records), 0)
    body = b"".join(struct.pack("<IIQQQ", *record) for record in records)
    data = header + body
    if len(header) != 72 or len(data) != 72 + 32 * len(records):
      raise DriverError("P14_PLAN_LENGTH", f"invalid plan length: {target}")
    path = FIXTURE_DIR / f"{target}-plan.bin"
    path.write_bytes(data)
    result[target] = {
      "path": relative(path), "bytes": len(data), "sha256": sha256(path),
      "target_id": TARGET_IDS[target], "records": records,
    }
  write_json(FIXTURE_DIR / "plans.json", {
    "schema": "flick.benchmark-plans/v1", "plans": result})
  return result


def terminate_group(process: subprocess.Popen, stop_seconds: float) -> dict:
  """terminate_group 在 deadline 后有限终止自有进程组。"""
  outcome = {"sigterm": False, "sigkill": False, "return_code": None}
  if process.poll() is None:
    os.killpg(process.pid, signal.SIGTERM)
    outcome["sigterm"] = True
    try:
      process.wait(timeout=stop_seconds)
    except subprocess.TimeoutExpired:
      os.killpg(process.pid, signal.SIGKILL)
      outcome["sigkill"] = True
      process.wait(timeout=5)
  outcome["return_code"] = process.returncode
  return outcome


def run_owned(argv: list[str], stage: str, deadline_seconds: float,
              output_dir: Path, sequence: int,
              expected: tuple[int, ...] = (0,)) -> dict:
  """run_owned 执行带进程组 deadline 和持久日志的命令。"""
  stdout_path = output_dir / f"command-{sequence:02d}.stdout.txt"
  stderr_path = output_dir / f"command-{sequence:02d}.stderr.txt"
  started = time.monotonic()
  process = subprocess.Popen(
    argv, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    text=True, start_new_session=True)
  timed_out = False
  termination = None
  try:
    stdout, stderr = process.communicate(timeout=deadline_seconds)
  except subprocess.TimeoutExpired:
    timed_out = True
    termination = terminate_group(process, 5.0)
    stdout, stderr = process.communicate()
  duration = time.monotonic() - started
  stdout_path.write_text(stdout, encoding="utf-8")
  stderr_path.write_text(stderr, encoding="utf-8")
  record = {
    "argv": argv,
    "cwd": ".",
    "exit_code": process.returncode,
    "expected_exit_codes": list(expected),
    "duration_ms": int(duration * 1000),
    "stdout": artifact(stdout_path, "stdout", "text/plain"),
    "stderr": artifact(stderr_path, "stderr", "text/plain"),
  }
  if timed_out:
    raise DriverError("P14_STAGE_TIMEOUT", f"{stage} deadline exceeded", {
      "stage": stage, "deadline_seconds": deadline_seconds,
      "elapsed_seconds": duration, "termination": termination,
      "stdout": record["stdout"], "stderr": record["stderr"],
    })
  if process.returncode not in expected:
    raise DriverError("P14_COMMAND_FAILED", f"{stage} failed", record)
  return record


def validate_capability(path: Path) -> dict:
  """validate_capability 核对正式 Release benchmark 能力。"""
  capability = load_json(path)
  instrumentation = capability.get("instrumentation", {})
  if (capability.get("schema") != "flick.build-capabilities/v1" or
      capability.get("profile") != "release" or
      instrumentation.get("tests_built") is not True or
      instrumentation.get("benchmarks_requested") is not True or
      instrumentation.get("benchmark_targets_present") is not True or
      instrumentation.get("profiling") is not False or
      instrumentation.get("fuzz_targets_present") is not False):
    raise DriverError("P14_CAPABILITY", "Release benchmark capability mismatch")
  CAPABILITY_SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
  source = path.read_bytes()
  if CAPABILITY_SNAPSHOT.exists() and CAPABILITY_SNAPSHOT.read_bytes() != source:
    raise DriverError("P14_CAPABILITY_CONFLICT",
                      "immutable capability snapshot conflicts")
  if not CAPABILITY_SNAPSHOT.exists():
    CAPABILITY_SNAPSHOT.write_bytes(source)
  return capability


def validate_target_record(path: Path, target: str, workload: dict,
                           workload_sha: str, plan: dict) -> dict:
  """validate_target_record 复算 C target 的全部样本聚合。"""
  value = load_json(path)
  required = {
    "schema", "target", "seed", "warmup_count", "sample_count",
    "started_at", "finished_at", "duration_ms", "workload_sha256",
    "plan", "fixture_inputs", "cases", "checks",
  }
  if set(value) != required or value["schema"] != "flick.benchmark-target/v1":
    raise DriverError("P14_TARGET_SCHEMA", f"target schema mismatch: {target}")
  if (value["target"] != target or value["seed"] != FORMAL_SEED or
      value["warmup_count"] != FORMAL_WARMUPS or
      value["sample_count"] != FORMAL_SAMPLES or
      value["workload_sha256"] != workload_sha or
      value["plan"]["target_id"] != TARGET_IDS[target] or
      value["plan"]["case_count"] != len(workload[target]["cases"]) or
      not all(value["checks"].values())):
    raise DriverError("P14_TARGET_IDENTITY", f"target identity mismatch: {target}")
  expected_cases = workload[target]["cases"]
  if [item.get("name") for item in value["cases"]] != [
      item["name"] for item in expected_cases]:
    raise DriverError("P14_TARGET_CASE_ORDER", f"case order mismatch: {target}")
  for actual, expected in zip(value["cases"], expected_cases):
    if (actual.get("phase") != expected["phase"] or
        not all(actual.get("checks", {}).values())):
      raise DriverError("P14_TARGET_CASE", f"case check mismatch: {target}")
    measurements = actual.get("measurements", [])
    if [item.get("unit") for item in measurements] != expected["units"]:
      raise DriverError("P14_TARGET_UNITS", f"unit mismatch: {target}")
    for item in measurements:
      samples = item.get("samples", [])
      if (len(samples) != FORMAL_SAMPLES or
          not all(finite_number(sample) for sample in samples) or
          item["minimum"] != min(samples) or
          item["maximum"] != max(samples) or
          item["p50"] != nearest_rank(samples, 0.50) or
          item["p95"] != nearest_rank(samples, 0.95) or
          item["p99"] != nearest_rank(samples, 0.99)):
        raise DriverError("P14_TARGET_AGGREGATE",
                          f"aggregate mismatch: {target}/{actual['name']}")
  plan_path = ROOT / plan["path"]
  if sha256(plan_path) != plan["sha256"]:
    raise DriverError("P14_PLAN_MUTATED", f"plan mutated: {target}")
  return value


class EchoServer:
  """EchoServer 用单个 selector 线程承载大量本地连接。"""

  def __init__(self):
    self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.listener.bind(("127.0.0.1", 0))
    self.listener.listen(16384)
    self.listener.setblocking(False)
    self.port = self.listener.getsockname()[1]
    self.selector = selectors.DefaultSelector()
    self.selector.register(self.listener, selectors.EVENT_READ, None)
    self.buffers: dict[socket.socket, bytearray] = {}
    self.stop_event = threading.Event()
    self.thread = threading.Thread(target=self._run, name="p14-echo")
    self.thread.start()

  def _close(self, connection: socket.socket) -> None:
    """_close 从 selector 移除单条连接。"""
    try:
      self.selector.unregister(connection)
    except (KeyError, ValueError):
      pass
    self.buffers.pop(connection, None)
    try:
      connection.close()
    except OSError:
      pass

  def _run(self) -> None:
    """_run 接收并回显字节，不创建每连接线程。"""
    while not self.stop_event.is_set():
      try:
        events = self.selector.select(0.1)
      except OSError:
        break
      for key, mask in events:
        if key.fileobj is self.listener:
          while True:
            try:
              connection, _ = self.listener.accept()
              connection.setblocking(False)
              self.buffers[connection] = bytearray()
              self.selector.register(connection, selectors.EVENT_READ,
                                     connection)
            except BlockingIOError:
              break
            except OSError:
              break
          continue
        connection = key.fileobj
        if mask & selectors.EVENT_READ:
          try:
            data = connection.recv(65536)
          except BlockingIOError:
            data = None
          except OSError:
            data = b""
          if data:
            self.buffers[connection].extend(data)
            self.selector.modify(
              connection, selectors.EVENT_READ | selectors.EVENT_WRITE,
              connection)
          elif data == b"":
            self._close(connection)
            continue
        if mask & selectors.EVENT_WRITE and connection in self.buffers:
          pending = self.buffers[connection]
          if pending:
            try:
              sent = connection.send(pending)
              del pending[:sent]
            except BlockingIOError:
              pass
            except OSError:
              self._close(connection)
              continue
          if not pending and connection in self.buffers:
            self.selector.modify(connection, selectors.EVENT_READ,
                                 connection)

  def stop(self) -> None:
    """stop 关闭 listener 与全部已接纳连接。"""
    self.stop_event.set()
    try:
      self.listener.close()
    except OSError:
      pass
    self.thread.join(timeout=5)
    for connection in list(self.buffers):
      self._close(connection)
    self.selector.close()
    if self.thread.is_alive():
      raise DriverError("P14_ECHO_STOP", "echo server did not stop")


def recv_exact(connection: socket.socket, length: int) -> bytes:
  """recv_exact 有界读取固定长度。"""
  output = bytearray()
  while len(output) < length:
    chunk = connection.recv(length - len(output))
    if not chunk:
      raise DriverError("P14_SOCKET_EOF", "unexpected socket EOF")
    output.extend(chunk)
  return bytes(output)


class ReferenceSocksServer:
  """ReferenceSocksServer 提供受控本地 SOCKS5 上游。"""

  def __init__(self, username: str | None = None,
               password: str | None = None):
    self.username = username
    self.password = password
    self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.listener.bind(("127.0.0.1", 0))
    self.listener.listen(512)
    self.listener.settimeout(0.2)
    self.port = self.listener.getsockname()[1]
    self.stop_event = threading.Event()
    self.children: list[threading.Thread] = []
    self.connections: set[socket.socket] = set()
    self.lock = threading.Lock()
    self.thread = threading.Thread(target=self._accept, name="p14-socks")
    self.thread.start()

  def _accept(self) -> None:
    """_accept 为低并发上游样本创建有限工作线程。"""
    while not self.stop_event.is_set():
      try:
        connection, _ = self.listener.accept()
      except socket.timeout:
        continue
      except OSError:
        break
      with self.lock:
        self.connections.add(connection)
      thread = threading.Thread(
        target=self._serve, args=(connection,), name="p14-socks-client")
      thread.start()
      self.children.append(thread)

  def _serve(self, client: socket.socket) -> None:
    """_serve 完成握手并双向转发。"""
    upstream = None
    try:
      client.settimeout(10)
      version, method_count = recv_exact(client, 2)
      methods = recv_exact(client, method_count)
      required = 2 if self.username is not None else 0
      if version != 5 or required not in methods:
        client.sendall(b"\x05\xff")
        return
      client.sendall(bytes((5, required)))
      if required == 2:
        auth_version, user_length = recv_exact(client, 2)
        username = recv_exact(client, user_length).decode("utf-8")
        password_length = recv_exact(client, 1)[0]
        password = recv_exact(client, password_length).decode("utf-8")
        success = (auth_version == 1 and username == self.username and
                   password == self.password)
        client.sendall(bytes((1, 0 if success else 1)))
        if not success:
          return
      version, command, reserved, address_type = recv_exact(client, 4)
      if version != 5 or command != 1 or reserved != 0:
        return
      if address_type == 1:
        host = socket.inet_ntoa(recv_exact(client, 4))
      elif address_type == 3:
        host = recv_exact(client, recv_exact(client, 1)[0]).decode("ascii")
        if host == "echo.test":
          host = "127.0.0.1"
      else:
        return
      port = int.from_bytes(recv_exact(client, 2), "big")
      upstream = socket.create_connection((host, port), timeout=10)
      client.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
      client.setblocking(False)
      upstream.setblocking(False)
      relay_selector = selectors.DefaultSelector()
      relay_selector.register(client, selectors.EVENT_READ, upstream)
      relay_selector.register(upstream, selectors.EVENT_READ, client)
      while not self.stop_event.is_set():
        events = relay_selector.select(0.2)
        if not events:
          continue
        finished = False
        for key, _ in events:
          source = key.fileobj
          target = key.data
          try:
            data = source.recv(65536)
          except BlockingIOError:
            continue
          if not data:
            finished = True
            break
          target.setblocking(True)
          target.sendall(data)
          target.setblocking(False)
        if finished:
          break
      relay_selector.close()
    except (OSError, UnicodeError, DriverError):
      pass
    finally:
      if upstream is not None:
        try:
          upstream.close()
        except OSError:
          pass
      with self.lock:
        self.connections.discard(client)
      try:
        client.close()
      except OSError:
        pass

  def stop(self) -> None:
    """stop 终止受控上游和所有连接。"""
    self.stop_event.set()
    try:
      self.listener.close()
    except OSError:
      pass
    with self.lock:
      for connection in list(self.connections):
        try:
          connection.shutdown(socket.SHUT_RDWR)
        except OSError:
          pass
        connection.close()
    self.thread.join(timeout=5)
    for thread in self.children:
      thread.join(timeout=5)
    if self.thread.is_alive() or any(thread.is_alive()
                                     for thread in self.children):
      raise DriverError("P14_SOCKS_STOP", "reference SOCKS did not stop")


class DnsServer:
  """DnsServer 只回答 echo.test A 127.0.0.1。"""

  def __init__(self):
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.socket.bind(("127.0.0.1", 0))
    self.socket.settimeout(0.2)
    self.port = self.socket.getsockname()[1]
    self.stop_event = threading.Event()
    self.thread = threading.Thread(target=self._run, name="p14-dns")
    self.thread.start()

  @staticmethod
  def _question_end(query: bytes) -> int:
    """_question_end 返回 A/IN question 结束位置。"""
    cursor = 12
    while cursor < len(query) and query[cursor] != 0:
      cursor += 1 + query[cursor]
    if cursor + 5 > len(query):
      raise DriverError("P14_DNS_QUERY", "malformed DNS query")
    return cursor + 5

  def _run(self) -> None:
    """_run 构造最小成功 A response。"""
    while not self.stop_event.is_set():
      try:
        query, address = self.socket.recvfrom(512)
      except socket.timeout:
        continue
      except OSError:
        break
      try:
        end = self._question_end(query)
        header = bytearray(query[:12])
        header[2:4] = b"\x81\x80"
        header[6:8] = b"\x00\x01"
        header[8:12] = b"\x00\x00\x00\x00"
        answer = (b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c"
                  b"\x00\x04\x7f\x00\x00\x01")
        self.socket.sendto(bytes(header) + query[12:end] + answer, address)
      except (OSError, DriverError):
        continue

  def stop(self) -> None:
    """stop 关闭 DNS fixture。"""
    self.stop_event.set()
    self.socket.close()
    self.thread.join(timeout=5)
    if self.thread.is_alive():
      raise DriverError("P14_DNS_STOP", "DNS server did not stop")


def free_port() -> int:
  """free_port 为串行本地启动选择临时端口。"""
  probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  probe.bind(("127.0.0.1", 0))
  port = probe.getsockname()[1]
  probe.close()
  return port


def product_config(port: int, dns_port: int, target: str = "DIRECT",
                   proxy_port: int | None = None,
                   inbound_auth: bool = False,
                   proxy_auth: bool = False) -> str:
  """product_config 生成带 10000 Session 预算的正式本地配置。"""
  users = "\n    users:\n      alice: secret" if inbound_auth else ""
  dns = ""
  proxies = ""
  if target == "DIRECT":
    dns = f"""dns:
  enable: false
  direct:
    - udp://127.0.0.1:{dns_port}
  timeout: 500ms
  attempts: 1
  failure-cache-size: 64
  failure-cache-ttl: 1s
"""
  else:
    credentials = ("\n    username: upstream\n    password: upstream-secret"
                   if proxy_auth else "")
    proxies = f"""proxies:
  - name: upstream
    type: socks5
    server: 127.0.0.1
    port: {proxy_port}
    udp: false{credentials}
"""
  return f"""schema-version: 1
mode: rule
ipv6: false
log-level: warn
limits:
  sessions: 10000
  handshakes: 256
  fds: 32768
  memory: 128MiB
  cleanup-reserve: 2MiB
  buffers: 32MiB
  async-operations: 32768
  workers: 2
  worker-jobs: 64
  lazy-waiters: 1024
  lazy-waiters-per-object: 128
  resource-waiters: 1024
  resolver-pending: 64
  retired-runtimes: 2
timeouts:
  handshake: 10s
  connect: 10s
  tcp-idle: 10m
  drain: 60s
  resource-wait: 1s
  worker-task: 30s
{dns}inbounds:
  - name: bench-in
    type: socks5
    listen: 127.0.0.1
    port: {port}
    udp: false{users}
{proxies}rules:
  - MATCH,{target}
"""


class ProductProcess:
  """ProductProcess 管理一个真实 flick 子进程及测试指标管道。"""

  sequence = 0

  def __init__(self, config_path: Path, startup_deadline: float):
    ProductProcess.sequence += 1
    self.ident = ProductProcess.sequence
    self.config_path = config_path
    self.stdout_path = RESULT_DIR / f"product-{self.ident:03d}.stdout.jsonl"
    self.stderr_path = RESULT_DIR / f"product-{self.ident:03d}.stderr.txt"
    read_fd, write_fd = os.pipe()
    os.set_blocking(read_fd, False)
    environment = os.environ.copy()
    environment["FN_TEST_METRICS_FD"] = str(write_fd)
    self.metrics_fd = read_fd
    self.metrics_buffer = b""
    self.started_monotonic = time.monotonic()
    self.process = subprocess.Popen(
      [str(ROOT / "build/release/flick"), "--output", "json",
       "--config", str(config_path), "run"], cwd=ROOT,
      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
      env=environment, pass_fds=(write_fd,), start_new_session=True)
    os.close(write_fd)
    ready, _, _ = select.select([self.process.stdout], [], [],
                                startup_deadline)
    if not ready:
      terminate_group(self.process, 5.0)
      raise DriverError("P14_STARTUP_TIMEOUT", "flick startup deadline exceeded")
    line = self.process.stdout.readline()
    self.stdout_path.write_text(line, encoding="utf-8")
    if not line:
      _, stderr = self.process.communicate(timeout=2)
      self.stderr_path.write_text(stderr, encoding="utf-8")
      raise DriverError("P14_STARTUP_EXIT", "flick exited before readiness")
    event = json.loads(line)
    if event.get("event") != "started":
      raise DriverError("P14_STARTUP_EVENT", "flick readiness event mismatch")
    self.startup_ms = (time.monotonic() - self.started_monotonic) * 1000.0

  @property
  def pid(self) -> int:
    """pid 返回产品进程 ID。"""
    return self.process.pid

  def metrics(self, deadline: float = 10.0) -> dict:
    """metrics 请求一次内部结构化资源快照。"""
    os.kill(self.pid, signal.SIGUSR1)
    end = time.monotonic() + deadline
    while time.monotonic() < end:
      if b"\n" in self.metrics_buffer:
        line, self.metrics_buffer = self.metrics_buffer.split(b"\n", 1)
        value = json.loads(line.decode("utf-8"))
        if value.get("schema") != "flick.test-metrics/v1":
          raise DriverError("P14_METRICS_SCHEMA", "metrics schema mismatch")
        return value
      ready, _, _ = select.select([self.metrics_fd], [], [],
                                  max(0.0, end - time.monotonic()))
      if not ready:
        break
      chunk = os.read(self.metrics_fd, 65536)
      if not chunk:
        break
      self.metrics_buffer += chunk
    raise DriverError("P14_METRICS_TIMEOUT", "product metrics deadline exceeded")

  def stop(self, deadline: float = 70.0) -> dict:
    """stop 请求干净 drain 并保留终态事件。"""
    if self.process.poll() is None:
      os.kill(self.pid, signal.SIGTERM)
    try:
      stdout, stderr = self.process.communicate(timeout=deadline)
    except subprocess.TimeoutExpired:
      termination = terminate_group(self.process, 5.0)
      stdout, stderr = self.process.communicate()
      raise DriverError("P14_PRODUCT_STOP_TIMEOUT", "product stop timed out",
                        termination)
    with self.stdout_path.open("a", encoding="utf-8") as stream:
      stream.write(stdout)
    self.stderr_path.write_text(stderr, encoding="utf-8")
    os.close(self.metrics_fd)
    lines = self.stdout_path.read_text(encoding="utf-8").splitlines()
    terminal = json.loads(lines[-1]) if len(lines) >= 2 else None
    if (self.process.returncode != 0 or terminal is None or
        terminal.get("event") != "stopped" or
        terminal.get("status") != "ok"):
      raise DriverError("P14_PRODUCT_EXIT", "product did not stop cleanly", {
        "return_code": self.process.returncode, "terminal": terminal})
    return terminal


def process_cpu_seconds(pid: int) -> float:
  """process_cpu_seconds 读取进程 user+system CPU。"""
  text = Path(f"/proc/{pid}/stat").read_text()
  fields = text[text.rfind(")") + 2:].split()
  return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def process_resources(process: ProductProcess) -> dict:
  """process_resources 合并 /proc、内部账本与可归属 socket memory。"""
  values = {"rss_bytes": 0, "pss_bytes": 0}
  for line in Path(f"/proc/{process.pid}/smaps_rollup").read_text().splitlines():
    if line.startswith("Rss:"):
      values["rss_bytes"] = int(line.split()[1]) * 1024
    elif line.startswith("Pss:"):
      values["pss_bytes"] = int(line.split()[1]) * 1024
  internal = process.metrics()
  values["owned_bytes"] = internal["owned_bytes"]
  values["active_sessions"] = internal["active_sessions"]
  values["owned_session_bytes"] = internal["owned_session_bytes"]
  values["pool_live_blocks"] = internal["pool_live_blocks"]
  values["resource_waiters"] = internal["resource_waiters"]
  values["fd_count"] = len(list(Path(f"/proc/{process.pid}/fd").iterdir()))
  completed = subprocess.run(
    ["ss", "-mnp"], capture_output=True, text=True, check=False, timeout=10)
  socket_memory = 0
  if completed.returncode == 0:
    lines = completed.stdout.splitlines()
    for index, line in enumerate(lines):
      if f"pid={process.pid}," not in line:
        continue
      candidates = [line]
      if index + 1 < len(lines):
        candidates.append(lines[index + 1])
      for candidate in candidates:
        match = re.search(r"skmem:\(r(\d+),rb\d+,t(\d+),", candidate)
        if match:
          socket_memory += int(match.group(1)) + int(match.group(2))
  values["socket_memory_bytes"] = socket_memory
  return values


def socks_connect(inbound_port: int, host: str, port: int,
                  credentials: tuple[str, str] | None,
                  deadline: float) -> tuple[socket.socket, float]:
  """socks_connect 完成真实 SOCKS5 CONNECT 并返回建连耗时。"""
  started = time.monotonic()
  connection = socket.create_connection(("127.0.0.1", inbound_port),
                                        timeout=deadline)
  connection.settimeout(deadline)
  try:
    method = 2 if credentials else 0
    connection.sendall(bytes((5, 1, method)))
    if recv_exact(connection, 2) != bytes((5, method)):
      raise DriverError("P14_SOCKS_METHOD", "SOCKS method mismatch")
    if credentials:
      username = credentials[0].encode()
      password = credentials[1].encode()
      connection.sendall(bytes((1, len(username))) + username +
                         bytes((len(password),)) + password)
      if recv_exact(connection, 2) != b"\x01\x00":
        raise DriverError("P14_SOCKS_AUTH", "SOCKS authentication failed")
    try:
      address = b"\x01" + socket.inet_aton(host)
    except OSError:
      encoded = host.encode("ascii")
      address = b"\x03" + bytes((len(encoded),)) + encoded
    connection.sendall(b"\x05\x01\x00" + address + port.to_bytes(2, "big"))
    header = recv_exact(connection, 4)
    if header[:2] != b"\x05\x00":
      raise DriverError("P14_SOCKS_REPLY", f"SOCKS reply failed: {header.hex()}")
    if header[3] == 1:
      recv_exact(connection, 6)
    elif header[3] == 3:
      recv_exact(connection, recv_exact(connection, 1)[0] + 2)
    elif header[3] == 4:
      recv_exact(connection, 18)
    else:
      raise DriverError("P14_SOCKS_ADDRESS", "SOCKS reply address invalid")
    return connection, (time.monotonic() - started) * 1000.0
  except BaseException:
    connection.close()
    raise


@functools.lru_cache(maxsize=128)
def payload_cycle(seed: int) -> bytes:
  """payload_cycle 缓存 251 字节的确定性周期。"""
  return bytes((seed + index * 131) % 251 for index in range(251))


def payload_bytes(seed: int, offset: int, length: int) -> bytes:
  """payload_bytes 以绝对偏移快速生成可复算 payload。"""
  cycle = payload_cycle(seed)
  phase = offset % len(cycle)
  repeated = cycle * ((phase + length + len(cycle) - 1) // len(cycle))
  return repeated[phase:phase + length]


def product_roundtrip(connection: socket.socket, payload_size: int,
                      seed: int, deadline: float) -> tuple[float, int]:
  """product_roundtrip 验证上行和回显下行的全部应用字节。"""
  connection.settimeout(deadline)
  started = time.monotonic()
  offset = 0
  chunk_size = 16384
  while offset < payload_size:
    length = min(chunk_size, payload_size - offset)
    sent = payload_bytes(seed, offset, length)
    connection.sendall(sent)
    received = recv_exact(connection, length)
    if received != sent:
      raise DriverError("P14_PAYLOAD_MISMATCH", "relay payload mismatch")
    offset += length
  elapsed = time.monotonic() - started
  return elapsed, payload_size * 2


def case_result(name: str, phase: str,
                values: dict[str, tuple[str, list[float]]]) -> dict:
  """case_result 把 unit 样本转换为统一 case JSON。"""
  return {
    "name": name,
    "phase": phase,
    "measurements": [
      measurement(unit, direction, samples)
      for unit, (direction, samples) in values.items()
    ],
    "checks": {"behavior": True, "cleanup": True},
  }


def write_product_config(name: str, text: str) -> Path:
  """write_product_config 固定生成配置供证据引用。"""
  path = RESULT_DIR / name
  path.write_text(text, encoding="utf-8")
  return path


def cache_cold(paths: list[Path]) -> None:
  """cache_cold 请求内核丢弃指定文件页缓存。"""
  if not hasattr(os, "posix_fadvise") or not hasattr(os, "POSIX_FADV_DONTNEED"):
    raise DriverError("P14_CACHE_METHOD", "posix_fadvise is unavailable")
  for path in paths:
    descriptor = os.open(path, os.O_RDONLY)
    try:
      os.posix_fadvise(descriptor, 0, 0, os.POSIX_FADV_DONTNEED)
    finally:
      os.close(descriptor)


def cache_hot(paths: list[Path]) -> None:
  """cache_hot 在启动前完整读取固定输入。"""
  for path in paths:
    with path.open("rb") as stream:
      while stream.read(1024 * 1024):
        pass


def run_startup_cases(dns: DnsServer, deadlines: dict) -> list[dict]:
  """run_startup_cases 分别测 cold/hot readiness 与资源。"""
  config = write_product_config(
    "config-startup.yaml", product_config(free_port(), dns.port))
  binary = ROOT / "build/release/flick"
  output = []
  for name, phase, prepare in (
      ("startup_cold_file_cache", "cold", cache_cold),
      ("startup_hot_file_cache", "hot", cache_hot)):
    values = {unit: [] for unit in
              ("ms/start", "rss_bytes", "pss_bytes", "owned_bytes")}
    for index in range(FORMAL_WARMUPS + FORMAL_SAMPLES):
      prepare([binary, config])
      process = ProductProcess(config, deadlines["startup_ready_seconds"])
      resources = process_resources(process)
      process.stop(deadlines["process_stop_seconds"])
      if index >= FORMAL_WARMUPS:
        values["ms/start"].append(process.startup_ms)
        values["rss_bytes"].append(resources["rss_bytes"])
        values["pss_bytes"].append(resources["pss_bytes"])
        values["owned_bytes"].append(resources["owned_bytes"])
    output.append(case_result(name, phase, {
      unit: ("lower-is-better", samples) for unit, samples in values.items()}))
  return output


def run_connect_case(name: str, config: Path, inbound_port: int,
                     echo_port: int, host: str,
                     credentials: tuple[str, str] | None,
                     operations: int, deadlines: dict) -> dict:
  """run_connect_case 测量 50 次真实产品握手/建连。"""
  values = {unit: [] for unit in
            ("ms/connect", "connections/s", "cpu_seconds")}
  process = ProductProcess(config, deadlines["startup_ready_seconds"])
  try:
    for index in range(FORMAL_WARMUPS + FORMAL_SAMPLES):
      cpu_before = process_cpu_seconds(process.pid)
      started = time.monotonic()
      latencies = []
      for _ in range(operations):
        connection, latency = socks_connect(
          inbound_port, host, echo_port, credentials,
          deadlines["product_connect_seconds"])
        latencies.append(latency)
        connection.close()
      elapsed = time.monotonic() - started
      cpu = process_cpu_seconds(process.pid) - cpu_before
      if index >= FORMAL_WARMUPS:
        values["ms/connect"].append(sum(latencies) / len(latencies))
        values["connections/s"].append(operations / elapsed)
        values["cpu_seconds"].append(cpu)
  finally:
    process.stop(deadlines["process_stop_seconds"])
  return case_result(name, "steady", {
    "ms/connect": ("lower-is-better", values["ms/connect"]),
    "connections/s": ("higher-is-better", values["connections/s"]),
    "cpu_seconds": ("lower-is-better", values["cpu_seconds"]),
  })


def run_product_relay_case(name: str, config: Path, inbound_port: int,
                           echo_port: int, host: str,
                           credentials: tuple[str, str] | None,
                           payload_size: int, include_connect: bool,
                           deadlines: dict) -> dict:
  """run_product_relay_case 测量真实 flick relay 的双向应用字节。"""
  units = ["bytes/s", "cpu_seconds", "rss_bytes", "pss_bytes",
           "owned_bytes", "socket_memory_bytes"]
  if include_connect:
    units.append("ms/connect")
  values = {unit: [] for unit in units}
  process = ProductProcess(config, deadlines["startup_ready_seconds"])
  try:
    for index in range(FORMAL_WARMUPS + FORMAL_SAMPLES):
      connection, connect_ms = socks_connect(
        inbound_port, host, echo_port, credentials,
        deadlines["product_connect_seconds"])
      cpu_before = process_cpu_seconds(process.pid)
      elapsed, verified = product_roundtrip(
        connection, payload_size, FORMAL_SEED + index,
        deadlines["throughput_sample_seconds"])
      cpu = process_cpu_seconds(process.pid) - cpu_before
      connection.close()
      resources = process_resources(process)
      if index >= FORMAL_WARMUPS:
        values["bytes/s"].append(verified / elapsed)
        values["cpu_seconds"].append(cpu)
        for unit in ("rss_bytes", "pss_bytes", "owned_bytes",
                     "socket_memory_bytes"):
          values[unit].append(resources[unit])
        if include_connect:
          values["ms/connect"].append(connect_ms)
  finally:
    process.stop(deadlines["process_stop_seconds"])
  directions = {
    "bytes/s": "higher-is-better",
    "cpu_seconds": "lower-is-better",
    "rss_bytes": "lower-is-better",
    "pss_bytes": "lower-is-better",
    "owned_bytes": "lower-is-better",
    "socket_memory_bytes": "lower-is-better",
    "ms/connect": "lower-is-better",
  }
  return case_result(name, "steady", {
    unit: (directions[unit], samples) for unit, samples in values.items()})


def run_idle_case(config: Path, deadlines: dict, interval: float) -> dict:
  """run_idle_case 在单个持久产品上采集稳定空闲资源。"""
  units = ("rss_bytes", "pss_bytes", "owned_bytes", "fd_count",
           "socket_memory_bytes")
  values = {unit: [] for unit in units}
  process = ProductProcess(config, deadlines["startup_ready_seconds"])
  try:
    target = time.monotonic()
    for index in range(FORMAL_WARMUPS + FORMAL_SAMPLES):
      target += interval
      time.sleep(max(0.0, target - time.monotonic()))
      resources = process_resources(process)
      if index >= FORMAL_WARMUPS:
        for unit in units:
          values[unit].append(resources[unit])
  finally:
    process.stop(deadlines["process_stop_seconds"])
  return case_result("idle_stable_minimal", "steady", {
    unit: ("lower-is-better", samples) for unit, samples in values.items()})


def probe_connect_samples(inbound_port: int, echo_port: int,
                          deadlines: dict) -> tuple[list[float], list[float]]:
  """probe_connect_samples 为每个容量拓扑采集独立连接样本。"""
  latency_values = []
  rate_values = []
  for index in range(FORMAL_WARMUPS + FORMAL_SAMPLES):
    started = time.monotonic()
    connection, latency = socks_connect(
      inbound_port, "127.0.0.1", echo_port, None,
      deadlines["product_connect_seconds"])
    elapsed = time.monotonic() - started
    connection.close()
    if index >= FORMAL_WARMUPS:
      latency_values.append(latency)
      rate_values.append(1.0 / elapsed)
  return latency_values, rate_values


def open_capacity_connections(inbound_port: int, echo_port: int,
                              requested: int, batch_size: int,
                              deadline: float) -> tuple[list[socket.socket],
                                                        list[str]]:
  """open_capacity_connections 按 128 条批次建立并持有 Session。"""
  connections: list[socket.socket] = []
  warnings = []
  while len(connections) < requested:
    count = min(batch_size, requested - len(connections))
    started = time.monotonic()

    def connect_one(_: int) -> socket.socket:
      connection, _ = socks_connect(
        inbound_port, "127.0.0.1", echo_port, None, deadline)
      return connection

    batch: list[socket.socket] = []
    errors = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
      futures = [executor.submit(connect_one, index) for index in range(count)]
      for future in futures:
        try:
          batch.append(future.result(timeout=deadline))
        except BaseException as error:
          errors.append(str(error))
    elapsed = time.monotonic() - started
    connections.extend(batch)
    if elapsed > deadline:
      for connection in connections:
        connection.close()
      raise DriverError("P14_CAPACITY_TIMEOUT", "capacity batch deadline exceeded", {
        "requested": requested, "achieved": len(connections),
        "elapsed_seconds": elapsed, "deadline_seconds": deadline})
    if errors:
      warnings.append(
        f"capacity admission stopped cleanly at {len(connections)}/{requested}: "
        f"{errors[0]}")
      break
  return connections, warnings


def wait_reclaimed(process: ProductProcess, deadline: float) -> dict:
  """wait_reclaimed 等待 Session 与动态资源回到基线。"""
  end = time.monotonic() + deadline
  last = None
  while time.monotonic() < end:
    last = process_resources(process)
    if (last["active_sessions"] == 0 and
        last["owned_session_bytes"] == 0 and
        last["pool_live_blocks"] == 0 and
        last["resource_waiters"] == 0):
      return last
    time.sleep(0.1)
  raise DriverError("P14_RECLAIM_TIMEOUT", "capacity reclaim deadline exceeded",
                    last or {})


def run_capacity_cases(config: Path, inbound_port: int, echo_port: int,
                       workload: dict, deadlines: dict) -> tuple[list[dict],
                                                                  list[str],
                                                                  list[dict]]:
  """run_capacity_cases 执行 1/100/1000/10000 持有连接阶梯。"""
  output = []
  warnings = []
  observations = []
  process = ProductProcess(config, deadlines["startup_ready_seconds"])
  try:
    for requested in workload["capacity"]["connection_counts"]:
      latency_values, rate_values = probe_connect_samples(
        inbound_port, echo_port, deadlines)
      connections, admission_warnings = open_capacity_connections(
        inbound_port, echo_port, requested,
        workload["capacity"]["open_batch_size"],
        deadlines["capacity_batch_seconds"])
      warnings.extend(admission_warnings)
      achieved = len(connections)
      resource_values = {unit: [] for unit in
                         ("rss_bytes", "pss_bytes", "owned_bytes",
                          "fd_count", "socket_memory_bytes")}
      target = time.monotonic()
      for index in range(FORMAL_WARMUPS + FORMAL_SAMPLES):
        target += workload["capacity"]["metrics_interval_seconds"]
        time.sleep(max(0.0, target - time.monotonic()))
        resources = process_resources(process)
        if resources["active_sessions"] != achieved:
          raise DriverError("P14_CAPACITY_SESSIONS",
                            "active Session count differs from held sockets", {
                              "requested": requested, "achieved": achieved,
                              "active_sessions": resources["active_sessions"]})
        observations.append({
          "requested_count": requested,
          "achieved_count": achieved,
          "warmup": index < FORMAL_WARMUPS,
          **resources,
        })
        if index >= FORMAL_WARMUPS:
          for unit in resource_values:
            resource_values[unit].append(resources[unit])
      for connection in connections:
        connection.close()
      wait_reclaimed(process, deadlines["reclaim_seconds"])
      output.append(case_result(f"held_connections_{requested}", "steady", {
        "ms/connect": ("lower-is-better", latency_values),
        "connections/s": ("higher-is-better", rate_values),
        **{unit: ("lower-is-better", samples)
           for unit, samples in resource_values.items()},
      }))
  finally:
    process.stop(deadlines["process_stop_seconds"])
  return output, warnings, observations


def run_product_cases(workload: dict) -> tuple[list[dict], list[str], dict]:
  """run_product_cases 运行 11 个 driver-owned 本地产品 case。"""
  deadlines = workload["deadlines"]
  echo = EchoServer()
  dns = DnsServer()
  upstream = ReferenceSocksServer("upstream", "upstream-secret")
  topology = {
    "schema": "flick.benchmark-topology/v1",
    "network_scope": "loopback-only",
    "echo": f"127.0.0.1:{echo.port}",
    "dns": f"127.0.0.1:{dns.port}",
    "reference_socks": f"127.0.0.1:{upstream.port}",
  }
  cases = []
  warnings: list[str] = []
  capacity_observations: list[dict] = []
  try:
    cases.extend(run_startup_cases(dns, deadlines))

    no_auth_port = free_port()
    no_auth_config = write_product_config(
      "config-direct.yaml", product_config(no_auth_port, dns.port))
    cases.append(run_connect_case(
      "product_no_auth_ipv4_connect", no_auth_config, no_auth_port,
      echo.port, "127.0.0.1", None,
      workload["socks"]["product_cases"][0]["operations_per_sample"],
      deadlines))

    auth_port = free_port()
    auth_config = write_product_config(
      "config-socks.yaml",
      product_config(auth_port, dns.port, "upstream", upstream.port,
                     inbound_auth=True, proxy_auth=True))
    cases.append(run_connect_case(
      "product_userpass_domain_connect", auth_config, auth_port,
      echo.port, "echo.test", ("alice", "secret"),
      workload["socks"]["product_cases"][1]["operations_per_sample"],
      deadlines))

    cases.append(run_product_relay_case(
      "product_direct", no_auth_config, no_auth_port, echo.port,
      "127.0.0.1", None,
      workload["relay"]["product_cases"][0]["payload_bytes_per_sample"],
      False, deadlines))
    cases.append(run_product_relay_case(
      "product_socks_chain", auth_config, auth_port, echo.port,
      "echo.test", ("alice", "secret"),
      workload["relay"]["product_cases"][1]["payload_bytes_per_sample"],
      True, deadlines))

    idle_port = free_port()
    idle_config = write_product_config(
      "config-idle.yaml", product_config(idle_port, dns.port))
    cases.append(run_idle_case(
      idle_config, deadlines, workload["idle"]["recorded_interval_seconds"]))

    capacity_port = free_port()
    capacity_config = write_product_config(
      "config-capacity.yaml", product_config(capacity_port, dns.port))
    capacity_cases, capacity_warnings, capacity_observations = \
      run_capacity_cases(capacity_config, capacity_port, echo.port,
                         workload, deadlines)
    cases.extend(capacity_cases)
    warnings.extend(capacity_warnings)
  finally:
    upstream.stop()
    dns.stop()
    echo.stop()
  if len(cases) != 11:
    raise DriverError("P14_PRODUCT_CASE_COUNT", "product case count mismatch")
  topology["capacity_observations"] = len(capacity_observations)
  write_json(RESULT_DIR / "topology.json", topology)
  write_json(RESULT_DIR / "capacity-observations.json", {
    "schema": "flick.benchmark-capacity-observations/v1",
    "observations": capacity_observations})
  write_json(RESULT_DIR / "product-cases.json", {
    "schema": "flick.benchmark-product-cases/v1",
    "cases": cases, "warnings": warnings})
  return cases, warnings, topology


def source_files() -> list[Path]:
  """source_files 返回足以复现 P14 的源码与冻结输入。"""
  fixed = [
    ROOT / "CMakeLists.txt",
    ROOT / "CMakePresets.json",
    ROOT / "document/FlickNet-Technical-Baseline-V1.0.md",
    ROOT / "document/FlickNet-Background-and-References-V1.0.md",
    ROOT / "document/FlickNet-Requirements-Freeze-Audit-V0.1.md",
    ROOT / "document/FlickNet-V0.1-Engineering-Plan.md",
    ROOT / "document/FlickNet-DDRA-Feasibility-Review-V0.1.md",
    ROOT / "references/p14-benchmark-notes.md",
    ROOT / "tests/fixtures/evidence/v0_1/validation-result.schema.json",
    ROOT / "tests/fixtures/config/v1/valid/minimal-direct.yaml",
    ROOT / "tests/fixtures/socks5/v0_1/manifest.json",
    ROOT / "tests/fixtures/dns/v0_1/manifest.json",
    ROOT / "third_party/dependencies-v0.1.json",
    ROOT / "third_party/submodule-policy-v0.1.json",
  ]
  discovered = []
  for directory, suffixes in (
      (ROOT / "bench", {".c", ".h", ".py", ".json"}),
      (ROOT / "cmake", {".cmake", ".in"}),
      (ROOT / "include", {".h"}),
      (ROOT / "src", {".c", ".h"})):
    discovered.extend(path for path in directory.rglob("*")
                      if path.is_file() and path.suffix in suffixes)
  return sorted(set(fixed + discovered), key=relative)


def write_source_manifest() -> Path:
  """write_source_manifest 固定 P14 运行使用的本地源码字节。"""
  path = RESULT_DIR / "source-manifest.txt"
  missing = [relative(item) for item in source_files() if not item.is_file()]
  if missing:
    raise DriverError("P14_SOURCE_MISSING", "source input is missing",
                      {"paths": missing})
  path.write_text("".join(
    f"{sha256(item)}  {relative(item)}\n" for item in source_files()),
    encoding="utf-8")
  return path


def read_optional(path: Path) -> str | None:
  """read_optional 读取可选的单行系统属性。"""
  try:
    return path.read_text(encoding="utf-8").strip()
  except OSError:
    return None


def capture_benchmark_environment() -> Path:
  """capture_benchmark_environment 记录不修改的性能环境。"""
  affinity = sorted(os.sched_getaffinity(0)) if hasattr(
    os, "sched_getaffinity") else None
  value = {
    "schema": "flick.benchmark-environment/v1",
    "captured_at": utc_now(),
    "network_scope": "loopback-only",
    "platform": platform.platform(),
    "machine": platform.machine(),
    "python": platform.python_version(),
    "cpu_count": os.cpu_count(),
    "cpu_affinity": affinity,
    "load_average": list(os.getloadavg()),
    "governor": read_optional(Path(
      "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")),
    "clocksource": read_optional(Path(
      "/sys/devices/system/clocksource/clocksource0/current_clocksource")),
    "nofile": list(resource.getrlimit(resource.RLIMIT_NOFILE)),
    "notes": [
      "The driver records but does not change affinity, governor or clocksource.",
      "This host is not a target router and results are a local V0.1 baseline.",
    ],
  }
  path = RESULT_DIR / "environment.json"
  write_json(path, value)
  return path


def expected_cases(workload: dict) -> list[tuple[str, str, list[str]]]:
  """expected_cases 返回固定 case 顺序、所有者和单位。"""
  output = []
  for owner in TARGET_ORDER:
    output.extend((owner, item["name"], item["units"])
                  for item in workload[owner]["cases"])
  output.extend(("product", item["name"], item["units"])
                for item in workload["socks"]["product_cases"])
  output.extend(("product", item["name"], item["units"])
                for item in workload["relay"]["product_cases"])
  output.extend(("product", item["name"], item["units"])
                for item in workload["startup"]["cases"])
  output.extend(("product", item["name"], item["units"])
                for item in workload["idle"]["cases"])
  output.extend(("product", f"held_connections_{count}",
                 workload["capacity"]["units"])
                for count in workload["capacity"]["connection_counts"])
  return output


def validate_all_cases(workload: dict, target_records: dict[str, dict],
                       product_cases: list[dict]) -> tuple[list[dict],
                                                           list[dict]]:
  """validate_all_cases 核对恰好 28 case、105 指标与全部原始样本。"""
  actual: dict[tuple[str, str], dict] = {}
  for owner in TARGET_ORDER:
    for case in target_records[owner]["cases"]:
      key = (owner, case["name"])
      if key in actual:
        raise DriverError("P14_DUPLICATE_CASE", f"duplicate case: {key}")
      actual[key] = case
  for case in product_cases:
    key = ("product", case["name"])
    if key in actual:
      raise DriverError("P14_DUPLICATE_CASE", f"duplicate case: {key}")
    actual[key] = case

  expected = expected_cases(workload)
  if len(expected) != 28 or set(actual) != {
      (owner, name) for owner, name, _ in expected}:
    raise DriverError("P14_CASE_SET", "benchmark case set mismatch", {
      "expected": [[owner, name] for owner, name, _ in expected],
      "actual": [list(key) for key in sorted(actual)],
    })
  cases = []
  metrics = []
  for owner, name, units in expected:
    case = actual[(owner, name)]
    if [item.get("unit") for item in case.get("measurements", [])] != units:
      raise DriverError("P14_UNIT_SET", f"metric units mismatch: {name}")
    if not all(case.get("checks", {}).values()):
      raise DriverError("P14_CASE_CHECK", f"case checks failed: {name}")
    cases.append({"owner": owner, **case})
    for item in case["measurements"]:
      samples = item.get("samples", [])
      if (len(samples) != FORMAL_SAMPLES or
          not all(finite_number(value) for value in samples)):
        raise DriverError("P14_METRIC_SAMPLES",
                          f"metric sample contract failed: {name}/{item['unit']}")
      metrics.append({
        "name": f"{owner}.{name}.{item['unit']}",
        "unit": item["unit"],
        "samples": samples,
        "minimum": item["minimum"],
        "maximum": item["maximum"],
        "p50": item["p50"],
        "p95": item["p95"],
        "p99": item["p99"],
      })
  if len(cases) != 28 or len(metrics) != 105 or len({
      item["name"] for item in metrics}) != 105:
    raise DriverError("P14_METRIC_COUNT", "28/105 contract mismatch")
  return cases, metrics


def metric_by_name(metrics: list[dict], name: str) -> dict:
  """metric_by_name 返回唯一指标。"""
  matches = [item for item in metrics if item["name"] == name]
  if len(matches) != 1:
    raise DriverError("P14_METRIC_LOOKUP", f"metric is not unique: {name}")
  return matches[0]


def build_comparison(metrics: list[dict], warnings: list[str],
                     workload: dict) -> tuple[Path, list[str]]:
  """build_comparison 生成目标预警和无可比历史基线说明。"""
  thresholds = workload["warnings"]
  generated = list(warnings)
  idle = metric_by_name(
    metrics, "product.idle_stable_minimal.rss_bytes")["p50"]
  if idle > thresholds["idle_rss_target_bytes"]:
    generated.append(
      f"idle RSS p50 {idle:.0f} exceeds target "
      f"{thresholds['idle_rss_target_bytes']} bytes")
  if idle > thresholds["idle_rss_upper_bytes"]:
    generated.append(
      f"idle RSS p50 {idle:.0f} exceeds warning upper bound "
      f"{thresholds['idle_rss_upper_bytes']} bytes")
  for phase in ("cold", "hot"):
    name = f"product.startup_{phase}_file_cache.ms/start"
    value = metric_by_name(metrics, name)["p99"]
    if value > thresholds["startup_target_ms"]:
      generated.append(
        f"{name} p99 {value:.3f} exceeds target "
        f"{thresholds['startup_target_ms']} ms")
  for case in ("steady_match_ipv4", "steady_match_domain_resolved"):
    name = f"rule.{case}.ns/op"
    value = metric_by_name(metrics, name)["p99"]
    if value > thresholds["pure_rule_p99_target_ns"]:
      generated.append(
        f"{name} p99 {value:.3f} exceeds target "
        f"{thresholds['pure_rule_p99_target_ns']} ns")
  generated = list(dict.fromkeys(generated))
  report = {
    "schema": "flick.benchmark-comparison/v1",
    "baseline": None,
    "comparable": False,
    "regression_threshold_percent": thresholds[
      "comparable_regression_percent"],
    "comparisons": [],
    "warnings": generated,
    "limitation": (
      "No earlier result with identical source, workload, build and environment "
      "exists; regression percentages are intentionally omitted."),
  }
  path = RESULT_DIR / "comparison.json"
  write_json(path, report)
  return path, generated


def input_artifacts(source_manifest: Path) -> list[dict]:
  """input_artifacts 固定正式结果引用的输入。"""
  values = [
    (ROOT / ".harness/reviews/environment.json", "environment",
     "application/json"),
    (ROOT / "third_party/dependencies-v0.1.json", "dependency-lock",
     "application/json"),
    (ROOT / "third_party/submodule-policy-v0.1.json", "dependency-policy",
     "application/json"),
    (ROOT / "document/FlickNet-Technical-Baseline-V1.0.md", "task-source",
     "text/markdown"),
    (ROOT / "document/FlickNet-Background-and-References-V1.0.md",
     "task-source", "text/markdown"),
    (ROOT / "document/FlickNet-Requirements-Freeze-Audit-V0.1.md",
     "task-source", "text/markdown"),
    (ROOT / "document/FlickNet-V0.1-Engineering-Plan.md", "task-source",
     "text/markdown"),
    (ROOT / "document/FlickNet-DDRA-Feasibility-Review-V0.1.md",
     "task-source", "text/markdown"),
    (ROOT / "references/p14-benchmark-notes.md", "reference-analysis",
     "text/markdown"),
    (WORKLOAD_PATH, "benchmark-workload", "application/json"),
    (ROOT / "tests/fixtures/socks5/v0_1/manifest.json", "fixture-manifest",
     "application/json"),
    (ROOT / "tests/fixtures/dns/v0_1/manifest.json", "fixture-manifest",
     "application/json"),
    (ROOT / "tests/fixtures/evidence/v0_1/validation-result.schema.json",
     "result-schema", "application/schema+json"),
    (source_manifest, "source-manifest", "text/plain"),
  ]
  return [artifact(path, role, media_type)
          for path, role, media_type in values]


def git_source(source_manifest: Path) -> dict:
  """git_source 读取本地未提交仓库状态。"""
  revision_result = subprocess.run(
    ["git", "rev-parse", "--verify", "HEAD"], cwd=ROOT,
    capture_output=True, text=True, check=False)
  status_result = subprocess.run(
    ["git", "status", "--porcelain"], cwd=ROOT,
    capture_output=True, text=True, check=False)
  revision = (revision_result.stdout.strip()
              if revision_result.returncode == 0 else None)
  return {
    "revision": revision,
    "dirty": revision is None or bool(status_result.stdout.strip()),
    "manifest_sha256": sha256(source_manifest),
    "manifest": artifact(source_manifest, "source-manifest", "text/plain"),
  }


def run_benchmark(output: Path, targets: tuple[str, ...]) -> dict:
  """run_benchmark 执行正式 Release benchmark 并生成统一证据。"""
  started_at = utc_now()
  started = time.monotonic()
  RESULT_DIR.mkdir(parents=True, exist_ok=True)
  command_dir = RESULT_DIR / "commands"
  command_dir.mkdir(parents=True, exist_ok=True)
  workload, workload_sha = validate_workload(WORKLOAD_PATH)
  if targets != TARGET_ORDER:
    raise DriverError("P14_TARGET_SET",
                      "formal benchmark requires rule,socks,dns,relay")
  materialize_fixtures(workload)
  plans = materialize_plans(workload, workload_sha)
  source_manifest = write_source_manifest()
  environment_path = capture_benchmark_environment()
  deadlines = workload["deadlines"]
  commands = []
  commands.append(run_owned(
    ["cmake", "--preset", "release"], "configure",
    deadlines["configure_seconds"], command_dir, 1))
  commands.append(run_owned(
    ["cmake", "--build", "--preset", "release", "--parallel"],
    "build", deadlines["build_seconds"], command_dir, 2))
  capability = validate_capability(CAPABILITY_SOURCE)

  target_records = {}
  for index, target in enumerate(targets, start=3):
    target_output = RESULT_DIR / f"{target}.json"
    argv = [
      str(ROOT / f"build/release/bench_{target}"),
      "--workload", str(WORKLOAD_PATH),
      "--workload-sha256", workload_sha,
      "--plan", str(ROOT / plans[target]["path"]),
      "--fixture-dir", str(FIXTURE_DIR),
      "--warmup", str(FORMAL_WARMUPS),
      "--samples", str(FORMAL_SAMPLES),
      "--seed", str(FORMAL_SEED),
      "--output", str(target_output),
    ]
    commands.append(run_owned(
      argv, f"target-{target}", deadlines["target_process_seconds"],
      command_dir, index))
    target_records[target] = validate_target_record(
      target_output, target, workload, workload_sha, plans[target])

  product_cases, product_warnings, topology = run_product_cases(workload)
  cases, metrics = validate_all_cases(
    workload, target_records, product_cases)
  cases_path = RESULT_DIR / "all-cases.json"
  write_json(cases_path, {
    "schema": "flick.benchmark-cases/v1", "cases": cases})
  comparison_path, warnings = build_comparison(
    metrics, product_warnings, workload)
  elapsed = time.monotonic() - started
  if elapsed > deadlines["overall_seconds"]:
    raise DriverError("P14_OVERALL_TIMEOUT", "overall deadline exceeded", {
      "elapsed_seconds": elapsed,
      "deadline_seconds": deadlines["overall_seconds"]})

  inputs = input_artifacts(source_manifest)
  artifacts = [
    artifact(CAPABILITY_SNAPSHOT, "capability-manifest", "application/json"),
    artifact(environment_path, "benchmark-environment", "application/json"),
    artifact(FIXTURE_DIR / "mapping.json", "fixture-map", "application/json"),
    artifact(FIXTURE_DIR / "plans.json", "benchmark-plans", "application/json"),
    artifact(RESULT_DIR / "product-cases.json", "product-cases",
             "application/json"),
    artifact(RESULT_DIR / "capacity-observations.json",
             "capacity-observations", "application/json"),
    artifact(RESULT_DIR / "topology.json", "loopback-topology",
             "application/json"),
    artifact(cases_path, "benchmark-cases", "application/json"),
    artifact(comparison_path, "comparison-report", "application/json"),
  ]
  artifacts.extend(artifact(
    RESULT_DIR / f"{target}.json", "target-result", "application/json")
                   for target in targets)
  reference_path = ROOT / "references/p14-benchmark-notes.md"
  dependency_values = capability["dependencies"]
  result = {
    "schema": "flick.validation-result/v1",
    "record_status": "evidence",
    "scope": "product-validation",
    "task": "P14",
    "kind": "benchmark",
    "result": "pass",
    "started_at": started_at,
    "finished_at": utc_now(),
    "duration_ms": int(elapsed * 1000),
    "source": git_source(source_manifest),
    "environment": {
      "snapshot_path": ".harness/reviews/environment.json",
      "snapshot_sha256": sha256(
        ROOT / ".harness/reviews/environment.json"),
    },
    "build": {
      "preset": "release",
      "build_type": "Release",
      "compiler": capability["compiler"],
      "dependencies": [
        {"name": name, "version": version}
        for name, version in sorted(dependency_values.items())
      ],
      "capability_manifest": artifact(
        CAPABILITY_SNAPSHOT, "capability-manifest", "application/json"),
      "instrumentation": [],
    },
    "commands": commands,
    "inputs": inputs,
    "input_hashes": {item["path"]: item["sha256"] for item in inputs},
    "artifacts": artifacts,
    "counts": {"planned": 28, "executed": 28, "passed": 28,
               "failed": 0, "skipped": 0},
    "metrics": metrics,
    "reference_analysis": {
      "background_reviewed": True,
      "records": [relative(reference_path)],
      "details": [
        {"path": relative(reference_path), "sha256": sha256(reference_path),
         "upstream": "https://github.com/SagerNet/sing-box.git",
         "revision": "2ff3985c0a8fd628ab10b9ec9cd3d37512909c57",
         "license": "GPL-3.0-or-later", "copied_code": False},
        {"path": relative(reference_path), "sha256": sha256(reference_path),
         "upstream": "https://github.com/c-ares/c-ares.git",
         "revision": "c7a3138dcfe3bb0eaaf10c0c24c36dc66dc790ab",
         "license": "MIT", "copied_code": False},
        {"path": relative(reference_path), "sha256": sha256(reference_path),
         "upstream": "https://github.com/zfl9/ipt2socks.git",
         "revision": "b2f1461976817417ebf0c9c14210a9f199a22438",
         "license": "AGPL-3.0", "copied_code": False},
      ],
    },
    "defects": [],
    "limitations": [
      "All network traffic is local loopback; this is not a router-device result.",
      "No comparable earlier P14 baseline exists, so no regression percentage is reported.",
      "Performance targets produce warnings and do not replace functional, resource or cleanup gates.",
      *warnings,
    ],
  }
  schema = load_json(
    ROOT / "tests/fixtures/evidence/v0_1/validation-result.schema.json")
  jsonschema.Draft202012Validator.check_schema(schema)
  jsonschema.validate(result, schema)
  write_json(output, result)
  return result


def parse_targets(value: str) -> tuple[str, ...]:
  """parse_targets 拒绝重复、未知和重排的正式 target。"""
  targets = tuple(value.split(","))
  if (targets != TARGET_ORDER or len(set(targets)) != len(targets) or
      any(target not in TARGET_IDS for target in targets)):
    raise argparse.ArgumentTypeError(
      "targets must be exactly rule,socks,dns,relay")
  return targets


def output_path(value: str) -> Path:
  """output_path 把输出限制在仓库内。"""
  path = Path(value)
  if not path.is_absolute():
    path = ROOT / path
  path = path.resolve()
  if ROOT not in path.parents:
    raise argparse.ArgumentTypeError("output must be inside the repository")
  return path


def main() -> int:
  """main 解析并执行唯一正式 V0.1 benchmark 合同。"""
  parser = argparse.ArgumentParser(
    description="Run the fixed local FlickNet V0.1 benchmark.")
  parser.add_argument("--preset", required=True, choices=("release",))
  parser.add_argument("--targets", required=True, type=parse_targets)
  parser.add_argument("--warmup", required=True, type=int)
  parser.add_argument("--samples", required=True, type=int)
  parser.add_argument("--seed", required=True, type=int)
  parser.add_argument("--output", required=True, type=output_path)
  args = parser.parse_args()
  if (args.warmup != FORMAL_WARMUPS or args.samples != FORMAL_SAMPLES or
      args.seed != FORMAL_SEED):
    parser.error("formal values are --warmup 5 --samples 30 --seed 104729")
  try:
    result = run_benchmark(args.output, args.targets)
  except BaseException as error:
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    failure = {
      "schema": "flick.benchmark-failure/v1",
      "captured_at": utc_now(),
      "error_type": type(error).__name__,
      "message": str(error),
    }
    if isinstance(error, DriverError):
      failure["code"] = error.code
      failure["details"] = error.details
    write_json(RESULT_DIR / "failure.json", failure)
    print(json.dumps(failure, ensure_ascii=False), file=sys.stderr)
    return 1
  print(json.dumps({
    "result": result["result"],
    "cases": result["counts"]["passed"],
    "metrics": len(result["metrics"]),
    "output": relative(args.output),
  }, ensure_ascii=False))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
