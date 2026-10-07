#!/usr/bin/env python3
"""运行 P13 V0.1 loopback 混合流量长稳，并写统一验证记录。"""

import argparse
import asyncio
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import random
import select
import shutil
import signal
import socket
import statistics
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from run_p01_validation import (  # noqa: E402
  artifact,
  git_state,
  relative,
  run_command,
  sha256,
  utc_now,
)


ROOT = Path(__file__).resolve().parents[2]
FORMAL_DURATION_SECONDS = 86400
FORMAL_SAMPLE_INTERVAL_SECONDS = 10
FORMAL_SEED = 104729
LONG_PAYLOAD_BYTES = 4096
LONG_CONNECTIONS = {
  "direct_ipv4": 32,
  "direct_domain": 16,
  "socks_no_auth": 8,
  "socks_auth": 8,
}
FAULT_NAMES = (
  "slow_read",
  "connection_refused",
  "upstream_reset",
  "dns_malformed",
  "dns_timeout",
  "auth_failure",
)
FAULT_EXPECTATIONS = {
  "slow_read": {"wire": "echo-verified", "log": None},
  "connection_refused": {
    "wire": "socks-reply-5", "log": "SESSION_FAILED:tcp_connect"},
  "upstream_reset": {
    "wire": "peer-reset-or-eof", "log": "SESSION_FAILED:relay"},
  "dns_malformed": {
    "wire": "socks-reply-1", "log": "SESSION_FAILED:resolve"},
  "dns_timeout": {
    "wire": "socks-reply-4", "log": "SESSION_FAILED:resolve"},
  "auth_failure": {
    "wire": "auth-reply-1", "log": "HANDSHAKE_FAILED:socks_auth"},
}


class SoakFailure(RuntimeError):
  """SoakFailure 表示受控拓扑或验证条件失败。"""


class SocksReplyError(SoakFailure):
  """SocksReplyError 保留 SOCKS REP 供预期故障核对。"""

  def __init__(self, reply):
    super().__init__(f"SOCKS CONNECT failed with reply {reply}.")
    self.reply = reply


@dataclass
class Route:
  """Route 描述一条产品入站到受控目标的路径。"""

  name: str
  endpoints: tuple
  target_host: str
  target_port: int
  credentials: tuple | None = None


@dataclass
class WorkloadState:
  """WorkloadState 保存单线程 asyncio workload 的确定性计数。"""

  seed: int
  stopping: bool = False
  active_generation: int = 0
  active_clients: int = 0
  long_ready: int = 0
  long_cycles: int = 0
  long_deadline_misses: int = 0
  short_success: int = 0
  dns_success: int = 0
  payload_bytes_up: int = 0
  payload_bytes_down: int = 0
  payload_mismatches: int = 0
  replacements: int = 0
  unexpected_failures: int = 0
  expected_faults: dict = field(
    default_factory=lambda: {name: 0 for name in FAULT_NAMES})
  fault_events: list = field(default_factory=list)
  errors: list = field(default_factory=list)

  def unexpected(self, message):
    """unexpected 记录有限错误样本和完整错误计数。"""
    self.unexpected_failures += 1
    if len(self.errors) < 100:
      self.errors.append(str(message))

  def snapshot(self):
    """snapshot 返回可直接序列化的 workload 计数。"""
    return {
      "active_generation": self.active_generation,
      "active_clients": self.active_clients,
      "long_ready": self.long_ready,
      "long_cycles": self.long_cycles,
      "long_deadline_misses": self.long_deadline_misses,
      "short_success": self.short_success,
      "dns_success": self.dns_success,
      "payload_bytes_up": self.payload_bytes_up,
      "payload_bytes_down": self.payload_bytes_down,
      "payload_mismatches": self.payload_mismatches,
      "replacements": self.replacements,
      "unexpected_failures": self.unexpected_failures,
      "expected_faults": dict(self.expected_faults),
    }


class DnsProtocol(asyncio.DatagramProtocol):
  """DnsProtocol 为 DIRECT domain 路径提供确定性的 UDP A 响应。"""

  def __init__(self, state):
    self.state = state
    self.transport = None

  def connection_made(self, transport):
    self.transport = transport

  def datagram_received(self, data, address):
    try:
      name, question_end = dns_question(data)
      if name == "timeout.test":
        return
      if name == "malformed.test":
        self.transport.sendto(data[:5], address)
        return
      self.transport.sendto(dns_a_response(data, question_end), address)
    except BaseException as error:
      if not self.state.stopping:
        self.state.unexpected(f"DNS service error: {error}")


@dataclass
class ProductProcess:
  """ProductProcess 管理一个带测试采样 fd 的真实 flick 进程。"""

  name: str
  config_path: Path
  stdout_path: Path
  stderr_path: Path
  process: subprocess.Popen | None = None
  stdout_file: object | None = None
  stderr_file: object | None = None
  metrics_fd: int = -1
  metrics_buffer: bytes = b""
  terminal: dict | None = None

  def start(self, binary):
    """start 启动前台产品进程并等待 started JSON 事件。"""
    read_fd, write_fd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
    environment = os.environ.copy()
    environment["FN_TEST_METRICS_FD"] = str(write_fd)
    self.stdout_file = self.stdout_path.open("wb", buffering=0)
    self.stderr_file = self.stderr_path.open("wb", buffering=0)
    self.process = subprocess.Popen(
      [str(binary), "--output", "json", "--config",
       str(self.config_path), "run"],
      cwd=ROOT, env=environment, pass_fds=(write_fd,),
      stdout=self.stdout_file, stderr=self.stderr_file,
      start_new_session=True)
    os.close(write_fd)
    self.metrics_fd = read_fd
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
      if self.process.poll() is not None:
        raise SoakFailure(
          f"{self.name} exited during startup with {self.process.returncode}.")
      lines = self.stdout_path.read_text(errors="replace").splitlines()
      if lines:
        event = json.loads(lines[0])
        if event.get("event") != "started":
          raise SoakFailure(f"{self.name} emitted an invalid start event.")
        return event
      time.sleep(0.02)
    raise SoakFailure(f"{self.name} did not publish a start event.")

  def request_metrics(self):
    """request_metrics 请求 owning loop 写一份真实内部快照。"""
    if self.process is None or self.process.poll() is not None:
      raise SoakFailure(f"{self.name} is not running for metrics.")
    os.kill(self.process.pid, signal.SIGUSR1)

  def take_metric_line(self):
    """take_metric_line 从已有缓冲取出一个完整 JSON 行。"""
    if b"\n" not in self.metrics_buffer:
      return None
    line, self.metrics_buffer = self.metrics_buffer.split(b"\n", 1)
    value = json.loads(line.decode("utf-8"))
    if value.get("schema") != "flick.test-metrics/v1":
      raise SoakFailure(f"{self.name} emitted an invalid metrics schema.")
    return value

  def stop(self):
    """stop 发送一次有限 drain 信号并核对干净退出。"""
    if self.process is None:
      return
    if self.process.poll() is None:
      os.kill(self.process.pid, signal.SIGTERM)
      try:
        self.process.wait(timeout=70)
      except subprocess.TimeoutExpired:
        os.kill(self.process.pid, signal.SIGINT)
        self.process.wait(timeout=10)
    if self.stdout_file is not None:
      self.stdout_file.close()
    if self.stderr_file is not None:
      self.stderr_file.close()
    if self.metrics_fd >= 0:
      os.close(self.metrics_fd)
      self.metrics_fd = -1
    lines = self.stdout_path.read_text(errors="replace").splitlines()
    if len(lines) >= 2:
      self.terminal = json.loads(lines[-1])


def dns_question(data):
  """dns_question 解析受控单问题查询并返回规范域名和问题末端。"""
  if len(data) < 17 or int.from_bytes(data[4:6], "big") != 1:
    raise SoakFailure("DNS query header is invalid.")
  labels = []
  offset = 12
  while True:
    if offset >= len(data):
      raise SoakFailure("DNS query name is truncated.")
    length = data[offset]
    offset += 1
    if length == 0:
      break
    if length > 63 or offset + length > len(data):
      raise SoakFailure("DNS query label is invalid.")
    labels.append(data[offset:offset + length].decode("ascii").lower())
    offset += length
  if offset + 4 > len(data):
    raise SoakFailure("DNS query type is truncated.")
  return ".".join(labels), offset + 4


def dns_a_response(query, question_end):
  """dns_a_response 构造与请求 ID 和 question 完全关联的 A 响应。"""
  header = (query[:2] + b"\x81\x80\x00\x01\x00\x01" +
            b"\x00\x00\x00\x00")
  answer = (b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c" +
            b"\x00\x04\x7f\x00\x00\x01")
  return header + query[12:question_end] + answer


async def echo_handler(state, kind, reader, writer):
  """echo_handler 提供普通、慢读和 reset 三种受控 loopback 行为。"""
  try:
    if kind == "reset":
      native = writer.get_extra_info("socket")
      if native is not None:
        native.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                          struct.pack("ii", 1, 0))
      writer.close()
      return
    while True:
      if kind == "slow":
        await asyncio.sleep(0.02)
      data = await reader.read(4096 if kind == "slow" else 65536)
      if not data:
        break
      writer.write(data)
      await writer.drain()
  except (ConnectionError, asyncio.CancelledError):
    pass
  except BaseException as error:
    if not state.stopping:
      state.unexpected(f"Echo service {kind} error: {error}")
  finally:
    writer.close()
    try:
      await writer.wait_closed()
    except ConnectionError:
      pass


async def read_exact(reader, length, timeout=10.0):
  """read_exact 对协议字段使用有界精确读取。"""
  return await asyncio.wait_for(reader.readexactly(length), timeout)


async def pipe_stream(reader, writer):
  """pipe_stream 转发参考 SOCKS 的单向字节流并传播半关闭。"""
  try:
    while True:
      data = await reader.read(65536)
      if not data:
        break
      writer.write(data)
      await writer.drain()
    if writer.can_write_eof():
      writer.write_eof()
      await writer.drain()
  except (ConnectionError, asyncio.IncompleteReadError):
    pass


async def socks_reference_handler(state, require_auth, reader, writer):
  """socks_reference_handler 实现本地 RFC 1928/1929 CONNECT 子集。"""
  upstream_writer = None
  try:
    greeting = await read_exact(reader, 2)
    if greeting[0] != 5:
      raise SoakFailure("Reference SOCKS greeting version mismatch.")
    methods = await read_exact(reader, greeting[1])
    selected = 2 if require_auth else 0
    if selected not in methods:
      writer.write(bytes((5, 255)))
      await writer.drain()
      return
    writer.write(bytes((5, selected)))
    await writer.drain()
    if require_auth:
      prefix = await read_exact(reader, 2)
      username = await read_exact(reader, prefix[1])
      password_length = (await read_exact(reader, 1))[0]
      password = await read_exact(reader, password_length)
      valid = (prefix[0] == 1 and username == b"upstream" and
               password == b"upstream-secret")
      writer.write(bytes((1, 0 if valid else 1)))
      await writer.drain()
      if not valid:
        return
    request = await read_exact(reader, 4)
    if request[:3] != b"\x05\x01\x00":
      raise SoakFailure("Reference SOCKS request prefix mismatch.")
    if request[3] == 1:
      host = socket.inet_ntoa(await read_exact(reader, 4))
    elif request[3] == 3:
      length = (await read_exact(reader, 1))[0]
      host = (await read_exact(reader, length)).decode("ascii")
      if host in {"echo.test", "malformed.test", "timeout.test"}:
        host = "127.0.0.1"
    else:
      writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
      await writer.drain()
      return
    port = int.from_bytes(await read_exact(reader, 2), "big")
    upstream_reader, upstream_writer = await asyncio.open_connection(host, port)
    writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
    await writer.drain()
    await asyncio.gather(
      pipe_stream(reader, upstream_writer),
      pipe_stream(upstream_reader, writer))
  except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError):
    pass
  except BaseException as error:
    if not state.stopping:
      state.unexpected(f"Reference SOCKS error: {error}")
  finally:
    if upstream_writer is not None:
      upstream_writer.close()
      try:
        await upstream_writer.wait_closed()
      except ConnectionError:
        pass
    writer.close()
    try:
      await writer.wait_closed()
    except ConnectionError:
      pass


def free_tcp_port():
  """free_tcp_port 为随后立即启动的产品 listener 选择 loopback 端口。"""
  probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  probe.bind(("127.0.0.1", 0))
  port = probe.getsockname()[1]
  probe.close()
  return port


def config_text(port, target, dns_port, proxy_port=None,
                inbound_auth=False, proxy_auth=False):
  """config_text 生成有明确预算和 deadline 的 V0.1 soak 配置。"""
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
    credentials = ""
    if proxy_auth:
      credentials = "\n    username: upstream\n    password: upstream-secret"
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
  sessions: 1024
  handshakes: 256
  fds: 4096
  memory: 128MiB
  cleanup-reserve: 2MiB
  buffers: 32MiB
  async-operations: 4096
  workers: 2
  worker-jobs: 64
  lazy-waiters: 1024
  lazy-waiters-per-object: 128
  resource-waiters: 1024
  resolver-pending: 64
  retired-runtimes: 2
timeouts:
  handshake: 5s
  connect: 3s
  tcp-idle: 10m
  drain: 60s
  resource-wait: 1s
  worker-task: 30s
{dns}inbounds:
  - name: soak-in
    type: socks5
    listen: 127.0.0.1
    port: {port}
    udp: false{users}
{proxies}rules:
  - MATCH,{target}
"""


async def socks_connect(endpoint, host, port, credentials=None):
  """socks_connect 建立真实 SOCKS5 CONNECT 并保留稳定 wire 结果。"""
  reader, writer = await asyncio.wait_for(
    asyncio.open_connection("127.0.0.1", endpoint), 5.0)
  try:
    methods = b"\x02" if credentials is not None else b"\x00"
    writer.write(bytes((5, 1)) + methods)
    await writer.drain()
    selection = await read_exact(reader, 2, 5.0)
    expected_method = 2 if credentials is not None else 0
    if selection != bytes((5, expected_method)):
      raise SoakFailure(
        f"SOCKS method mismatch: {selection.hex()} expected {expected_method}.")
    if credentials is not None:
      username, password = (item.encode("utf-8") for item in credentials)
      if len(username) > 255 or len(password) > 255:
        raise SoakFailure("SOCKS credentials exceed the wire limit.")
      writer.write(bytes((1, len(username))) + username +
                   bytes((len(password),)) + password)
      await writer.drain()
      authentication = await read_exact(reader, 2, 5.0)
      if authentication != b"\x01\x00":
        raise SocksReplyError(256 + authentication[1])
    try:
      address = b"\x01" + socket.inet_aton(host)
    except OSError:
      encoded = host.encode("ascii")
      if not encoded or len(encoded) > 255:
        raise SoakFailure("SOCKS domain is outside 1..255 bytes.")
      address = b"\x03" + bytes((len(encoded),)) + encoded
    writer.write(b"\x05\x01\x00" + address + port.to_bytes(2, "big"))
    await writer.drain()
    response = await read_exact(reader, 4, 10.0)
    if response[0] != 5:
      raise SoakFailure(f"SOCKS reply version mismatch: {response.hex()}.")
    if response[1] != 0:
      raise SocksReplyError(response[1])
    if response[3] == 1:
      await read_exact(reader, 6, 5.0)
    elif response[3] == 4:
      await read_exact(reader, 18, 5.0)
    elif response[3] == 3:
      length = (await read_exact(reader, 1, 5.0))[0]
      await read_exact(reader, length + 2, 5.0)
    else:
      raise SoakFailure(f"SOCKS reply ATYP is invalid: {response[3]}.")
    return reader, writer
  except BaseException:
    writer.close()
    try:
      await writer.wait_closed()
    except ConnectionError:
      pass
    raise


def payload_for(seed, identity, sequence, length):
  """payload_for 生成跨运行稳定且可逐字节核对的载荷。"""
  prefix = f"{seed}:{identity}:{sequence}:".encode("ascii")
  output = bytearray()
  counter = 0
  while len(output) < length:
    output.extend(hashlib.sha256(prefix + str(counter).encode("ascii")).digest())
    counter += 1
  return bytes(output[:length])


async def close_writer(writer):
  """close_writer 统一执行容忍对端已关闭的流清理。"""
  writer.close()
  try:
    await writer.wait_closed()
  except (ConnectionError, asyncio.TimeoutError):
    pass


async def exchange_once(state, route, identity, sequence, length=1024):
  """exchange_once 经当前 A/B 端点执行一次完整短连接校验。"""
  endpoint = route.endpoints[state.active_generation]
  reader = None
  writer = None
  try:
    reader, writer = await socks_connect(
      endpoint, route.target_host, route.target_port, route.credentials)
    payload = payload_for(state.seed, identity, sequence, length)
    writer.write(payload)
    await writer.drain()
    echoed = await read_exact(reader, len(payload), 10.0)
    if echoed != payload:
      state.payload_mismatches += 1
      raise SoakFailure(f"Payload mismatch on {route.name}.")
    state.payload_bytes_up += len(payload)
    state.payload_bytes_down += len(echoed)
  finally:
    if writer is not None:
      await close_writer(writer)


async def long_connection(state, route, identity, ready_event):
  """long_connection 保持固定端点，每秒双向核对 4096 字节。"""
  reader = None
  writer = None
  try:
    reader, writer = await socks_connect(
      route.endpoints[0], route.target_host, route.target_port,
      route.credentials)
    state.long_ready += 1
    state.active_clients += 1
    ready_event.set()
    sequence = 0
    next_cycle = time.monotonic()
    while not state.stopping:
      payload = payload_for(state.seed, identity, sequence,
                            LONG_PAYLOAD_BYTES)
      writer.write(payload)
      await asyncio.wait_for(writer.drain(), 10.0)
      echoed = await read_exact(reader, len(payload), 10.0)
      if echoed != payload:
        state.payload_mismatches += 1
        raise SoakFailure(f"Long payload mismatch on {route.name}.")
      state.payload_bytes_up += len(payload)
      state.payload_bytes_down += len(echoed)
      state.long_cycles += 1
      sequence += 1
      next_cycle += 1.0
      delay = next_cycle - time.monotonic()
      if delay < -0.5:
        state.long_deadline_misses += 1
      if delay > 0:
        await asyncio.sleep(delay)
  except asyncio.CancelledError:
    raise
  except BaseException as error:
    if not state.stopping:
      state.unexpected(f"Long connection {identity} failed: {error}")
  finally:
    if writer is not None:
      await close_writer(writer)
    if state.active_clients > 0:
      state.active_clients -= 1
    ready_event.set()


async def short_scheduler(state, routes, started_monotonic):
  """short_scheduler 每秒提交八条短连接和两条 DOMAIN 查询路径。"""
  sequence = 0
  while not state.stopping:
    target_time = started_monotonic + sequence + 1.0
    delay = target_time - time.monotonic()
    if delay > 0:
      await asyncio.sleep(delay)
    if state.stopping:
      break
    calls = []
    for index in range(8):
      route = routes[(sequence * 8 + index) % len(routes)]
      calls.append(exchange_once(
        state, route, f"short-{sequence}-{index}", sequence * 8 + index))
    for index in range(2):
      calls.append(exchange_once(
        state, routes[1], f"dns-{sequence}-{index}",
        sequence * 2 + index, 256))
    outcomes = await asyncio.gather(*calls, return_exceptions=True)
    for index, outcome in enumerate(outcomes):
      if isinstance(outcome, BaseException):
        state.unexpected(f"Short workload failed: {outcome}")
      elif index < 8:
        state.short_success += 1
      else:
        state.dns_success += 1
    sequence += 1


async def expect_reply(endpoint, host, port, expected_reply,
                       credentials=None):
  """expect_reply 要求 CONNECT 或认证按稳定 wire code 失败。"""
  try:
    reader, writer = await socks_connect(
      endpoint, host, port, credentials)
  except SocksReplyError as error:
    if error.reply != expected_reply:
      raise SoakFailure(
        f"SOCKS failure {error.reply} does not match {expected_reply}.")
    return error.reply
  await close_writer(writer)
  raise SoakFailure("SOCKS request unexpectedly succeeded.")


async def fault_probe(state, name, routes, slow_port, reset_port,
                      refused_port):
  """fault_probe 执行一项故障并核对该故障的协议可见结果。"""
  direct = routes[0]
  auth = routes[3]
  endpoint = direct.endpoints[state.active_generation]
  if name == "slow_read":
    slow = Route("slow_read", direct.endpoints, "127.0.0.1", slow_port)
    await exchange_once(state, slow, f"fault-slow-{time.monotonic_ns()}",
                        state.expected_faults[name], 65536)
    outcome = "echo-verified"
  elif name == "connection_refused":
    reply = await expect_reply(endpoint, "127.0.0.1", refused_port, 5)
    outcome = f"socks-reply-{reply}"
  elif name == "upstream_reset":
    reader, writer = await socks_connect(
      endpoint, "127.0.0.1", reset_port)
    try:
      writer.write(b"reset-probe")
      await writer.drain()
      received = await asyncio.wait_for(reader.read(1), 5.0)
      if received:
        raise SoakFailure("Reset target unexpectedly returned payload.")
      outcome = "peer-reset-or-eof"
    except (ConnectionError, asyncio.IncompleteReadError):
      outcome = "peer-reset-or-eof"
    finally:
      await close_writer(writer)
  elif name == "dns_malformed":
    reply = await expect_reply(
      endpoint, "malformed.test", direct.target_port, 1)
    outcome = f"socks-reply-{reply}"
  elif name == "dns_timeout":
    reply = await expect_reply(
      endpoint, "timeout.test", direct.target_port, 4)
    outcome = f"socks-reply-{reply}"
  elif name == "auth_failure":
    reply = await expect_reply(
      auth.endpoints[state.active_generation], auth.target_host,
      auth.target_port, 257, ("alice", "wrong-secret"))
    outcome = f"auth-reply-{reply - 256}"
  else:
    raise SoakFailure(f"Unknown fault: {name}.")
  state.expected_faults[name] += 1
  return outcome


async def fault_scheduler(state, routes, slow_port, reset_port, refused_port,
                          duration, started_monotonic):
  """fault_scheduler 按固定 seed 轮换六类 30 秒故障窗口。"""
  randomizer = random.Random(state.seed)
  schedule = list(FAULT_NAMES)
  randomizer.shuffle(schedule)
  formal = duration >= FORMAL_DURATION_SECONDS
  interval = 300.0 if formal else max(4.0, min(8.0, duration / 8.0))
  window = 30.0 if formal else min(2.0, interval / 3.0)
  index = 0
  while not state.stopping:
    start_at = started_monotonic + interval * (index + 1)
    if start_at >= started_monotonic + duration:
      break
    delay = start_at - time.monotonic()
    if delay > 0:
      await asyncio.sleep(delay)
    if state.stopping:
      break
    name = schedule[index % len(schedule)]
    window_end = min(start_at + window, started_monotonic + duration)
    probes = 0
    while not state.stopping and time.monotonic() < window_end:
      probe_started = time.monotonic()
      try:
        outcome = await fault_probe(
          state, name, routes, slow_port, reset_port, refused_port)
        probes += 1
        state.fault_events.append({
          "fault": name,
          "elapsed_seconds": probe_started - started_monotonic,
          "outcome": outcome,
          "expected_mapping": FAULT_EXPECTATIONS[name],
          "expected": True,
        })
      except BaseException as error:
        state.unexpected(f"Fault {name} failed validation: {error}")
        state.fault_events.append({
          "fault": name,
          "elapsed_seconds": probe_started - started_monotonic,
          "outcome": str(error),
          "expected_mapping": FAULT_EXPECTATIONS[name],
          "expected": False,
        })
      sleep_for = min(1.0, window_end - time.monotonic())
      if sleep_for > 0:
        await asyncio.sleep(sleep_for)
    if probes == 0 and not state.stopping:
      state.unexpected(f"Fault window {name} executed no probe.")
    index += 1


async def replacement_scheduler(state, duration, started_monotonic,
                                helper, log_path):
  """replacement_scheduler 周期验证事务并切换后续连接的 A/B 入口。"""
  formal = duration >= FORMAL_DURATION_SECONDS
  interval = 600.0 if formal else max(5.0, min(10.0, duration / 3.0))
  sequence = 0
  with log_path.open("w", encoding="utf-8") as log:
    while not state.stopping:
      target_time = started_monotonic + interval * (sequence + 1)
      delay = target_time - time.monotonic()
      if delay > 0:
        await asyncio.sleep(delay)
      if state.stopping:
        break
      process = await asyncio.create_subprocess_exec(
        str(helper), cwd=ROOT,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)
      stdout, stderr = await process.communicate()
      event = {
        "sequence": sequence + 1,
        "elapsed_seconds": time.monotonic() - started_monotonic,
        "exit_code": process.returncode,
        "from_generation": state.active_generation,
        "to_generation": 1 - state.active_generation,
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stderr": stderr.decode("utf-8", errors="replace"),
      }
      log.write(json.dumps(event, sort_keys=True) + "\n")
      log.flush()
      if process.returncode != 0:
        state.unexpected(
          f"Runtime replacement helper exited {process.returncode}.")
      else:
        state.active_generation = 1 - state.active_generation
        state.replacements += 1
      sequence += 1


def process_memory(pid):
  """process_memory 从 smaps_rollup 读取真实 RSS/PSS 字节。"""
  values = {}
  for line in Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines():
    parts = line.split()
    if len(parts) >= 2 and parts[0] in {"Rss:", "Pss:"}:
      values[parts[0][:-1].lower() + "_bytes"] = int(parts[1]) * 1024
  if "rss_bytes" not in values or "pss_bytes" not in values:
    raise SoakFailure(f"Process {pid} has no complete smaps_rollup.")
  values["fd_count"] = len(list(Path(f"/proc/{pid}/fd").iterdir()))
  return values


def collect_internal_metrics(products, timeout=5.0):
  """collect_internal_metrics 经继承 fd 收齐六个 owning loop 快照。"""
  for product in products:
    while product.take_metric_line() is not None:
      pass
    product.request_metrics()
  pending = {product.metrics_fd: product for product in products}
  metrics = {}
  deadline = time.monotonic() + timeout
  while pending and time.monotonic() < deadline:
    readable, _, _ = select.select(
      list(pending), [], [], max(0.0, deadline - time.monotonic()))
    if not readable:
      break
    for descriptor in readable:
      product = pending[descriptor]
      try:
        chunk = os.read(descriptor, 65536)
      except BlockingIOError:
        continue
      if not chunk:
        raise SoakFailure(f"Metrics pipe for {product.name} closed.")
      product.metrics_buffer += chunk
      value = product.take_metric_line()
      if value is not None:
        metrics[product.name] = value
        del pending[descriptor]
  if pending:
    names = ", ".join(sorted(product.name for product in pending.values()))
    raise SoakFailure(f"Metrics timeout for: {names}.")
  return metrics


def collect_sample(products, state, phase, started_monotonic=None):
  """collect_sample 合并内部预算、proc 内存、fd 与 workload 进度。"""
  sampled_at = time.monotonic()
  internal = collect_internal_metrics(products)
  processes = {}
  for product in products:
    if product.process is None or product.process.poll() is not None:
      raise SoakFailure(f"{product.name} exited before sampling.")
    external = process_memory(product.process.pid)
    processes[product.name] = {
      "pid": product.process.pid,
      **external,
      "internal": internal[product.name],
    }
  totals = {
    "rss_bytes": sum(item["rss_bytes"] for item in processes.values()),
    "pss_bytes": sum(item["pss_bytes"] for item in processes.values()),
    "fd_count": sum(item["fd_count"] for item in processes.values()),
  }
  for name in (
      "active_connections", "active_handshakes", "active_sessions",
      "owned_session_bytes", "owned_bytes", "owned_limit",
      "candidate_bytes", "retained_bytes", "buffer_bytes", "buffer_limit",
      "fd_budget", "fd_limit", "pool_live_blocks", "pool_cached_blocks",
      "resource_waiters", "runtime_candidates", "retained_runtimes",
      "async_operations", "lazy_waiters", "loop_iterations",
      "io_callbacks", "terminal_callbacks", "accepted_connections",
      "completed_sessions", "failed_sessions", "bytes_up", "bytes_down"):
    totals[name] = sum(
      item["internal"][name] for item in processes.values())
  workload = state.snapshot()
  workload["progress"] = (
    workload["long_cycles"] + workload["short_success"] +
    workload["dns_success"] + sum(workload["expected_faults"].values()))
  return {
    "schema": "flick.soak-sample/v1",
    "phase": phase,
    "monotonic_seconds": sampled_at,
    "elapsed_seconds": (None if started_monotonic is None else
                        sampled_at - started_monotonic),
    "wall_time": utc_now(),
    "processes": processes,
    "totals": totals,
    "workload": workload,
  }


async def wait_for_long_connections(state, ready_event, expected, timeout):
  """wait_for_long_connections 等待全部长连接完成握手后才启动计时。"""
  deadline = time.monotonic() + timeout
  while state.long_ready < expected and time.monotonic() < deadline:
    ready_event.clear()
    try:
      await asyncio.wait_for(ready_event.wait(), 0.25)
    except asyncio.TimeoutError:
      pass
  if state.long_ready != expected or state.unexpected_failures != 0:
    raise SoakFailure(
      f"Only {state.long_ready}/{expected} long connections became ready.")


async def sample_scheduler(products, state, samples, raw_file,
                           started_monotonic, duration, interval):
  """sample_scheduler 按绝对单调时点采样，避免累积调度漂移。"""
  sequence = 0
  while not state.stopping:
    target_time = started_monotonic + sequence * interval
    delay = target_time - time.monotonic()
    if delay > 0:
      await asyncio.sleep(delay)
    if state.stopping:
      break
    try:
      sample = collect_sample(
        products, state, "running", started_monotonic)
      sample["sequence"] = sequence
      samples.append(sample)
      raw_file.write(json.dumps(sample, sort_keys=True) + "\n")
      raw_file.flush()
    except BaseException as error:
      state.unexpected(f"Metrics collection failed: {error}")
      state.stopping = True
      break
    sequence += 1
    if time.monotonic() >= started_monotonic + duration:
      break


async def duration_monitor(state, started_monotonic, duration):
  """duration_monitor 只以单调时钟终止正式测量窗口。"""
  while not state.stopping:
    remaining = started_monotonic + duration - time.monotonic()
    if remaining <= 0:
      state.stopping = True
      return
    await asyncio.sleep(min(1.0, remaining))


def median(values):
  """median 对非空测量集合返回浮点中位数。"""
  if not values:
    raise SoakFailure("A required metric window has no samples.")
  return float(statistics.median(values))


def sample_statistics(samples, started_monotonic, ended_monotonic,
                      idle_samples):
  """sample_statistics 汇总缺口、进展、内存窗口与空闲 fd 基线。"""
  running = [item for item in samples if item["phase"] == "running"]
  if len(running) < 2:
    raise SoakFailure("The soak produced fewer than two running samples.")
  gaps = [running[index]["monotonic_seconds"] -
          running[index - 1]["monotonic_seconds"]
          for index in range(1, len(running))]
  last_progress_time = running[0]["monotonic_seconds"]
  last_progress = running[0]["workload"]["progress"]
  stagnant = []
  for item in running[1:]:
    progress = item["workload"]["progress"]
    if progress > last_progress:
      stagnant.append(item["monotonic_seconds"] - last_progress_time)
      last_progress_time = item["monotonic_seconds"]
      last_progress = progress
  stagnant.append(ended_monotonic - last_progress_time)
  idle_fd = {}
  for name in idle_samples[0]["processes"]:
    idle_fd[name] = median([
      item["processes"][name]["fd_count"] for item in idle_samples])
  return {
    "actual_duration_seconds": ended_monotonic - started_monotonic,
    "sample_count": len(running),
    "maximum_sample_gap_seconds": max(gaps),
    "maximum_progress_gap_seconds": max(stagnant),
    "maximum_rss_bytes": max(item["totals"]["rss_bytes"]
                             for item in running),
    "maximum_pss_bytes": max(item["totals"]["pss_bytes"]
                             for item in running),
    "idle_fd_median_by_process": idle_fd,
  }


def write_slope_input(samples, path, formal):
  """write_slope_input 写入全部有效 warm-up 后样本供 C 工具精确枚举。"""
  running = [item for item in samples if item["phase"] == "running"]
  eligible = [item for item in running
              if not formal or item["elapsed_seconds"] >= 3600.0]
  if len(eligible) < 2:
    eligible = running
  with path.open("wb") as stream:
    for item in eligible:
      stream.write(struct.pack(
        "dd", item["monotonic_seconds"], item["totals"]["rss_bytes"]))
  return eligible


def window_medians(samples, formal):
  """window_medians 计算 warm-up 后首末 30 分钟 RSS 中位数。"""
  running = [item for item in samples if item["phase"] == "running"]
  if not formal:
    split = max(1, len(running) // 2)
    return (
      median([item["totals"]["rss_bytes"] for item in running[:split]]),
      median([item["totals"]["rss_bytes"] for item in running[-split:]]),
    )
  first = [item["totals"]["rss_bytes"] for item in running
           if 3600.0 <= item["elapsed_seconds"] < 5400.0]
  last_elapsed = running[-1]["elapsed_seconds"]
  last = [item["totals"]["rss_bytes"] for item in running
          if item["elapsed_seconds"] >= last_elapsed - 1800.0]
  return median(first), median(last)


def source_paths():
  """source_paths 枚举 P13 长稳实际依赖的源码、合同和参考记录。"""
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
    ROOT / "tests/soak/run_v0_1.py",
    ROOT / "tests/soak/theil_sen.c",
    ROOT / "tests/fixtures/evidence/v0_1/validation-result.schema.json",
  ]
  for directory in ("cmake", "include", "src", "tests/integration",
                    "tests/unit"):
    paths.extend(path for path in (ROOT / directory).rglob("*")
                 if path.is_file() and "__pycache__" not in path.parts and
                 path.suffix != ".pyc")
  return sorted(set(paths), key=lambda path: relative(path).encode("utf-8"))


def write_source_manifest(destination):
  """write_source_manifest 写 C06 要求的排序源输入清单。"""
  lines = [f"{sha256(path)}  {relative(path)}\n" for path in source_paths()]
  destination.write_bytes("".join(lines).encode("utf-8"))
  return sha256(destination)


def reference_analysis():
  """reference_analysis 固定长稳驱动实际采用的上游研究边界。"""
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


def write_json(path, value):
  """write_json 用统一双空格格式写可审阅 JSON。"""
  path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n",
                  encoding="utf-8")


def server_details(server):
  """server_details 提取 asyncio server 的 loopback 监听端点。"""
  return [f"{item.getsockname()[0]}:{item.getsockname()[1]}"
          for item in server.sockets]


async def run_workload(binary, helper, result_dir, duration, interval, seed):
  """run_workload 建立完整受控拓扑并运行单调计时的混合流量。"""
  state = WorkloadState(seed=seed)
  products = []
  servers = []
  dns_transport = None
  refused_socket = None
  long_tasks = []
  background_tasks = []
  samples = []
  idle_samples = []
  started_monotonic = None
  ended_monotonic = None
  raw_path = result_dir / "samples.jsonl"
  replacement_path = result_dir / "runtime-replacements.jsonl"
  topology_path = result_dir / "topology.json"
  fault_path = result_dir / "fault-events.json"
  config_paths = []
  topology = {}
  loop = asyncio.get_running_loop()
  raw_file = raw_path.open("w", encoding="utf-8")
  try:
    echo_server = await asyncio.start_server(
      lambda reader, writer: echo_handler(state, "normal", reader, writer),
      "127.0.0.1", 0)
    slow_server = await asyncio.start_server(
      lambda reader, writer: echo_handler(state, "slow", reader, writer),
      "127.0.0.1", 0)
    reset_server = await asyncio.start_server(
      lambda reader, writer: echo_handler(state, "reset", reader, writer),
      "127.0.0.1", 0)
    noauth_server = await asyncio.start_server(
      lambda reader, writer: socks_reference_handler(
        state, False, reader, writer), "127.0.0.1", 0)
    auth_server = await asyncio.start_server(
      lambda reader, writer: socks_reference_handler(
        state, True, reader, writer), "127.0.0.1", 0)
    servers = [echo_server, slow_server, reset_server,
               noauth_server, auth_server]
    dns_transport, _ = await loop.create_datagram_endpoint(
      lambda: DnsProtocol(state), local_addr=("127.0.0.1", 0))
    echo_port = echo_server.sockets[0].getsockname()[1]
    slow_port = slow_server.sockets[0].getsockname()[1]
    reset_port = reset_server.sockets[0].getsockname()[1]
    noauth_port = noauth_server.sockets[0].getsockname()[1]
    auth_port = auth_server.sockets[0].getsockname()[1]
    dns_port = dns_transport.get_extra_info("sockname")[1]
    refused_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    refused_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    refused_socket.bind(("127.0.0.1", 0))
    refused_port = refused_socket.getsockname()[1]

    product_specs = (
      ("direct-a", "DIRECT", None, False, False),
      ("direct-b", "DIRECT", None, False, False),
      ("socks-a", "upstream", noauth_port, False, False),
      ("socks-b", "upstream", noauth_port, False, False),
      ("auth-a", "upstream", auth_port, True, True),
      ("auth-b", "upstream", auth_port, True, True),
    )
    product_ports = {}
    for name, target, proxy_port, inbound_auth, proxy_auth in product_specs:
      port = free_tcp_port()
      product_ports[name] = port
      config_path = result_dir / f"{name}.yaml"
      config_path.write_text(
        config_text(port, target, dns_port, proxy_port,
                    inbound_auth, proxy_auth), encoding="utf-8")
      config_paths.append(config_path)
      product = ProductProcess(
        name=name,
        config_path=config_path,
        stdout_path=result_dir / f"{name}.stdout.jsonl",
        stderr_path=result_dir / f"{name}.stderr.txt")
      product.start(binary)
      products.append(product)

    direct_endpoints = (product_ports["direct-a"],
                        product_ports["direct-b"])
    noauth_endpoints = (product_ports["socks-a"],
                        product_ports["socks-b"])
    auth_endpoints = (product_ports["auth-a"],
                      product_ports["auth-b"])
    routes = [
      Route("direct_ipv4", direct_endpoints, "127.0.0.1", echo_port),
      Route("direct_domain", direct_endpoints, "echo.test", echo_port),
      Route("socks_no_auth", noauth_endpoints, "127.0.0.1", echo_port),
      Route("socks_auth", auth_endpoints, "echo.test", echo_port,
            ("alice", "secret")),
    ]
    topology = {
      "schema": "flick.soak-topology/v1",
      "seed": seed,
      "duration_seconds": duration,
      "sample_interval_seconds": interval,
      "services": {
        "echo": server_details(echo_server),
        "slow_echo": server_details(slow_server),
        "reset": server_details(reset_server),
        "socks_no_auth": server_details(noauth_server),
        "socks_auth": server_details(auth_server),
        "dns": [f"127.0.0.1:{dns_port}"],
        "refused": [f"127.0.0.1:{refused_port}"],
      },
      "products": [
        {"name": item.name, "pid": item.process.pid,
         "listen": f"127.0.0.1:{product_ports[item.name]}",
         "config": relative(item.config_path)} for item in products
      ],
      "long_connections": LONG_CONNECTIONS,
      "short_connections_per_second": 8,
      "dns_queries_per_second": 2,
      "faults": list(FAULT_NAMES),
    }
    write_json(topology_path, topology)

    for generation in (0, 1):
      state.active_generation = generation
      for index, route in enumerate(routes):
        await exchange_once(state, route, f"warm-{generation}-{index}", 0)
    state.active_generation = 0
    for sequence in range(3):
      idle = collect_sample(products, state, "warm-idle")
      idle["sequence"] = sequence
      idle_samples.append(idle)
      samples.append(idle)
      raw_file.write(json.dumps(idle, sort_keys=True) + "\n")
      raw_file.flush()
      await asyncio.sleep(0.1)

    ready_event = asyncio.Event()
    identity = 0
    for route in routes:
      for _ in range(LONG_CONNECTIONS[route.name]):
        long_tasks.append(asyncio.create_task(
          long_connection(state, route, f"long-{identity}", ready_event)))
        identity += 1
    await wait_for_long_connections(
      state, ready_event, sum(LONG_CONNECTIONS.values()), 30.0)
    started_monotonic = time.monotonic()
    background_tasks = [
      asyncio.create_task(short_scheduler(state, routes, started_monotonic)),
      asyncio.create_task(fault_scheduler(
        state, routes, slow_port, reset_port, refused_port,
        duration, started_monotonic)),
      asyncio.create_task(replacement_scheduler(
        state, duration, started_monotonic, helper, replacement_path)),
      asyncio.create_task(sample_scheduler(
        products, state, samples, raw_file, started_monotonic,
        duration, interval)),
      asyncio.create_task(duration_monitor(
        state, started_monotonic, duration)),
    ]
    await background_tasks[-1]
    ended_monotonic = time.monotonic()
    state.stopping = True
    await asyncio.gather(*background_tasks[:-1], return_exceptions=True)
    await asyncio.gather(*long_tasks, return_exceptions=True)

    drain_deadline = time.monotonic() + 60.0
    while True:
      sample = collect_sample(
        products, state, "drain", started_monotonic)
      sample["sequence"] = len(samples)
      samples.append(sample)
      raw_file.write(json.dumps(sample, sort_keys=True) + "\n")
      raw_file.flush()
      totals = sample["totals"]
      drained = all(totals[name] == 0 for name in (
        "active_connections", "active_handshakes", "active_sessions",
        "owned_session_bytes", "pool_live_blocks", "resource_waiters",
        "runtime_candidates", "retained_runtimes", "async_operations",
        "lazy_waiters"))
      if drained or time.monotonic() >= drain_deadline:
        break
      await asyncio.sleep(min(interval, 1.0))
    write_json(fault_path, {
      "schema": "flick.soak-fault-events/v1",
      "seed": seed,
      "events": state.fault_events,
    })
  finally:
    state.stopping = True
    for task in background_tasks + long_tasks:
      if not task.done():
        task.cancel()
    if background_tasks or long_tasks:
      await asyncio.gather(*(background_tasks + long_tasks),
                           return_exceptions=True)
    raw_file.close()
    for product in products:
      try:
        product.stop()
      except BaseException as error:
        state.unexpected(f"Product {product.name} stop failed: {error}")
    for server in servers:
      server.close()
    for server in servers:
      await server.wait_closed()
    if dns_transport is not None:
      dns_transport.close()
    if refused_socket is not None:
      refused_socket.close()
  if started_monotonic is None or ended_monotonic is None:
    raise SoakFailure("The measured workload did not start.")
  return {
    "state": state,
    "products": products,
    "samples": samples,
    "idle_samples": idle_samples,
    "started_monotonic": started_monotonic,
    "ended_monotonic": ended_monotonic,
    "raw_path": raw_path,
    "replacement_path": replacement_path,
    "topology_path": topology_path,
    "fault_path": fault_path,
    "config_paths": config_paths,
    "topology": topology,
  }


def self_command(index, result_dir, argv, started_ns, exit_code,
                 stdout_text, stderr_text):
  """self_command 为驱动内部 workload 阶段写与 C06 相同的命令记录。"""
  stdout_path = result_dir / f"command-{index:02d}.stdout.txt"
  stderr_path = result_dir / f"command-{index:02d}.stderr.txt"
  stdout_path.write_text(stdout_text, encoding="utf-8")
  stderr_path.write_text(stderr_text, encoding="utf-8")
  return {
    "argv": argv,
    "cwd": ".",
    "exit_code": exit_code,
    "expected_exit_codes": [0],
    "duration_ms": (time.monotonic_ns() - started_ns) // 1_000_000,
    "stdout": artifact(stdout_path, "stdout", "text/plain"),
    "stderr": artifact(stderr_path, "stderr", "text/plain"),
  }


def logger_summary(products):
  """logger_summary 汇总结构化 code/stage 行而不依赖自由文本判断。"""
  summary = {}
  for product in products:
    entries = {}
    for line in product.stderr_path.read_text(errors="replace").splitlines():
      parts = line.split()
      if len(parts) < 4 or "stage=" not in line:
        continue
      code = parts[1]
      stage = next((part[6:] for part in parts if part.startswith("stage=")),
                   "unknown")
      key = f"{code}:{stage}"
      entries[key] = entries.get(key, 0) + 1
    summary[product.name] = entries
  return summary


def evaluate_workload(data, duration, formal, slope):
  """evaluate_workload 对正式门槛逐项给出布尔结果和缺陷标识。"""
  state = data["state"]
  samples = data["samples"]
  stats = sample_statistics(
    samples, data["started_monotonic"], data["ended_monotonic"],
    data["idle_samples"])
  first_median, last_median = window_medians(samples, formal)
  running = [item for item in samples if item["phase"] == "running"]
  final = samples[-1]
  product_exits = {
    product.name: {
      "return_code": (product.process.returncode
                      if product.process is not None else None),
      "terminal": product.terminal,
    } for product in data["products"]
  }
  logs = logger_summary(data["products"])
  observed_log_mappings = {
    mapping for entries in logs.values() for mapping in entries
  }
  required_log_mappings = {
    item["log"] for item in FAULT_EXPECTATIONS.values()
    if item["log"] is not None
  }
  budget_ok = all(
    process["internal"]["owned_bytes"] <=
    process["internal"]["owned_limit"] and
    process["internal"]["buffer_bytes"] <=
    process["internal"]["buffer_limit"] and
    process["internal"]["fd_budget"] <=
    process["internal"]["fd_limit"]
    for sample in samples for process in sample["processes"].values())
  drained = all(final["totals"][name] == 0 for name in (
    "active_connections", "active_handshakes", "active_sessions",
    "owned_session_bytes", "pool_live_blocks", "resource_waiters",
    "runtime_candidates", "retained_runtimes", "async_operations",
    "lazy_waiters"))
  fd_drained = all(
    final["processes"][name]["fd_count"] <= baseline + 2
    for name, baseline in stats["idle_fd_median_by_process"].items())
  cache_bounded = all(
    process["internal"]["pool_cached_blocks"] <= 8
    for sample in samples for process in sample["processes"].values())
  terminal_ok = all(
    item["return_code"] == 0 and item["terminal"] is not None and
    item["terminal"].get("event") == "stopped" and
    item["terminal"].get("status") == "ok"
    for item in product_exits.values())
  expected_long = sum(LONG_CONNECTIONS.values()) * duration
  expected_short = 8 * duration
  expected_dns = 2 * duration
  rate_fraction = 0.95 if formal else 0.65
  replacement_minimum = (143 if formal else
                         (1 if duration >= 10 else 0))
  checks = {
    "monotonic_duration": stats["actual_duration_seconds"] >= duration,
    "all_long_connections_ready": (
      state.long_ready == sum(LONG_CONNECTIONS.values())),
    "long_rate": state.long_cycles >= expected_long * rate_fraction,
    "short_rate": state.short_success >= expected_short * rate_fraction,
    "dns_rate": state.dns_success >= expected_dns * rate_fraction,
    "long_deadlines": state.long_deadline_misses <= max(
      1, int(state.long_cycles * 0.01)),
    "payload_integrity": state.payload_mismatches == 0,
    "no_unexpected_failure": state.unexpected_failures == 0,
    "all_faults_covered": all(
      state.expected_faults[name] > 0 for name in FAULT_NAMES),
    "fault_code_stage_mapping": (
      required_log_mappings <= observed_log_mappings),
    "runtime_replacements": state.replacements >= replacement_minimum,
    "sample_gap": stats["maximum_sample_gap_seconds"] <= 60.0,
    "progress_gap": stats["maximum_progress_gap_seconds"] <= 60.0,
    "budgets_bounded": budget_ok,
    "drained": drained,
    "fd_drained": fd_drained,
    "pool_cache_bounded": cache_bounded,
    "processes_clean_exit": terminal_ok,
    "rss_theil_sen": (not formal or slope <= 1.0),
    "rss_window": (not formal or
                   last_median <= first_median + 16 * 1024 * 1024),
  }
  defect_names = {
    "monotonic_duration": "P13_SOAK_DURATION_SHORT",
    "all_long_connections_ready": "P13_SOAK_LONG_CONNECTION_SETUP",
    "long_rate": "P13_SOAK_LONG_RATE_LOW",
    "short_rate": "P13_SOAK_SHORT_RATE_LOW",
    "dns_rate": "P13_SOAK_DNS_RATE_LOW",
    "long_deadlines": "P13_SOAK_DEADLINE_MISSES",
    "payload_integrity": "P13_SOAK_PAYLOAD_MISMATCH",
    "no_unexpected_failure": "P13_SOAK_UNEXPECTED_FAILURE",
    "all_faults_covered": "P13_SOAK_FAULT_COVERAGE",
    "fault_code_stage_mapping": "P13_SOAK_FAULT_MAPPING",
    "runtime_replacements": "P13_SOAK_REPLACEMENT_COVERAGE",
    "sample_gap": "P13_SOAK_SAMPLE_GAP",
    "progress_gap": "P13_SOAK_PROGRESS_GAP",
    "budgets_bounded": "P13_SOAK_BUDGET_EXCEEDED",
    "drained": "P13_SOAK_DRAIN_INCOMPLETE",
    "fd_drained": "P13_SOAK_FD_RETAINED",
    "pool_cache_bounded": "P13_SOAK_POOL_EXCEEDED",
    "processes_clean_exit": "P13_SOAK_PROCESS_EXIT",
    "rss_theil_sen": "P13_SOAK_RSS_SLOPE",
    "rss_window": "P13_SOAK_RSS_WINDOW",
  }
  defects = [defect_names[name] for name, passed in checks.items()
             if not passed]
  summary = {
    "schema": "flick.soak-summary/v1",
    "formal": formal,
    "statistics": stats,
    "workload": state.snapshot(),
    "checks": checks,
    "rss": {
      "theil_sen_mib_per_hour": slope,
      "first_post_warmup_30m_median_bytes": first_median,
      "last_30m_median_bytes": last_median,
    },
    "processes": product_exits,
    "logger_code_stage_counts": logs,
    "errors": state.errors,
  }
  return summary, defects


def capability_matches(capability):
  """capability_matches 核对正式 soak 使用带测试目标的 Release 构建。"""
  return (capability.get("profile") == "release" and
          capability.get("instrumentation", {}).get("tests_built") is True)


def main():
  """main 执行 P13 长稳；只有精确 24 小时参数可形成正式证据。"""
  parser = argparse.ArgumentParser(
    description="Run the FlickNet V0.1 controlled loopback soak.")
  parser.add_argument("--preset", choices=("release",), required=True)
  parser.add_argument("--duration", type=int, default=FORMAL_DURATION_SECONDS)
  parser.add_argument("--seed", type=int, default=FORMAL_SEED)
  parser.add_argument("--sample-interval", type=float,
                      default=FORMAL_SAMPLE_INTERVAL_SECONDS)
  parser.add_argument("--development-smoke", action="store_true")
  parser.add_argument("--output", type=Path, required=True)
  args = parser.parse_args()
  formal_arguments = (
    args.duration == FORMAL_DURATION_SECONDS and
    args.seed == FORMAL_SEED and
    args.sample_interval == FORMAL_SAMPLE_INTERVAL_SECONDS)
  if args.duration <= 0:
    parser.error("--duration must be positive")
  if args.sample_interval <= 0 or args.sample_interval > 60:
    parser.error("--sample-interval must be within (0, 60]")
  if args.development_smoke:
    if args.duration >= FORMAL_DURATION_SECONDS:
      parser.error("--development-smoke requires a duration below 86400")
  elif not formal_arguments:
    parser.error("formal evidence requires duration=86400, seed=104729 and sample-interval=10")

  result_dir = ROOT / "build/release/soak-v0_1"
  output_path = args.output if args.output.is_absolute() else ROOT / args.output
  shutil.rmtree(result_dir, ignore_errors=True)
  result_dir.mkdir(parents=True)
  output_path.parent.mkdir(parents=True, exist_ok=True)
  source_manifest = result_dir / "source-manifest.txt"
  source_hash = write_source_manifest(source_manifest)
  commands = []
  started_at = utc_now()
  overall_started_ns = time.monotonic_ns()
  command_specs = [
    ["cmake", "--preset", args.preset],
    ["cmake", "--build", "--preset", args.preset, "--parallel"],
  ]
  for index, argv in enumerate(command_specs, start=1):
    command = run_command(argv, index, result_dir, None, [0])
    commands.append(command)
    if command["exit_code"] != 0:
      break

  data = None
  setup_error = None
  if len(commands) == len(command_specs) and all(
      command["exit_code"] == 0 for command in commands):
    workload_started_ns = time.monotonic_ns()
    try:
      data = asyncio.run(run_workload(
        ROOT / "build/release/flick",
        ROOT / "build/release/fn_p12_runtime_replacement_test",
        result_dir, args.duration, args.sample_interval, args.seed))
      workload_stdout = (
        f"Controlled workload completed for {args.duration} seconds.\n")
      workload_stderr = ""
      workload_exit = 0
    except BaseException as error:
      setup_error = str(error)
      workload_stdout = ""
      workload_stderr = f"Controlled workload failed: {error}\n"
      workload_exit = 1
    commands.append(self_command(
      3, result_dir,
      ["python3", "tests/soak/run_v0_1.py", "--preset", args.preset,
       "--duration", str(args.duration), "--seed", str(args.seed),
       "--sample-interval", str(args.sample_interval), "--output",
       relative(output_path)] +
      (["--development-smoke"] if args.development_smoke else []),
      workload_started_ns, workload_exit, workload_stdout, workload_stderr))

  summary = None
  defects = []
  slope = 0.0
  slope_path = result_dir / "theil-sen.json"
  slope_input = result_dir / "theil-sen-input.bin"
  summary_path = result_dir / "summary.json"
  if data is not None:
    eligible = write_slope_input(
      data["samples"], slope_input, not args.development_smoke)
    command = run_command(
      [relative(ROOT / "build/release/fn_p13_theil_sen"),
       relative(slope_input), relative(slope_path)],
      4, result_dir, None, [0])
    commands.append(command)
    if command["exit_code"] == 0:
      slope = json.loads(slope_path.read_text())["slope_mib_per_hour"]
      summary, defects = evaluate_workload(
        data, args.duration, not args.development_smoke, slope)
      summary["rss"]["slope_sample_count"] = len(eligible)
      write_json(summary_path, summary)
    else:
      defects.append("P13_SOAK_SLOPE_TOOL_FAILED")
  elif setup_error is not None:
    defects.append("P13_SOAK_SETUP_FAILED")
  if any(command["exit_code"] != 0 for command in commands):
    defects.append("P13_SOAK_COMMAND_FAILED")

  capability_path = ROOT / "build/release/flick-capabilities.json"
  capability = (json.loads(capability_path.read_text())
                if capability_path.is_file() else None)
  if capability is None or not capability_matches(capability):
    defects.append("P13_SOAK_CAPABILITY_MISMATCH")
  defects = list(dict.fromkeys(defects))
  passed = (not defects and summary is not None and
            all(summary["checks"].values()))
  result = "pass" if passed else "fail"

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
  if data is not None:
    inputs.extend(artifact(path, "soak-config", "application/yaml")
                  for path in data["config_paths"])
    inputs.append(artifact(data["topology_path"], "soak-topology",
                           "application/json"))
    artifacts.extend([
      artifact(data["raw_path"], "raw-samples", "application/x-ndjson"),
      artifact(data["replacement_path"], "runtime-replacements",
               "application/x-ndjson"),
      artifact(data["topology_path"], "soak-topology", "application/json"),
      artifact(data["fault_path"], "fault-events", "application/json"),
      artifact(slope_input, "theil-sen-input", "application/octet-stream"),
    ])
    if slope_path.is_file():
      artifacts.append(artifact(
        slope_path, "theil-sen-result", "application/json"))
    if summary_path.is_file():
      artifacts.append(artifact(
        summary_path, "soak-summary", "application/json"))
    for product in data["products"]:
      artifacts.extend([
        artifact(product.stdout_path, "product-events",
                 "application/x-ndjson"),
        artifact(product.stderr_path, "product-log", "text/plain"),
      ])
  revision, dirty = git_state()
  dependencies = capability["dependencies"] if capability else {
    "libev": "unavailable", "libyaml": "unavailable"}
  raw_metric_artifact = (
    artifact(data["raw_path"], "raw-samples", "application/x-ndjson")
    if data is not None else artifact(
      source_manifest, "missing-samples-placeholder", "text/plain"))
  metrics = [
    {
      "name": "soak_monotonic_duration",
      "unit": "seconds",
      "samples": [summary["statistics"]["actual_duration_seconds"]
                  if summary is not None else 0.0],
      "value": (summary["statistics"]["actual_duration_seconds"]
                if summary is not None else 0.0),
    },
    {
      "name": "aggregate_rss",
      "unit": "bytes",
      "samples_artifact": raw_metric_artifact,
      "maximum": (summary["statistics"]["maximum_rss_bytes"]
                  if summary is not None else 0.0),
    },
    {
      "name": "rss_theil_sen",
      "unit": "MiB/hour",
      "samples": [slope],
      "value": slope,
    },
    {
      "name": "long_payload_cycles",
      "unit": "cycles",
      "samples": [data["state"].long_cycles if data is not None else 0],
      "value": data["state"].long_cycles if data is not None else 0,
    },
  ]
  record = {
    "schema": "flick.validation-result/v1",
    "record_status": "example" if args.development_smoke else "evidence",
    "scope": "product-validation",
    "task": "P13",
    "kind": "soak",
    "result": result,
    "started_at": started_at,
    "finished_at": utc_now(),
    "duration_ms": (time.monotonic_ns() - overall_started_ns) // 1_000_000,
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
      "preset": "release",
      "build_type": "Release",
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
      "instrumentation": [],
    },
    "commands": commands,
    "inputs": inputs,
    "input_hashes": {item["path"]: item["sha256"] for item in inputs},
    "artifacts": artifacts,
    "counts": {
      "planned": 4,
      "executed": len(commands),
      "passed": sum(command["exit_code"] == 0 for command in commands),
      "failed": sum(command["exit_code"] != 0 for command in commands),
      "skipped": 4 - len(commands),
    },
    "metrics": metrics,
    "reference_analysis": reference_analysis(),
    "defects": defects,
    "limitations": [
      "The workload uses controlled loopback services and does not represent production network diversity.",
      "V0.1 has no public reload API; replacement evidence combines the P12 Runtime transaction with process-level A/B admission switching while established sessions remain pinned.",
    ] + ([
      "This development smoke is shorter than 86400 seconds and cannot satisfy the V0.1 soak gate.",
    ] if args.development_smoke else []),
  }
  write_json(output_path, record)
  actual = metrics[0]["value"]
  print(f"P13 soak: {result}; duration={actual:.3f}s; "
        f"samples={(summary['statistics']['sample_count'] if summary else 0)}; "
        f"defects={len(defects)}.")
  print(f"Record: {relative(output_path)}")
  raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
  main()
