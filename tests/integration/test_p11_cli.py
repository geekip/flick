#!/usr/bin/env python3
"""以子进程验证 P11 CLI、真实 listener、JSON 和信号生命周期。"""

import argparse
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import tempfile
import threading
import time


FEATURES = [
  "direct_tcp",
  "dns_failure_cache",
  "dns_resolver",
  "dns_upstream_tcp",
  "dns_upstream_udp",
  "socks_in_tcp",
  "socks_out_tcp",
]


def check(condition, message):
  """check 在失败时保留明确的验收原因。"""
  if not condition:
    raise AssertionError(message)


def run(binary, *arguments, env=None, timeout=5):
  """run 执行短命令并捕获两个文本通道。"""
  return subprocess.run(
    [str(binary), *map(str, arguments)], capture_output=True, text=True,
    env=env, timeout=timeout, check=False)


def free_port():
  """free_port 返回用于隔离测试的临时 loopback 端口。"""
  probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  probe.bind(("127.0.0.1", 0))
  port = probe.getsockname()[1]
  probe.close()
  return port


def config_text(port, target="DIRECT", drain="2s"):
  """config_text 生成只含 V0.1 字段的最小配置。"""
  dns = ""
  if target == "DIRECT":
    dns = """dns:
  enable: false
  direct:
    - udp://127.0.0.1:9
"""
  return f"""schema-version: 1
mode: rule
ipv6: false
log-level: warn
timeouts:
  drain: {drain}
{dns}inbounds:
  - name: socks-in
    type: socks5
    listen: 127.0.0.1
    port: {port}
    udp: false
rules:
  - MATCH,{target}
"""


def proxy_config_text(port, proxy_port):
  """proxy_config_text 生成数字节点且业务域名远端解析的配置。"""
  return f"""schema-version: 1
mode: rule
ipv6: false
log-level: warn
inbounds:
  - name: socks-in
    type: socks5
    listen: 127.0.0.1
    port: {port}
    udp: false
proxies:
  - name: upstream
    type: socks5
    server: 127.0.0.1
    port: {proxy_port}
    udp: false
rules:
  - MATCH,upstream
"""


def write_config(directory, text, name="config.yaml"):
  """write_config 写入受控临时配置。"""
  path = Path(directory) / name
  path.write_text(text, encoding="utf-8")
  return path


def read_line(process, timeout=5):
  """read_line 为启动事件提供有界等待。"""
  ready, _, _ = select.select([process.stdout], [], [], timeout)
  check(ready, "run did not publish its first event")
  line = process.stdout.readline()
  check(line, "run closed stdout before its first event")
  return line.rstrip("\n")


def expect_command_result(completed, exit_code, command, status):
  """expect_command_result 核对单对象 JSON 契约。"""
  check(completed.returncode == exit_code,
        f"unexpected exit: {completed.returncode}, stderr={completed.stderr}")
  lines = completed.stdout.splitlines()
  check(len(lines) == 1, f"expected one JSON object, got {lines!r}")
  value = json.loads(lines[0])
  check(value["format_version"] == 1, "format version mismatch")
  check(value["schema"] == "flick.command-result", "schema mismatch")
  check(value["command"] == command, "command mismatch")
  check(value["status"] == status, "status mismatch")
  check(value["exit_code"] == exit_code, "JSON exit mismatch")
  return value


def test_short_commands(binary, root, directory):
  """test_short_commands 覆盖 version、用法、配置与 test 边界。"""
  completed = run(binary, "--output", "json", "version", "--features")
  value = expect_command_result(completed, 0, "version", "ok")
  check(value["details"]["features"] == FEATURES,
        "version features are not exact and sorted")
  check(value["details"]["tls_backend"] == "none",
        "unimplemented TLS backend was reported")

  fake_home = Path(directory) / "home"
  (fake_home / ".flick").mkdir(parents=True)
  (fake_home / ".flick" / "config.yaml").write_text(
    "this: [is: malformed", encoding="utf-8")
  environment = os.environ.copy()
  environment["HOME"] = str(fake_home)
  completed = run(binary, "--output", "json", "--config", "a",
                  "--config", "b", "check", env=environment)
  value = expect_command_result(completed, 2, "cli", "error")
  check(value["errors"][0]["code"] == "E_CLI_USAGE",
        "CLI error was replaced by default config parsing")

  completed = run(binary, "--output", "json", "stop")
  value = expect_command_result(completed, 4, "stop", "error")
  check(value["errors"][0]["code"] == "E_UNSUPPORTED_VERSION",
        "unsupported command code mismatch")

  invalid = root / "tests/fixtures/config/v1/invalid/unknown-field.yaml"
  completed = run(binary, "--output", "json", "--config", invalid,
                  "check")
  value = expect_command_result(completed, 3, "check", "error")
  check(value["errors"][0]["code"] == "E_UNKNOWN_FIELD",
        "config error code mismatch")
  check(value["errors"][0]["line"] is not None,
        "available source mark was omitted")

  unsupported = root / "tests/fixtures/config/v1/invalid/unsupported-udp.yaml"
  completed = run(binary, "--output", "json", "--config", unsupported,
                  "check")
  value = expect_command_result(completed, 4, "check", "error")
  check(value["errors"][0]["code"] == "E_UNSUPPORTED_VERSION",
        "unsupported config did not use exit 4")

  oversized = Path(directory) / "oversized.yaml"
  oversized.write_bytes(b"x" * (1024 * 1024 + 1))
  completed = run(binary, "--output", "json", "--config", oversized,
                  "check")
  value = expect_command_result(completed, 3, "check", "error")
  check(value["errors"][0]["code"] == "E_CONFIG_SIZE",
        "config size code mismatch")

  occupied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  occupied.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  occupied.bind(("127.0.0.1", 0))
  occupied.listen()
  occupied_port = occupied.getsockname()[1]
  occupied_config = write_config(
    directory, config_text(occupied_port, "REJECT"), "occupied.yaml")
  completed = run(binary, "--output", "json", "--config",
                  occupied_config, "check")
  expect_command_result(completed, 0, "check", "ok")
  completed = run(binary, "--output", "json", "--config",
                  occupied_config, "test")
  value = expect_command_result(completed, 5, "test", "error")
  check(value["errors"][0]["code"] == "E_EXTERNAL_DEPENDENCY",
        "occupied port did not fail prepare")
  occupied.close()

  available_config = write_config(
    directory, proxy_config_text(free_port(), free_port()), "available.yaml")
  completed = run(binary, "--output", "json", "--config",
                  available_config, "test")
  value = expect_command_result(completed, 0, "test", "ok")
  check(value["details"]["lazy_external_dependencies"] == "not_verified",
        "test did not disclose lazy validation status")


def test_direct_run(binary, directory):
  """test_direct_run 验证真实 listener、relay、计数和干净停止。"""
  target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  target.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  target.bind(("127.0.0.1", 0))
  target.listen()
  target_port = target.getsockname()[1]
  observed = []

  def echo_server():
    connection, _ = target.accept()
    payload = connection.recv(64)
    observed.append(payload)
    connection.sendall(payload[::-1])
    connection.shutdown(socket.SHUT_WR)
    connection.close()
    target.close()

  thread = threading.Thread(target=echo_server)
  thread.start()
  inbound_port = free_port()
  config = write_config(directory, config_text(inbound_port), "run.yaml")
  process = subprocess.Popen(
    [str(binary), "--output", "json", "--config", str(config), "run"],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
  first = json.loads(read_line(process))
  check(first["sequence"] == 1 and first["event"] == "started",
        "run first event mismatch")
  children_path = Path(f"/proc/{process.pid}/task/{process.pid}/children")
  if children_path.exists():
    check(children_path.read_text().strip() == "",
          "run created a daemon or watchdog child")

  client = socket.create_connection(("127.0.0.1", inbound_port), timeout=2)
  client.sendall(b"\x05\x01\x00")
  check(client.recv(2) == b"\x05\x00", "SOCKS method reply mismatch")
  payload = b"p11-process-chain"
  request = (b"\x05\x01\x00\x01\x7f\x00\x00\x01" +
             target_port.to_bytes(2, "big") + payload)
  client.sendall(request)
  reply = client.recv(10)
  check(len(reply) == 10 and reply[:4] == b"\x05\x00\x00\x01",
        f"SOCKS CONNECT reply mismatch: {reply!r}")
  check(client.recv(len(payload)) == payload[::-1], "relay payload mismatch")
  client.close()
  thread.join(timeout=2)
  check(not thread.is_alive() and observed == [payload],
        "target service did not receive the payload")

  os.kill(process.pid, signal.SIGTERM)
  rest, errors = process.communicate(timeout=5)
  check(process.returncode == 0, f"clean stop failed: {errors}")
  lines = rest.splitlines()
  check(len(lines) == 1, f"unexpected run terminal lines: {lines!r}")
  terminal = json.loads(lines[0])
  check(terminal["sequence"] == 2 and terminal["event"] == "stopped",
        "run terminal event mismatch")
  counters = terminal["counters"]
  check(counters["accepted_connections"] == 1, "accept counter mismatch")
  check(counters["completed_sessions"] == 1, "session counter mismatch")
  check(counters["loop_iterations"] > 0 and counters["io_callbacks"] > 0,
        "loop counters did not progress")


def test_forced_stop(binary, directory):
  """test_forced_stop 验证第二次信号的退出码和终结事件。"""
  inbound_port = free_port()
  config = write_config(
    directory, config_text(inbound_port, "REJECT", "5s"), "forced.yaml")
  process = subprocess.Popen(
    [str(binary), "--output", "json", "--config", str(config), "run"],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
  first = json.loads(read_line(process))
  check(first["event"] == "started", "forced-stop run did not start")
  client = socket.create_connection(("127.0.0.1", inbound_port), timeout=2)
  client.sendall(b"\x05")
  time.sleep(0.05)
  os.kill(process.pid, signal.SIGTERM)
  os.kill(process.pid, signal.SIGINT)
  rest, _ = process.communicate(timeout=5)
  client.close()
  check(process.returncode == 8, "second signal did not return exit 8")
  lines = rest.splitlines()
  check(len(lines) == 1, "forced stop emitted an invalid JSONL sequence")
  terminal = json.loads(lines[0])
  check(terminal["sequence"] == 2 and terminal["event"] == "failed",
        "forced stop terminal event mismatch")
  check(terminal["errors"][0]["code"] == "E_SHUTDOWN_TIMEOUT",
        "forced stop diagnostic mismatch")


def recv_exact(connection, length):
  """recv_exact 为参考 SOCKS 服务读取固定 wire 字段。"""
  output = bytearray()
  while len(output) < length:
    part = connection.recv(length - len(output))
    check(part, "unexpected EOF in reference SOCKS server")
    output.extend(part)
  return bytes(output)


def test_socks_outbound_run(binary, directory):
  """test_socks_outbound_run 验证进程级 SOCKS 出站和 DOMAIN 转交。"""
  target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  target.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  target.bind(("127.0.0.1", 0))
  target.listen()
  target_port = target.getsockname()[1]
  proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  proxy.bind(("127.0.0.1", 0))
  proxy.listen()
  proxy_port = proxy.getsockname()[1]
  observed = []
  thread_errors = []

  def proxy_server():
    try:
      client, _ = proxy.accept()
      check(recv_exact(client, 3) == b"\x05\x01\x00",
            "outbound greeting mismatch")
      client.sendall(b"\x05\x00")
      prefix = recv_exact(client, 5)
      check(prefix[:4] == b"\x05\x01\x00\x03",
            "outbound DOMAIN request prefix mismatch")
      domain = recv_exact(client, prefix[4])
      port = int.from_bytes(recv_exact(client, 2), "big")
      observed.append((domain, port))
      upstream = socket.create_connection(
        ("127.0.0.1", target_port), timeout=2)
      client.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" +
                     target_port.to_bytes(2, "big"))
      payload = recv_exact(client, len(b"p11-socks-out"))
      upstream.sendall(payload)
      response = recv_exact(upstream, len(payload))
      client.sendall(response)
      client.shutdown(socket.SHUT_WR)
      client.close()
      upstream.close()
      proxy.close()
    except BaseException as error:
      thread_errors.append(error)

  def target_server():
    try:
      connection, _ = target.accept()
      payload = recv_exact(connection, len(b"p11-socks-out"))
      connection.sendall(payload[::-1])
      connection.shutdown(socket.SHUT_WR)
      connection.close()
      target.close()
    except BaseException as error:
      thread_errors.append(error)

  proxy_thread = threading.Thread(target=proxy_server)
  target_thread = threading.Thread(target=target_server)
  proxy_thread.start()
  target_thread.start()
  inbound_port = free_port()
  config = write_config(
    directory, proxy_config_text(inbound_port, proxy_port), "proxy-run.yaml")
  process = subprocess.Popen(
    [str(binary), "--output", "json", "--config", str(config), "run"],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
  check(json.loads(read_line(process))["event"] == "started",
        "SOCKS outbound run did not start")
  client = socket.create_connection(("127.0.0.1", inbound_port), timeout=2)
  client.sendall(b"\x05\x01\x00")
  check(recv_exact(client, 2) == b"\x05\x00", "inbound method mismatch")
  domain = b"target.test"
  payload = b"p11-socks-out"
  client.sendall(b"\x05\x01\x00\x03" + bytes([len(domain)]) + domain +
                 target_port.to_bytes(2, "big") + payload)
  reply = recv_exact(client, 10)
  check(reply[:4] == b"\x05\x00\x00\x01",
        "inbound SOCKS outbound reply mismatch")
  check(recv_exact(client, len(payload)) == payload[::-1],
        "SOCKS outbound relay payload mismatch")
  client.close()
  proxy_thread.join(timeout=2)
  target_thread.join(timeout=2)
  check(not proxy_thread.is_alive() and not target_thread.is_alive(),
        "reference SOCKS topology did not finish")
  check(not thread_errors, f"reference service failed: {thread_errors!r}")
  check(observed == [(domain, target_port)],
        "business DOMAIN was not passed unchanged to the proxy")
  os.kill(process.pid, signal.SIGTERM)
  rest, errors = process.communicate(timeout=5)
  check(process.returncode == 0, f"SOCKS outbound run stop failed: {errors}")
  terminal = json.loads(rest.strip())
  check(terminal["counters"]["completed_sessions"] == 1,
        "SOCKS outbound session counter mismatch")


def main():
  """main 运行全部 P11 子进程验收。"""
  parser = argparse.ArgumentParser()
  parser.add_argument("--binary", required=True, type=Path)
  parser.add_argument("--root", required=True, type=Path)
  args = parser.parse_args()
  binary = args.binary.resolve()
  root = args.root.resolve()
  with tempfile.TemporaryDirectory(prefix="flick-p11-") as directory:
    test_short_commands(binary, root, directory)
    test_direct_run(binary, directory)
    test_socks_outbound_run(binary, directory)
    test_forced_stop(binary, directory)
  print("p11 cli integration tests passed")


if __name__ == "__main__":
  main()
