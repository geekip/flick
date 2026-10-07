#!/usr/bin/env python3
"""用解析斜率输入验证 P13 Theil–Sen 工具。"""

import argparse
import json
from pathlib import Path
import struct
import subprocess


def main():
  """main 写四个共线样本并核对全部六个样本对的精确中位数。"""
  parser = argparse.ArgumentParser(description="Test the Theil-Sen helper.")
  parser.add_argument("--binary", type=Path, required=True)
  parser.add_argument("--work-directory", type=Path, required=True)
  args = parser.parse_args()
  args.work_directory.mkdir(parents=True, exist_ok=True)
  input_path = args.work_directory / "samples.bin"
  output_path = args.work_directory / "result.json"
  bytes_per_hour = 2.0 * 1024.0 * 1024.0
  with input_path.open("wb") as stream:
    for seconds in (0.0, 10.0, 25.0, 60.0):
      stream.write(struct.pack(
        "dd", seconds, 4096.0 + bytes_per_hour * seconds / 3600.0))
  result = subprocess.run(
    [str(args.binary), str(input_path), str(output_path)],
    check=False, capture_output=True, text=True)
  if result.returncode != 0:
    raise SystemExit(
      f"Theil-Sen helper exited {result.returncode}: {result.stderr}")
  value = json.loads(output_path.read_text(encoding="utf-8"))
  if value.get("schema") != "flick.theil-sen/v1":
    raise SystemExit("Theil-Sen helper emitted an invalid schema.")
  if value.get("samples") != 4 or value.get("pairs") != 6:
    raise SystemExit("Theil-Sen helper emitted invalid sample counts.")
  if abs(value.get("slope_mib_per_hour", 0.0) - 2.0) > 1e-12:
    raise SystemExit("Theil-Sen helper emitted an incorrect slope.")
  print("Theil-Sen helper test passed.")


if __name__ == "__main__":
  main()
