#!/usr/bin/env python3
"""Exercise a real worker after its stdout observer closes, without SSH."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import selectors
import shlex
import struct
import subprocess
import sys
import time
import uuid


def frames(raw):
    result = []
    offset = 0
    while offset < len(raw):
        if len(raw) - offset < 5:
            raise ValueError("incomplete frame header")
        kind, length = raw[offset], struct.unpack(">I", raw[offset + 1:offset + 5])[0]
        end = offset + 5 + length
        if end > len(raw):
            raise ValueError("incomplete frame body")
        result.append((kind, raw[offset + 5:end]))
        offset = end
    return result


def cli_pipe_preserves_sigpipe(binary):
    import os
    import signal
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    try:
        result = subprocess.run([str(binary), "--help"], stdout=write_fd,
                                stderr=subprocess.PIPE, timeout=10)
    finally:
        os.close(write_fd)
    return result.returncode == -signal.SIGPIPE


def run(binary, output):
    output.mkdir(parents=True, exist_ok=False)
    nonce = uuid.uuid4().hex
    ready = f"READY:{nonce}\n".encode()
    go, done = output / "go", output / "child-result"
    child_script = output / "child.py"
    child_script.write_text('''import pathlib, sys, time
go, done = map(pathlib.Path, sys.argv[1:3])
print("READY:" + sys.argv[3], flush=True)
deadline = time.monotonic() + 10
while not go.exists():
    if time.monotonic() > deadline:
        raise RuntimeError("test did not release child")
    time.sleep(0.01)
try:
    for _ in range(4):
        print("AFTER:" + sys.argv[3], flush=True)
        time.sleep(0.03)
except BrokenPipeError:
    done.write_text("broken-pipe")
    raise SystemExit(23)
done.write_text("completed")
raise SystemExit(7)
''')
    command = shlex.join([sys.executable, "-u", str(child_script), str(go), str(done), nonce])
    process = subprocess.Popen([str(binary), "worker"], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    initial = bytearray()
    try:
        process.stdin.write(b"__REXEC_CMD__=" + command.encode() + b"\0")
        process.stdin.close()
        deadline = time.monotonic() + 10
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while ready not in initial:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise TimeoutError("worker did not forward child readiness")
                import os
                chunk = os.read(process.stdout.fileno(), 8192)
                if not chunk:
                    raise RuntimeError("worker exited before child readiness")
                initial.extend(chunk)
        assert any(kind == 3 and int.from_bytes(payload, "big") == process.pid
                   for kind, payload in frames(initial))
        process.stdout.close()
        go.touch(exist_ok=False)
        status = process.wait(timeout=10)
        deadline = time.monotonic() + 3
        while not done.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        log = Path.home() / ".rexec/logs" / f"{process.pid}.log"
        raw = log.read_bytes()
        assert ready in raw
        (output / "worker-frames.bin").write_bytes(raw)
        decoded = frames(raw)
        exit_codes = [int.from_bytes(payload, "big", signed=True) for kind, payload in decoded if kind == 4]
        result = {"worker_exit": status, "child_result": done.read_text() if done.exists() else None,
                  "logged_exit_codes": exit_codes, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
        passed = status == 0 and result["child_result"] == "completed" and exit_codes == [7]
        if passed:
            attached = subprocess.check_output([str(binary), "attach", "--pid", str(process.pid), "--offset", "0"], timeout=10)
            result["attach_replays_exact_log"] = attached == raw
            passed = attached == raw
        result["cli_sigpipe_preserved"] = cli_pipe_preserves_sigpipe(binary)
        passed = passed and result["cli_sigpipe_preserved"]
        result["status"] = "PASS_WORKER_DISCONNECT" if passed else "FAIL_WORKER_DISCONNECT"
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result))
        return passed
    finally:
        go.touch(exist_ok=True)
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if process.stderr is not None:
            (output / "worker-stderr.txt").write_bytes(process.stderr.read())
            process.stderr.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    if not run(args.binary.resolve(strict=True), args.output_dir.resolve()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
