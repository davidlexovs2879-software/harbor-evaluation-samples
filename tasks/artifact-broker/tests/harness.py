"""JSON transport for unprivileged candidate processes; expectations stay in the verifier."""
import json
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time

CHECKS = 0


def equal(actual, expected):
    global CHECKS
    CHECKS += 1
    if actual != expected:
        raise AssertionError(f"expected {expected!r}; received {actual!r}")


def require(condition, message):
    global CHECKS
    CHECKS += 1
    if not condition:
        raise AssertionError(message)


def directory():
    path = Path(tempfile.mkdtemp(prefix="broker-"))
    os.chown(path, 1000, 1000)
    return path


class Client:
    def __init__(self, config, path=None):
        self.path = path if path is not None else directory()
        config_path = self.path / "config.json"
        config_path.write_text(json.dumps(config))
        os.chmod(config_path, 0o444)
        self.err = tempfile.TemporaryFile()
        self.process = subprocess.Popen(["runuser", "-u", "agent", "--", "python", "-B", "/app/broker/main.py",
                                         str(config_path), str(self.path / "state")],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.err,
                                        env={"PATH": os.environ["PATH"], "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1"},
                                        start_new_session=True)
        self.buffer = b""

    def raw(self, line):
        self.process.stdin.write(line.encode() + b"\n")
        self.process.stdin.flush()
        deadline = time.monotonic() + 5
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise AssertionError("candidate response timed out")
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                self.err.seek(0)
                raise AssertionError(f"candidate exited: {self.err.read(2000)!r}")
            self.buffer += chunk
            if len(self.buffer) > 16 * 1024 * 1024:
                raise AssertionError("candidate output exceeds limit")
        line, self.buffer = self.buffer.split(b"\n", 1)
        return json.loads(line)

    def call(self, op, token, **fields):
        return self.raw(json.dumps({"op": op, "token": token, **fields}))

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, 9)
                self.process.wait()
        self.err.close()

    def kill(self):
        os.killpg(self.process.pid, 9)
        self.process.wait(timeout=5)
        self.err.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
