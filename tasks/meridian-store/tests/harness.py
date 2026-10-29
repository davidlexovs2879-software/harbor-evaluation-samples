"""Keep untrusted candidate code in its own unprivileged process."""
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
    path = Path(tempfile.mkdtemp(prefix="meridian-"))
    os.chown(path, 1000, 1000)
    return path


class Client:
    def __init__(self, path, crash=None):
        self.path = path
        env = {"PATH": os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"}
        if crash:
            env["MERIDIAN_CRASH_AT"] = crash
        self.err = tempfile.TemporaryFile()
        self.process = subprocess.Popen(["runuser", "-u", "agent", "--", "python", "-B",
                                         "/app/store/main.py", str(path)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=self.err, env=env, start_new_session=True)
        self.buffer = b""

    def send(self, value):
        self.process.stdin.write((json.dumps(value) + "\n").encode())
        self.process.stdin.flush()

    def read(self):
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
                raise AssertionError("candidate output exceeds response limit")
        line, self.buffer = self.buffer.split(b"\n", 1)
        return json.loads(line)

    def call(self, op, **fields):
        self.send({"op": op, **fields})
        return self.read()

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


def put(client, tx, key, value):
    equal(client.call("begin", tx=tx), {"ok": True, "snapshot": client.call("root")["seq"]})
    equal(client.call("put", tx=tx, key=key, value=value), {"ok": True})
    return client.call("commit", tx=tx)
