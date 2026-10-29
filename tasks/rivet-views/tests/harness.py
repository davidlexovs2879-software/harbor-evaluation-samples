import json
import os
import select
import subprocess
import tempfile
import time

CHECKS = 0


def equal(actual, expected):
    global CHECKS
    CHECKS += 1
    if actual != expected:
        raise AssertionError(f"expected {str(expected)[:900]}; received {str(actual)[:900]}")


def require(condition, message):
    global CHECKS
    CHECKS += 1
    if not condition:
        raise AssertionError(message)


class Client:
    def __init__(self):
        self.err = tempfile.TemporaryFile()
        self.process = subprocess.Popen(["runuser", "-u", "agent", "--", "python", "-B", "/app/views/main.py"],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.err,
                                        env={"PATH": os.environ["PATH"], "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1"},
                                        start_new_session=True)
        self.buffer = b""

    def raw(self, line):
        self.process.stdin.write(line.encode() + b"\n")
        self.process.stdin.flush()
        deadline = time.monotonic() + 10
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise AssertionError("candidate response exceeded ten seconds")
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                self.err.seek(0)
                raise AssertionError(f"candidate exited: {self.err.read(2000)!r}")
            self.buffer += chunk
            if len(self.buffer) > 32 * 1024 * 1024:
                raise AssertionError("response exceeded limit")
        line, self.buffer = self.buffer.split(b"\n", 1)
        return json.loads(line)

    def call(self, request):
        return self.raw(json.dumps(request, ensure_ascii=True))

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, 9)
                self.process.wait()
        self.err.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
