"""Public protocol example; these checks are intentionally small."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory() as directory:
    commands = [
        {"op": "begin", "tx": "a"},
        {"op": "put", "tx": "a", "key": "hello", "value": "world"},
        {"op": "commit", "tx": "a"},
        {"op": "begin", "tx": "b"},
        {"op": "get", "tx": "b", "key": "hello"},
    ]
    result = subprocess.run([sys.executable, str(Path(__file__).with_name("main.py")), directory],
                            input="".join(json.dumps(c) + "\n" for c in commands), text=True,
                            capture_output=True, check=True, timeout=20)
    expected = [{"ok": True, "snapshot": 0}, {"ok": True}, {"ok": True, "seq": 1},
                {"ok": True, "snapshot": 1}, {"value": "world"}]
    assert [json.loads(line) for line in result.stdout.splitlines()] == expected, result.stdout
print("public smoke passed")
