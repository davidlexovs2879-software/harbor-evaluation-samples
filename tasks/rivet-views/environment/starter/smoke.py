import json
from pathlib import Path
import subprocess
import sys

requests = [
    {"op": "create", "nodes": [{"id": "s", "op": "source", "columns": ["int"]},
                               {"id": "d", "op": "distinct", "input": "s"}], "outputs": ["d"]},
    {"op": "apply", "id": "one", "updates": [{"source": "s", "row": [7], "weight": 3}]},
    {"op": "apply", "id": "two", "updates": [{"source": "s", "row": [7], "weight": -2}]},
    {"op": "get", "node": "d"},
]
result = subprocess.run([sys.executable, str(Path(__file__).with_name("main.py"))],
                        input="".join(json.dumps(r) + "\n" for r in requests), text=True,
                        capture_output=True, check=True, timeout=20)
assert [json.loads(line) for line in result.stdout.splitlines()] == [
    {"ok": True, "seq": 0, "outputs": {"d": []}},
    {"ok": True, "seq": 1, "deltas": {"d": [{"row": [7], "weight": 1}]}},
    {"ok": True, "seq": 2, "deltas": {"d": []}},
    {"seq": 2, "rows": [{"row": [7], "weight": 1}]},
], result.stdout
print("public smoke passed")
