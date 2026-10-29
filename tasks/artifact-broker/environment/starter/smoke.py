"""Public broker protocol example using disposable credentials."""
import base64
import hashlib
import hmac
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def encoded(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    config = {"secret": "disposable-local-smoke-signing-material", "issuer": "lab", "audience": "broker",
              "now": 1000, "principals": {"builder": {"tenant": "red", "role": "writer", "disabled": False}}}
    (root / "config.json").write_text(json.dumps(config))
    claims = {"iss": "lab", "aud": "broker", "sub": "builder", "tenant": "red", "iat": 900,
              "exp": 2000, "jti": "smoke", "kind": "session"}
    message = encoded({"alg": "HS256", "typ": "JWT", "kid": "primary"}) + "." + encoded(claims)
    token = message + "." + base64.urlsafe_b64encode(hmac.new(config["secret"].encode(), message.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    requests = [{"op": "write", "token": token, "path": "build/result", "data": "ok", "request_id": "one"},
                {"op": "read", "token": token, "path": "build/result"},
                {"op": "read", "token": "unsigned", "path": "build/result"}]
    result = subprocess.run([sys.executable, str(Path(__file__).with_name("main.py")),
                             str(root / "config.json"), str(root / "state")],
                            input="".join(json.dumps(r) + "\n" for r in requests), capture_output=True,
                            text=True, check=True, timeout=20)
    assert [json.loads(line) for line in result.stdout.splitlines()] == [
        {"status": 200, "body": {"ok": True}}, {"status": 200, "body": {"data": "ok"}},
        {"status": 401, "body": {"error": "unauthorized"}}], result.stdout
print("public smoke passed")
