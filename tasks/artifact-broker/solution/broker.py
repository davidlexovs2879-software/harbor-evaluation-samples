#!/usr/bin/env python3
"""Tenant-isolated artifact operations with attenuated bearer capabilities."""
import base64
import binascii
import copy
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import sys
import tarfile
import unicodedata
from urllib.parse import unquote_to_bytes

ACTIONS = {"read", "list", "write", "delete", "import", "delegate"}
ROLES = {"reader": {"read", "list"}, "writer": ACTIONS, "admin": ACTIONS | {"audit"}}
MUTATIONS = {"write", "delete", "import", "batch", "delegate"}
ERRORS = {400: "invalid", 401: "unauthorized", 403: "forbidden", 404: "not_found", 409: "conflict"}


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def identifier(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value) is not None


def data_ok(value):
    try:
        return isinstance(value, str) and len(value.encode("utf-8")) <= 65536
    except UnicodeError:
        return False


def path_name(value, prefix=False):
    if not isinstance(value, str):
        raise ValueError("path type")
    if re.search(r"%(?![A-Fa-f0-9]{2})", value):
        raise ValueError("invalid percent escape")
    value = unicodedata.normalize("NFC", unquote_to_bytes(value).decode("utf-8", "strict"))
    if (len(value.encode("utf-8")) > 512 or "%" in value or "\\" in value
            or any(unicodedata.category(c).startswith("C") for c in value)):
        raise ValueError("unsafe path")
    if prefix and value == "":
        return value
    if any(segment in ("", ".", "..") for segment in value.split("/")):
        raise ValueError("unsafe component")
    return value


def contained(prefix, value):
    return prefix == "" or value == prefix or value.startswith(prefix + "/")


def encode64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode64(segment):
    if not isinstance(segment, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", segment):
        raise ValueError("invalid token segment")
    data = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    if encode64(data) != segment:
        raise ValueError("noncanonical token segment")
    return data


def sign(secret, payload):
    header = {"alg": "HS256", "typ": "JWT", "kid": "primary"}
    message = encode64(canonical(header)) + "." + encode64(canonical(payload))
    return message + "." + encode64(hmac.digest(secret, message.encode(), "sha256"))


def actions_ok(actions):
    return (isinstance(actions, list) and bool(actions) and all(isinstance(a, str) and a in ACTIONS for a in actions)
            and len(set(actions)) == len(actions))


def shape(request):
    fields = {"read": {"path"}, "list": {"prefix"}, "write": {"path", "data", "request_id"},
              "delete": {"path", "request_id"}, "delegate": {"prefix", "actions", "exp", "depth", "request_id"},
              "import": {"prefix", "archive", "request_id"}, "batch": {"operations", "request_id"}, "audit": set()}
    if not isinstance(request, dict) or not isinstance(request.get("op"), str):
        return False
    op = request["op"]
    if op not in fields or set(request) != fields[op] | {"op", "token"} or not isinstance(request["token"], str):
        return False
    for name in ("path", "prefix", "archive"):
        if name in request and not isinstance(request[name], str):
            return False
    if "request_id" in request and not identifier(request["request_id"]):
        return False
    if op == "write" and not data_ok(request["data"]):
        return False
    if op == "delegate" and (not actions_ok(request["actions"]) or type(request["exp"]) is not int
                              or type(request["depth"]) is not int):
        return False
    if op == "batch":
        if not isinstance(request["operations"], list) or not 1 <= len(request["operations"]) <= 64:
            return False
        for item in request["operations"]:
            if not isinstance(item, dict) or item.get("op") not in ("write", "delete"):
                return False
            expected = {"op", "path", "data"} if item["op"] == "write" else {"op", "path"}
            if set(item) != expected or not isinstance(item["path"], str):
                return False
            if item["op"] == "write" and not data_ok(item["data"]):
                return False
    return True


class Broker:
    def __init__(self, config_file, state_dir):
        self.config = json.loads(Path(config_file).read_text(), object_pairs_hook=unique)
        self.secret = self.config["secret"].encode()
        self.directory = Path(state_dir)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.state = {"objects": {}, "used": [], "audit": []}
        file = self.directory / "state.json"
        if file.exists():
            wrapper = json.loads(file.read_text(), object_pairs_hook=unique)
            if (set(wrapper) != {"version", "payload", "checksum"} or wrapper["version"] != 1
                    or hashlib.sha256(canonical(wrapper["payload"])).hexdigest() != wrapper["checksum"]):
                raise ValueError("corrupt state")
            state = wrapper["payload"]
            if (not isinstance(state, dict) or set(state) != {"objects", "used", "audit"}
                    or not isinstance(state["objects"], dict) or not isinstance(state["used"], list)
                    or not isinstance(state["audit"], list)):
                raise ValueError("invalid state schema")
            previous = "0" * 64
            for seq, event in enumerate(state["audit"], 1):
                if (set(event) != {"seq", "op", "sub", "tenant", "path", "status", "previous", "hash"}
                        or event["seq"] != seq or event["previous"] != previous
                        or event["hash"] != hashlib.sha256(canonical({k: v for k, v in event.items() if k != "hash"})).hexdigest()):
                    raise ValueError("corrupt audit chain")
                previous = event["hash"]
            self.state = state

    def authenticate(self, token):
        try:
            a, b, signature = token.split(".")
            header = json.loads(decode64(a).decode("utf-8"), object_pairs_hook=unique)
            claims = json.loads(decode64(b).decode("utf-8"), object_pairs_hook=unique)
            if header != {"alg": "HS256", "typ": "JWT", "kid": "primary"}:
                return None
            if not hmac.compare_digest(decode64(signature), hmac.digest(self.secret, (a + "." + b).encode(), "sha256")):
                return None
            if not isinstance(claims, dict):
                return None
            fields = {"iss", "aud", "sub", "tenant", "iat", "exp", "jti", "kind"}
            kind = claims.get("kind")
            if kind == "capability":
                fields |= {"prefix", "actions", "depth"}
            elif kind != "session":
                return None
            if set(claims) != fields:
                return None
            if (claims["iss"] != self.config["issuer"] or claims["aud"] != self.config["audience"]
                    or not identifier(claims["sub"]) or not identifier(claims["tenant"])
                    or not identifier(claims["jti"]) or type(claims["iat"]) is not int or type(claims["exp"]) is not int
                    or not 0 <= claims["iat"] <= self.config["now"] < claims["exp"]
                    or claims["exp"] - claims["iat"] > 86400):
                return None
            principal = self.config["principals"].get(claims["sub"])
            if principal is None or principal["disabled"] or principal["tenant"] != claims["tenant"]:
                return None
            if kind == "capability":
                if (not isinstance(claims["prefix"], str) or path_name(claims["prefix"], True) != claims["prefix"]
                        or not actions_ok(claims["actions"]) or type(claims["depth"]) is not int
                        or not 0 <= claims["depth"] <= 2):
                    return None
            return claims
        except (ValueError, TypeError, UnicodeError, KeyError, binascii.Error, RecursionError):
            return None

    def persist(self, state):
        payload = {"version": 1, "payload": state, "checksum": hashlib.sha256(canonical(state)).hexdigest()}
        temporary = self.directory / "state.tmp"
        with open(temporary, "wb") as file:
            file.write(canonical(payload))
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, self.directory / "state.json")
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        self.state = state

    def finish(self, request, claims, path, status, body=None, state=None):
        response = {"status": status, "body": body if body is not None else {"error": ERRORS[status]}}
        if request["op"] == "audit":
            return response
        state = copy.deepcopy(self.state) if state is None else state
        event = {"seq": len(state["audit"]) + 1, "op": request["op"],
                 "sub": claims["sub"] if claims else None, "tenant": claims["tenant"] if claims else None,
                 "path": path, "status": status,
                 "previous": state["audit"][-1]["hash"] if state["audit"] else "0" * 64}
        event["hash"] = hashlib.sha256(canonical(event)).hexdigest()
        state["audit"].append(event)
        self.persist(state)
        return response

    def archive_files(self, encoded, prefix):
        data = base64.b64decode(encoded, validate=True)
        if len(data) > 2 * 1024 * 1024:
            raise ValueError("archive too large")
        files = {}
        total = 0
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for member in archive:
                relative = path_name(member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name)
                destination = path_name(prefix + "/" + relative if prefix else relative)
                if member.isdir():
                    continue
                if not member.isreg() or member.sparse is not None or member.size < 0 or member.size > 65536:
                    raise ValueError("unsafe archive member")
                if destination in files or len(files) >= 128:
                    raise ValueError("duplicate or excessive members")
                raw = archive.extractfile(member).read()
                total += len(raw)
                if total > 1048576 or len(raw) != member.size:
                    raise ValueError("invalid archive size")
                files[destination] = raw.decode("utf-8", "strict")
        if not files:
            raise ValueError("empty archive")
        return files

    def execute(self, request):
        if not shape(request):
            return {"status": 400, "body": {"error": "invalid"}}
        op = request["op"]
        claims = self.authenticate(request["token"])
        if claims is None:
            return self.finish(request, None, None, 401)
        role = self.config["principals"][claims["sub"]]["role"]
        effective = ROLES[role]
        prefix = ""
        parent_depth = 3
        if claims["kind"] == "capability":
            effective = effective & set(claims["actions"])
            prefix, parent_depth = claims["prefix"], claims["depth"]
        if op == "audit":
            if role != "admin" or claims["kind"] != "session":
                return self.finish(request, claims, None, 403)
            return {"status": 200, "body": {"events": copy.deepcopy(self.state["audit"])}}
        path = None
        try:
            if "path" in request:
                path = path_name(request["path"])
            elif "prefix" in request:
                path = path_name(request["prefix"], True)
            operations = []
            if op == "batch":
                operations = [item | {"path": path_name(item["path"])} for item in request["operations"]]
        except (ValueError, UnicodeError):
            return self.finish(request, claims, None, 400)
        required = {op}
        if op == "import":
            required = {"import", "write"}
        if op == "batch":
            required = {item["op"] for item in operations}
        if (not required <= effective or (path is not None and not contained(prefix, path))
                or any(not contained(prefix, item["path"]) for item in operations)):
            return self.finish(request, claims, path, 403)
        replay_key = [claims["tenant"], claims["sub"], request.get("request_id")]
        if op in MUTATIONS and replay_key in self.state["used"]:
            return self.finish(request, claims, path, 409)
        state = copy.deepcopy(self.state)
        objects = state["objects"].setdefault(claims["tenant"], {})
        body = {"ok": True}
        if op == "read":
            if path not in objects:
                return self.finish(request, claims, path, 404)
            body = {"data": objects[path]}
        elif op == "list":
            body = {"paths": sorted(k for k in objects if contained(path, k))}
        elif op == "write":
            objects[path] = request["data"]
        elif op == "delete":
            if path not in objects:
                return self.finish(request, claims, path, 404)
            del objects[path]
        elif op == "delegate":
            if (not set(request["actions"]) <= effective or not self.config["now"] < request["exp"] <= claims["exp"]
                    or not 0 <= request["depth"] < parent_depth):
                return self.finish(request, claims, path, 403)
            child = {k: claims[k] for k in ("iss", "aud", "sub", "tenant")}
            child.update(iat=self.config["now"], exp=request["exp"], kind="capability", prefix=path,
                         actions=request["actions"], depth=request["depth"],
                         jti=hmac.digest(self.secret, (claims["jti"] + ":" + request["request_id"]).encode(), "sha256").hex()[:32])
            body = {"token": sign(self.secret, child)}
        elif op == "import":
            try:
                files = self.archive_files(request["archive"], path)
            except (ValueError, UnicodeError, binascii.Error, tarfile.TarError, EOFError, OSError):
                return self.finish(request, claims, path, 400)
            if any(not contained(prefix, name) for name in files):
                return self.finish(request, claims, path, 403)
            objects.update(files)
            body = {"count": len(files)}
        elif op == "batch":
            for item in operations:
                if item["op"] == "write":
                    objects[item["path"]] = item["data"]
                elif item["path"] not in objects:
                    return self.finish(request, claims, None, 404)
                else:
                    del objects[item["path"]]
            body = {"count": len(operations)}
        if op in MUTATIONS:
            state["used"].append(replay_key)
        return self.finish(request, claims, path, 200, body, state)


def main():
    broker = Broker(sys.argv[1], sys.argv[2])
    for line in sys.stdin:
        try:
            request = json.loads(line, object_pairs_hook=unique)
        except (ValueError, UnicodeError, RecursionError):
            response = {"status": 400, "body": {"error": "invalid"}}
        else:
            response = broker.execute(request)
        print(json.dumps(response, ensure_ascii=True, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
