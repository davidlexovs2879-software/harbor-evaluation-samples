"""Adversarial protocol replays with independent token construction and audit hashing."""
import base64
import copy
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import random
import tarfile

import harness as h
from harness import Client, equal, require

NOW = 1800000000
CONFIG = {"secret": "lab-only-" + hashlib.sha256(b"independent-broker-fixture-v1").hexdigest(),
          "issuer": "isolated-build-issuer", "audience": "artifact-broker", "now": NOW,
          "principals": {"alice": {"tenant": "red", "role": "admin", "disabled": False},
                         "bob": {"tenant": "blue", "role": "writer", "disabled": False},
                         "carol": {"tenant": "red", "role": "reader", "disabled": False},
                         "dana": {"tenant": "red", "role": "writer", "disabled": False},
                         "disabled": {"tenant": "red", "role": "admin", "disabled": True}}}


def compact(obj):
    return json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def claims(subject="alice", **updates):
    value = {"iss": CONFIG["issuer"], "aud": CONFIG["audience"], "sub": subject,
             "tenant": CONFIG["principals"].get(subject, {"tenant": "red"})["tenant"],
             "iat": NOW - 60, "exp": NOW + 3600, "jti": "session_" + subject, "kind": "session"}
    value.update(updates)
    return value


def token(payload=None, header=None, payload_bytes=None, secret=None):
    header = {"alg": "HS256", "typ": "JWT", "kid": "primary"} if header is None else header
    message = b64(compact(header)) + "." + b64(payload_bytes if payload_bytes is not None else compact(payload or claims()))
    signature = hmac.new((secret or CONFIG["secret"]).encode(), message.encode(), hashlib.sha256).digest()
    return message + "." + b64(signature)


ALICE, BOB, CAROL, DANA = (token(claims(name)) for name in ("alice", "bob", "carol", "dana"))


def ok(body=None):
    return {"status": 200, "body": {"ok": True} if body is None else body}


def error(status):
    return {"status": status, "body": {"error": {400: "invalid", 401: "unauthorized", 403: "forbidden",
                                                404: "not_found", 409: "conflict"}[status]}}


def seed(c):
    equal(c.call("write", ALICE, path="releases/r1/output", data="red-data", request_id="seed_red"), ok())
    equal(c.call("write", BOB, path="releases/r1/output", data="blue-data", request_id="seed_blue"), ok())


def authentication():
    with Client(CONFIG) as c:
        seed(c)
        equal(c.call("read", ALICE, path="releases/r1/output"), ok({"data": "red-data"}))
        cases = ["", "unsigned", "a.b.c", ALICE + "=", ALICE.rsplit(".", 1)[0] + ".AA",
                 token(secret="wrong-disposable-secret"), token(claims("disabled")), token(claims("unknown")),
                 token(claims(exp=NOW)), token(claims(iat=NOW + 1)), token(claims(iat=-1)),
                 token(claims(exp=NOW + 86401)), token(claims(iat=True)), token(claims(exp=True)),
                 token(claims(aud=[CONFIG["audience"]])), token(claims(iss="different")),
                 token(claims(tenant="blue")), token(claims(jti="../../id")), token(claims(extra="claim")),
                 token(header={"alg": "none", "typ": "JWT", "kid": "primary"}),
                 token(header={"alg": "HS256", "typ": "JWT", "kid": "other"}),
                 token(header={"alg": "HS256", "typ": "JWT", "kid": "primary", "jku": "https://invalid.example/key"}),
                 token(payload_bytes=b'[]'), token(payload_bytes=b'null'), token(payload_bytes=b'\xff'),
                 token(payload_bytes=compact(claims())[:-1] + b',"sub":"alice"}'),
                 token(claims(kind="capability", prefix="releases/../private", actions=["read"], depth=0)),
                 token(claims(kind="capability", prefix="", actions=["audit"], depth=0)),
                 token(claims(kind="capability", prefix="", actions=["read", "read"], depth=0)),
                 token(claims(kind="capability", prefix="", actions=["read"], depth=True))]
        padded_header = ALICE.split(".")
        padded_header[0] += "="
        cases.append(".".join(padded_header))
        for bad in cases:
            equal(c.call("read", bad, path="releases/r1/output"), error(401))
        malformed = ["{", "[]", "null", '{"op":"list","op":"read","token":"x","prefix":""}',
                     json.dumps({"op": "read", "token": ALICE, "path": "releases/r1/output", "tenant": "blue"}),
                     json.dumps({"op": "write", "token": ALICE, "path": "x", "data": 2, "request_id": "a"}),
                     json.dumps({"op": "delegate", "token": ALICE, "prefix": "", "actions": ["read"],
                                 "exp": True, "depth": 0, "request_id": "a"})]
        for raw in malformed:
            equal(c.raw(raw), error(400))
        equal(c.call("list", CAROL, prefix="releases"), ok({"paths": ["releases/r1/output"]}))


def isolation():
    with Client(CONFIG) as c:
        seed(c)
        equal(c.call("read", BOB, path="releases/r1/output"), ok({"data": "blue-data"}))
        equal(c.call("read", CAROL, path="releases/r1/output"), ok({"data": "red-data"}))
        for op, fields in [("write", {"path": "x", "data": "bad", "request_id": "rw"}),
                           ("delete", {"path": "releases/r1/output", "request_id": "rd"}),
                           ("audit", {})]:
            equal(c.call(op, CAROL, **fields), error(403))
        for path in ["../private", "releases/../private", "/absolute", "a//b", "a/./b", "a/", "",
                     "a\\b", "%2e%2e/private", "%252e%252e/private", "%2fabsolute", "a/%00b",
                     "a/%ff", "a/%GG", "a/%", "a/\u202eb", "a/\ud800", "a" * 513]:
            equal(c.call("read", ALICE, path=path), error(400))
        equal(c.call("read", "forged", path="../private"), error(401))
        equal(c.call("write", ALICE, path="releases/cafe\u0301/file", data="unicode", request_id="nfc"), ok())
        equal(c.call("read", ALICE, path="releases/caf%C3%A9/file"), ok({"data": "unicode"}))
        equal(c.call("write", ALICE, path="space/a%20b", data="space", request_id="space"), ok())
        equal(c.call("read", ALICE, path="space/a b"), ok({"data": "space"}))
        equal(c.call("read", BOB, path="space/a b"), error(404))
        equal(c.call("list", BOB, prefix=""), ok({"paths": ["releases/r1/output"]}))
        equal(c.call("write", ALICE, path="releases/r10/secret", data="sibling", request_id="sibling"), ok())
        cap = token(claims(kind="capability", prefix="releases/r1", actions=["read", "list"], depth=0))
        equal(c.call("read", cap, path="releases/r1/output"), ok({"data": "red-data"}))
        for path in ["releases/r10/secret", "releases/r1evil", "private/missing"]:
            equal(c.call("read", cap, path=path), error(403))
        equal(c.call("list", cap, prefix="releases"), error(403))
        equal(c.call("list", cap, prefix="releases/r1"), ok({"paths": ["releases/r1/output"]}))
    rng = random.Random(3817207)
    for index in range(8):
        config = copy.deepcopy(CONFIG)
        config["secret"] = rng.randbytes(32).hex()
        config["now"] += rng.randrange(100, 10000)
        config["issuer"] = f"issuer-{rng.randrange(1000000)}"
        config["audience"] = f"audience-{rng.randrange(1000000)}"
        red, blue = f"tenant-{rng.randrange(1000000)}", f"other-{rng.randrange(1000000)}"
        config["principals"]["alice"]["tenant"] = red
        config["principals"]["bob"]["tenant"] = blue
        now = config["now"]
        a = claims(iss=config["issuer"], aud=config["audience"], tenant=red, iat=now - 1, exp=now + 100)
        b = claims("bob", iss=config["issuer"], aud=config["audience"], tenant=blue, iat=now - 1, exp=now + 100)
        ta, tb = token(a, secret=config["secret"]), token(b, secret=config["secret"])
        resource = f"runs/{rng.randrange(1, 10)}/result"
        value = rng.randbytes(24).hex()
        with Client(config) as c:
            equal(c.call("write", ta, path=resource, data=value, request_id="same"), ok())
            equal(c.call("write", tb, path=resource, data="other", request_id="same"), ok())
            equal(c.call("read", ta, path=resource), ok({"data": value}))
            equal(c.call("read", tb, path=resource), ok({"data": "other"}))
            forged = token(a | {"tenant": blue}, secret=config["secret"])
            equal(c.call("read", forged, path=resource), error(401))
            equal(c.call("write", ta, path=resource, data="replay", request_id="same"), error(409))
            equal(c.call("read", ta, path=resource), ok({"data": value}))


def child_claims(parent, request_id, prefix, actions, exp, depth):
    child = {k: parent[k] for k in ("iss", "aud", "sub", "tenant")}
    child.update(iat=NOW, exp=exp, kind="capability", prefix=prefix, actions=actions, depth=depth,
                 jti=hmac.new(CONFIG["secret"].encode(), (parent["jti"] + ":" + request_id).encode(), hashlib.sha256).hexdigest()[:32])
    return child


def delegation():
    with Client(CONFIG) as c:
        seed(c)
        request = {"prefix": "releases/r1", "actions": ["read", "list", "delegate"],
                   "exp": NOW + 1800, "depth": 2, "request_id": "child"}
        child = child_claims(claims(), "child", "releases/r1", request["actions"], NOW + 1800, 2)
        child_token = token(child)
        equal(c.call("delegate", ALICE, **request), ok({"token": child_token}))
        equal(c.call("read", child_token, path="releases/r1/output"), ok({"data": "red-data"}))
        equal(c.call("write", child_token, path="releases/r1/output", data="bad", request_id="no_write"), error(403))
        grand = child_claims(child, "grand", "releases/r1/output", ["read"], NOW + 900, 0)
        equal(c.call("delegate", child_token, prefix="releases/r1/output", actions=["read"], exp=NOW + 900,
                     depth=0, request_id="grand"), ok({"token": token(grand)}))
        equal(c.call("read", token(grand), path="releases/r1/output"), ok({"data": "red-data"}))
        invalid = [dict(prefix="releases/r10", actions=["read"], exp=NOW + 900, depth=0),
                   dict(prefix="releases/r1", actions=["write"], exp=NOW + 900, depth=0),
                   dict(prefix="releases/r1", actions=["read"], exp=NOW + 1801, depth=0),
                   dict(prefix="releases/r1", actions=["read"], exp=NOW, depth=0),
                   dict(prefix="releases/r1", actions=["read"], exp=NOW + 900, depth=2),
                   dict(prefix="releases/r1", actions=["read"], exp=NOW + 900, depth=-1)]
        for index, fields in enumerate(invalid):
            equal(c.call("delegate", child_token, request_id=f"bad{index}", **fields), error(403))
        equal(c.call("delegate", CAROL, prefix="", actions=["read"], exp=NOW + 1, depth=0, request_id="reader"), error(403))
        equal(c.call("audit", child_token), error(403))
        equal(c.call("delegate", ALICE, **request), error(409))
        no_depth = token(claims(kind="capability", prefix="", actions=["read", "delegate"], depth=0))
        equal(c.call("delegate", no_depth, prefix="", actions=["read"], exp=NOW + 1, depth=0, request_id="no_depth"), error(403))
        path = c.path
    with Client(CONFIG, path) as c:
        equal(c.call("read", child_token, path="releases/r1/output"), ok({"data": "red-data"}))
    downgraded = copy.deepcopy(CONFIG)
    downgraded["principals"]["alice"]["role"] = "reader"
    writecap = token(claims(kind="capability", prefix="releases/r1", actions=["write", "read"], depth=0))
    with Client(downgraded, path) as c:
        equal(c.call("write", writecap, path="releases/r1/output", data="bad", request_id="downgrade"), error(403))
        equal(c.call("read", writecap, path="releases/r1/output"), ok({"data": "red-data"}))


def archive(members, mode="w"):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode=mode, format=tarfile.PAX_FORMAT) as tar:
        for name, data, kind in members:
            entry = tarfile.TarInfo(name)
            entry.mtime = 0
            entry.type = kind
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                entry.linkname = "../../outside"
            entry.size = len(data) if kind == tarfile.REGTYPE else 0
            tar.addfile(entry, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return base64.b64encode(stream.getvalue()).decode()


def archives():
    with Client(CONFIG) as c:
        cap = token(claims(kind="capability", prefix="build", actions=["import", "write", "read", "list"], depth=0))
        good = archive([("dir/", b"", tarfile.DIRTYPE), ("dir/one", b"first", tarfile.REGTYPE),
                        ("two", "東京".encode(), tarfile.REGTYPE)])
        equal(c.call("import", cap, prefix="build", archive=good, request_id="good"), ok({"count": 2}))
        equal(c.call("read", cap, path="build/dir/one"), ok({"data": "first"}))
        equal(c.call("read", cap, path="build/two"), ok({"data": "東京"}))
        bad_archives = ["not base64", base64.b64encode(b"not tar").decode(),
                        archive([("safe", b"ok", tarfile.REGTYPE)], mode="w:gz"), archive([])]
        for name in ["../outside", "/absolute", "nested/../../outside", "%2e%2e/outside", "a\\b", "a//b", "a/%ff"]:
            bad_archives.append(archive([("atomic", b"must-not-write", tarfile.REGTYPE), (name, b"bad", tarfile.REGTYPE)]))
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE]:
            bad_archives.append(archive([("atomic", b"must-not-write", tarfile.REGTYPE), ("unsafe", b"", kind)]))
        bad_archives += [archive([("same", b"a", tarfile.REGTYPE), ("same", b"b", tarfile.REGTYPE)]),
                         archive([("caf\u00e9", b"a", tarfile.REGTYPE), ("cafe\u0301", b"b", tarfile.REGTYPE)]),
                         archive([("a%20b", b"a", tarfile.REGTYPE), ("a b", b"b", tarfile.REGTYPE)]),
                         archive([("huge", b"x" * 65537, tarfile.REGTYPE)]),
                         archive([("binary", b"\xff", tarfile.REGTYPE)]),
                         archive([(f"f{i}", b"x", tarfile.REGTYPE) for i in range(129)]),
                         archive([(f"f{i}", b"x" * 65536, tarfile.REGTYPE) for i in range(17)])]
        for i, bad in enumerate(bad_archives):
            equal(c.call("import", cap, prefix="build", archive=bad, request_id=f"bad{i}"), error(400))
            equal(c.call("list", cap, prefix="build"), ok({"paths": ["build/dir/one", "build/two"]}))
        equal(c.call("import", cap, prefix="build-sibling", archive=good, request_id="escape"), error(403))
        import_only = token(claims(kind="capability", prefix="build", actions=["import"], depth=0))
        equal(c.call("import", import_only, prefix="build", archive=good, request_id="missing_write"), error(403))
        equal(c.call("import", cap, prefix="build", archive=good, request_id="bad0"), ok({"count": 2}))


def atomic_replay():
    with Client(CONFIG) as c:
        seed(c)
        operations = [{"op": "write", "path": "build/a", "data": "one"},
                      {"op": "write", "path": "build/b", "data": "two"},
                      {"op": "delete", "path": "build/a"}]
        equal(c.call("batch", ALICE, operations=operations, request_id="batch"), ok({"count": 3}))
        equal(c.call("list", ALICE, prefix="build"), ok({"paths": ["build/b"]}))
        equal(c.call("batch", ALICE, operations=operations, request_id="batch"), error(409))
        bad = [{"op": "write", "path": "build/b", "data": "corrupt"}, {"op": "delete", "path": "missing"}]
        equal(c.call("batch", ALICE, operations=bad, request_id="retry"), error(404))
        equal(c.call("read", ALICE, path="build/b"), ok({"data": "two"}))
        equal(c.call("write", ALICE, path="build/b", data="after-retry", request_id="retry"), ok())
        equal(c.call("delete", ALICE, path="build/b", request_id="retry"), error(409))
        rotated = token(claims(jti="rotated"))
        equal(c.call("write", rotated, path="build/b", data="bad", request_id="retry"), error(409))
        equal(c.call("write", DANA, path="build/dana", data="other-user", request_id="retry"), ok())
        equal(c.call("write", BOB, path="build/b", data="other-tenant", request_id="retry"), ok())
        cap = token(claims(kind="capability", prefix="build", actions=["write", "delete"], depth=0))
        mixed = [{"op": "write", "path": "build/b", "data": "bad"},
                 {"op": "write", "path": "build-sibling/x", "data": "outside"}]
        equal(c.call("batch", cap, operations=mixed, request_id="mixed"), error(403))
        equal(c.call("read", ALICE, path="build/b"), ok({"data": "after-retry"}))
        equal(c.call("list", ALICE, prefix="build-sibling"), ok({"paths": []}))
        equal(c.call("write", ALICE, path="empty", data="", request_id="empty"), ok())
        equal(c.call("read", ALICE, path="empty"), ok({"data": ""}))
        equal(c.call("delete", ALICE, path="absent", request_id="failed_delete"), error(404))
        equal(c.call("write", ALICE, path="absent", data="new", request_id="failed_delete"), ok())
        for malformed in [[], [{"op": "read", "path": "build/b"}],
                          [{"op": "write", "path": "x", "data": "v", "tenant": "blue"}],
                          [{"op": "delete", "path": "x"}] * 65]:
            equal(c.call("batch", ALICE, operations=malformed, request_id="invalid"), error(400))


def audit_durability():
    expected = []
    def event(op, sub, tenant, path, status):
        item = {"seq": len(expected) + 1, "op": op, "sub": sub, "tenant": tenant, "path": path,
                "status": status, "previous": expected[-1]["hash"] if expected else "0" * 64}
        item["hash"] = hashlib.sha256(compact(item)).hexdigest()
        expected.append(item)
    c = Client(CONFIG)
    path = c.path
    try:
        equal(c.call("write", ALICE, path="secret/%61rtifact", data="sensitive-payload", request_id="durable"), ok())
        event("write", "alice", "red", "secret/artifact", 200)
        equal(c.call("read", "unsigned", path="secret/artifact"), error(401))
        event("read", None, None, None, 401)
        equal(c.call("write", CAROL, path="secret/artifact", data="bad", request_id="reader"), error(403))
        event("write", "carol", "red", "secret/artifact", 403)
        equal(c.call("read", ALICE, path="../bad"), error(400))
        event("read", "alice", "red", None, 400)
        equal(c.call("read", ALICE, path="not-found"), error(404))
        event("read", "alice", "red", "not-found", 404)
        equal(c.call("write", ALICE, path="secret/artifact", data="replay", request_id="durable"), error(409))
        event("write", "alice", "red", "secret/artifact", 409)
        equal(c.raw('{"op":"read","token":false,"path":"x"}'), error(400))
        equal(c.call("audit", CAROL), error(403))
        equal(c.call("audit", ALICE), ok({"events": expected}))
        c.kill()
    finally:
        c.close()
    with Client(CONFIG, path) as c:
        equal(c.call("audit", ALICE), ok({"events": expected}))
        equal(c.call("read", ALICE, path="secret/artifact"), ok({"data": "sensitive-payload"}))
        event("read", "alice", "red", "secret/artifact", 200)
        equal(c.call("write", ALICE, path="secret/artifact", data="bad", request_id="durable"), error(409))
        event("write", "alice", "red", "secret/artifact", 409)
        equal(c.call("audit", ALICE), ok({"events": expected}))
        serialized = json.dumps(expected)
        for sensitive in [ALICE, "sensitive-payload", CONFIG["secret"], "unsigned"]:
            require(sensitive not in serialized, "sensitive content leaked into audit")
    # Portable persisted state, independent of the original directory/config path.
    import shutil
    moved = h.directory()
    shutil.copytree(path / "state", moved / "state")
    for item in (moved / "state").rglob("*"):
        os.chown(item, 1000, 1000)
    os.chown(moved / "state", 1000, 1000)
    with Client(CONFIG, moved) as c:
        equal(c.call("audit", ALICE), ok({"events": expected}))
    files = [p for p in (moved / "state").iterdir() if p.is_file() and p.suffix == ".json"]
    require(bool(files), "durable JSON state missing")
    evidence = {}
    for file in files:
        file.write_bytes(file.read_bytes() + b"\nCORRUPT")
        evidence[file] = file.read_bytes()
    with Client(CONFIG, moved) as c:
        c.process.stdin.close()
        require(c.process.wait(timeout=5) != 0, "corrupt state accepted")
    for file, original in evidence.items():
        equal(file.read_bytes(), original)


def main():
    outcomes = []
    for function in [authentication, isolation, delegation, archives, atomic_replay, audit_durability]:
        before = h.CHECKS
        try:
            function()
            outcomes.append({"group": function.__name__, "passed": True, "checks": h.CHECKS - before})
        except Exception as exc:
            outcomes.append({"group": function.__name__, "passed": False,
                             "checks": h.CHECKS - before, "error": str(exc)[:2000]})
        print(json.dumps(outcomes[-1]), flush=True)
    score = sum(item["passed"] for item in outcomes) / len(outcomes)
    output = Path("/logs/verifier")
    output.mkdir(parents=True, exist_ok=True)
    (output / "details.json").write_text(json.dumps({"groups": outcomes, "score": score}, indent=2))
    (output / "reward.txt").write_text(f"{score:.12f}\n")


if __name__ == "__main__":
    main()
