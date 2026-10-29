"""Independent protocol, transaction, cryptographic and crash-consistency checks."""
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import struct
import zlib

import harness as h
from harness import Client, directory, equal, require, put


def basic():
    with Client(directory()) as c:
        equal(c.call("begin", tx="a"), {"ok": True, "snapshot": 0})
        equal(c.call("begin", tx="a"), {"error": "exists"})
        equal(c.call("get", tx="a", key="absent"), {"value": None})
        for key, value in [("a", ""), ("b", "line\nzero\x00"), ("é", "東京"), ("🦀", "value")]:
            equal(c.call("put", tx="a", key=key, value=value), {"ok": True})
            equal(c.call("get", tx="a", key=key), {"value": value})
        equal(c.call("scan", tx="a", start="a", end="🦁", limit=2), {"items": [["a", ""], ["b", "line\nzero\x00"]]})
        equal(c.call("commit", tx="a"), {"ok": True, "seq": 1})
        equal(c.call("commit", tx="a"), {"error": "missing"})
        equal(c.call("begin", tx="a"), {"ok": True, "snapshot": 1})
        equal(c.call("delete", tx="a", key="a"), {"ok": True})
        equal(c.call("get", tx="a", key="a"), {"value": None})
        equal(c.call("abort", tx="a"), {"ok": True})
        equal(c.call("begin", tx="a"), {"ok": True, "snapshot": 1})
        equal(c.call("get", tx="a", key="a"), {"value": ""})
        equal(c.call("commit", tx="a"), {"ok": True, "seq": 1})
        invalid = [None, [], 3, {}, {"op": []}, {"op": "unknown"}, {"op": "root", "extra": 1},
                   {"op": "begin", "tx": ""}, {"op": "begin", "tx": "é"},
                   {"op": "get", "tx": "none", "key": ""},
                   {"op": "get", "tx": "none", "key": "x" * 257},
                   {"op": "put", "tx": "none", "key": "x", "value": None},
                   {"op": "put", "tx": "none", "key": "x", "value": "\ud800"},
                   {"op": "scan", "tx": "none", "start": "a", "end": "z", "limit": True},
                   {"op": "scan", "tx": "none", "start": "z", "end": "a", "limit": 1}]
        for request in invalid:
            c.send(request)
            equal(c.read(), {"error": "invalid"})
        equal(c.call("get", tx="none", key="valid"), {"error": "missing"})
        equal(c.call("begin", tx="limits"), {"ok": True, "snapshot": 1})
        large = "🦀" * 262144
        equal(c.call("put", tx="limits", key="é" * 128, value=large), {"ok": True})
        equal(c.call("get", tx="limits", key="é" * 128), {"value": large})
        equal(c.call("put", tx="limits", key="é" * 129, value="x"), {"error": "invalid"})
        equal(c.call("put", tx="limits", key="x", value=large + "x"), {"error": "invalid"})
        equal(c.call("abort", tx="limits"), {"ok": True})


def snapshots():
    with Client(directory()) as c:
        equal(put(c, "s", "k", "v0"), {"ok": True, "seq": 1})
        equal(c.call("begin", tx="old"), {"ok": True, "snapshot": 1})
        for i in range(1, 9):
            equal(put(c, "s", "k", f"v{i}"), {"ok": True, "seq": i + 1})
            equal(c.call("get", tx="old", key="k"), {"value": "v0"})
        equal(c.call("put", tx="old", key="local", value="own"), {"ok": True})
        equal(c.call("scan", tx="old", start="a", end="z", limit=100),
              {"items": [["k", "v0"], ["local", "own"]]})
        equal(c.call("commit", tx="old"), {"error": "conflict"})
        equal(c.call("get", tx="old", key="k"), {"error": "missing"})
        equal(c.call("begin", tx="left"), {"ok": True, "snapshot": 9})
        equal(put(c, "right", "unrelated", "ok"), {"ok": True, "seq": 10})
        equal(c.call("get", tx="left", key="k"), {"value": "v8"})
        equal(c.call("commit", tx="left"), {"ok": True, "seq": 10})
        equal(c.call("begin", tx="del"), {"ok": True, "snapshot": 10})
        equal(c.call("delete", tx="del", key="never"), {"ok": True})
        equal(c.call("commit", tx="del"), {"ok": True, "seq": 11})
        equal(c.call("begin", tx="watch"), {"ok": True, "snapshot": 11})
        equal(c.call("get", tx="watch", key="never"), {"value": None})
        equal(put(c, "writer", "never", "appeared"), {"ok": True, "seq": 12})
        equal(c.call("commit", tx="watch"), {"error": "conflict"})
        equal(c.call("begin", tx="watch"), {"ok": True, "snapshot": 12})
        equal(c.call("get", tx="watch", key="k"), {"value": "v8"})
        equal(c.call("put", tx="watch", key="side", value="local"), {"ok": True})
        equal(put(c, "writer", "k", "changed"), {"ok": True, "seq": 13})
        equal(c.call("commit", tx="watch"), {"error": "conflict"})


class Model:
    def __init__(self):
        self.seq, self.state, self.stamps, self.tx = 0, {}, {}, {}

    def execute(self, op, **f):
        tx = f["tx"]
        if op == "begin":
            if tx in self.tx:
                return {"error": "exists"}
            self.tx[tx] = [self.seq, dict(self.state), {}, set(), []]
            return {"ok": True, "snapshot": self.seq}
        if tx not in self.tx:
            return {"error": "missing"}
        seq, snapshot, writes, reads, ranges = self.tx[tx]
        if op == "get":
            reads.add(f["key"])
            return {"value": writes.get(f["key"], snapshot.get(f["key"]))}
        if op in ("put", "delete"):
            writes[f["key"]] = f.get("value")
            return {"ok": True}
        if op == "scan":
            ranges.append((f["start"], f["end"]))
            view = snapshot | writes
            return {"items": [[k, view[k]] for k in sorted(view)
                              if view[k] is not None and f["start"] <= k < f["end"]][:f["limit"]]}
        del self.tx[tx]
        if op == "abort":
            return {"ok": True}
        changed = {k for k, stamp in self.stamps.items() if stamp > seq}
        if changed & (reads | set(writes)) or any(a <= k < b for a, b in ranges for k in changed):
            return {"error": "conflict"}
        if writes:
            self.seq += 1
            for k, v in writes.items():
                self.stamps[k] = self.seq
                if v is None:
                    self.state.pop(k, None)
                else:
                    self.state[k] = v
        return {"ok": True, "seq": self.seq}


def serializability():
    with Client(directory()) as c:
        m = Model()
        def call(op, **f):
            equal(c.call(op, **f), m.execute(op, **f))
        # A limited scan must still protect the unseen tail and transient inserts.
        call("begin", tx="seed")
        call("put", tx="seed", key="a", value="0")
        call("commit", tx="seed")
        call("begin", tx="reader")
        call("scan", tx="reader", start="a", end="z", limit=1)
        call("begin", tx="writer")
        call("put", tx="writer", key="y", value="x")
        call("commit", tx="writer")
        call("begin", tx="writer")
        call("delete", tx="writer", key="y")
        call("commit", tx="writer")
        call("commit", tx="reader")
        rng = random.Random(719333)
        for _ in range(1600):
            tx = "t" + str(rng.randrange(8))
            op = rng.choice(["begin", "get", "put", "delete", "scan", "commit", "abort"])
            fields = {"tx": tx}
            if op in ("get", "put", "delete"):
                fields["key"] = chr(97 + rng.randrange(12))
            if op == "put":
                fields["value"] = str(rng.randrange(1000))
            if op == "scan":
                a, b = sorted(rng.sample(range(14), 2))
                fields.update(start=chr(97 + a), end=chr(97 + b), limit=rng.randrange(1, 4))
            call(op, **fields)


def digest(data):
    return hashlib.sha256(data).digest()


def independent_root(state):
    leaves = [(int.from_bytes(digest(k.encode()), "big"),
               digest(b"\0" + digest(k.encode()) + len(v.encode()).to_bytes(4, "big") + v.encode()))
              for k, v in state.items()]
    empties = [digest(b"\2")]
    for _ in range(256):
        empties.append(digest(b"\1" + empties[-1] * 2))
    def tree(items, depth):
        if not items:
            return empties[256 - depth]
        if depth == 256:
            return items[0][1]
        bit = 1 << (255 - depth)
        return digest(b"\1" + tree([p for p in items if not p[0] & bit], depth + 1)
                      + tree([p for p in items if p[0] & bit], depth + 1))
    return tree(leaves, 0).hex()


def proofs():
    with Client(directory()) as c:
        state = {}
        equal(c.call("root"), {"seq": 0, "root": independent_root(state)})
        for seq, (key, value) in enumerate([("a", ""), ("東京", "🦀"), ("a", "changed"),
                                          ("prefix/a", "A"), ("prefix/b", "B")], 1):
            equal(put(c, "w", key, value), {"ok": True, "seq": seq})
            state[key] = value
            root = independent_root(state)
            equal(c.call("root"), {"seq": seq, "root": root})
            for target in [key, "missing", "東京", "prefix/a"]:
                proof = c.call("proof", key=target)
                equal(set(proof), {"seq", "root", "key", "value", "siblings"})
                equal((proof["seq"], proof["root"], proof["key"], proof["value"]),
                      (seq, root, target, state.get(target)))
                equal(len(proof["siblings"]), 256)
                path = digest(target.encode())
                value = state.get(target)
                node = (digest(b"\2") if value is None else
                        digest(b"\0" + path + len(value.encode()).to_bytes(4, "big") + value.encode()))
                bits = int.from_bytes(path, "big")
                for sibling in proof["siblings"]:
                    require(isinstance(sibling, str) and len(sibling) == 64 and sibling == sibling.lower(), "invalid sibling")
                    other = bytes.fromhex(sibling)
                    node = digest(b"\1" + (other + node if bits & 1 else node + other))
                    bits >>= 1
                equal(node.hex(), root)
        equal(c.call("begin", tx="w"), {"ok": True, "snapshot": 5})
        equal(c.call("delete", tx="w", key="東京"), {"ok": True})
        equal(c.call("root"), {"seq": 5, "root": independent_root(state)})
        equal(c.call("commit", tx="w"), {"ok": True, "seq": 6})
        del state["東京"]
        equal(c.call("root"), {"seq": 6, "root": independent_root(state)})


def encode(magic, obj):
    data = json.dumps(obj, ensure_ascii=False).encode()
    return magic + len(data).to_bytes(4, "big") + data + zlib.crc32(data).to_bytes(4, "big")


def write(path, data):
    path.write_bytes(data)
    os.chown(path, 1000, 1000)


def read_state(c, expected, seq):
    equal(c.call("begin", tx="verify"), {"ok": True, "snapshot": seq})
    equal(c.call("scan", tx="verify", start="a", end="zzzz", limit=10000),
          {"items": sorted([k, v] for k, v in expected.items())})
    equal(c.call("commit", tx="verify"), {"ok": True, "seq": seq})


def recovery():
    path = directory()
    c = Client(path)
    equal(put(c, "w", "a", "acknowledged"), {"ok": True, "seq": 1})
    equal(c.call("begin", tx="dirty"), {"ok": True, "snapshot": 1})
    equal(c.call("put", tx="dirty", key="dirty", value="uncommitted"), {"ok": True})
    c.kill()
    moved = directory()
    shutil.copytree(path, moved, dirs_exist_ok=True)
    for file in moved.iterdir():
        os.chown(file, 1000, 1000)
    with Client(moved) as c:
        read_state(c, {"a": "acknowledged"}, 1)
    first = encode(b"KVL1", {"seq": 1, "writes": [["a", "one"]]})
    second = encode(b"KVL1", {"seq": 2, "writes": [["b", "two"]]})
    third = encode(b"KVL1", {"seq": 3, "writes": [["c", "three"]]})
    tails = [second[:cut] for cut in [1, 3, 4, 7, 8, 12, len(second) - 1]]
    tails += [second[:-1] + bytes([second[-1] ^ 1]), b"junk" + second,
              b"KVL1\xff\xff\xff\xff", third,
              encode(b"KVL1", {"seq": 2, "writes": [["b", "x"], ["b", "y"]]}),
              encode(b"KVL1", {"seq": True, "writes": [["b", "x"]]}),
              encode(b"KVL1", {"seq": 2, "writes": [["c", "x"], ["b", "y"]]}),
              encode(b"KVL1", {"seq": 2, "writes": [["", "x"]]}),
              encode(b"KVL1", {"seq": 2, "writes": []})]
    for tail in tails:
        path = directory()
        write(path / "wal.bin", first + tail + third)
        with Client(path) as c:
            read_state(c, {"a": "one"}, 1)
            equal((path / "wal.bin").stat().st_size, len(first))
            equal(put(c, "w", "b", "new"), {"ok": True, "seq": 2})
        with Client(path) as c:
            read_state(c, {"a": "one", "b": "new"}, 2)
    path = directory()
    with Client(path, "wal_synced") as c:
        equal(c.call("begin", tx="w"), {"ok": True, "snapshot": 0})
        equal(c.call("put", tx="w", key="a", value="durable"), {"ok": True})
        c.send({"op": "commit", "tx": "w"})
        equal(c.process.wait(timeout=5), 86)
    with Client(path) as c:
        read_state(c, {"a": "durable"}, 1)


def checkpoints():
    path = directory()
    with Client(path) as c:
        equal(put(c, "w", "a", "old"), {"ok": True, "seq": 1})
        equal(c.call("begin", tx="reader"), {"ok": True, "snapshot": 1})
        equal(put(c, "w", "a", "new"), {"ok": True, "seq": 2})
        equal(c.call("checkpoint"), {"ok": True, "seq": 2})
        equal((path / "wal.bin").stat().st_size, 0)
        equal(c.call("get", tx="reader", key="a"), {"value": "old"})
        equal(c.call("commit", tx="reader"), {"error": "conflict"})
    with Client(path) as c:
        read_state(c, {"a": "new"}, 2)
    for boundary in ["checkpoint_synced", "checkpoint_replaced", "wal_reset"]:
        path = directory()
        with Client(path) as c:
            equal(put(c, "w", "a", "kept"), {"ok": True, "seq": 1})
        with Client(path, boundary) as c:
            equal(c.call("root")["seq"], 1)
            c.send({"op": "checkpoint"})
            equal(c.process.wait(timeout=5), 86)
        with Client(path) as c:
            read_state(c, {"a": "kept"}, 1)
            equal(put(c, "w", "b", "after"), {"ok": True, "seq": 2})
            equal(c.call("checkpoint"), {"ok": True, "seq": 2})
            equal((path / "wal.bin").stat().st_size, 0)
        with Client(path) as c:
            read_state(c, {"a": "kept", "b": "after"}, 2)
    path = directory()
    write(path / "checkpoint.bin", encode(b"KVC1", {"seq": 5, "items": [["a", "latest"]]}))
    write(path / "wal.bin", encode(b"KVL1", {"seq": 4, "writes": [["a", "stale"]]})
          + encode(b"KVL1", {"seq": 5, "writes": [["a", "latest"]]})
          + encode(b"KVL1", {"seq": 6, "writes": [["b", "fresh"]]}))
    write(path / "checkpoint.tmp", b"abandoned temporary bytes")
    with Client(path) as c:
        read_state(c, {"a": "latest", "b": "fresh"}, 6)
    valid = encode(b"KVC1", {"seq": 1, "items": [["a", "x"]]})
    for bad in [b"", valid[:-1], valid + b"extra", valid[:-1] + bytes([valid[-1] ^ 1]),
                encode(b"KVC1", {"seq": 1, "items": [["a", None]]})]:
        path = directory()
        write(path / "checkpoint.bin", bad)
        write(path / "wal.bin", b"preserve evidence")
        with Client(path) as c:
            c.process.stdin.close()
            require(c.process.wait(timeout=5) != 0, "corrupt checkpoint accepted")
        equal((path / "checkpoint.bin").read_bytes(), bad)
        equal((path / "wal.bin").read_bytes(), b"preserve evidence")
    require(set(p.name for p in path.iterdir()) <= {"wal.bin", "checkpoint.bin", "checkpoint.tmp"}, "unexpected durable files")


def main():
    outcomes = []
    for function in [basic, snapshots, serializability, proofs, recovery, checkpoints]:
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
