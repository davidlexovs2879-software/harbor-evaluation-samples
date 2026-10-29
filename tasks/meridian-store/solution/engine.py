#!/usr/bin/env python3
"""Serializable snapshot store with a framed redo log and sparse Merkle proofs."""
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
import zlib

MAX_FRAME = 16 * 1024 * 1024


def utf8(value, maximum, empty=True):
    if not isinstance(value, str) or (not empty and not value):
        return False
    try:
        return len(value.encode("utf-8")) <= maximum
    except UnicodeError:
        return False


def key_ok(key):
    return utf8(key, 256, False)


def pairs_ok(pairs, nullable):
    if not isinstance(pairs, list):
        return False
    previous = None
    for pair in pairs:
        if not isinstance(pair, list) or len(pair) != 2:
            return False
        key, value = pair
        if not key_ok(key) or (previous is not None and key <= previous):
            return False
        if not (nullable and value is None) and not utf8(value, 1048576):
            return False
        previous = key
    return True


def canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def frame(magic, value):
    payload = canonical(value)
    if len(payload) > MAX_FRAME:
        raise ValueError("frame exceeds maximum")
    return magic + struct.pack(">I", len(payload)) + payload + struct.pack(">I", zlib.crc32(payload))


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate field")
        obj[key] = value
    return obj


def read_frame(data, offset, magic, field, nullable):
    if len(data) - offset < 12 or data[offset:offset + 4] != magic:
        raise ValueError("bad frame header")
    size = struct.unpack_from(">I", data, offset + 4)[0]
    end = offset + 8 + size
    if size > MAX_FRAME or end + 4 > len(data):
        raise ValueError("bad frame length")
    payload = data[offset + 8:end]
    if zlib.crc32(payload) != struct.unpack_from(">I", data, end)[0]:
        raise ValueError("bad checksum")
    obj = json.loads(payload.decode("utf-8"), object_pairs_hook=unique_object)
    if (not isinstance(obj, dict) or set(obj) != {"seq", field}
            or type(obj["seq"]) is not int or obj["seq"] < 0
            or not pairs_ok(obj[field], nullable)):
        raise ValueError("bad frame payload")
    if field == "writes" and (not obj[field] or obj["seq"] == 0):
        raise ValueError("empty commit")
    return obj, end + 4


def hash_bytes(data):
    return hashlib.sha256(data).digest()


EMPTY = [hash_bytes(b"\x02")]
for _ in range(256):
    EMPTY.append(hash_bytes(b"\x01" + EMPTY[-1] + EMPTY[-1]))


def merkle(state, proof_key=None):
    level = {}
    for key, value in state.items():
        path = hash_bytes(key.encode())
        encoded = value.encode()
        level[int.from_bytes(path, "big")] = hash_bytes(b"\x00" + path + struct.pack(">I", len(encoded)) + encoded)
    position = int.from_bytes(hash_bytes(proof_key.encode()), "big") if proof_key is not None else 0
    siblings = []
    for height in range(256):
        if proof_key is not None:
            siblings.append(level.get(position ^ 1, EMPTY[height]).hex())
        parents = {}
        for parent in {index >> 1 for index in level}:
            parents[parent] = hash_bytes(b"\x01" + level.get(parent * 2, EMPTY[height])
                                         + level.get(parent * 2 + 1, EMPTY[height]))
        level = parents
        position >>= 1
    return level.get(0, EMPTY[256]).hex(), siblings


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.seq = 0
        self.current = {}
        self.versions = {}
        self.stamps = {}
        self.transactions = {}
        checkpoint = self.directory / "checkpoint.bin"
        if checkpoint.exists():
            data = checkpoint.read_bytes()
            obj, end = read_frame(data, 0, b"KVC1", "items", False)
            if end != len(data):
                raise ValueError("trailing checkpoint bytes")
            self.seq = obj["seq"]
            for key, value in obj["items"]:
                self.current[key] = value
                self.versions[key] = [(self.seq, value)]
                self.stamps[key] = self.seq
        checkpoint_seq = self.seq
        path = self.directory / "wal.bin"
        data = path.read_bytes() if path.exists() else b""
        offset = 0
        while offset < len(data):
            try:
                obj, end = read_frame(data, offset, b"KVL1", "writes", True)
                if obj["seq"] > checkpoint_seq:
                    if obj["seq"] != self.seq + 1:
                        break
                    self.publish(obj["seq"], dict(obj["writes"]))
                offset = end
            except (ValueError, UnicodeError, TypeError, RecursionError):
                break
        self.wal = open(path, "a+b", buffering=0)
        self.wal.truncate(offset)
        os.fsync(self.wal.fileno())
        self.sync_directory()

    def sync_directory(self):
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def crash(self, boundary):
        if os.environ.get("MERIDIAN_CRASH_AT") == boundary:
            os._exit(86)

    def publish(self, seq, writes):
        self.seq = seq
        for key, value in writes.items():
            if value is None:
                self.current.pop(key, None)
            else:
                self.current[key] = value
            self.versions.setdefault(key, []).append((seq, value))
            self.stamps[key] = seq

    def visible(self, transaction, key):
        if key in transaction["writes"]:
            return transaction["writes"][key]
        for seq, value in reversed(self.versions.get(key, [])):
            if seq <= transaction["snapshot"]:
                return value
        return None

    def checkpoint(self):
        data = frame(b"KVC1", {"seq": self.seq, "items": sorted(self.current.items())})
        temporary = self.directory / "checkpoint.tmp"
        with open(temporary, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        self.crash("checkpoint_synced")
        os.replace(temporary, self.directory / "checkpoint.bin")
        self.sync_directory()
        self.crash("checkpoint_replaced")
        self.wal.truncate(0)
        os.fsync(self.wal.fileno())
        self.crash("wal_reset")
        return {"ok": True, "seq": self.seq}

    def execute(self, request):
        if not isinstance(request, dict):
            return {"error": "invalid"}
        op = request.get("op")
        fields = {"begin": {"tx"}, "get": {"tx", "key"}, "put": {"tx", "key", "value"},
                  "delete": {"tx", "key"}, "scan": {"tx", "start", "end", "limit"},
                  "commit": {"tx"}, "abort": {"tx"}, "root": set(), "proof": {"key"}, "checkpoint": set()}
        if not isinstance(op, str) or op not in fields or set(request) != fields[op] | {"op"}:
            return {"error": "invalid"}
        if "tx" in request and (not isinstance(request["tx"], str)
                                or re.fullmatch(r"[A-Za-z0-9]{1,32}", request["tx"]) is None):
            return {"error": "invalid"}
        if "key" in request and not key_ok(request["key"]):
            return {"error": "invalid"}
        if op == "put" and not utf8(request["value"], 1048576):
            return {"error": "invalid"}
        if op == "scan" and (not key_ok(request["start"]) or not key_ok(request["end"])
                             or request["start"] >= request["end"] or type(request["limit"]) is not int
                             or not 1 <= request["limit"] <= 10000):
            return {"error": "invalid"}
        tx = request.get("tx")
        if op == "begin":
            if tx in self.transactions:
                return {"error": "exists"}
            self.transactions[tx] = {"snapshot": self.seq, "writes": {}, "reads": set(), "ranges": []}
            return {"ok": True, "snapshot": self.seq}
        if tx is not None and tx not in self.transactions:
            return {"error": "missing"}
        if op == "checkpoint":
            return self.checkpoint()
        if op in ("root", "proof"):
            root, siblings = merkle(self.current, request.get("key"))
            result = {"seq": self.seq, "root": root}
            if op == "proof":
                result.update(key=request["key"], value=self.current.get(request["key"]), siblings=siblings)
            return result
        transaction = self.transactions[tx]
        if op == "get":
            transaction["reads"].add(request["key"])
            return {"value": self.visible(transaction, request["key"])}
        if op in ("put", "delete"):
            transaction["writes"][request["key"]] = request.get("value")
            return {"ok": True}
        if op == "scan":
            start, end = request["start"], request["end"]
            transaction["ranges"].append((start, end))
            items = []
            for key in sorted(set(self.versions) | set(transaction["writes"])):
                if start <= key < end:
                    value = self.visible(transaction, key)
                    if value is not None:
                        items.append([key, value])
                        if len(items) == request["limit"]:
                            break
            return {"items": items}
        del self.transactions[tx]
        if op == "abort":
            return {"ok": True}
        watched = transaction["reads"] | set(transaction["writes"])
        for key, stamp in self.stamps.items():
            if stamp > transaction["snapshot"] and (key in watched or any(
                    start <= key < end for start, end in transaction["ranges"])):
                return {"error": "conflict"}
        if transaction["writes"]:
            seq = self.seq + 1
            data = frame(b"KVL1", {"seq": seq, "writes": sorted(transaction["writes"].items())})
            view = memoryview(data)
            while view:
                written = self.wal.write(view)
                view = view[written:]
            os.fsync(self.wal.fileno())
            self.crash("wal_synced")
            self.publish(seq, transaction["writes"])
        return {"ok": True, "seq": self.seq}


def main():
    store = Store(sys.argv[1])
    for line in sys.stdin:
        try:
            request = json.loads(line, object_pairs_hook=unique_object)
            reply = store.execute(request)
        except (ValueError, TypeError, UnicodeError, RecursionError):
            reply = {"error": "invalid"}
        print(json.dumps(reply, ensure_ascii=True, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
