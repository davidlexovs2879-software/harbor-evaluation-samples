"""Independent full recomputation for correctness; indexed scale has analytic answers."""
from collections import Counter, defaultdict
import copy
import json
from pathlib import Path
import random
import time

import harness as h
from harness import Client, equal, require


def sorted_bag(bag):
    def key(row):
        return tuple((0, 0) if value is None else (1, value) if isinstance(value, int) else (2, value) for value in row)
    return [{"row": list(row), "weight": bag[row]} for row in sorted(bag, key=key) if bag[row] != 0]


def recompute(nodes, sources):
    bags = {}
    for node in nodes:
        op = node["op"]
        out = Counter()
        if op == "source":
            out = Counter(sources[node["id"]])
        elif op == "project":
            for row, weight in bags[node["input"]].items():
                out[tuple(row[i] for i in node["columns"])] += weight
        elif op == "union":
            for parent in node["inputs"]:
                out.update(bags[parent])
        elif op == "filter":
            for row, weight in bags[node["input"]].items():
                left, right, predicate = row[node["column"]], node.get("value"), node["predicate"]
                keep = False
                if predicate == "is_null":
                    keep = left is None
                elif predicate == "is_not_null":
                    keep = left is not None
                elif left is not None and right is not None:
                    compare = (left > right) - (left < right)
                    keep = {"eq": compare == 0, "ne": compare != 0, "lt": compare < 0,
                            "le": compare <= 0, "gt": compare > 0, "ge": compare >= 0}[predicate]
                if keep:
                    out[row] += weight
        elif op == "distinct":
            out = Counter({row: 1 for row, weight in bags[node["input"]].items() if weight})
        elif op == "join":
            right_schema = schema_for(nodes, node["right"])
            for left, copies in bags[node["left"]].items():
                matched = False
                for right, others in bags[node["right"]].items():
                    if all(left[a] is not None and right[b] is not None and left[a] == right[b] for a, b in node["on"]):
                        out[left + right] += copies * others
                        matched = True
                if not matched and node["mode"] == "left":
                    out[left + (None,) * len(right_schema)] += copies
        elif op == "group":
            groups = defaultdict(list)
            for row, copies in bags[node["input"]].items():
                groups[tuple(row[i] for i in node["keys"])].append((row, copies))
            if not node["keys"]:
                groups.setdefault((), [])
            for key, rows in groups.items():
                result = list(key)
                for aggregate in node["aggregates"]:
                    kind = aggregate["op"]
                    if kind == "count_all":
                        result.append(sum(copies for _, copies in rows))
                        continue
                    values = [(row[aggregate["column"]], copies) for row, copies in rows
                              if row[aggregate["column"]] is not None]
                    if kind == "count":
                        result.append(sum(copies for _, copies in values))
                    elif not values:
                        result.append(None)
                    elif kind == "sum":
                        result.append(sum(value * copies for value, copies in values))
                    else:
                        result.append((min if kind == "min" else max)(value for value, _ in values))
                out[tuple(result)] = 1
        bags[node["id"]] = Counter({r: w for r, w in out.items() if w})
    return bags


def schema_for(nodes, name):
    schemas = {}
    for node in nodes:
        op = node["op"]
        if op == "source":
            schema = node["columns"]
        elif op == "join":
            schema = schemas[node["left"]] + schemas[node["right"]]
        elif op == "project":
            schema = [schemas[node["input"]][i] for i in node["columns"]]
        elif op == "union":
            schema = schemas[node["inputs"][0]]
        elif op == "group":
            schema = [schemas[node["input"]][i] for i in node["keys"]]
            schema += ["int" if a["op"] in ("count_all", "count", "sum") else schemas[node["input"]][a["column"]]
                       for a in node["aggregates"]]
        else:
            schema = schemas[node["input"]]
        schemas[node["id"]] = schema
    return schemas[name]


class Session:
    def __init__(self, client, nodes, outputs=None):
        self.client, self.nodes = client, nodes
        self.outputs = outputs if outputs is not None else [node["id"] for node in nodes]
        self.sources = {node["id"]: Counter() for node in nodes if node["op"] == "source"}
        self.bags = recompute(nodes, self.sources)
        self.seq = 0
        equal(client.call({"op": "create", "nodes": nodes, "outputs": self.outputs}),
              {"ok": True, "seq": 0, "outputs": {n: sorted_bag(self.bags[n]) for n in self.outputs}})

    def apply(self, updates, identity=None):
        name = identity if identity is not None else f"t{self.seq + 1}"
        sources = copy.deepcopy(self.sources)
        for source, row, weight in updates:
            sources[source][tuple(row)] += weight
        if any(weight < 0 for bag in sources.values() for weight in bag.values()):
            expected = {"error": "negative"}
        else:
            sources = {name: Counter({r: w for r, w in bag.items() if w}) for name, bag in sources.items()}
            after = recompute(self.nodes, sources)
            changes = {}
            for output in self.outputs:
                difference = Counter(after[output])
                difference.subtract(self.bags[output])
                changes[output] = sorted_bag(difference)
            self.seq += 1
            expected = {"ok": True, "seq": self.seq, "deltas": changes}
            self.bags, self.sources = after, sources
        request = {"op": "apply", "id": name, "updates": [
            {"source": source, "row": row, "weight": weight} for source, row, weight in updates]}
        equal(self.client.call(request), expected)
        return request, expected

    def get_all(self):
        for node in self.nodes:
            equal(self.client.call({"op": "get", "node": node["id"]}),
                  {"seq": self.seq, "rows": sorted_bag(self.bags[node["id"]])})


def source(name="s", columns=None):
    return {"id": name, "op": "source", "columns": ["int", "text"] if columns is None else columns}


def validation():
    with Client() as c:
        equal(c.call({"op": "get", "node": "s"}), {"error": "missing"})
        equal(c.call({"op": "apply", "id": "a", "updates": [{"nonsense": True}]}), {"error": "missing"})
        for invalid in ["null", "[]", "{", '{"op":"get","op":"get","node":"s"}',
                        '{"op":"get","node":true}', '{"op":"apply","id":"a","updates":[]}']:
            equal(c.raw(invalid), {"error": "invalid"})
        invalid_plans = [[], [source(), source()],
                         [source(columns=[])], [source(columns=["float"])],
                         [{"id": "d", "op": "distinct", "input": "future"}, source("future")],
                         [source(), {"id": "p", "op": "project", "input": "s", "columns": [True]}],
                         [source(), {"id": "p", "op": "project", "input": "s", "columns": [2]}],
                         [source(), {"id": "u", "op": "union", "inputs": []}],
                         [source(), source("b", ["text"]), {"id": "u", "op": "union", "inputs": ["s", "b"]}],
                         [source(), {"id": "j", "op": "join", "left": "s", "right": "s", "on": [[0, 1]], "mode": "inner"}],
                         [source(), {"id": "g", "op": "group", "input": "s", "keys": [0, 0], "aggregates": [{"op": "count_all"}]}],
                         [source(), {"id": "g", "op": "group", "input": "s", "keys": [], "aggregates": [{"op": "sum", "column": 1}]}],
                         [source(), {"id": "f", "op": "filter", "input": "s", "column": 0, "predicate": "is_null", "value": 0}]]
        for nodes in invalid_plans:
            equal(c.call({"op": "create", "nodes": nodes, "outputs": ["s"]}), {"error": "invalid"})
        session = Session(c, [source()])
        equal(c.call({"op": "create", "nodes": [source()], "outputs": ["s"]}), {"error": "exists"})
        equal(c.call({"op": "create", "nodes": [], "outputs": ["s"]}), {"error": "invalid"})
        for row, weight in [([True, "x"], 1), ([1.0, "x"], 1), ([1, "x"], True), ([1, "x"], 0),
                            ([1, "x"], 1000001), ([1 << 63, "x"], 1), ([1, "é" * 129], 1),
                            ([1, "\ud800"], 1), ([1], 1)]:
            equal(c.call({"op": "apply", "id": "bad", "updates": [{"source": "s", "row": row, "weight": weight}]}), {"error": "invalid"})
        session.apply([("s", [-(1 << 63), "é" * 128], 1)])
        session.get_all()


def linear():
    nodes = [source(), {"id": "p", "op": "project", "input": "s", "columns": [1, 1]},
             {"id": "u", "op": "union", "inputs": ["p", "p"]},
             {"id": "d", "op": "distinct", "input": "u"}]
    with Client() as c:
        s = Session(c, nodes)
        s.apply([("s", [1, "same"], 2), ("s", [2, "same"], 3), ("s", [None, None], 1)])
        s.get_all()
        s.apply([("s", [1, "same"], -2), ("s", [2, "same"], -2)])
        s.get_all()
        s.apply([("s", [2, "same"], -1)])
        s.get_all()
    for predicate in ["eq", "ne", "lt", "le", "gt", "ge", "is_null", "is_not_null"]:
        for value in ([0, None] if predicate not in ("is_null", "is_not_null") else [None]):
            node = {"id": "f", "op": "filter", "input": "s", "column": 0, "predicate": predicate}
            if predicate not in ("is_null", "is_not_null"):
                node["value"] = value
            with Client() as c:
                s = Session(c, [source(), node])
                s.apply([("s", [number, str(number)], 2) for number in [None, -1, 0, 1]])
                s.get_all()
                s.apply([("s", [0, "0"], -1)])
                s.get_all()


def joins():
    for mode in ["inner", "left"]:
        nodes = [source("l"), source("r"),
                 {"id": "j", "op": "join", "left": "l", "right": "r", "on": [[0, 0]], "mode": mode},
                 {"id": "self", "op": "join", "left": "l", "right": "l", "on": [[0, 0]], "mode": mode},
                 {"id": "multi", "op": "join", "left": "l", "right": "r", "on": [[0, 0], [1, 1]], "mode": mode}]
        with Client() as c:
            s = Session(c, nodes)
            s.apply([("l", [1, "a"], 2), ("l", [None, "null"], 3), ("l", [2, "b"], 1)])
            s.apply([("r", [1, "a"], 3), ("r", [None, "null"], 5)])
            s.get_all()
            s.apply([("l", [1, "a"], 1), ("r", [1, "a"], -2), ("r", [2, "b"], 4)])
            s.get_all()
            s.apply([("r", [1, "a"], -1), ("r", [2, "b"], -4)])
            s.get_all()
            s.apply([("r", [1, "a"], 2), ("r", [1, "replacement"], 1), ("l", [1, "a"], -3)])
            s.get_all()
    rng = random.Random(917773)
    nodes = [source("l"), source("r"),
             {"id": "j", "op": "join", "left": "l", "right": "r", "on": [[0, 0]], "mode": "left"},
             {"id": "d", "op": "distinct", "input": "j"},
             {"id": "g", "op": "group", "input": "d", "keys": [0],
              "aggregates": [{"op": "count_all"}, {"op": "min", "column": 3}]}]
    with Client() as c:
        s = Session(c, nodes)
        for _ in range(260):
            updates = []
            for side in rng.sample(["l", "r"], rng.randint(1, 2)):
                if s.sources[side] and rng.random() < 0.45:
                    row = rng.choice(list(s.sources[side]))
                    updates.append((side, list(row), -1))
                else:
                    updates.append((side, [rng.choice([None, 0, 1, 2]), rng.choice([None, "a", "b"])], 1))
            s.apply(updates)
            if s.seq % 17 == 0:
                s.get_all()


def aggregates():
    measures = [{"op": "count_all"}, {"op": "count", "column": 1}, {"op": "sum", "column": 1},
                {"op": "min", "column": 1}, {"op": "max", "column": 1},
                {"op": "min", "column": 2}, {"op": "max", "column": 2}]
    nodes = [source("s", ["text", "int", "text"]),
             {"id": "g", "op": "group", "input": "s", "keys": [0], "aggregates": measures},
             {"id": "global", "op": "group", "input": "s", "keys": [], "aggregates": measures},
             {"id": "again", "op": "group", "input": "g", "keys": [], "aggregates": [{"op": "count_all"}]}]
    with Client() as c:
        s = Session(c, nodes)
        entries = [("s", ["a", 9, "z"], 3), ("s", ["a", -4, "a"], 2),
                   ("s", [None, None, None], 4), ("s", ["a", None, None], 5),
                   ("s", ["big", (1 << 63) - 1, "東京"], 100)]
        s.apply(entries)
        s.get_all()
        s.apply([("s", ["a", -4, "a"], -2)])
        s.get_all()
        s.apply([("s", ["a", 9, "z"], -3)])
        s.get_all()
        s.apply([("s", ["a", None, None], -5), ("s", [None, None, None], -4),
                 ("s", ["big", (1 << 63) - 1, "東京"], -100)])
        s.get_all()
    rng = random.Random(47119)
    with Client() as c:
        s = Session(c, nodes)
        for _ in range(220):
            if s.sources["s"] and rng.random() < 0.5:
                row = rng.choice(list(s.sources["s"]))
                updates = [("s", list(row), -1)]
            else:
                updates = [("s", [rng.choice([None, "a", "b"]), rng.choice([None, -7, 0, 8]), rng.choice([None, "a", "z"])], 1)]
            s.apply(updates)
            if s.seq % 19 == 0:
                s.get_all()


def atomic_replay():
    nodes = [source("l"), source("r"),
             {"id": "j", "op": "join", "left": "l", "right": "r", "on": [[0, 0]], "mode": "left"}]
    with Client() as c:
        s = Session(c, nodes)
        request, response = s.apply([("l", [1, "left"], 1), ("r", [1, "right"], 2)], "first")
        s.apply([("r", [1, "right"], -2)])
        equal(c.call(request), response)
        s.get_all()
        equal(c.call({"op": "apply", "id": "first", "updates": [{"source": "absent", "row": [], "weight": 0}]}), {"error": "replay"})
        s.apply([("l", [1, "left"], -2), ("r", [1, "right"], 8)], "failed")
        s.get_all()
        s.apply([("l", [1, "left"], -2), ("l", [1, "left"], 2)], "netzero")
        s.get_all()
        s.apply([("r", [1, "right"], 1)], "failed")
        invalid = {"op": "apply", "id": "invalid", "updates": [
            {"source": "l", "row": [1, "left"], "weight": -9},
            {"source": "r", "row": [True, "bad"], "weight": 1}]}
        equal(c.call(invalid), {"error": "invalid"})
        s.get_all()
        s.apply([("l", [1, "left"], 1)], "invalid")
        s.get_all()


def scale():
    nodes = [source("l", ["int", "int"]), source("r", ["int", "int"]),
             {"id": "j", "op": "join", "left": "l", "right": "r", "on": [[0, 0]], "mode": "left"},
             {"id": "g", "op": "group", "input": "j", "keys": [0],
              "aggregates": [{"op": "count_all"}, {"op": "sum", "column": 3}]}]
    with Client() as c:
        equal(c.call({"op": "create", "nodes": nodes, "outputs": ["j", "g"]}),
              {"ok": True, "seq": 0, "outputs": {"j": [], "g": []}})
        for side, seq in [("l", 1), ("r", 2)]:
            updates = [{"source": side, "row": [key, key * (2 if side == "r" else 1)], "weight": 1} for key in range(10000)]
            response = c.call({"op": "apply", "id": side, "updates": updates})
            equal(response["seq"], seq)
            changed_join, changed_group = Counter(), Counter()
            for key in range(10000):
                if side == "l":
                    changed_join[(key, key, None, None)] = 1
                    changed_group[(key, 1, None)] = 1
                else:
                    changed_join[(key, key, key, key * 2)] = 1
                    changed_join[(key, key, None, None)] = -1
                    changed_group[(key, 1, key * 2)] = 1
                    changed_group[(key, 1, None)] = -1
            equal(response["deltas"], {"j": sorted_bag(changed_join), "g": sorted_bag(changed_group)})
        # The right load changes both padded and matched rows; verify current state.
        equal(c.call({"op": "get", "node": "j"}), {"seq": 2, "rows": sorted_bag(Counter({
            (key, key, key, key * 2): 1 for key in range(10000)}))})
        start = time.monotonic()
        for step in range(600):
            key = (step * 7919) % 10000
            # These keys are distinct over the loop, making each analytic answer independent.
            request = {"op": "apply", "id": f"u{step}", "updates": [
                {"source": "r", "row": [key, key * 2], "weight": -1},
                {"source": "r", "row": [key, -1], "weight": 1}]}
            delta_join = Counter({(key, key, key, -1): 1})
            delta_join[(key, key, key, key * 2)] -= 1
            delta_group = Counter({(key, 1, -1): 1})
            delta_group[(key, 1, key * 2)] -= 1
            equal(c.call(request), {"ok": True, "seq": step + 3,
                                   "deltas": {"j": sorted_bag(delta_join), "g": sorted_bag(delta_group)}})
        elapsed = time.monotonic() - start
        require(elapsed <= 20, f"600-update loop took {elapsed:.3f}s (limit 20s)")
        print(json.dumps({"scale_loop_seconds": round(elapsed, 6)}), flush=True)


def main():
    outcomes = []
    for function in [validation, linear, joins, aggregates, atomic_replay, scale]:
        before = h.CHECKS
        try:
            function()
            outcomes.append({"group": function.__name__, "passed": True, "checks": h.CHECKS - before})
        except Exception as exc:
            outcomes.append({"group": function.__name__, "passed": False, "checks": h.CHECKS - before,
                             "error": str(exc)[:2000]})
        print(json.dumps(outcomes[-1]), flush=True)
    score = sum(group["passed"] for group in outcomes) / len(outcomes)
    directory = Path("/logs/verifier")
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "details.json").write_text(json.dumps({"groups": outcomes, "score": score}, indent=2))
    (directory / "reward.txt").write_text(f"{score:.12f}\n")


if __name__ == "__main__":
    main()
