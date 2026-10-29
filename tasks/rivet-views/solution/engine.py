#!/usr/bin/env python3
"""Incremental signed-bag propagation through a typed relational DAG."""
import json
import re
import sys


def identifier(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,31}", value) is not None


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def scalar(value, kind):
    if value is None:
        return True
    if kind == "int":
        return type(value) is int and -(1 << 63) <= value < (1 << 63)
    try:
        return isinstance(value, str) and len(value.encode("utf-8")) <= 256
    except UnicodeError:
        return False


def add(bag, row, weight):
    value = bag.get(row, 0) + weight
    if value:
        bag[row] = value
    else:
        bag.pop(row, None)


def order(row):
    return tuple((0, 0) if x is None else (1, x) if type(x) is int else (2, x) for x in row)


def packed(bag):
    return [{"row": list(row), "weight": bag[row]} for row in sorted(bag, key=order) if bag[row]]


def index(value, schema):
    if type(value) is not int or not 0 <= value < len(schema):
        raise ValueError("column index")
    return schema[value]


def plan(nodes, outputs):
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= 32:
        raise ValueError("nodes")
    if (not isinstance(outputs, list) or not 1 <= len(outputs) <= 32
            or not all(identifier(x) for x in outputs) or len(set(outputs)) != len(outputs)):
        raise ValueError("outputs")
    schemas = {}
    for node in nodes:
        if not isinstance(node, dict) or not identifier(node.get("id")) or node["id"] in schemas:
            raise ValueError("node id")
        op = node.get("op")
        fields = {"source": {"columns"}, "filter": {"input", "column", "predicate"},
                  "project": {"input", "columns"}, "union": {"inputs"},
                  "join": {"left", "right", "on", "mode"}, "distinct": {"input"},
                  "group": {"input", "keys", "aggregates"}}
        if not isinstance(op, str) or op not in fields:
            raise ValueError("operator")
        expected = fields[op] | {"id", "op"}
        if op == "filter" and node.get("predicate") not in ("is_null", "is_not_null"):
            expected = expected | {"value"}
        if set(node) != expected:
            raise ValueError("node fields")
        if op == "source":
            schema = node["columns"]
            if not isinstance(schema, list) or not 1 <= len(schema) <= 8 or any(x not in ("int", "text") for x in schema):
                raise ValueError("source schema")
        elif op in ("filter", "project", "distinct", "group"):
            if not identifier(node["input"]) or node["input"] not in schemas:
                raise ValueError("input")
            parent = schemas[node["input"]]
            if op == "filter":
                kind = index(node["column"], parent)
                if node["predicate"] not in ("eq", "ne", "lt", "le", "gt", "ge", "is_null", "is_not_null"):
                    raise ValueError("predicate")
                if "value" in node and not scalar(node["value"], kind):
                    raise ValueError("predicate value")
                schema = parent
            elif op == "project":
                if not isinstance(node["columns"], list) or not 1 <= len(node["columns"]) <= 8:
                    raise ValueError("projection")
                schema = [index(i, parent) for i in node["columns"]]
            elif op == "distinct":
                schema = parent
            else:
                keys, aggregates = node["keys"], node["aggregates"]
                if (not isinstance(keys, list) or len(keys) > 8 or any(type(i) is not int for i in keys)
                        or len(set(keys)) != len(keys) or not isinstance(aggregates, list) or not 1 <= len(aggregates) <= 8):
                    raise ValueError("group shape")
                schema = [index(i, parent) for i in keys]
                for aggregate in aggregates:
                    if not isinstance(aggregate, dict):
                        raise ValueError("aggregate")
                    kind = aggregate.get("op")
                    if kind == "count_all":
                        if set(aggregate) != {"op"}:
                            raise ValueError("aggregate fields")
                        schema.append("int")
                    else:
                        if kind not in ("count", "sum", "min", "max") or set(aggregate) != {"op", "column"}:
                            raise ValueError("aggregate fields")
                        column_type = index(aggregate["column"], parent)
                        if kind == "sum" and column_type != "int":
                            raise ValueError("sum requires integers")
                        schema.append("int" if kind in ("sum", "count") else column_type)
        elif op == "union":
            names = node["inputs"]
            if (not isinstance(names, list) or not 1 <= len(names) <= 8
                    or any(not identifier(n) or n not in schemas for n in names)):
                raise ValueError("union inputs")
            schema = schemas[names[0]]
            if any(schemas[n] != schema for n in names):
                raise ValueError("union type mismatch")
        else:
            if any(not identifier(node[side]) or node[side] not in schemas for side in ("left", "right")):
                raise ValueError("join inputs")
            left, right = schemas[node["left"]], schemas[node["right"]]
            if node["mode"] not in ("inner", "left") or not isinstance(node["on"], list) or not 1 <= len(node["on"]) <= 8:
                raise ValueError("join shape")
            seen = set()
            for pair in node["on"]:
                if not isinstance(pair, list) or len(pair) != 2:
                    raise ValueError("join pair")
                if index(pair[0], left) != index(pair[1], right) or tuple(pair) in seen:
                    raise ValueError("join types")
                seen.add(tuple(pair))
            schema = left + right
        if len(schema) > 16:
            raise ValueError("wide derived row")
        schemas[node["id"]] = list(schema)
    if any(name not in schemas for name in outputs):
        raise ValueError("unknown output")
    return schemas


def selected(node, row):
    value, predicate = row[node["column"]], node["predicate"]
    if predicate == "is_null":
        return value is None
    if predicate == "is_not_null":
        return value is not None
    other = node["value"]
    if value is None or other is None:
        return False
    if predicate == "eq":
        return value == other
    if predicate == "ne":
        return value != other
    if predicate == "lt":
        return value < other
    if predicate == "le":
        return value <= other
    if predicate == "gt":
        return value > other
    return value >= other


class Join:
    def __init__(self, node, width):
        self.node, self.width = node, width
        self.indices = [{}, {}]

    def key(self, row, side):
        key = tuple(row[pair[side]] for pair in self.node["on"])
        return None if None in key else key

    def modify(self, side, row, weight):
        key = self.key(row, side)
        bucket = self.indices[side].setdefault(key, {})
        add(bucket, row, weight)
        if not bucket:
            del self.indices[side][key]

    def update(self, left_delta, right_delta):
        result = {}
        outer = self.node["mode"] == "left"
        for left, weight in left_delta.items():
            key = self.key(left, 0)
            matches = self.indices[1].get(key, {}) if key is not None else {}
            if matches:
                for right, copies in matches.items():
                    add(result, left + right, weight * copies)
            elif outer:
                add(result, left + (None,) * self.width, weight)
            self.modify(0, left, weight)
        for right, weight in right_delta.items():
            key = self.key(right, 1)
            if key is not None:
                old_total = sum(self.indices[1].get(key, {}).values())
                new_total = old_total + weight
                for left, copies in self.indices[0].get(key, {}).items():
                    add(result, left + right, copies * weight)
                    if outer and old_total == 0 and new_total > 0:
                        add(result, left + (None,) * self.width, -copies)
                    if outer and old_total > 0 and new_total == 0:
                        add(result, left + (None,) * self.width, copies)
            self.modify(1, right, weight)
        return result


class Group:
    def __init__(self, node):
        self.node = node
        self.buckets = {(): {}} if not node["keys"] else {}

    def value(self, key):
        rows = self.buckets.get(key, {})
        if not rows and self.node["keys"]:
            return None
        result = list(key)
        for aggregate in self.node["aggregates"]:
            kind = aggregate["op"]
            if kind == "count_all":
                result.append(sum(rows.values()))
                continue
            column = aggregate["column"]
            values = [(row[column], weight) for row, weight in rows.items() if row[column] is not None]
            if kind == "count":
                result.append(sum(w for _, w in values))
            elif not values:
                result.append(None)
            elif kind == "sum":
                result.append(sum(v * w for v, w in values))
            elif kind == "min":
                result.append(min(v for v, _ in values))
            else:
                result.append(max(v for v, _ in values))
        return tuple(result)

    def update(self, delta, initial):
        affected = {tuple(row[i] for i in self.node["keys"]) for row in delta}
        if initial and not self.node["keys"]:
            affected.add(())
        before = {key: (None if initial else self.value(key)) for key in affected}
        for row, weight in delta.items():
            key = tuple(row[i] for i in self.node["keys"])
            add(self.buckets.setdefault(key, {}), row, weight)
            if not self.buckets[key] and self.node["keys"]:
                del self.buckets[key]
        result = {}
        for key in affected:
            if before[key] is not None:
                add(result, before[key], -1)
            after = self.value(key)
            if after is not None:
                add(result, after, 1)
        return result


class Graph:
    def __init__(self, nodes, outputs, schemas):
        self.nodes, self.outputs, self.schemas = nodes, outputs, schemas
        self.bags = {node["id"]: {} for node in nodes}
        self.joins = {n["id"]: Join(n, len(schemas[n["right"]])) for n in nodes if n["op"] == "join"}
        self.groups = {n["id"]: Group(n) for n in nodes if n["op"] == "group"}
        self.sources = {n["id"] for n in nodes if n["op"] == "source"}
        self.seq, self.replays = 0, {}
        self.propagate({}, True)

    def propagate(self, changes, initial=False):
        deltas = {}
        for node in self.nodes:
            name, op = node["id"], node["op"]
            delta = {}
            if op == "source":
                delta = changes.get(name, {})
            elif op == "union":
                for parent in node["inputs"]:
                    for row, weight in deltas[parent].items():
                        add(delta, row, weight)
            elif op == "join":
                delta = self.joins[name].update(deltas[node["left"]], deltas[node["right"]])
            else:
                parent_delta = deltas[node["input"]]
                if op == "group":
                    delta = self.groups[name].update(parent_delta, initial)
                else:
                    for row, weight in parent_delta.items():
                        if op == "filter" and selected(node, row):
                            add(delta, row, weight)
                        elif op == "project":
                            add(delta, tuple(row[i] for i in node["columns"]), weight)
                        elif op == "distinct":
                            new = self.bags[node["input"]].get(row, 0)
                            old = new - weight
                            add(delta, row, int(new > 0) - int(old > 0))
            for row, weight in delta.items():
                add(self.bags[name], row, weight)
            deltas[name] = delta
        return {name: packed(deltas[name]) for name in self.outputs}

    def apply(self, request):
        identity = request["id"]
        payload = json.dumps(request["updates"], sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        if identity in self.replays:
            previous, response = self.replays[identity]
            return response if payload == previous else {"error": "replay"}
        changes = {}
        for update in request["updates"]:
            if not isinstance(update, dict) or set(update) != {"source", "row", "weight"}:
                return {"error": "invalid"}
            name, row, weight = update["source"], update["row"], update["weight"]
            if not identifier(name) or name not in self.sources:
                return {"error": "invalid"}
            schema = self.schemas[name]
            if (not isinstance(row, list) or len(row) != len(schema)
                    or any(not scalar(value, kind) for value, kind in zip(row, schema))
                    or type(weight) is not int or weight == 0 or abs(weight) > 1000000):
                return {"error": "invalid"}
            add(changes.setdefault(name, {}), tuple(row), weight)
        for name, delta in changes.items():
            if any(not 0 <= self.bags[name].get(row, 0) + weight <= 1000000000 for row, weight in delta.items()):
                return {"error": "negative"}
        deltas = self.propagate(changes)
        self.seq += 1
        response = {"ok": True, "seq": self.seq, "deltas": deltas}
        self.replays[identity] = (payload, response)
        return response


class Service:
    def __init__(self):
        self.graph = None

    def execute(self, request):
        if not isinstance(request, dict):
            return {"error": "invalid"}
        op = request.get("op")
        if op == "create":
            if set(request) != {"op", "nodes", "outputs"}:
                return {"error": "invalid"}
            schemas = plan(request["nodes"], request["outputs"])
            if self.graph is not None:
                return {"error": "exists"}
            self.graph = Graph(request["nodes"], request["outputs"], schemas)
            return {"ok": True, "seq": 0, "outputs": {n: packed(self.graph.bags[n]) for n in self.graph.outputs}}
        if op == "get":
            if set(request) != {"op", "node"} or not identifier(request["node"]):
                return {"error": "invalid"}
        elif op == "apply":
            if (set(request) != {"op", "id", "updates"} or not identifier(request["id"])
                    or not isinstance(request["updates"], list) or not 1 <= len(request["updates"]) <= 10000):
                return {"error": "invalid"}
        else:
            return {"error": "invalid"}
        if self.graph is None:
            return {"error": "missing"}
        if op == "get":
            if request["node"] not in self.graph.bags:
                return {"error": "invalid"}
            return {"seq": self.graph.seq, "rows": packed(self.graph.bags[request["node"]])}
        return self.graph.apply(request)


def main():
    service = Service()
    for line in sys.stdin:
        try:
            request = json.loads(line, object_pairs_hook=unique)
            response = service.execute(request)
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            response = {"error": "invalid"}
        print(json.dumps(response, ensure_ascii=True, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
