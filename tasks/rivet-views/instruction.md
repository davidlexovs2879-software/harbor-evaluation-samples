# Rivet: incremental relational views

Build a small in-memory relational engine in `/app/views/main.py`. A client
defines a graph of multiset queries, then sends insertions and retractions to
its source tables. The engine must maintain every view and emit the exact net
change to each requested output. This is view maintenance, including duplicate
rows, outer joins, SQL-style nulls, aggregates and atomic updates across tables.

Run `python /app/views/main.py`, using Python 3.11 and its standard library only.
Do not use SQLite, a subprocess database, or a third-party package. Input and
output are one JSON object per line. Flush every response; send diagnostics to
stderr. State lasts for the process lifetime. No disk persistence is required.
You may add files under `/app/views`.

## Protocol and ordering

Requests must have exactly the documented fields. Unknown fields/operations,
malformed JSON, duplicate JSON fields, incorrect types and failed validation
return `{"error":"invalid"}` with no effects. Boolean values are not integers.
Continue processing after errors. Identifiers match `[A-Za-z][A-Za-z0-9_]{0,31}`.

* `{"op":"create","nodes":[NODE,...],"outputs":[ID,...]}` installs a graph
  into an uninitialized process and returns
  `{"ok":true,"seq":0,"outputs":{ID:BAG,...}}`. A second create returns
  `{"error":"exists"}`. Validate a create before checking exists. A failed
  create leaves the process uninitialized. There are 1..32 nodes and 1..32
  distinct output IDs, each naming a defined node. Nodes are in topological
  order: inputs must refer to earlier nodes. Node IDs are unique.
* `{"op":"apply","id":ID,"updates":[UPDATE,...]}` atomically updates source
  bags and returns `{"ok":true,"seq":N,"deltas":{OUTPUT_ID:BAG,...}}`. Updates
  are `{"source":ID,"row":[VALUE,...],"weight":SIGNED_INTEGER}`. A batch has
  1..10000 updates; each weight is nonzero and its absolute value is at most
  1000000. Combine all updates before checking source multiplicities. Every
  resulting source multiplicity must be in 0..1000000000; a violation returns
  `{"error":"negative"}` and changes nothing, including replay history.
  Validate every update's schema and shape before checking multiplicities.
  Every successful new apply advances sequence once, even for a net-zero batch.
* `{"op":"get","node":ID}` returns `{"seq":N,"rows":BAG}` for any defined
  node. Unknown nodes are invalid. Before create, validly shaped apply/get
  requests return `{"error":"missing"}`; validate their outer shape first.

A BAG is an array of objects exactly `{"row":[VALUE,...],"weight":INTEGER}`.
Omit zero weights and combine equal rows. Stored bags have positive weights;
deltas may have negative weights. Include every output ID, with `[]` for no
change. Emit rows in lexicographic order using the per-value order null, then
integers by numeric value, then strings by Unicode code point. A shorter equal
prefix sorts first. JSON object field order is irrelevant.

For replay handling, remember every successful apply ID and its response. An
identical repeat returns the original response without changing state/sequence,
even after later batches. Compare payloads by canonical JSON (sorted object
keys; array order remains significant). Reusing an ID with a different payload
returns `{"error":"replay"}`. Failed requests reserve no ID. Validate the
outer shape and ID before replay lookup; a stored ID with a different updates
payload returns replay before interpreting that payload's updates.

## Types and operators

Sources declare column types `int` or `text`, 1..8 columns. Source values are
null, signed 64-bit integers, or UTF-8 strings of at most 256 bytes, consistent
with the declared type. Unpaired surrogates and booleans are invalid. Null is
valid in any column. Derived arithmetic uses unbounded exact integers. No floats.
Every index below is zero-based and must be in bounds. Nodes have exactly the
fields in their definition; plan errors are invalid.

| op | Node fields in addition to id, op | Meaning |
| --- | --- | --- |
| source | `columns` | Empty input multiset with those types. |
| filter | `input`, `column`, `predicate`, and `value` except for null predicates | Keep rows satisfying the predicate, preserving multiplicity. |
| project | `input`, `columns` | Select 1..8 column indices in that order; duplicates allowed. Equal projected rows combine. |
| union | `inputs` | Bag sum of 1..8 inputs with identical schemas. Repeating an input repeats its contribution. |
| join | `left`, `right`, `on`, `mode` | Equijoin; concatenate the entire left and right row. |
| distinct | `input` | Each present input row has output weight one. |
| group | `input`, `keys`, `aggregates` | Group by 0..8 distinct column indices and append aggregate results in declared order. |

Filter predicates are eq, ne, lt, le, gt, ge, is_null and is_not_null. The value
must match the chosen column type, or be null. A comparison involving null is
unknown and does not select the row, including `ne`. Filter constants use the
same integer and string bounds as source values. The two null predicates
have no value field. All comparisons use the declared type's natural ordering.

Join `on` is a list of 1..8 distinct pairs `[LEFT_COLUMN,RIGHT_COLUMN]`, each with
matching column types. All pairs must match; null never equals anything in a
join, including another null. Mode is inner or left. Joined weight is the
product of both input weights. A left row with no matching right row appears
with the right columns padded by null and retains its left weight. If a matching
row is inserted, retract the padded row; recreate it when the last match leaves.
Either side may name the same node, and both sides may change in the same batch.
Do not emit intermediate changes that cancel within a batch.

Aggregates are 1..8 objects. `{"op":"count_all"}` counts all input copies.
`{"op":"count","column":I}` counts non-null copies in that column.
`sum`, `min`, and `max` have the same op/column shape. Sum accepts only an int
column; min/max accept either type. Ignore nulls for these aggregates. Sum,
min and max of no non-null values are null. Rows group nulls together. An empty
key list is global aggregation: it always has exactly one output row with
weight one, including on an empty input (counts zero, other aggregates null).
A non-global empty group has no output row. An aggregate result row always has
weight one, regardless of the number of contributing copies.

## Scale and scoring

Correctness fixtures include independent recomputation on small graphs, signed
bag updates, aliases, self-joins, simultaneous inserts/retractions, nullable keys,
duplicate projection, disappearing groups, net-zero batches and replay after
later mutations. Inputs never produce more than 30000 distinct rows in any node,
at most 1000000 total source copies, 16 columns in a derived row, or 2000 apply
IDs. There is no requirement to defend against malicious executable code.

Maintain indexes or equivalent incremental state. A scale fixture loads two
10000-row source tables joined on unique integer keys, then applies 600 single-row
updates and checks exact join/aggregate deltas. The entire 600-update loop must
finish within 20 seconds on the supplied two-CPU environment. The initial load
and each other request have a 10-second deadline. Setup is not charged to that
20-second loop. Scanning both entire tables or rebuilding the entire join for
every update will not reliably meet this workload. The scale fixture is one of
six equally weighted groups; the others cover plan validation, linear operators,
join semantics, aggregates, and atomic updates/replay. A group earns credit only
when all its checks pass. A complete solution earns 1.0.

Run `python /app/views/smoke.py` for a public example. The machine is offline and
includes everything needed to implement and test the engine.
