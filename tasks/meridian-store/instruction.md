# Meridian: recoverable transactions and authenticated snapshots

Implement a storage engine in `/app/store/main.py`, using Python 3.11 and its
standard library. Start it with `python /app/store/main.py DIRECTORY`. DIRECTORY
is the entire persistent database; create it if absent. One process owns a
directory at a time. Multiple transactions may be interleaved within that process.
Do not use SQLite, dbm, pickle, an external server, or a third-party package.

Read one JSON object per stdin line and immediately write one JSON object per
stdout line. Diagnostics belong on stderr. Objects below specify the complete
response; additional response fields are not accepted. JSON object field order
does not matter. The process must continue after a command error. EOF exits cleanly.

## Commands

Keys are nonempty UTF-8 strings, at most 256 bytes. Values are UTF-8 strings,
at most 1,048,576 bytes. Unpaired surrogates are invalid. Transaction identifiers
are nonempty ASCII alphanumeric strings of at most 32 characters. Unknown fields,
unknown commands, incorrect types (including bool as integer), and invalid bounds
produce `{"error":"invalid"}` without side effects. Commands use `op`:

| Request fields in addition to op | Response |
| --- | --- |
| `begin`: `tx` | `{"ok":true,"snapshot":N}` |
| `get`: `tx`, `key` | `{"value":STRING_OR_NULL}` |
| `put`: `tx`, `key`, `value` | `{"ok":true}` |
| `delete`: `tx`, `key` | `{"ok":true}` |
| `scan`: `tx`, `start`, `end`, `limit` | `{"items":[[KEY,VALUE],...]}` |
| `commit`: `tx` | `{"ok":true,"seq":N}` or `{"error":"conflict"}` |
| `abort`: `tx` | `{"ok":true}` |
| `root`: no other fields | `{"seq":N,"root":HEX}` |
| `proof`: `key` | `{"seq":N,"root":HEX,"key":KEY,"value":STRING_OR_NULL,"siblings":[HEX,...]}` |
| `checkpoint`: no other fields | `{"ok":true,"seq":N}` |

`begin` of an active identifier produces `{"error":"exists"}`. Other transaction
commands on an inactive identifier produce `{"error":"missing"}`. Validate the
complete request before checking identifier existence. Invalid JSON and non-object
JSON produce `invalid`. `scan` bounds are keys with `start < end`, and limit is an
integer in 1..10000. Ranges are half-open and sorted by Python string order.

## Transaction semantics

Sequence starts at zero. Begin captures the latest committed sequence. Reads and
scans see that snapshot plus the transaction's own writes. Last write wins within
a transaction, and deletion of an absent key is permitted. A successful commit
with any staged writes advances sequence exactly once, even if the writes make
no visible change. A read-only commit returns the current sequence without
advancing it. Commit and abort always remove the transaction; a conflicting
transaction is removed too. Reusing its identifier then starts a new snapshot.

Use optimistic serializable validation: commit conflicts if any key read OR
written by this transaction was committed by another transaction after its
snapshot. A scan records its ENTIRE requested range, including keys beyond limit
and keys absent at the snapshot. Commit also conflicts if any key in any recorded
range was committed after the snapshot, including a deletion or an inserted then
deleted key. Validate read-only transactions too. Unrelated writes do not conflict.

## Authenticated current state

`root` and `proof` concern committed state only. Hash means SHA-256; HEX is 64
lowercase hexadecimal characters. Derive a 256-bit path from SHA-256 of the UTF-8
key, taking bits most significant first. Use a sparse binary Merkle tree of depth
256. An absent leaf is `H(0x02)`. A present leaf is
`H(0x00 || H(key_utf8) || uint32_be(len(value_utf8)) || value_utf8)`.
Every internal node is `H(0x01 || left_hash || right_hash)`. Empty subtrees are
recursively hashed; the empty root is not just the absent leaf. A proof contains
exactly 256 sibling hashes, ordered from the leaf level toward the root. Support
membership and non-membership proofs, Unicode, empty values, updates and deletes.

## Persistence and crash recovery

All successful commits must survive immediate SIGKILL. Uncommitted and aborted
writes must never survive restart. Transactions do not survive restart. Persist
only `wal.bin`, `checkpoint.bin` and an optional `checkpoint.tmp` in DIRECTORY;
do not store durable state elsewhere. Tests may copy a directory to a fresh
location and reopen it. There is no required asymptotic performance target, but
each command must complete within five seconds on the provided two-CPU machine.
Evaluation workloads contain at most 500 live keys, 64 active transactions, and
8 MiB of encoded JSON in either a checkpoint or a single committed write set.

WAL is consecutive frames: ASCII `KVL1`, a uint32 big-endian payload length,
UTF-8 JSON payload, then uint32 big-endian CRC32 of the payload. Payload is exactly
`{"seq":N,"writes":[[KEY,STRING_OR_NULL],...]}` with unique sorted keys. JSON
serialization whitespace is unrestricted. Maximum frame payload is 16 MiB.
Recover the longest valid contiguous WAL prefix. Stop at a torn header, impossible
length, bad CRC, malformed payload, invalid key/value, duplicate/unsorted writes,
or sequence gap. Truncate the unusable suffix before accepting new writes. Never
search forward for a later valid frame. Frames with `seq <= checkpoint sequence`
are obsolete and skipped, but their framing and payload must still validate.
Nonobsolete sequences must start at checkpoint sequence + 1 and be contiguous.

A checkpoint uses the same framing with magic `KVC1` and payload exactly
`{"seq":N,"items":[[KEY,VALUE],...]}` containing current live keys in sorted
order. Checkpoint must be one complete valid frame with no trailing bytes. If
present but invalid, fail startup with nonzero exit, without changing any file.
Ignore a leftover `checkpoint.tmp`. A checkpoint must fsync a temporary file,
atomically replace `checkpoint.bin`, fsync DIRECTORY, then truncate and fsync
the WAL. Keep active transaction snapshots and validation history correct across
checkpointing. Once checkpoint succeeds, WAL size must be zero.

For deterministic crash tests, read `MERIDIAN_CRASH_AT` on startup. If it is one
of the following strings, call `os._exit(86)` at the named boundary when reached:
`wal_synced` (commit fsync complete, before publishing in memory/reply),
`checkpoint_synced` (temporary checkpoint fsync complete, before replace),
`checkpoint_replaced` (replace and directory fsync complete, before WAL reset),
`wal_reset` (WAL truncation/fsync complete, before checkpoint reply).
Ordinary runs omit this variable. Crash boundaries are mandatory test hooks.

## Development and scoring

Run `python /app/store/smoke.py` for public examples. You may modify or add files
under `/app/store`; the entrypoint remains main.py. The evaluator uses fresh
directories, unseen interleavings, independent Merkle calculations, corruption
fixtures, abrupt process death and recovery in fresh processes. Six equally
weighted groups cover basic operations, snapshot visibility, serializability,
Merkle proofs, WAL recovery and checkpoint crash consistency. Each group requires
all of its checks to pass. A complete implementation earns 1.0.
