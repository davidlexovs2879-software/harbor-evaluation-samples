# Artifact broker: contain the delegated authority incident

A build coordinator used one shared artifact broker for several tenants. The
legacy transport trusted object paths and did not enforce the caller's authority.
An investigation found that delegated credentials could reach sibling release
prefixes and archive imports could escape their destination. Repair the broker
without breaking authorized builds. This is a synthetic, offline security lab;
there are no external targets or live credentials.

Implement `/app/broker/main.py` in Python 3.11, standard library only. Invocation:
`python /app/broker/main.py CONFIG_JSON STATE_DIRECTORY`. One process owns the
state directory. Read one JSON request per stdin line and emit one JSON response
per line, flushing immediately. This transport models HTTP requests without
network timing. Preserve the transport; do not add a server dependency.

CONFIG_JSON contains `secret` (a test-only UTF-8 HMAC key), `issuer`, `audience`,
`now` (fixed Unix time), and `principals`, a mapping from subject to an object
with `tenant`, `role` and `disabled`. Roles are reader, writer or admin. Tenants
and subjects are ASCII letters, digits, underscores and hyphens, length 1..64.
The evaluator supplies fresh configurations. Do not hardcode fixtures or time.

## Authentication

Bearer tokens are compact JWTs signed with HMAC-SHA256 over `header.payload`.
All three segments use canonical unpadded base64url: ASCII letters, digits,
underscore and hyphen only, with encoding round-trip equality. Reject padding,
invalid UTF-8/JSON, duplicate JSON fields at any depth, and non-object header or
payload. Compare the signature in constant time. Header must have exactly
`{"alg":"HS256","typ":"JWT","kid":"primary"}`. Do not honor an alternative
algorithm, key identifier, URL or embedded key.

Every payload has exactly these common claims: `iss`, `aud`, `sub`, `tenant`,
`iat`, `exp`, `jti`, `kind`. `iss` and `aud` must equal configuration strings.
`sub` must name an enabled principal and its configured tenant must equal `tenant`.
`iat` and `exp` are true integers: `0 <= iat <= now < exp` and `exp-iat <= 86400`.
`jti` is an ASCII identifier of length 1..64. `kind` is `session` or `capability`.
A session has no additional claims. A capability also has exactly `prefix`,
`actions` and `depth`; prefix must already be canonical, actions is a nonempty
list of distinct delegable actions, and depth is an integer in 0..2.
Invalid or disabled authentication always returns 401 `unauthorized`.

## Canonical resources and authority

Object identity is `(authenticated tenant, canonical path)`. A caller cannot
choose a tenant through a request field. A path is a UTF-8 string of at most
512 bytes after canonicalization. Decode percent escapes exactly once as strict
UTF-8, rejecting malformed escapes, then normalize Unicode to NFC. Reject any
remaining `%`, backslash, control character (Unicode category C), leading slash,
empty component, `.` or `..` component. An object path is nonempty. A prefix may
be empty, meaning the entire tenant. Otherwise prefixes follow the same rules
and have no trailing slash. Archive directory entries may have one trailing slash
removed before this validation. Canonicalization applies before policy matching.

Scope containment is on component boundaries: prefix `releases/r1` permits that
exact path and its descendants, but not `releases/r10`. A list or delegation
prefix must itself be inside the credential's prefix. Never authorize by raw
string prefix, caller-provided tenant, or an unverified token claim.

Readers may read and list. Writers may read, list, write, delete, import and
delegate. Admins additionally may audit. A capability intersects its actions
with its principal's current role and its prefix with every requested resource.
Delegable actions are read, list, write, delete, import and delegate. Audit
requires an admin session; capabilities cannot audit. Import requires both
import and write. Batch requires the action for every contained operation.

## Request/response contract

Every request has exactly `op`, `token` and the fields below. Responses are
exactly `{"status":INTEGER,"body":OBJECT}`. No extra fields are allowed.

| op | Additional fields | Success body (status 200) |
| --- | --- | --- |
| read | `path` | `{"data":STRING}` |
| list | `prefix` | `{"paths":[CANONICAL_PATH,...]}` sorted in Python string order |
| write | `path`, `data`, `request_id` | `{"ok":true}` |
| delete | `path`, `request_id` | `{"ok":true}` |
| delegate | `prefix`, `actions`, `exp`, `depth`, `request_id` | `{"token":JWT}` |
| import | `prefix`, `archive`, `request_id` | `{"count":REGULAR_FILE_COUNT}` |
| batch | `operations`, `request_id` | `{"count":OPERATION_COUNT}` |
| audit | none | `{"events":[EVENT,...]}` |

`token`, paths/prefixes, `data` and `archive` are strings. `request_id` has the
same ASCII identifier syntax as jti. Data is UTF-8, at most 65,536 bytes. Batch
contains 1..64 objects, each exactly a write (`op,path,data`) or delete (`op,path`).
Delegate actions must be a nonempty distinct list of delegable actions, and exp
and depth must be true integers. Outer request fields/types, data sizes and batch
shape are validated first; malformed JSON (including duplicate fields), unknown
fields/ops and invalid shapes return 400 `invalid` without an audit event.
Then authenticate, canonicalize resources, authorize, check replay, and execute
in that order. Invalid canonical paths return 400, forbidden authority returns
403 `forbidden`, missing reads/deletes return 404 `not_found`, and repeated
successful mutation IDs return 409 `conflict`. Denial responses must contain
only `{"error":ERROR_STRING}`. Unknown tenant resources never leak through errors.

Delegation preserves sub, tenant, issuer and audience. Issued iat equals now;
requested exp must be strictly greater than now and no later than the parent's
exp. A session has delegation depth 3 and its role's actions. A child depth must
be nonnegative and strictly less than parent depth. Requested actions must be a
subset of the parent's effective actions, and requested prefix must be contained
in the parent's prefix. Violating any attenuation rule returns 403. The child's
jti is the first 32 lowercase hex characters of
`HMAC_SHA256(secret, (parent_jti + ":" + request_id).encode("utf-8"))`.
Serialize token header/payload with sorted keys, compact separators and
`ensure_ascii=True` before base64url encoding. Children are independently usable
after process restart, and role changes in configuration still restrict them.

Archive is strict standard base64 of an uncompressed tar (at most 2 MiB decoded).
Allow regular UTF-8 files and directory entries only: reject symlinks, hardlinks,
devices, FIFOs, sparse members and other special entries. At most 128 regular
files, at most 1 MiB total regular-file bytes, and at most 65,536 bytes per file.
Reject empty imports and duplicate canonical file destinations. Prefix the
validated relative member path with the authorized import prefix, then verify
scope again. Validate the entire archive before writing anything. Invalid tar,
bad base64, unsafe members or exceeded limits return 400. Files overwrite prior
objects only after all members pass. Directories create no stored objects.

Batch runs in order against a private copy of tenant state. Validate and authorize
all paths/actions before executing; on the first missing delete, return 404 and
discard the entire copy. Failed imports/batches must leave no partial changes.
Successful write, delete, import, batch and delegate consume request_id in the
namespace `(tenant, sub, request_id)`, across operations and credential rotations.
Failed requests consume no ID. Reads, lists and audit have no replay ID.

## Durable audit and restart behavior

Every well-shaped request except audit appends one event, including authentication
and policy failures. Audit never appends an event, even if denied. Event fields
are exactly `seq`, `op`, `sub`, `tenant`, `path`, `status`, `previous`, `hash`.
Sequence starts at 1. For failed authentication sub and tenant are null; otherwise
use verified identity. Path is canonical path/prefix for single-resource requests
after successful canonicalization, otherwise null; batch always uses null.
The first previous value is 64 zeroes. Each later previous is the preceding hash.
Hash is SHA-256 of the UTF-8 JSON event excluding hash, serialized with sorted
keys, compact separators and ensure_ascii=True. No token, data or archive may
appear in the audit. Persist object changes, consumed IDs and their audit event
atomically before responding; acknowledged state must survive immediate SIGKILL.

Keep durable state entirely in STATE_DIRECTORY, using JSON (no pickle, eval,
exec, SQLite or external services). The on-disk schema is your choice. Corrupt
state must cause nonzero startup exit without overwriting evidence. The evaluator
copies directories and restarts the broker with new configurations. A single
command must finish within five seconds; scenarios use at most 500 objects and
2,000 audit events. You may add files under `/app/broker`.

## Development and scoring

`python /app/broker/smoke.py` exercises one authorized workflow and one denial.
The evaluator replays fresh signed requests, unsigned/forged credentials, Unicode
and encoded paths, delegation chains, hostile tar members, mixed-authority batches,
and process restarts. Six equally weighted groups cover authentication, isolation,
delegation, archives, atomic replay handling and audit durability. Each group
requires all checks to pass, including legitimate operations, so denying every
request earns no credit. Full repair earns 1.0. This lab measures executable
security behavior; a prose incident report is not required.
