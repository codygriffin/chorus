# Chorus MVP Implementation Specification

**Name:** Chorus  
**Status:** Implementation baseline  
**Date:** 8 August 2026  
**Target:** resource-constrained Linux hosts on `x86_64` and `aarch64`  
**Primary client interface:** PostgreSQL wire protocol, usable through `psql` and ordinary PostgreSQL drivers  
**Implementation language:** Rust

The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

---

## 1. Executive decision

Chorus is a small, fully replicated distributed SQL database for resource-constrained deployments with a handful of Linux hosts.

Every participating host runs the same monolithic process. Every process:

- accepts local PostgreSQL connections;
- parses, plans, and executes SQL;
- holds a complete local copy of the database;
- participates in, or follows, one Raft group;
- can serve strict reads from a local storage snapshot after a linearizable read barrier;
- can accept a transaction locally and forward its commit to the current Raft leader.

The MVP has one serialization domain and one replicated state machine. It deliberately has:

- no sharding;
- no range leases;
- no distributed query execution;
- no distributed two-phase commit;
- no intents;
- no hybrid logical clocks;
- no multi-tenancy or row-level security;
- no separate database appliance.

Concurrency control is **global-epoch optimistic concurrency control**:

1. A transaction takes a linearizable local snapshot at database epoch `E`.
2. It executes entirely against that snapshot plus a local write overlay.
3. At commit, its mutation batch is ordered through Raft.
4. The replicated state machine accepts the batch only if the current database epoch is still `E`.
5. A successful mutation batch applies atomically and advances the epoch to `E + 1`.
6. Otherwise the transaction aborts with PostgreSQL SQLSTATE `40001`.

This is intentionally conservative. Two unrelated write transactions based on the same snapshot cannot both commit without retry. For the intended low-to-moderate write rate, that is a better first trade than importing the machinery of a sharded distributed database.

---

## 2. Motivation

Many applications need a small, strongly consistent relational database but do not need the operational or architectural weight of a general-purpose distributed database platform.

The target environment already has at least three Linux hosts that run the primary application. Requiring a separate database appliance, Kubernetes cluster, managed edge service, or dedicated VM adds:

- deployment work;
- hardware and infrastructure cost;
- another failure domain;
- patching and monitoring burden;
- extra network dependencies;
- another service that must be discovered, configured, and recovered.

Chorus makes the existing hosts the database cluster. A colocated application connects to a local PostgreSQL endpoint; Chorus replicates durable relational state across the participating nodes and hides leader placement from clients.

The intended workload is small-to-moderate, durable OLTP and coordination state. The design deliberately spends scale in exchange for a much smaller implementation and operational model: every replica stores the whole database, and one Raft group orders every committed mutation.

This database is not intended to be a telemetry lake, event-stream platform, object store, analytical warehouse, or hard real-time control component. Large or high-frequency data belongs elsewhere.

## 3. Goals

### 3.1 Functional goals

The MVP MUST:

1. Run as one Rust process per participating host.
2. Form a three-node or five-node Raft cluster.
3. Permit every healthy node, including learners, to accept PostgreSQL connections.
4. Work with `psql` and ordinary PostgreSQL drivers.
5. Support a documented PostgreSQL SQL subset sufficient to:
   - create and evolve tables;
   - create primary and secondary indexes;
   - insert, select, update, and delete rows;
   - execute prepared statements;
   - run autocommit and explicit multi-statement transactions;
   - perform conditional state transitions atomically using DML and `RETURNING`.
6. Provide strict serializability for all supported SQL transactions.
7. Keep a complete copy of the logical database on every replica.
8. Continue strict operation while a Raft majority is mutually reachable.
9. Reject new strict work rather than serve stale data when no majority can be confirmed.
10. Recover automatically after process crash, power loss, leader change, follower lag, and snapshot installation.
11. expose enough catalog metadata for useful `psql` inspection, including `\dt` and basic `\d`.
12. provide an administration interface for status, membership, snapshots, backup, and recovery.

### 3.2 Non-functional goals

Priority order is:

1. **Simplicity and auditability**
2. **Correctness**
3. **Resource usage**
4. **Latency**
5. **Throughput**
6. Breadth of PostgreSQL compatibility

The process MUST be resource-light enough to coexist with the primary application on the same host. It MUST have bounded:

- storage cache;
- query memory;
- active query workers;
- connection count;
- transaction age;
- transaction mutation size;
- result size;
- Raft message size;
- snapshot bandwidth.

Background maintenance MUST be bounded, observable, and subordinate to foreground query and replication work.

### 3.3 Product success criteria

The MVP is successful when:

- three or five independent processes can be launched with separate disks and ports;
- every process accepts `psql`;
- schema and writes performed through one node are immediately observable by a new transaction through every other healthy node;
- transaction anomaly and strict-serializability tests pass;
- a majority continues through minority failure and partition;
- minority nodes reject new strict reads and writes;
- killed nodes restart and converge without manual repair;
- every acknowledged write survives leader loss and ordinary crash recovery;
- resource and latency gates in this specification pass on the reference platform.

---

## 4. Non-goals

The MVP MUST NOT attempt to provide:

- horizontal write scaling;
- data sharding or range partitioning;
- multi-region placement;
- distributed scans or joins;
- tenant isolation;
- row-level security;
- multiple administrative roles;
- foreign keys;
- general `CHECK` constraints;
- triggers;
- stored procedures;
- user-defined functions;
- extensions;
- logical or physical PostgreSQL replication;
- PostgreSQL WAL compatibility;
- full `pg_dump` compatibility;
- materialized views;
- partitioned tables;
- recursive CTEs;
- window functions;
- advisory locks;
- `SELECT ... FOR UPDATE`;
- savepoints;
- prepared distributed transactions;
- sequences or `SERIAL`;
- online schema changes;
- `CREATE INDEX CONCURRENTLY`;
- arbitrary collations;
- hard-real-time control paths;
- high-rate telemetry, logs, media streams, bulk objects, or other write-heavy event data.

The architecture SHOULD leave clean seams for better conflict granularity later. It MUST NOT implement those future mechanisms prematurely.

---

## 5. Workload and deployment contract

### 5.1 Intended data

Appropriate replicated data includes:

- transactional application state;
- workflow and job state;
- configuration and control-plane records;
- durable ownership or lease records;
- idempotency keys;
- outbox and inbox records;
- small relational metadata;
- artifact or object references;
- low-rate lifecycle and audit events.

Inappropriate replicated data includes:

- high-rate telemetry;
- logs and traces better shipped elsewhere;
- media streams;
- bulk binary objects;
- append-heavy event streams;
- model or analytical datasets;
- high-frequency control data;
- ephemeral heartbeat traffic.

High-frequency heartbeats SHOULD remain soft state outside Chorus. Durable state transitions derived from liveness MAY be committed when they matter to application correctness.

### 5.2 Supported scale for the MVP

The implementation and release tests target:

- 3 or 5 voting replicas;
- up to 16 total replicas including learners;
- up to 32 PostgreSQL sessions per node by default;
- up to 8 concurrently executing queries per node, with a default of 2–4 workers;
- a logical database up to 1 GiB as the primary release envelope;
- validation testing up to 10 GiB;
- rows up to 256 KiB by default, configurable to 1 MiB;
- transactions up to 4 MiB of replicated mutations by default;
- expected steady write rate below 50 committed transactions per second;
- short bursts of several hundred autocommit writes per second on suitable storage;
- ordinary transactions shorter than one second;
- a default maximum transaction lifetime of 30 seconds.

These are product boundaries, not theoretical limits.

### 5.3 Network assumptions

Consensus nodes require:

- routable bidirectional TCP connectivity;
- stable node identity independent of IP address;
- mutual TLS for all internal traffic;
- enough connectivity for a majority to communicate.

Correctness MUST NOT depend on multicast, broadcast, NTP accuracy, bounded network delay, or synchronized node clocks.

### 5.4 Failure and trust model

Chorus is crash-fault tolerant, not Byzantine-fault tolerant. It assumes:

- a process, node, disk, or network path may stop, restart, partition, delay, duplicate, or reorder traffic;
- storage may return an explicit I/O error;
- a valid cluster member runs the intended Chorus binary and does not deliberately forge commands;
- cluster PKI and host hardening are responsible for excluding unauthorized members.

Compromise of an authenticated member is outside the consensus threat model and may compromise the database. Internal mTLS prevents outsiders and cross-cluster confusion; it does not turn Raft into a Byzantine protocol.

---

## 6. Required invariants

The following are hard invariants.

1. **One logical state:** All replicas that have applied the same committed log prefix have the same logical database state.
2. **Atomic apply:** A transaction’s catalog, row, index, epoch, deduplication, and applied-index changes are applied in one local storage transaction.
3. **Monotonic epoch:** `db_epoch` increases by exactly one for each successful state-changing SQL transaction and never for an abort, duplicate, or read-only transaction.
4. **No stale strict transaction start:** A transaction that reads database state begins only after a quorum-confirmed Raft read barrier and local catch-up.
5. **No stale write acceptance:** A write transaction commits only when its `base_epoch` equals the state machine’s current `db_epoch`.
6. **No duplicate effects:** Re-submitting the same internal request never applies its mutations twice.
7. **Durability after acknowledgement:** Once `COMMIT` is acknowledged, the command is durably represented on a Raft quorum.
8. **No minority progress:** A node unable to confirm a majority cannot start a new strict transaction or commit one.
9. **Deterministic state machine:** Replicated apply does not consult wall clocks, randomness, environment variables, local node state, or network services.
10. **Stable encodings:** Persisted rows, keys, commands, and snapshots are explicitly versioned.
11. **Membership continuity:** State-machine snapshots and installs preserve OpenRaft's last-applied log ID and stored membership exactly.
12. **Crash-safe request identity:** Every process boot activates a fresh origin before writes, so an internal request ID is never reused after a crash, replacement, or ambiguous commit.
13. **Bounded resources:** Every user-controlled allocation has a configured limit or participates in a global budget.
14. **No hard-real-time coupling:** Loss of Chorus quorum MUST NOT be placed on a hard-real-time or availability-critical local control path.

Any violation is a release blocker.

---

## 7. Cluster topology

### 7.1 Roles

A node is either:

- **voter:** participates in elections and quorum;
- **learner:** receives the full log and state but does not count toward quorum.

Both roles:

- store a full database copy;
- accept local PostgreSQL connections;
- execute reads locally after a barrier;
- forward commits to the leader.

Recommended topology:

| Cluster size | Voters | Learners |
|---:|---:|---:|
| 3 | 3 | 0 |
| 4 | 3 | 1 |
| 5–7 | 5 | remainder |
| 8+ | 5 | remainder |

Voters SHOULD be nodes with the best expected uptime, storage, and network conditions. Membership MUST NOT churn in response to ordinary network flapping.

### 7.2 Quorum behavior

- Three voters tolerate one unavailable voter.
- Five voters tolerate two unavailable voters.
- A majority partition may continue.
- A minority partition MUST reject new catalog/table reads and all writes.
- Cluster-independent expressions and session diagnostics such as `SELECT 1`, `SHOW application_name`, and `version()` MAY succeed without quorum because they observe no replicated state. They MUST be clearly separated from database reads in the executor.
- Existing pinned read-only transactions MAY finish within their transaction deadline because they can serialize at their existing snapshot.
- Existing read-write transactions on a minority MUST fail to commit.
- Application behavior outside Chorus continues according to application policy.

### 7.3 Monolithic node layout

```text
+---------------------------------------------------------------+
| Chorus process                                               |
|                                                               |
| PostgreSQL listener(s)                                        |
|   -> session / protocol state                                 |
|   -> parser -> binder -> planner -> executor                  |
|                         |                                     |
|                         v                                     |
|                 transaction snapshot + overlay                |
|                         |                                     |
|          +--------------+----------------+                    |
|          |                               |                    |
|   local redb snapshot             commit sequencer            |
|                                          |                    |
|                                  consensus adapter             |
|                                          |                    |
|              +---------------------------+----------------+   |
|              | OpenRaft | peer RPC | read barriers        |   |
|              +---------------------------+----------------+   |
|                                          |                    |
|                                replicated state machine        |
|                                          |                    |
|                           raft.redb     state.redb              |
|                                                               |
| admin/status/metrics/snapshot manager                          |
+---------------------------------------------------------------+
```

There are no separate SQL, transaction, metadata, or storage services.

---

## 8. Transaction and consistency design

### 8.1 Isolation level

Chorus exposes one isolation level: **strict serializable**.

Requests for PostgreSQL `SERIALIZABLE`, `REPEATABLE READ`, `READ COMMITTED`, or `READ UNCOMMITTED` MAY be accepted, but the implementation always provides the stronger Chorus semantics. `SHOW transaction_isolation` SHOULD report `serializable`.

Applications MUST be prepared to retry SQLSTATE `40001`, as with PostgreSQL serializable transactions.

### 8.2 Transaction state

Each SQL session has one of:

```rust
enum SessionTxnState {
    Idle,
    InTransaction(Transaction),
    FailedTransaction(Transaction),
}
```

A transaction contains:

```rust
struct Transaction {
    transaction_id: [u8; 16],
    snapshot: Option<Arc<ReadSnapshot>>,
    base_epoch: Option<u64>,
    base_log_id: Option<LogId>,
    overlay: BTreeMap<PhysicalKey, Option<PhysicalValue>>,
    frozen_values: RetryValueMap,
    transaction_timestamp_us: i64,
    statement_timestamp_us: i64,
    statement_ordinal: u32,
    started_at: Instant,
    mutation_bytes: usize,
    mutation_count: usize,
    read_only: bool,
}
```

`None` in the overlay is a tombstone.

A snapshot is acquired lazily on the first operation that reads catalog or table state. `BEGIN` itself need not contact the cluster.

### 8.3 Linearizable snapshot acquisition

To acquire a snapshot on any node:

1. The node submits a read-barrier request to the current leader.
2. The leader invokes OpenRaft’s linearizable-read mechanism.
3. The leader confirms leadership by contacting a quorum and returns a `read_log_id`.
4. The requesting node waits until its local state machine has applied at least `read_log_id`.
5. The node opens a `redb::ReadTransaction`.
6. From that exact snapshot, it reads:
   - `last_applied_log_id`;
   - `db_epoch`;
   - `catalog_epoch`.
7. Those values become the transaction’s actual base version.

The local state may advance between steps 4 and 5. That is safe: the opened snapshot is simply newer than the barrier.

Read barriers MUST be coalesced while one barrier is in flight. A completed barrier MUST NOT be cached for requests that arrive later. Reusing a completed barrier could violate real-time ordering.

A query such as `SELECT 1` that touches no database state MAY execute without a barrier.

### 8.4 Local reads and read-your-writes

All table and index reads use a transaction-aware storage facade:

```rust
trait TransactionalRead {
    fn get(&self, key: &[u8]) -> Result<Option<Bytes>>;
    fn scan(&self, range: KeyRange) -> Result<RowCursor>;
}
```

Behavior:

- point reads check the overlay before the base snapshot;
- range scans merge the ordered base iterator with the ordered overlay;
- overlay puts replace base values;
- overlay tombstones hide base values;
- all statements in an explicit transaction observe one pinned snapshot plus prior writes.

No read-set tracking is required in the global-epoch MVP.

### 8.5 Local writes

DML produces canonical physical mutations in the overlay:

- row puts and deletes;
- primary-key changes;
- secondary-index puts and deletes;
- exact table row-count updates;
- catalog mutations where permitted.

Constraint checks are evaluated against snapshot plus overlay.

Each DML statement MUST have stable statement semantics:

- determine its target primary keys from the transaction view at statement start;
- do not revisit a row merely because the statement changes an indexed key;
- evaluate `UPDATE` expressions from the old row and expose the new row to `RETURNING`;
- roll back every mutation produced by the statement if statement execution fails;
- in an explicit transaction, any statement error moves the whole transaction to failed state because savepoints do not exist.

Implement this with a statement-local overlay/checkpoint or by collecting target row keys in bounded batches before mutating the transaction overlay. The executor MUST avoid Halloween-style repeated updates.

Before commit, mutations MUST be:

- sorted by physical key;
- deduplicated;
- checked against per-row, per-transaction, and message-size limits;
- encoded in a stable versioned format.

### 8.6 Commit request

The logical command is:

```rust
struct CommitTransactionV1 {
    request_id: RequestId,
    payload_hash: [u8; 32],
    base_epoch: u64,
    mutations: Vec<KvMutationV1>,
}

struct OriginId {
    node_id: u64,
    boot_nonce: [u8; 16],
}

struct RequestId {
    origin: OriginId,
    sequence: u64,
}

enum KvMutationV1 {
    Put { key: Bytes, value: Bytes },
    Delete { key: Bytes },
}

enum ReplicatedCommandV1 {
    ActivateOrigin(ActivateOriginV1),
    CommitTransaction(CommitTransactionV1),
    SchemaChange(SchemaCommandV1),
}

struct SchemaCommandV1 {
    request_id: RequestId,
    payload_hash: [u8; 32],
    base_epoch: u64,
    operation: SchemaOperationV1,
}

enum SchemaOperationV1 {
    CreateTable(CreateTableSpecV1),
    DropTable { table_id: u32, expected_version: u32 },
    AddColumn(AddColumnSpecV1),
    DropColumn { table_id: u32, column_id: u32, expected_version: u32 },
    RenameTable { table_id: u32, new_name: String, expected_version: u32 },
    RenameColumn { table_id: u32, column_id: u32, new_name: String, expected_version: u32 },
    CreateIndex(CreateIndexSpecV1),
    DropIndex { index_id: u32, expected_table_version: u32 },
}
```

Ordinary DML commits canonical physical mutations. DDL uses a compact semantic `SchemaCommandV1` so index creation and logical object deletion do not place an entire table rewrite in the Raft log. Schema commands carry the same origin request ID, payload hash, and base epoch. After validation, every replica performs the same deterministic catalog/row scan and atomic local change. Names, expected descriptor versions, and all resolved defaults are carried explicitly; object IDs are allocated from replicated catalog metadata during apply.

### 8.7 Per-origin commit sequencing and deduplication

Every process start generates a fresh random 128-bit `boot_nonce` from the operating-system CSPRNG. Together with the stable Raft node ID, it forms the process `OriginId`. A local data-directory lock prevents two processes from intentionally sharing one installation; origin fencing remains the distributed backstop.

Before accepting write transactions, the process submits an internal, idempotent command:

```rust
struct ActivateOriginV1 {
    origin: OriginId,
}
```

The leader accepts activation only from the authenticated Raft node named by `origin.node_id`. In Raft order, activation:

- is a no-op when the same origin is already active;
- otherwise fences the previous origin for that node;
- installs the new origin with `last_sequence = 0` and an empty result ring;
- does not advance `db_epoch` because it changes no SQL-visible state.

This is the crash boundary. If an old process had an ambiguous command, Raft orders it either before activation, in which case it may apply once, or after activation, in which case it is rejected as `StaleOrigin`. No local per-commit fsync or pending-request journal is required.

Each active process has one in-memory `CommitSequencer`. The sequencer:

- permits many transactions to execute concurrently;
- permits only one unresolved replicated command from that origin at a time;
- assigns contiguous sequence numbers beginning at 1;
- retains the exact encoded pending command in memory;
- retries an uncertain request with the same request ID and exact payload bytes;
- assigns the next sequence only after the prior sequence has a definite result.

The replicated state stores one bounded record per Raft node:

```rust
struct NodeOriginState {
    active_origin: OriginId,
    last_sequence: u64,
    recent_results: RingBuffer<RequestResult, 16>,
}

struct RequestResult {
    sequence: u64,
    payload_hash: [u8; 32],
    result: ApplyResult,
}
```

State-machine rules for a transaction command:

- origin is not the active origin for its node: return `StaleOrigin`, never apply;
- `sequence == last + 1`: process, advance `last_sequence`, and record the deterministic result;
- recent duplicate with matching hash: return the recorded result;
- duplicate with a different hash: return an internal protocol error and never apply;
- older duplicate outside the ring: return `AlreadyProcessed`, never apply;
- sequence gap: reject as an internal protocol error.

Every deterministic terminal result for a valid next sequence—including commit, serialization failure, and command rejection—consumes and records that sequence. A local storage failure does not fabricate a result.

A process restart always activates a new origin and waits for that activation to be locally applied before advertising write readiness. A `StaleOrigin` result means another process has fenced this process; it MUST stop accepting writes and report unhealthy rather than automatically fighting to reactivate. A lost client connection may leave an outcome unknown, as ordinary PostgreSQL connections can, but it cannot cause duplicate effects or sequence reuse. The active-origin table is bounded by Raft membership rather than cluster lifetime.

The `payload_hash` is BLAKE3 over the canonical command version, request ID, base epoch, and mutation payload; the hash field itself is excluded from the hashed bytes.

### 8.8 Replicated apply algorithm

The state machine handles all OpenRaft entry payloads:

- blank/no-op entry: update `last_applied_log_id`;
- membership entry: atomically update `stored_membership` and `last_applied_log_id`;
- origin activation: install/fence the node origin and update `last_applied_log_id`;
- transaction or schema command: execute the validation/epoch algorithm below, then apply its deterministic command body.

At committed Raft log index `L`, for a transaction or schema command:

```text
begin one state.redb write transaction

load node origin state

if request origin is stale:
    update last_applied_log_id = L
    commit
    return StaleOrigin

if request is a known duplicate:
    update last_applied_log_id = L
    commit
    return cached result

if request sequence is invalid:
    update last_applied_log_id = L
    commit
    return protocol error

validate canonical payload hash, command version, key prefixes, ordering,
mutation limits, and integer overflow

if validation rejects the command:
    record terminal rejection and advance origin sequence
    update last_applied_log_id = L
    commit
    return rejection

if command.base_epoch != db_epoch:
    result = SerializationFailure {
        expected: command.base_epoch,
        actual: db_epoch
    }
    record terminal result and advance origin sequence
    update last_applied_log_id = L
    commit
    return result

apply the deterministic command body:
    - transaction: apply every mutation in key order
    - schema change: apply catalog change and any bounded deterministic scan
checked_increment(db_epoch)
record terminal result and advance origin sequence:
    Committed { epoch: db_epoch, log_id: L }
update last_applied_log_id = L

commit state.redb transaction
return result
```

Blank, membership, origin-activation, rejected, aborted, duplicate, and successful entries all advance `last_applied_log_id`. Only a successful state-changing SQL command advances `db_epoch`. Membership and origin activation do not.

A storage error during apply is fatal to that replica. It MUST stop serving strict SQL, report unhealthy, and recover or rejoin. It MUST NOT invent a different logical result.

### 8.9 Read-only commit

A transaction with no mutations requires no Raft command. It closes its snapshot and succeeds. It serializes at its snapshot version.

An `UPDATE` or `DELETE` matching zero rows is read-only for this purpose.

### 8.10 Strict-serializability argument

Let a transaction read snapshot epoch `E`.

A successful write transaction changes the epoch exactly once, in Raft order.

A read-write transaction based on `E` is accepted only if the state machine is still at `E`. Therefore no successful state-changing transaction occurred between its snapshot and its apply. Its reads are exactly the state immediately preceding its write. It can be serialized at its atomic apply point.

A read-only transaction can be serialized at its snapshot.

The read barrier ensures a transaction begun after an acknowledged commit cannot take a snapshot preceding that commit. Consequently the serial order respects real-time order.

This proof depends on the invariants in Section 6. Any optimization that weakens them requires a new proof and new verification.

### 8.11 Retry policy

Autocommit statements MAY be retried internally on `40001` when they are classified as retry-safe.

Default policy:

- maximum 8 attempts;
- maximum total retry time 250 ms;
- exponential backoff with small jitter;
- acquire a fresh barrier and re-execute the statement each attempt;
- preserve the transaction ID, statement timestamp, resolved stable defaults, and other frozen retry values while discarding the old snapshot and overlay.

Internal retry is forbidden when the statement contains an unsupported volatile operation or has exposed an external side effect.

Explicit multi-statement transactions MUST NOT be replayed invisibly. They return `40001` and the client retries the whole transaction.

### 8.12 Time and volatile functions

Clocks do not determine ordering.

The gateway evaluates time functions:

- `transaction_timestamp()` / `now()`: fixed at transaction start;
- `statement_timestamp()`: fixed when the query message is received;
- `clock_timestamp()`: unsupported in the MVP.

Resolved values are stored in mutations before replication.

Random SQL functions are unsupported in the MVP. Internal identifiers needed by execution—such as hidden row IDs—are generated once from the transaction's 128-bit ID plus statement and row ordinals and are frozen across an internal retry. User-defined functions do not exist in the MVP.

### 8.13 Transaction limits

Defaults:

| Limit | Default |
|---|---:|
| maximum transaction age | 30 s |
| idle-in-transaction timeout | 15 s |
| maximum mutation bytes | 4 MiB |
| maximum mutations | 10,000 |
| maximum single row | 256 KiB |
| maximum SQL message | 1 MiB |
| maximum autocommit `RETURNING` buffer | 8 MiB |
| maximum retry attempts | 8 |

A limit breach returns an appropriate PostgreSQL program-limit SQLSTATE and aborts the transaction. Epochs, request sequences, object IDs, schema versions, and row counters use checked arithmetic; exhaustion fails closed with an internal/program-limit error rather than wrapping.

---

## 9. Consensus and replication

### 9.1 Consensus library

Use **OpenRaft 0.9.x**, pinned to the exact tested patch release. The researched implementation baseline is `0.9.25`. Do not use the `0.10` alpha line for the MVP.

OpenRaft is wrapped behind an internal interface:

```rust
#[async_trait]
trait Consensus {
    async fn read_barrier(&self, deadline: Instant) -> Result<LogId>;
    async fn submit(
        &self,
        command: ReplicatedCommand,
        deadline: Instant,
    ) -> Result<ApplyResult>;
    async fn wait_applied(&self, log_id: LogId, deadline: Instant) -> Result<()>;
    fn status(&self) -> ConsensusStatus;
}
```

No SQL or transaction crate may depend directly on OpenRaft types beyond the adapter crate.

### 9.2 One Raft group

There is one Raft group for:

- catalog;
- table data;
- indexes;
- transaction ordering;
- schema changes;
- origin deduplication;
- cluster membership metadata, including OpenRaft's stored membership.

There is no separate metadata group.

### 9.3 Commit acknowledgement

`COMMIT` is acknowledged after:

1. the command is committed according to Raft;
2. the leader state machine has applied it and produced a definite result.

The gateway replica need not have applied the entry before replying. The next transaction on that gateway performs a barrier and local catch-up, preserving read-after-commit behavior.

If a client loses the connection after submission but before receiving the result, the outcome may be ambiguous. Repeating the same internal request ID resolves the result without duplicate effects. A SQL client whose process connection vanished may receive SQLSTATE `08007` or a connection error and must treat the transaction as outcome-unknown.

### 9.4 Elections

Initial defaults:

- heartbeat interval: 250 ms;
- election timeout: randomized 1.2–2.4 s;
- pre-vote: enabled;
- automatic leader transfer on graceful shutdown: enabled where possible.

These values are configurable and MUST be validated on the actual deployment network. Leadership leases MUST NOT be used for SQL correctness in the MVP.

### 9.5 Internal transport

Use Tokio plus Tonic/Prost over persistent HTTP/2 connections.

Services:

- Raft vote;
- Raft append;
- Raft snapshot install;
- forwarded client command;
- read barrier;
- node status;
- controlled membership operations.

Requirements:

- mutual TLS with Rustls;
- one persistent multiplexed channel per peer;
- bounded request and response queues;
- maximum ordinary message size of 8 MiB;
- streaming snapshots in bounded chunks;
- deadlines on every RPC;
- backpressure rather than unbounded task creation;
- cluster ID and node ID validation from certificate identity and message envelope.

A bespoke transport MAY replace Tonic only after profiling proves material benefit. It is not an MVP science project.

### 9.6 Bootstrap

Static bootstrap is the MVP path.

Every initial node receives the same signed manifest containing:

- cluster ID;
- cluster incarnation;
- stable node IDs;
- node IDs;
- initial voter set;
- initial endpoint seeds;
- CA and certificate references.

Only the deterministic bootstrap node, normally the lowest node ID, may initialize an empty cluster. Other nodes wait and join. Bootstrap is an explicit administrative action; ordinary `run` MUST never create a fresh cluster merely because peers are unreachable. Initialization MUST be rejected if local durable state already belongs to another cluster or incarnation. The bootstrap node MUST initialize the signed initial voter set and MUST NOT report strict readiness until a quorum of that set is operational.

### 9.7 Address changes

Raft membership identifies stable node IDs, not IP addresses.

Endpoint resolution is a separate peer-directory concern. The MVP may use static addresses. Production integration SHOULD obtain current endpoints from the existing deployment peer-discovery mechanism. An IP change MUST NOT itself require a Raft membership change.

### 9.8 Membership changes

Membership changes are explicit administrative operations:

1. add new node as learner;
2. transfer snapshot and catch up;
3. verify health and lag;
4. promote to voter if desired;
5. remove or demote the old voter.

The system MUST NOT automatically promote, demote, add, or remove voters based only on liveness timeouts. Applying a final member-removal entry MAY delete that node's active-origin record; commands from nonmembers are rejected before proposal and again by deterministic state-machine validation.

---

## 10. Storage engine

### 10.1 Storage choice

Use **redb 4.x**, with the implementation baseline pinned to `4.1.0`.

Reasons:

- pure Rust;
- ACID local transactions;
- copy-on-write B-trees;
- concurrent MVCC readers with one writer;
- ordered key iteration;
- crash-safe transaction format;
- explicit cache sizing;
- no C++ runtime or autonomous compaction thread farm.

The single local writer matches the single replicated state-machine apply stream.

The storage layer MUST remain behind a narrow trait so redb can be replaced if recovery, space amplification, or performance gates fail.

### 10.2 Files

```text
<data-dir>/
    identity.toml
    raft.redb
    state/
        active.redb
        snapshots/
        install/
    tmp/
```

`identity.toml` contains immutable installation identity, including cluster binding and Raft node ID. A process boot nonce is ephemeral and becomes durable only through replicated origin activation. Secrets remain in protected key files, not this document.

`raft.redb` contains:

- vote and term state;
- log entries;
- last-purged log ID;
- OpenRaft log metadata.

`state/active.redb` contains:

- logical catalog;
- rows;
- indexes;
- database and catalog epochs;
- last-applied log ID;
- OpenRaft stored membership;
- origin deduplication state;
- logical format metadata.

Raft log and SQL state MUST use separate files so state-machine application cannot block or deadlock Raft log persistence.

### 10.3 Cache sizing

redb’s cache MUST be explicitly configured; its library default is inappropriate for a resource-constrained host process.

Initial defaults:

- `state.redb`: 32 MiB;
- `raft.redb`: 8 MiB.

Both are configurable. The sum participates in the process memory budget.

### 10.4 Durability model

Raft log and vote persistence use redb `Durability::Immediate`.

Two state-apply modes exist:

#### Correctness baseline

`state_apply_durability = immediate`

Every state-machine apply is immediately durable. This is the initial bring-up and diagnostic mode.

#### Production target

`state_apply_durability = raft-backed`

- state-machine applies use `Durability::None`;
- data and `last_applied_log_id` remain atomic and immediately visible;
- acknowledged durability comes from the quorum-durable Raft log;
- a local immediate checkpoint runs periodically, on graceful shutdown, and before any log purge;
- after crash, entries newer than durable `last_applied_log_id` replay from the Raft log.

Before purging any log entry `<= S`, the node MUST have either:

- an immediately durable state checkpoint through `S`; or
- a validated, fsynced local snapshot through `S` and a tested recovery path that installs it.

The production mode is enabled only after the crash/replay verification gate passes.

### 10.5 redb tables

Use a small number of typed redb tables:

```rust
const META: TableDefinition<&[u8], &[u8]>;
const KV: TableDefinition<&[u8], &[u8]>;
```

`META` contains fixed system records.

`KV` contains all catalog, row, and index keys in one ordered logical keyspace. A unified keyspace simplifies scans, snapshots, hashing, and mutation application.

### 10.6 Physical keyspace

Normative prefixes:

```text
0x10 | schema-name   | normalized-name
0x11 | table-name    | schema-id | normalized-name
0x12 | table-desc    | table-id
0x13 | index-name    | table-id  | normalized-name
0x14 | index-desc    | index-id
0x20 | row           | table-id  | encoded-row-key
0x21 | index         | index-id  | encoded-index-key | encoded-row-key
0x22 | unique-index  | index-id  | encoded-index-key
0x30 | virtual/system reserved
```

System metadata such as epochs and request origins remains in `META`.

IDs are unsigned 32-bit object IDs in the MVP so they can map cleanly to PostgreSQL OID fields. A replicated `next_object_id` allocator is part of catalog metadata; schema commands allocate deterministically during apply. IDs are monotonic, checked for exhaustion, and never reused.

### 10.7 Memcomparable key encoding

Key encoding MUST preserve the SQL sort order lexicographically.

Required rules include:

- signed integers: big-endian after sign-bit transformation;
- UUID: raw 16-byte order;
- timestamps: signed integer transformation;
- booleans: fixed single-byte order;
- text: UTF-8 bytes with escaping and terminator;
- composite keys: field type tag, null marker, escaped value, terminator;
- descending indexes: bytewise inversion of the encoded field;
- NULL ordering: explicitly encoded according to index definition;
- floats: one documented total order, including canonical NaN behavior.

Only binary `C` collation is supported. Indexed string ordering is bytewise UTF-8 ordering.

`MemComparableV1` uses these normative framing rules:

- fixed-width numeric values use the transformations above with no terminator;
- variable bytes escape `0x00` as `0x00 0xFF` and terminate with `0x00 0x00`;
- each nullable field begins with an explicit NULL/non-NULL marker chosen to implement the index's NULL ordering;
- descending fields invert every encoded field byte after NULL handling;
- composite values concatenate fields exactly in descriptor order;
- a physical key may not exceed 8 KiB and an indexed value may not exceed 4 KiB by default.

Codec properties MUST be property-tested: SQL comparator ordering and encoded byte ordering must agree. Golden vectors are part of the persistent-format contract.

### 10.8 Row encoding

Rows use stable column IDs:

```rust
struct EncodedRowV1 {
    format_version: u8,
    schema_version: u32,
    fields: Vec<(ColumnId, EncodedDatum)>,
}
```

Requirements:

- fields sorted by column ID;
- absent nullable fields decode as NULL or their nonvolatile default according to schema version;
- dropped columns are ignored;
- unknown format versions fail explicitly;
- maximum row size is checked before allocation.

Tables without an explicit primary key receive an internal 128-bit hidden row ID derived deterministically from:

```text
transaction ID | statement ordinal | row ordinal
```

The derivation uses a domain-separated hash and is frozen across an internal autocommit retry. Collision is checked as a normal primary-key conflict. This avoids a distributed sequence and does not require knowing the eventual commit request sequence while the statement executes.

### 10.9 Catalog

Catalog descriptors include:

```rust
struct TableDescriptor {
    oid: u32,
    schema_oid: u32,
    name: String,
    schema_version: u32,
    columns: Vec<ColumnDescriptor>,
    primary_key: Option<IndexDescriptorRef>,
    secondary_indexes: Vec<IndexDescriptorRef>,
    row_count: u64,
    state: ObjectState,
}

struct ColumnDescriptor {
    id: u32,
    name: String,
    data_type: DataType,
    nullable: bool,
    default: Option<ConstantOrStableDefault>,
    state: ColumnState,
}

struct IndexDescriptor {
    oid: u32,
    table_oid: u32,
    name: String,
    columns: Vec<IndexColumn>,
    unique: bool,
    state: IndexState,
}
```

`catalog_epoch` advances on successful schema changes. Prepared plans record it and rebind when it changes.

Default catalog limits are 1,024 live tables, 256 columns per table, 32 indexes per table, 16 key columns per index, and 63 UTF-8 bytes per identifier. Breaches fail cleanly before replication.

### 10.10 Indexes

The MVP supports:

- primary-key indexes;
- nonunique secondary indexes;
- simple unique secondary indexes;
- ascending or descending key columns;
- exact and range scans on a leading index prefix.

It does not support:

- expression indexes;
- partial indexes;
- included columns;
- GIN/GiST/BRIN;
- arbitrary collations;
- concurrent index build.

DML MUST maintain row and index entries in one transaction mutation batch.

PostgreSQL-compatible unique NULL behavior SHOULD be implemented: NULL-containing unique keys do not conflict unless a later explicit `NULLS NOT DISTINCT` feature is added.

### 10.11 Schema changes

MVP schema operations:

- `CREATE TABLE`;
- `DROP TABLE`;
- `ALTER TABLE ADD COLUMN`;
- `ALTER TABLE DROP COLUMN`;
- `ALTER TABLE RENAME TO`;
- `ALTER TABLE RENAME COLUMN`;
- `CREATE INDEX`;
- `CREATE UNIQUE INDEX`;
- `DROP INDEX`.

Rules:

- DDL is autocommit-only in the MVP;
- DDL inside an explicit transaction returns `25001 active_sql_transaction`;
- `ADD COLUMN` is metadata-only when nullable or when using a supported constant/stable default;
- `DROP COLUMN` is logical; old bytes are reclaimed by later snapshot rewrite or maintenance;
- `CREATE INDEX` is blocking and globally serialized;
- building an index over existing data is bounded by default to 100,000 rows, 256 MiB scanned, and 30 seconds; larger builds fail cleanly rather than stalling consensus indefinitely;
- `DROP TABLE` and `DROP INDEX` remove names and mark descriptors dropped atomically; their unreachable physical keys are reclaimed by a later snapshot rewrite or explicit maintenance pass rather than a giant replicated delete;
- schema apply iterates physical keys in byte order, uses no parallel reduction or unordered map iteration, and resolves no clock, random, or environment-dependent value inside the state machine.

### 10.12 Snapshots

A Raft snapshot is a logical, versioned stream, not a raw copy of a redb file.

Header fields:

```text
magic
snapshot format version
cluster ID
cluster incarnation
last included Raft log ID
stored membership log ID and member set
db_epoch
catalog_epoch
logical entry count
uncompressed byte count
compression identifier
```

The snapshot includes every replicated state-machine metadata record required to resume—epochs, object allocators, stored membership, origin deduplication state, and format metadata—followed by logical KV entries in physical-key order. Blocks:

- are independently length-delimited;
- are compressed with low-level Zstandard;
- carry checksums;
- contribute to a final BLAKE3 digest.

Snapshot construction:

1. open a pinned state read transaction;
2. read its exact `last_applied_log_id` and `stored_membership` from the same transaction;
3. stream logical metadata and KV entries;
4. fsync the completed snapshot;
5. publish snapshot metadata atomically.

Snapshot installation:

1. validate cluster, incarnation, format, sizes, and checksums;
2. build a new redb state file in a temporary generation;
3. fsync it;
4. atomically swap the active state generation;
5. reopen SQL service on the new generation;
6. retain the old generation until all old read snapshots close, then delete it.

Long transactions MAY be canceled before installation to bound duplicate disk usage.

### 10.13 Log compaction

Initial snapshot triggers:

- 50,000 new log entries since the last snapshot; or
- 128 MiB of retained log; or
- explicit administrative request.

Keep a trailing log window after snapshot for efficient follower catch-up.

Snapshot and transfer work MUST be bandwidth- and CPU-limited and lower priority than SQL commit and latency-sensitive host workloads.

### 10.14 Canonical state hash

Every node exposes a canonical logical-state hash calculated over:

- format version;
- epochs;
- catalog entries;
- live rows;
- live indexes;
- origin state;
- stored membership and its log ID.

Local file layout, free pages, and caches are excluded.

The hash is used for tests and diagnosis, not consensus.

---

## 11. SQL engine

### 11.1 PostgreSQL compatibility definition

Compatibility has three layers.

1. **Wire compatibility:** `psql`, libpq, and common drivers can connect and use simple and extended query flow.
2. **SQL-subset compatibility:** documented supported syntax and semantics follow PostgreSQL unless a divergence is listed.
3. **Tooling compatibility:** a small `pg_catalog` permits useful inspection.

Chorus does not claim to be a drop-in replacement for arbitrary PostgreSQL applications.

### 11.2 Parser

Use `sqlparser-rs` with `PostgreSqlDialect`, pinned to the exact tested release. The implementation baseline is `0.62.0`.

The parser is syntax-only. A Chorus binder MUST perform all semantic validation. Parser AST types MUST NOT escape the parser-adapter crate.

The entire simple-query string is parsed before execution, matching PostgreSQL’s behavior for syntax errors in multi-statement messages.

### 11.3 Binder

The binder MUST:

- normalize unquoted identifiers to lowercase;
- preserve quoted identifiers;
- resolve schema, table, alias, and column names;
- reject ambiguous names;
- expand `*`;
- assign stable object and column IDs;
- infer literal and parameter types;
- insert permitted implicit casts;
- implement NULLability and three-valued boolean typing;
- validate aggregates and grouping;
- resolve operators and built-in functions;
- reject unsupported syntax with SQLSTATE `0A000`;
- attach source spans where available;
- record the catalog epoch used for binding.

Parser acceptance never implies Chorus semantic support.

Implicit casts are deliberately small:

| From | To | Implicit |
|---|---|---|
| `SMALLINT` | `INTEGER`, `BIGINT`, `DOUBLE PRECISION` | yes |
| `INTEGER` | `BIGINT`, `DOUBLE PRECISION` | yes |
| `BIGINT` | `DOUBLE PRECISION` | yes, with ordinary precision loss |
| `VARCHAR` | `TEXT` | yes |
| unknown string literal | context-selected supported scalar type | yes |
| `TEXT` | numeric, UUID, date/time, JSONB | no; explicit cast required |
| floating point | integer | no; explicit cast required |

Comparison and arithmetic first choose a common supported type. Unsupported or ambiguous coercion returns a PostgreSQL-compatible datatype error rather than guessing.

### 11.4 Logical plan

Required logical operators:

```text
Values
TableScan
IndexScan
Filter
Project
Join
Aggregate
Sort
Limit
Insert
Update
Delete
```

### 11.5 Optimizer

The MVP optimizer is deterministic and rule-based.

Required rules:

- constant folding;
- boolean simplification;
- projection pruning;
- predicate pushdown;
- conversion of primary-key equality/range predicates into key scans;
- conversion of leading secondary-index predicates into index scans;
- reuse of index order for compatible `ORDER BY`;
- hash join for bounded equality joins;
- nested-loop join otherwise;
- join order as written, except for trivial two-relation choice;
- early limit propagation where semantics permit.

No Cascades framework, distributed optimizer, histograms, or JIT is required.

Exact table row counts are maintained. Heuristic selectivity estimates are sufficient for the MVP.

### 11.6 Executor

Use a pull-based executor that yields small batches:

```rust
trait Operator {
    fn next_batch(&mut self, cancel: &CancellationToken)
        -> Result<Option<RowBatch>>;
}
```

Default batch size: 128 rows.

Required physical operators:

- values;
- primary and secondary index scan;
- table scan;
- filter;
- projection;
- hash join;
- nested-loop join;
- hash aggregate;
- sort;
- limit/offset;
- insert/update/delete sink.

Sorts, hash joins, and hash aggregates participate in `work_mem`. The MVP does not spill to disk. Exceeding memory returns a clean resource-limit error.

Storage and CPU-heavy execution MUST NOT block Tokio reactor threads. Use a fixed-size query worker pool and bounded queues.

### 11.7 SQL surface

#### DDL

- `CREATE TABLE [IF NOT EXISTS]`
- `DROP TABLE [IF EXISTS]`
- listed `ALTER TABLE` operations
- `CREATE [UNIQUE] INDEX [IF NOT EXISTS]`
- `DROP INDEX [IF EXISTS]`

The MVP exposes one logical database and the `public` schema. `CREATE DATABASE`, `DROP DATABASE`, `CREATE SCHEMA`, and `DROP SCHEMA` are unsupported.

#### DML

- `SELECT`
- `INSERT`
- `UPDATE`
- `DELETE`
- `INSERT ... ON CONFLICT DO NOTHING`
- `INSERT ... ON CONFLICT (...) DO UPDATE SET ...` using `excluded` values, without conflict predicates
- `RETURNING` expressions for `INSERT`, `UPDATE`, and `DELETE`

`INSERT ... SELECT`, `MERGE`, `UPDATE ... FROM`, and `DELETE ... USING` are unsupported.

#### Transactions

- `BEGIN` / `START TRANSACTION`
- `COMMIT`
- `ROLLBACK`
- `SET TRANSACTION` for accepted isolation/read-only flags
- autocommit
- implicit transaction blocks for multi-statement simple-query messages

#### Query features

- aliases;
- `SELECT DISTINCT`;
- inner joins;
- left joins;
- `WHERE`;
- `GROUP BY`;
- `HAVING`;
- `ORDER BY`;
- `LIMIT`;
- `OFFSET`;
- literal-list `IN`, `BETWEEN`, `IS NULL`, `LIKE`;
- arithmetic, comparison, boolean, concatenation;
- `CASE`;
- `COALESCE`;
- `NULLIF`;
- aggregates: `COUNT`, `SUM`, `AVG`, `MIN`, `MAX`;
- built-ins: `lower`, `upper`, `length`, `octet_length`, `abs`, `greatest`, `least`;
- JSONB extraction operators `->` and `->>` for object keys and array indexes.

Explicitly unsupported query features include:

- scalar, correlated, `IN`, or `EXISTS` subqueries;
- CTEs;
- set operations such as `UNION`, `INTERSECT`, and `EXCEPT`;
- window functions;
- `DISTINCT ON`;
- lateral joins;
- `UPDATE ... FROM` and `DELETE ... USING`.

Aggregate result types are normative:

- `COUNT` returns `BIGINT`;
- `SUM(SMALLINT|INTEGER)` returns `BIGINT`;
- `SUM(BIGINT)` returns checked `BIGINT` and errors on overflow, a documented divergence from PostgreSQL's `NUMERIC` result;
- `AVG` of integer or floating inputs returns `DOUBLE PRECISION`, also a documented divergence for integer inputs;
- `MIN` and `MAX` preserve the input type.

Without `ORDER BY`, row order is unspecified. `ORDER BY` follows PostgreSQL's default NULL placement: ASC places NULL last and DESC places NULL first, unless explicitly overridden.

### 11.8 Data types

Required supported types and PostgreSQL OIDs:

| Type | OID |
|---|---:|
| `BOOLEAN` | 16 |
| `BYTEA` | 17 |
| `BIGINT` | 20 |
| `SMALLINT` | 21 |
| `INTEGER` | 23 |
| `TEXT` | 25 |
| `DOUBLE PRECISION` | 701 |
| `VARCHAR` | 1043 |
| `DATE` | 1082 |
| `TIMESTAMP` | 1114 |
| `TIMESTAMPTZ` | 1184 |
| `UUID` | 2950 |
| `JSONB` | 3802 |

Semantics:

- UTF-8 only;
- `VARCHAR(n)` limits Unicode characters, not encoded bytes;
- integer overflow and division-by-zero follow PostgreSQL error behavior;
- `DOUBLE PRECISION` preserves infinities, canonicalizes NaN for storage/indexing, treats all NaNs as equal for index consistency, and orders NaN after non-NaN values;
- UTC storage for `TIMESTAMPTZ`;
- session timezone initially restricted to UTC;
- JSONB validates JSON, discards duplicate object keys using last-key-wins semantics, and stores a deterministic canonical representation with sorted object keys;
- JSONB MVP operations are storage, equality, cast to/from text, and `->`/`->>` extraction;
- no arbitrary precision `NUMERIC`;
- no arrays, enums, domains, composites, or range types.

Both PostgreSQL text and binary wire encodings MUST be implemented for supported types because common drivers use binary parameters and results. Binary encodings use PostgreSQL's documented network-byte-order formats and epoch conventions; they are not Chorus's internal row encoding.

### 11.9 Constraints and defaults

Supported:

- primary key;
- `NOT NULL`;
- simple `UNIQUE`;
- literal defaults;
- stable time defaults such as `CURRENT_TIMESTAMP`.

Unsupported:

- foreign key;
- general `CHECK`;
- exclusion constraints;
- generated columns;
- deferred constraints.

Constraint validation occurs against transaction snapshot plus overlay. The global epoch ensures the validated state remains current if commit succeeds.

### 11.10 Prepared statements and portals

Extended query protocol requirements:

- one SQL statement per `Parse`;
- parameter OID inference;
- named and unnamed prepared statements;
- named and unnamed portals;
- text and binary parameter formats;
- text and binary result formats;
- `Describe`;
- `Close`;
- `Flush`;
- `Sync`;
- portal suspension and resume for nonzero execute row limits.

A prepared statement stores parsed SQL and parameter metadata. Binding and planning may be cached with the catalog epoch. A catalog-epoch change causes rebind/replan or a clean incompatibility error.

Per-session prepared statements and portals are bounded.

### 11.11 Autocommit `RETURNING`

An autocommit DML result MUST NOT be exposed as successful before commit succeeds.

Rows from autocommit `RETURNING` are buffered up to the configured limit, the commit is resolved, and only then are rows and `CommandComplete` sent.

In an explicit transaction, DML `RETURNING` may be returned before the later transaction commit, as in PostgreSQL.

### 11.12 Minimal `pg_catalog`

Implement virtual or synthesized relations sufficient for inspection:

- `pg_namespace`;
- `pg_class`;
- `pg_attribute`;
- `pg_type`;
- `pg_index`;
- `pg_constraint`;
- `pg_database`;
- `pg_roles`;
- selected `information_schema.tables`;
- selected `information_schema.columns`.

Required helper functions include the subset used by supported `psql` versions for:

- `\dt`;
- basic `\d table`;
- `version()`;
- `current_database()`;
- `current_schema()`;
- `current_user`;
- `pg_backend_pid()`;
- `format_type()`;
- `pg_get_indexdef()`.

Catalog compatibility is tested from captured `psql` queries. Unsupported inspection features return clean errors rather than fabricated metadata.

### 11.13 Session settings

Implement `SET`, `SHOW`, and `RESET` for the small whitelist needed by clients and operations:

- `application_name`;
- `search_path`, restricted to `public` and `pg_catalog`;
- `client_encoding`, restricted to UTF-8;
- `TimeZone`, restricted to UTC;
- `DateStyle`, restricted to ISO;
- `statement_timeout`;
- `idle_in_transaction_session_timeout`;
- `transaction_isolation`;
- `transaction_read_only`;
- `standard_conforming_strings`;
- `extra_float_digits`;
- `bytea_output`.

Unsupported settings return `0A000` or `42704`; they are not silently accepted when doing so could change SQL semantics.

### 11.14 Errors

At minimum map:

| Condition | SQLSTATE |
|---|---|
| serialization failure | `40001` |
| syntax error | `42601` |
| undefined table | `42P01` |
| undefined column | `42703` |
| duplicate table | `42P07` |
| duplicate key | `23505` |
| not-null violation | `23502` |
| failed transaction state | `25P02` |
| unsupported feature | `0A000` |
| query canceled | `57014` |
| active transaction prevents DDL | `25001` |
| cluster cannot serve strict request | `57P03` |
| transaction outcome unknown | `08007` |
| disk full | `53100` |
| resource/program limit | class `54` |
| internal invariant failure | `XX000` |

Error fields SHOULD include severity, code, message, detail, hint, and source position when available.

---

## 12. PostgreSQL wire server

### 12.1 Library

Use `pgwire`, pinned to the exact tested version. The implementation baseline is `0.40.5`.

Disable unnecessary default features. Prefer the Ring-backed server feature if it permits sharing the chosen Rustls crypto backend.

### 12.2 Protocol versions

Support:

- PostgreSQL protocol 3.0;
- protocol 3.2 negotiation where provided by the library;
- `psql` versions 14 through 18 in CI.

Required protocol paths include SSL negotiation, startup/authentication, `ParameterStatus`, `BackendKeyData`, empty-query response, simple query, extended Parse/Bind/Describe/Execute/Close/Flush/Sync, cancellation, `Terminate`, structured errors, notices needed by `psql`, and correct `ReadyForQuery` transaction status.

### 12.3 Listeners

Default production listeners:

- Unix-domain socket for local the application;
- loopback TCP for local diagnostics;
- remote PostgreSQL listener disabled.

Example:

```text
/run/chorus/.s.PGSQL.5432
127.0.0.1:5432
```

Remote PostgreSQL access, when enabled, MUST use TLS and certificate or SCRAM authentication.

### 12.4 Authentication model

Chorus has one trust domain and one logical database.

MVP principals:

- `app` for a local application;
- `chorus_admin` for local/remote administration.

Local Unix-socket access is controlled by filesystem ownership and permissions. RLS and general role management do not exist.

### 12.5 Startup parameters

Accept or report at least:

- `user`;
- `database`;
- `application_name`;
- `client_encoding=UTF8`;
- `DateStyle=ISO`;
- `TimeZone=UTC`;
- `standard_conforming_strings=on`;
- `server_version`;
- `server_version_num`;
- `integer_datetimes=on`.

Unknown optional parameters SHOULD be ignored or rejected consistently.

### 12.6 Simple query behavior

The implementation MUST follow PostgreSQL transaction semantics for a simple-query message containing multiple statements:

- parse the entire string first;
- execute statements as one implicit transaction unless explicit transaction control changes boundaries;
- stop at the first error;
- roll back the implicit transaction on error;
- emit one `ReadyForQuery` at message completion;
- preserve failed explicit transaction state until `ROLLBACK`;
- discard the failed transaction overlay promptly while retaining failed session state;
- permit only transaction-termination and harmless session-control commands while failed.

Because DDL is autocommit-only, a simple-query message containing DDL plus any other executable statement MUST be rejected before executing any statement. A single DDL statement in an otherwise idle session is permitted.

Once any row or command result from a multi-statement implicit transaction has been exposed to the client, Chorus MUST NOT invisibly replay that transaction. A final `40001` is returned if its commit loses the epoch race.

### 12.7 Extended query behavior

Implement PostgreSQL message sequencing and error resynchronization:

- after an extended-protocol error, discard until `Sync`;
- emit one `ReadyForQuery` for each `Sync`;
- maintain correct idle/in-transaction/failed transaction status;
- destroy unnamed statement and portal according to protocol rules;
- treat `COMMIT` in failed transaction state as rollback-compatible behavior and return the correct transaction status.

### 12.8 Cancellation

On startup, return `BackendKeyData`.

Each active statement has a cancellation token. Operators check cancellation at bounded intervals.

Cancellation rules:

- before commit submission: abort local work and return `57014`;
- after replicated commit submission: do not pretend the command was canceled; resolve it or report outcome unknown;
- connection loss aborts an unsubmitted transaction overlay;
- an already submitted command may finish and remains deduplicated.

### 12.9 COPY and replication protocol

`COPY`, PostgreSQL physical replication, and PostgreSQL logical replication are not MVP features. They return `0A000`.

---

## 13. Runtime architecture and resource control

### 13.1 Async and blocking work

Tokio runs:

- PostgreSQL socket state machines;
- internal RPC;
- Raft;
- timers;
- metrics and administration.

A fixed query worker pool runs:

- scans;
- expression execution;
- joins;
- aggregates;
- sorts;
- mutation construction.

A serialized state-apply worker owns state write transactions.

No unbounded `spawn_blocking` usage is permitted.

### 13.2 Default resource configuration

| Resource | Default |
|---|---:|
| state cache | 32 MiB |
| Raft cache | 8 MiB |
| global query work memory | 32 MiB |
| per-query work memory | 4 MiB |
| query workers | 2 |
| maximum active queries | 8 |
| PostgreSQL sessions | 32 |
| internal RPC queue per peer | 128 |
| snapshot chunk | 1 MiB |
| snapshot bandwidth | 20 MiB/s |
| ordinary internal message | 8 MiB max |
| runtime + query threads | 8 max by default |
| file descriptors | bounded/configured |

The process MUST refuse or queue work when budgets are exhausted. It MUST NOT silently exceed them. Buffered protocol results, including autocommit `RETURNING`, count against the global query-memory budget or a separately configured bounded result budget.

### 13.3 Reference resource gates

On the reference platform—4 ARM64 cores, local NVMe-class storage, 8 GiB RAM, five idle nodes—the release target is:

- idle RSS `<= 96 MiB` per process with default caches;
- stretch idle RSS `<= 64 MiB`;
- follower idle CPU `< 0.5%` of one core averaged over ten minutes;
- leader idle CPU `< 1%` of one core;
- leader idle consensus traffic `< 25 KiB/s`;
- follower idle consensus traffic `< 10 KiB/s`;
- stripped binary `< 50 MiB`;
- no unbounded growth over a 72-hour idle and fault soak.

Reference numbers MUST be measured rather than inferred from vibes.

### 13.4 Latency gates

Under healthy local networking with RTT `<= 2 ms`:

| Operation | p99 target |
|---|---:|
| established-snapshot primary-key lookup | 2 ms |
| autocommit primary-key `SELECT` including barrier | 15 ms |
| single-row autocommit write | 30 ms |
| ten-row transaction commit | 40 ms |
| leader loss to resumed writes | 3 s |

Loopback three-process CI SHOULD be materially faster.

### 13.5 Throughput gates

On the reference platform:

- at least 1,000 successful point-read transactions/s cluster-wide;
- at least 200 successful single-row autocommit writes/s;
- no correctness loss under hot-key contention;
- serialization retries counted separately from other failures.

Throughput is secondary to latency and predictable resource usage.

### 13.6 Backpressure

Backpressure points:

- accepted PostgreSQL connections;
- active query permits;
- global work memory;
- per-origin commit queue;
- leader proposal queue;
- per-peer RPC queue;
- snapshot sender;
- state apply queue.

Every queue MUST be bounded and observable.

### 13.7 Disk budget and headroom

The data directory MUST have a configured byte budget and low-space watermark. Defaults for the 1 GiB logical envelope:

- 4 GiB data-directory budget;
- refuse new snapshots or index builds below 2 GiB free;
- stop accepting new user writes below 512 MiB free or 10% filesystem free, whichever is larger;
- retain enough space for the active state, one replacement state generation, one recovery snapshot, and the configured Raft tail.

Low-space decisions are local health/admission signals, not consensus inputs. A low-space replica may fall unhealthy; the cluster continues only while a healthy quorum remains. Chorus MUST never delete the last usable snapshot or purge required log entries merely to make space.

---

## 14. Security

### 14.1 Internal identity

Every node has:

- stable Raft node ID;
- cluster ID;
- cluster incarnation;
- cluster-issued certificate and private key.

Internal mTLS MUST verify all of these. A certificate bound to another cluster or cluster incarnation cannot join or issue RPCs. The leader binds origin activation and forwarded commands to the authenticated node ID. Authenticated members are trusted; Chorus does not attempt Byzantine command validation.

### 14.2 PostgreSQL exposure

Production defaults:

- local Unix socket permitted;
- loopback TCP permitted;
- remote TCP disabled.

Remote enablement requires explicit configuration, TLS, and authentication.

### 14.3 At-rest encryption

Chorus relies on platform full-disk encryption for at-rest protection in the MVP. It does not implement transparent field encryption.

### 14.4 Input hardening

Requirements:

- length-prefix validation before allocation;
- SQL, row, message, and snapshot size caps;
- parser and wire-protocol fuzzing;
- bounded recursion;
- no unsafe code in Chorus-owned crates;
- prepared statements encouraged for applications;
- certificate and cluster identity checked before deserializing large internal messages where practical.

### 14.5 Supply chain

CI MUST run:

- `cargo audit`;
- `cargo deny`;
- license policy checks;
- locked dependency builds;
- reproducible release build checks where practical.

---

## 15. Operations

### 15.1 Configuration

Example:

```toml
cluster_id = "chorus-example"
cluster_incarnation = 1
node_id = 3
data_dir = "/var/lib/chorus"

[postgres]
unix_socket_dir = "/run/chorus"
listen = "127.0.0.1:5432"
remote_listen = ""
max_connections = 32

[raft]
listen = "0.0.0.0:7001"
heartbeat_ms = 250
election_timeout_min_ms = 1200
election_timeout_max_ms = 2400
snapshot_entries = 50000
snapshot_log_bytes = 134217728

[storage]
state_cache_bytes = 33554432
raft_cache_bytes = 8388608
# Release bring-up default; production may switch to "raft-backed" only after its crash/replay gate passes.
state_apply_durability = "immediate"
checkpoint_interval_ms = 250
checkpoint_commits = 128

[limits]
query_workers = 2
max_active_queries = 8
global_work_mem_bytes = 33554432
query_work_mem_bytes = 4194304
max_transaction_age_ms = 30000
idle_in_transaction_timeout_ms = 15000
max_transaction_bytes = 4194304
max_row_bytes = 262144
max_statement_bytes = 1048576

[tls]
ca = "/etc/chorus/cluster-ca.pem"
certificate = "/etc/chorus/node.pem"
private_key = "/etc/chorus/node-key.pem"

[[initial_nodes]]
node_id = 1
endpoint = "10.0.0.11:7001"
voter = true
```

Configuration affecting correctness or persistent format MUST be validated at startup and logged.

### 15.2 Process packaging

Ship one stripped binary plus configuration and certificates. The reference Linux deployment uses a system service with:

- a dedicated unprivileged user;
- `UMask=0077`;
- explicit data and runtime directories;
- restart-on-failure with backoff;
- file-descriptor and memory limits matching Chorus configuration;
- CPU and I/O weight below latency-sensitive or hard-real-time host services;
- network access SHOULD be limited to configured PostgreSQL listeners and the cluster peer port.

Build and test both `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`.

### 15.3 CLI

One binary provides:

```text
chorus run
chorus status
chorus bootstrap
chorus member list
chorus member add-learner
chorus member promote
chorus member demote
chorus member remove
chorus snapshot create
chorus snapshot export
chorus snapshot inspect
chorus restore
chorus check
chorus state-hash
```

Dangerous commands require explicit cluster ID and confirmation flags suitable for automation.

### 15.4 Health

Expose:

- liveness: process and event loop responsive;
- local readiness: state opened and applied;
- strict readiness: leader known and majority-confirmed read available;
- role: leader/follower/learner;
- current term;
- commit and applied log IDs;
- database epoch;
- replication lag;
- oldest transaction age;
- disk and cache state.

the application SHOULD distinguish local process health from cluster quorum health.

### 15.5 Metrics

Required low-cardinality metrics:

- PostgreSQL connections and active queries;
- query latency by normalized statement class;
- transaction commits, read-only completions, and aborts;
- `40001` count and retry count;
- read-barrier latency and coalescing ratio;
- proposal, quorum, apply, and end-to-end commit latency;
- current leader, term, commit index, and applied index;
- peer replication lag;
- Raft log bytes and entries;
- state and Raft file sizes;
- cache usage;
- snapshot build/install duration and bytes;
- transaction age and overlay bytes;
- worker and queue saturation;
- recovery/replay count.

Do not label metrics with raw SQL, job IDs, request IDs, or unbounded table names.

### 15.6 Logging

Use structured `tracing`.

Every request path carries:

- connection ID;
- session ID;
- transaction ID;
- request origin and sequence;
- Raft term and log ID when known;
- SQL fingerprint, not raw values by default.

Sensitive values MUST NOT be logged by default.

### 15.7 Graceful shutdown

On `SIGTERM`:

1. stop accepting new sessions;
2. reject new transactions;
3. allow a bounded drain period;
4. abort remaining local overlays;
5. resolve already submitted commits;
6. if leader, attempt transfer to the healthiest voter;
7. perform an immediate state checkpoint;
8. close storage cleanly.

`SIGKILL` recovery remains a release-tested path.

### 15.8 Backup

Any caught-up node may create a barrier-consistent logical backup. This is distinct from an OpenRaft recovery snapshot: it excludes live membership, active origins, request deduplication, and source cluster identity.

Backup export MUST include:

- cluster-independent logical data;
- schema;
- format metadata;
- final digest.

Restore creates a new cluster or requires all old nodes to be stopped and a new cluster incarnation. Backup upload to remote storage belongs to an external operator or uploader, not the core consensus path.

### 15.9 Disaster recovery

Without a majority, automatic writes stop.

A force-new-cluster operation MAY recover from the best surviving replica, but it is explicitly manual and dangerous. It MUST:

- require all reachable old members to be stopped or fenced;
- increment cluster incarnation;
- invalidate old membership;
- emit a prominent audit record;
- require rejoining other nodes from fresh snapshots.

### 15.10 Upgrades

The MVP does not support rolling mixed-version upgrades.

Requirements:

- all voters run the same compatibility version;
- internal handshake rejects incompatible command or snapshot formats;
- dependency versions are pinned;
- persisted formats have explicit versions and golden tests;
- cluster upgrade is a controlled cluster restart or learner replacement procedure.

---

## 16. Application integration contract

### 16.1 Local connection

Applications running on the same host SHOULD connect through the local Unix-domain socket:

```text
postgresql://app@/app?host=/run/chorus
```

Applications MUST NOT need to discover the current Raft leader. Any healthy node accepts PostgreSQL sessions; commits are forwarded internally when necessary.

Remote PostgreSQL TCP listeners MAY be enabled for administration or applications that cannot connect locally. They SHOULD be disabled by default unless required.

### 16.2 Transaction style

Applications SHOULD:

- use prepared statements for repeated queries;
- keep transactions short;
- use autocommit when one conditional statement is sufficient;
- treat SQLSTATE `40001` as a retryable serialization failure;
- use UUID or similarly decentralized primary keys where practical;
- avoid high-frequency liveness writes;
- avoid external side effects before commit is known;
- retry an entire transaction closure only when that closure is safe to replay.

Applications MUST NOT assume that a lost connection means the last commit did not occur. When commit outcome is ambiguous, application-level idempotency keys SHOULD be used for operations whose effects must not be duplicated.

### 16.3 Conditional ownership and claiming

A common coordination pattern is exclusive ownership of a durable job, lease, or resource. The recommended SQL shape is conditional DML with `RETURNING`:

```sql
UPDATE jobs
SET owner_id = $1,
    generation = generation + 1,
    state = 'claimed',
    updated_at = CURRENT_TIMESTAMP
WHERE id = $2
  AND state = 'ready'
RETURNING id, owner_id, generation;
```

Concurrent claimants may encounter `40001` and retry. After retries, exactly one claimant can observe a successful transition from the same prior state.

### 16.4 Fencing stale owners

Database serializability establishes one current database owner. It cannot revoke an external capability already exercised by an old owner before or during a partition.

Where ownership controls effects outside the database, the application SHOULD carry a monotonically increasing `generation` or fencing token with every operation. Consumers reject operations from older generations.

Example state transition:

```sql
UPDATE jobs
SET state = 'completed',
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1
  AND owner_id = $2
  AND generation = $3
  AND state = 'running'
RETURNING id;
```

A stale owner using an older generation updates zero rows. External systems participating in the same ownership protocol SHOULD also validate the fencing token where feasible.

### 16.5 External side effects

A database transaction does not make arbitrary external effects exactly once. Applications that cross the database boundary SHOULD use one or more of:

- durable idempotency keys;
- fencing generations;
- transactional outbox/inbox records;
- idempotent downstream operations;
- explicit acknowledgement state;
- reconciliation after ambiguous outcomes.

Chorus guarantees atomic, strictly serializable database state. Exactly-once semantics beyond that boundary remain an application protocol.

## 17. Rust project structure

A practical workspace:

```text
crates/
    chorus-common/        IDs, Datum, errors, limits
    chorus-codec/         keys, rows, command/snapshot formats
    chorus-storage/       storage traits
    chorus-redb/          redb log and state implementations
    chorus-consensus/     OpenRaft adapter and peer RPC
    chorus-txn/           snapshots, overlays, commit sequencing
    chorus-sql/           parser adapter, binder, planner, executor
    chorus-pg/            pgwire server and session state
    chorus-admin/         config, status, metrics, CLI services
    chorus-node/          monolithic binary
    chorus-testkit/       process clusters, fault injection, models
```

Important internal boundaries:

```rust
trait Consensus { ... }
trait StateStore { ... }
trait SqlParser { ... }
trait TransactionalKv { ... }
trait QueryEngine { ... }
```

Chorus-owned crates SHOULD use `#![forbid(unsafe_code)]`.

No panic is allowed on a client request path. Internal invariant violations become health-failing errors with diagnostic context.

The repository uses Rust edition 2024 and pins the compiler in `rust-toolchain.toml`. Release builds SHOULD begin with:

```toml
[profile.release]
lto = "thin"
codegen-units = 1
panic = "abort"
strip = "symbols"
```

Use the system allocator initially. Adding jemalloc, mimalloc, a JIT, or a custom async runtime requires measured evidence against the RSS and latency gates.

---

## 18. Dependencies and technology baseline

Core researched versions as of this specification:

| Purpose | Dependency | Baseline |
|---|---|---:|
| async runtime | Tokio | pinned tested 1.x |
| consensus | OpenRaft | `0.9.25` |
| embedded storage | redb | `4.1.0` |
| PostgreSQL wire | pgwire | `0.40.5` |
| SQL parser | sqlparser-rs | `0.62.0` |
| internal RPC | Tonic + Prost | pinned tested releases |
| TLS | Rustls | pinned tested release |
| buffers | bytes | pinned |
| errors | thiserror | pinned |
| tracing | tracing | pinned |
| configuration | serde + toml | pinned |
| metrics | metrics or equivalent facade | pinned |
| IDs | uuid | pinned |
| hashes | blake3 | pinned |
| snapshots | zstd | pinned |
| property tests | proptest | pinned |
| concurrency model tests | loom | pinned |
| SQL result tests | sqllogictest | `0.29.x` |
| PostgreSQL integration client | tokio-postgres | pinned |

Rules:

- commit `Cargo.lock`;
- pin exact core versions;
- isolate pre-1.0 APIs behind adapters;
- disable unused crate features;
- review transitive dependencies for runtime threads, caches, crypto backends, and native code;
- do not add DataFusion, RocksDB, Arrow, or a general ORM to the MVP without an architecture review;
- CI runs `rustfmt`, Clippy with warnings denied for Chorus crates, unit/property tests, and target builds for both supported architectures.

---

## 19. Verification plan

Testing is part of the architecture, not an appendix added when the demo stops smoking.

### 19.1 Reference model

Build a small in-memory reference implementation of:

- global epoch;
- snapshot reads;
- local overlays;
- commit validation;
- origin deduplication;
- canonical mutation apply.

Generate random transaction histories and compare accepted results and final state.

### 19.2 Unit and property tests

Mandatory property suites:

- Datum comparator vs key-byte ordering;
- composite key prefix and successor operations;
- row encode/decode round trip;
- unknown-version rejection;
- overlay point reads;
- overlay/base range merge;
- tombstone behavior;
- primary and secondary index maintenance;
- unique and NULL semantics;
- three-valued boolean logic;
- implicit cast rules;
- aggregate NULL and result-type behavior;
- implicit/explicit cast matrix;
- request deduplication;
- origin activation, fencing, and non-reuse;
- epoch monotonicity;
- snapshot block checksums;
- command codec golden vectors.

### 19.3 State-machine determinism

Feed identical command logs to:

- two independent redb state stores;
- the in-memory model;
- stores with different batch sizes and restart points.

After every command compare:

- apply result;
- epochs;
- catalog;
- row/index contents;
- canonical logical-state hash.

### 19.4 OpenRaft storage conformance

The custom Raft log and state-machine stores MUST pass OpenRaft’s complete storage test suite.

Run it:

- in memory;
- against redb;
- with restart between operations where possible.

### 19.5 SQL result correctness

Use SQLLogicTest for result semantics. It is not a transaction or concurrency test.

Maintain:

- a supported-feature corpus;
- PostgreSQL-generated expected results;
- no silent skip on unexpected errors;
- explicit tags for unsupported syntax.

Differentially execute generated supported SQL against PostgreSQL 18 and Chorus. Compare:

- rows;
- NULLs;
- types;
- ordering when specified;
- command tags;
- SQLSTATE class;
- final committed state.

### 19.6 PostgreSQL regression subset

Maintain a curated `pg_regress` schedule or extracted cases for:

- booleans;
- integer types;
- float;
- text and varchar;
- UUID;
- date and timestamp;
- insert;
- select;
- join;
- aggregates;
- update;
- delete;
- transactions.

Maintain custom `pg_isolation_regress` schedules for Chorus transaction behavior.

The project MUST report the exact subset. It MUST NOT claim broad PostgreSQL regression compatibility from a hand-picked dozen statements.

### 19.7 Wire-protocol tests

CI matrix:

- `psql` 14, 15, 16, 17, 18;
- libpq;
- `tokio-postgres`;
- one Python driver such as psycopg.

Test:

- startup and parameters;
- Unix socket and TCP;
- simple query;
- multi-statement simple query;
- extended parse/bind/describe/execute/sync;
- text and binary parameters/results;
- named and unnamed statements;
- portals and suspension;
- cancellation;
- failed transaction state;
- disconnect in transaction;
- connection to every node;
- basic `\dt` and `\d`.

### 19.8 Three-process acceptance test

Launch:

```text
node 1: pg 5433, raft 7001
node 2: pg 5434, raft 7002
node 3: pg 5435, raft 7003
```

Required flow:

1. connect `psql` to every port;
2. `SELECT 1`;
3. create schema through node 1;
4. insert through node 2;
5. immediately read through node 3;
6. update and roll back through node 3;
7. repeat and commit;
8. kill the leader;
9. continue through the surviving majority;
10. restart the killed node;
11. verify state hash and stored-membership convergence;
12. wipe one follower, rejoin it with a new installation origin, and verify snapshot recovery;
13. prove that ordinary `run` never bootstraps a new cluster while peers are merely unreachable.

### 19.9 Five-node contention test

Launch five Chorus nodes and have clients on all five concurrently contend on the same conditional state transition, for example claiming one row from `ready` to `claimed`.

Required:

- exactly one final owner is recorded;
- contenders either commit the winning transition, observe zero affected rows after retry, or receive a retryable `40001` before retry;
- every healthy replica converges on the same row contents and generation;
- retry of the winning internal request does not apply the mutation twice;
- repeating the test across leader changes and network delay preserves the same invariant.

### 19.10 Transaction anomaly tests

Hard gates:

- lost update;
- write skew;
- phantom insert;
- nonrepeatable read;
- read-your-writes;
- delete/insert race;
- unique-key race;
- cross-node real-time visibility;
- atomic multi-row transfer;
- stale ownership generation;
- autocommit retry hard-real-time;
- explicit transaction `40001`.

Example bank invariant:

```text
SUM(account.balance) = initial total
```

under concurrent transfers and faults.

### 19.11 Fault matrix

| Fault | Required result |
|---|---|
| kill leader before quorum replication | no acknowledged commit |
| kill leader after quorum, before response | commit may exist; same request resolves it |
| kill leader after acknowledgement | commit survives |
| partition one node from two-node majority | majority continues; minority rejects strict work |
| partition two from three in five-voter cluster | three-node majority continues |
| isolate old leader | it cannot serve new strict transactions |
| crash after Raft commit, before state apply | replay applies exactly once |
| crash during state redb commit | atomic old or new state; replay converges |
| duplicate command | no duplicate mutation |
| crash with an in-memory ambiguous request | restart activates a new origin; old request applies before activation or is fenced after it |
| delayed request from a prior boot | rejected as stale after new-origin activation |
| old ambiguous request ordered before new-origin activation | may apply exactly once; activation then fences it |
| two live processes claim one node ID | later activation fences the other; deployment health fails loudly |
| truncate uncommitted Raft tail | committed state remains |
| crash during snapshot build | old snapshot/log remain usable |
| crash during snapshot install | old or new generation boots, never partial |
| crash after snapshot, before log purge | safe |
| crash after log purge | snapshot/state sufficient for recovery |
| disk full during log append | no acknowledgement |
| disk full during state apply | replica unhealthy; no divergent logical result |
| transaction exceeds max age | clean abort |
| malformed or oversized RPC | rejected before unbounded allocation |

After each scenario, quiesce the cluster and compare logical-state hashes.

### 19.12 Jepsen and Elle

Run black-box histories through the PostgreSQL interface while introducing:

- process kills;
- network partitions;
- asymmetric packet loss;
- delay;
- pauses;
- leader churn;
- client timeouts;
- node restarts;
- extreme and discontinuous wall-clock skew on individual nodes.

Workloads:

- read/write registers;
- append;
- bank transfer;
- conditional job claiming;
- unique-key allocation;
- ownership-generation fencing.

Use Elle’s strict-serializability checks. A clean result is evidence, not proof; the proof obligation remains the protocol and invariants.

### 19.13 Crash fault injection

Compile a test-only failpoint build with points around:

- Raft log write;
- Raft log fsync;
- commit-index advancement;
- state apply start;
- state apply redb commit;
- response emission;
- checkpoint;
- snapshot header/block/footer;
- snapshot publication;
- state-generation swap;
- log purge.

A harness repeatedly kills the process at each point and verifies convergence.

### 19.14 Concurrency checking

Use Loom for small concurrency-sensitive components:

- read-barrier coalescer;
- commit sequencer and origin-activation handoff;
- cancellation handoff;
- apply-result waiter;
- state-generation swap;
- bounded queues.

Do not attempt to run the whole database under Loom.

### 19.15 Fuzzing

Use `cargo-fuzz` for:

- PostgreSQL startup and message decoding;
- SQL tokenizer/parser adapter;
- text and binary Datum decoders;
- row and key codecs;
- internal Protobuf envelopes;
- snapshot parser;
- malformed catalog/row recovery paths.

### 19.16 Resource tests

Automated gates measure:

- idle RSS;
- RSS under max connections;
- global work-memory enforcement;
- thread count;
- file descriptor count;
- idle CPU;
- idle internal network;
- snapshot throttling;
- transaction snapshot retention;
- file growth after repeated create/drop and update/delete;
- recovery time at 1 GiB and 10 GiB;
- low-disk admission, snapshot refusal, and log-retention hard-real-time.

### 19.17 Performance tests

Use custom `pgbench` scripts and internal microbenchmarks.

Report:

- p50, p95, p99, p99.9;
- successful TPS;
- `40001` rate;
- barrier latency;
- quorum latency;
- fsync latency;
- apply latency;
- query execution latency;
- retry attempts;
- follower lag.

Profiles:

- leader and follower gateway;
- 1, 8, 32 clients;
- point read;
- point write;
- ten-row transaction;
- scan/filter;
- indexed lookup;
- hot key;
- unrelated concurrent keys;
- leader election during load;
- process restart and origin activation before first write.

### 19.18 Soak test

A 72-hour five-node test MUST:

- run mixed the application-like workload;
- inject random process kills and short partitions;
- create periodic snapshots;
- restart nodes;
- maintain invariants;
- show bounded memory, disk, and descriptor usage;
- finish with matching logical-state hashes.

---

## 20. Implementation sequence

### Milestone 0 — contracts and executable model

Deliver:

- this specification in repository;
- architecture decision records;
- stable key/row/command and snapshot formats, including membership metadata;
- in-memory reference state machine for blank, membership, and normal entries;
- strict-serializability proof;
- property tests for epoch and deduplication.

Exit gate: random model histories agree with a legal serial execution.

### Milestone 1 — local storage and state machine

Deliver:

- redb state and Raft log adapters;
- physical KV format;
- state apply;
- origin activation/fencing, sequencing, and deduplication;
- snapshots and canonical state hash;
- crash/replay harness.

Exit gate: identical command logs converge through arbitrary restart points.

### Milestone 2 — transaction layer

Deliver:

- pinned snapshots;
- overlays;
- merged scans;
- local constraint validation;
- mutation construction;
- autocommit retry classifier;
- transaction limits and cancellation.

Exit gate: local lost-update, write-skew, phantom, and uniqueness tests pass.

### Milestone 3 — SQL core

Deliver:

- parser adapter;
- catalog;
- binder and type system;
- logical and physical plans;
- primary-key scan;
- table scan;
- DML;
- filters, projections, sort, limit;
- joins and aggregates;
- supported DDL.

Exit gate: supported SQLLogicTest and PostgreSQL differential corpus pass.

### Milestone 4 — PostgreSQL wire

Deliver:

- local socket/TCP server;
- startup parameters;
- simple query;
- extended query;
- prepared statements and portals;
- supported text/binary codecs;
- cancellation;
- transaction status;
- SQLSTATE mapping.

Exit gate: `psql` and driver matrix passes against one node.

### Milestone 5 — three-node consensus

Deliver:

- OpenRaft adapter;
- Tonic/Rustls peer transport;
- static bootstrap;
- proposal forwarding;
- read barriers and local catch-up;
- leader change;
- majority/minority behavior.

Exit gate: three-process acceptance, anomaly, and basic fault matrix pass.

### Milestone 6 — snapshots and membership

Deliver:

- logical snapshot transfer/install;
- log compaction;
- learners;
- explicit promotion/demotion;
- backup/export;
- state-generation swap.

Exit gate: wiped learner rejoins; crash during every snapshot phase is safe.

### Milestone 7 — practical PostgreSQL surface

Deliver:

- secondary and unique indexes;
- `ON CONFLICT`;
- `RETURNING`;
- migration-oriented `ALTER TABLE`;
- minimal `pg_catalog`;
- `psql \dt` and `\d`;
- the application schema and integration tests.

Exit gate: the application runs exclusively through Chorus in a five-process virtual cluster.

### Milestone 8 — hardening

Deliver:

- Jepsen/Elle;
- failpoint matrix;
- fuzzing;
- resource budgets;
- performance tuning;
- raft-backed state durability;
- observability;
- graceful shutdown;
- 72-hour soak.

Exit gate: every release gate in Section 21 passes.

---

## 21. Definition of done

The MVP is done only when all are true:

### Correctness

- strict-serializability proof reviewed;
- all invariants instrumented or tested;
- anomaly suite passes;
- Jepsen/Elle finds no violation in the release campaign;
- duplicate, ambiguous commit, origin-activation crash, and origin-replacement tests pass;
- state hashes converge after every fault campaign;
- membership entries and installed snapshots preserve identical stored membership.

### SQL and protocol

- documented SQL matrix complete;
- `psql` 14–18 connect to every node;
- prepared statements work through a common application driver;
- migrations create and evolve the the application schema;
- work claiming and fencing patterns pass.

### Replication and recovery

- three- and five-voter clusters pass;
- majority/minority behavior is correct;
- leader change stays within target;
- learner bootstrap and snapshot restore pass;
- kill-at-every-failpoint campaign passes;
- acknowledged writes survive ordinary power-loss simulation.

### Resources and performance

- default RSS, CPU, network, thread, and disk budgets pass;
- latency gates pass;
- queues and work memory remain bounded;
- 72-hour soak shows no growth trend;
- database recovery at the supported size meets the operational target.

### Operations and security

- mTLS rejects wrong cluster, cluster incarnation, node, and expired identities;
- local PostgreSQL permissions are correct;
- backup and restore are tested;
- dangerous recovery requires a new cluster incarnation;
- dependency and license checks pass;
- runbook covers bootstrap, quorum loss, replacement, backup, and disaster recovery.

No individual benchmark or demo substitutes for these gates.

---

## 22. Principal risks and kill criteria

| Risk | Why it matters | Mitigation / decision trigger |
|---|---|---|
| Global-epoch retry amplification | unrelated writers conflict | instrument `40001`; move first to per-table epochs only when the trigger in Section 23 is sustained |
| Quorum availability | unavailable voters stop strict cluster writes once a majority is lost | choose 3/5 stable voters deliberately; learners do not count; expose quorum health to applications |
| Unstable-network leader churn | raises tail latency and aborts in-flight work | conservative election timers, pre-vote, stable voter selection, deployment-network fault tests |
| PostgreSQL compatibility sprawl | can consume the project | publish an exact feature matrix; unsupported syntax returns `0A000`; the application tests define the real contract |
| redb space amplification | copy-on-write plus pinned snapshots can grow disk | short transaction limits, logical snapshot rewrite, disk headroom gates, 1/10 GiB recovery tests |
| Blocking schema changes | long apply stalls all new state | create indexes during deployment, hard scan/time limits, no online DDL claim |
| Pre-1.0 consensus API changes | library churn leaks into the system | exact pin plus the `Consensus` adapter and storage conformance suite |
| State-machine nondeterminism | replicas diverge silently | replicate resolved physical values, deterministic schema scans, cross-store hash tests after every command |
| Scope expansion | destroys the simplicity advantage | no sharding, SQL extensions, RLS, analytics engine, or compatibility work without a concrete application requirement |

A foundational dependency or design is rejected before production if it cannot meet correctness gates, stays above the hard resource budget after focused profiling, or requires weakening the invariants to pass ordinary cluster fault tests.

---

## 23. Evolution after the MVP

The first scaling move, only if measured contention requires it, is **per-table epochs**:

- record tables read and written;
- validate only their epochs;
- retain the same local snapshot, overlay, Raft log, and SQL architecture.

The second move is physical key-range certification.

Sharding, multiple Raft groups, intents, and distributed commit are much later decisions. They are justified only if a real cluster workload exceeds the fully replicated design.

Trigger for revisiting global epoch:

- sustained `40001` rate above 5% under the expected production workload;
- p99 commit latency misses target due primarily to retries;
- one cluster needs materially more write throughput than one Raft apply stream provides.

Until then, the global epoch is a feature: one tiny place where the truth is decided.

---

## 24. Research basis

Primary references used for the implementation choices:

- OpenRaft guide and API documentation: https://databendlabs.github.io/openraft/ and https://docs.rs/openraft/
- redb documentation: https://docs.rs/redb/
- pgwire documentation: https://docs.rs/pgwire/
- sqlparser-rs repository and documentation: https://github.com/apache/datafusion-sqlparser-rs and https://docs.rs/sqlparser/
- PostgreSQL frontend/backend protocol: https://www.postgresql.org/docs/current/protocol.html
- PostgreSQL transaction isolation: https://www.postgresql.org/docs/current/transaction-iso.html
- SQLLogicTest: https://sqlite.org/sqllogictest
- OpenRaft storage test guidance: https://docs.rs/openraft/latest/openraft/docs/getting_started/
- Jepsen Elle: https://github.com/jepsen-io/elle
- Loom: https://github.com/tokio-rs/loom
