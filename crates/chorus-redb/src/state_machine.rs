//! Concrete Chorus OpenRaft type configuration and durable state machine.
//!
//! The adapter persists a whole logical state envelope in one redb value for
//! the initial correctness milestone. It deliberately does not claim the
//! final physical `META`/`KV` layout, an OpenRaft runtime, peer transport, or
//! node serving integration.

use std::io::{self, Cursor, SeekFrom};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::task::{Context, Poll};

use chorus_codec::{ApplyResult, LogicalSnapshot, ReplicatedCommandV1, hash32};
use chorus_common::LogId as ChorusLogId;
use chorus_storage::{
    Membership as ChorusMembership, MemoryStateStore, StateData, StateSnapshot, StateStore,
    snapshot_from_store,
};
use openraft::entry::EntryPayload;
use openraft::storage::{RaftStateMachine, Snapshot, SnapshotMeta};
use openraft::{
    BasicNode, ErrorSubject, ErrorVerb, LogId, OptionalSend, RaftSnapshotBuilder, StorageError,
    StoredMembership,
};
use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};

use crate::PurgeFenceHandle;
use crate::purge_fence::{DurableSnapshotMarker, SNAPSHOT_MARKER_FORMAT_VERSION};

/// In-memory snapshot stream with an allocation bound enforced on every write.
///
/// This is intentionally a bounded correctness adapter, not the final
/// file-backed streaming snapshot transport.
#[derive(Debug)]
pub struct BoundedSnapshotData {
    inner: Cursor<Vec<u8>>,
}

impl BoundedSnapshotData {
    fn empty() -> Self {
        Self {
            inner: Cursor::new(Vec::new()),
        }
    }

    fn from_bytes(bytes: Vec<u8>) -> io::Result<Self> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(io_other("snapshot payload exceeds configured bound"));
        }
        Ok(Self {
            inner: Cursor::new(bytes),
        })
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.inner.into_inner()
    }

    fn checked_seek_target(&self, position: SeekFrom) -> io::Result<u64> {
        let base = match position {
            SeekFrom::Start(offset) => return self.validate_position(offset),
            SeekFrom::End(_) => self.inner.get_ref().len() as i128,
            SeekFrom::Current(_) => self.inner.position() as i128,
        };
        let delta = match position {
            SeekFrom::End(delta) | SeekFrom::Current(delta) => i128::from(delta),
            SeekFrom::Start(_) => unreachable!(),
        };
        let target = base
            .checked_add(delta)
            .ok_or_else(|| io_other("snapshot seek position overflow"))?;
        let target =
            u64::try_from(target).map_err(|_| io_other("snapshot seek position is negative"))?;
        self.validate_position(target)
    }

    fn validate_position(&self, position: u64) -> io::Result<u64> {
        if position > MAX_SNAPSHOT_BYTES as u64 {
            return Err(io_other("snapshot seek exceeds configured bound"));
        }
        Ok(position)
    }
}

impl AsyncRead for BoundedSnapshotData {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for BoundedSnapshotData {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let position = match usize::try_from(self.inner.position()) {
            Ok(position) => position,
            Err(_) => return Poll::Ready(Err(io_other("snapshot write position overflow"))),
        };
        let end = match position.checked_add(buffer.len()) {
            Some(end) => end,
            None => return Poll::Ready(Err(io_other("snapshot write length overflow"))),
        };
        if end > MAX_SNAPSHOT_BYTES {
            return Poll::Ready(Err(io_other("snapshot write exceeds configured bound")));
        }
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

impl AsyncSeek for BoundedSnapshotData {
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        self.checked_seek_target(position)?;
        Pin::new(&mut self.inner).start_seek(position)
    }

    fn poll_complete(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Pin::new(&mut self.inner).poll_complete(context)
    }
}

openraft::declare_raft_types!(
    pub ChorusRaftConfig:
        D = ReplicatedCommandV1,
        R = ApplyResult,
        NodeId = u64,
        Node = BasicNode,
        Entry = openraft::Entry<Self>,
        SnapshotData = BoundedSnapshotData,
        AsyncRuntime = openraft::TokioRuntime,
        Responder = openraft::impls::OneshotResponder<Self>,
);

const STATE_CACHE_BYTES: usize = 32 * 1024 * 1024;
const MAX_STATE_ENVELOPE_BYTES: usize = 256 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES: usize = 256 * 1024 * 1024;
const MAX_SNAPSHOT_META_BYTES: usize = 1024 * 1024;
const MAX_APPLY_ENTRIES: usize = 4096;
const VALUE_VERSION: u8 = 1;
const STATE_FORMAT_VERSION: u16 = 1;
const SNAPSHOT_FORMAT_VERSION: u16 = 1;

const STATE_META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("state_meta");
const KEY_STATE: &[u8] = b"state_envelope";
const KEY_SNAPSHOT_META: &[u8] = b"snapshot_meta";
const KEY_SNAPSHOT_DATA: &[u8] = b"snapshot_data";
const KEY_SNAPSHOT_PUBLICATION: &[u8] = b"snapshot_publication";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DurableStateEnvelope {
    format_version: u16,
    cluster_id: [u8; 16],
    cluster_incarnation: u64,
    state: StateData,
    last_applied: Option<LogId<u64>>,
    membership: StoredMembership<u64, BasicNode>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LogicalRaftSnapshot {
    format_version: u16,
    cluster_id: [u8; 16],
    cluster_incarnation: u64,
    last_applied: LogId<u64>,
    membership: StoredMembership<u64, BasicNode>,
    logical_state: LogicalSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum SnapshotSource {
    Local,
    Imported,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SnapshotPublication {
    source: SnapshotSource,
    marker: DurableSnapshotMarker<u64>,
}

#[derive(Clone)]
struct CachedSnapshot {
    meta: SnapshotMeta<u64, BasicNode>,
    bytes: Vec<u8>,
    publication: SnapshotPublication,
}

#[derive(Debug, thiserror::Error)]
pub enum RedbStateMachineError {
    #[error("invalid state-machine identity: {0}")]
    InvalidIdentity(String),
    #[error("redb state-machine error: {0}")]
    Redb(String),
    #[error("corrupt state-machine storage: {0}")]
    Corrupt(String),
}

#[derive(Clone)]
pub struct RedbStateMachine {
    db: Arc<Database>,
    write_lock: Arc<Mutex<()>>,
    current_snapshot: Arc<RwLock<Option<CachedSnapshot>>>,
    purge_fence: Option<PurgeFenceHandle<ChorusRaftConfig>>,
    cluster_id: [u8; 16],
    cluster_incarnation: u64,
}

impl RedbStateMachine {
    pub fn open(
        path: impl AsRef<Path>,
        cluster_id: [u8; 16],
        cluster_incarnation: u64,
    ) -> Result<Self, RedbStateMachineError> {
        Self::open_inner(path, cluster_id, cluster_incarnation, None)
    }

    /// Open a state machine whose locally-built snapshots may authorize purge
    /// in the matching durable Raft log store.
    ///
    /// The handle is an explicit opt-in capability obtained from
    /// [`crate::RedbRaftLogStore::purge_fence_handle`].  Identity is checked
    /// before any state is opened; a handle for another cluster or
    /// incarnation is rejected.
    pub fn open_with_purge_fence(
        path: impl AsRef<Path>,
        cluster_id: [u8; 16],
        cluster_incarnation: u64,
        purge_fence: PurgeFenceHandle<ChorusRaftConfig>,
    ) -> Result<Self, RedbStateMachineError> {
        if purge_fence.cluster_id() != cluster_id
            || purge_fence.cluster_incarnation() != cluster_incarnation
        {
            return Err(RedbStateMachineError::InvalidIdentity(
                "purge-fence identity does not match state-machine identity".into(),
            ));
        }
        Self::open_inner(path, cluster_id, cluster_incarnation, Some(purge_fence))
    }

    fn open_inner(
        path: impl AsRef<Path>,
        cluster_id: [u8; 16],
        cluster_incarnation: u64,
        purge_fence: Option<PurgeFenceHandle<ChorusRaftConfig>>,
    ) -> Result<Self, RedbStateMachineError> {
        if cluster_id == [0; 16] || cluster_incarnation == 0 {
            return Err(RedbStateMachineError::InvalidIdentity(
                "cluster id and incarnation must be nonzero".into(),
            ));
        }
        let db = redb::Builder::new()
            .set_cache_size(STATE_CACHE_BYTES)
            .create(path)
            .map_err(state_redb_error)?;
        initialize_or_validate(&db, cluster_id, cluster_incarnation)?;
        let mut state_machine = Self {
            db: Arc::new(db),
            write_lock: Arc::new(Mutex::new(())),
            current_snapshot: Arc::new(RwLock::new(None)),
            purge_fence,
            cluster_id,
            cluster_incarnation,
        };
        let envelope = state_machine
            .read_envelope()
            .map_err(|error| RedbStateMachineError::Corrupt(error.to_string()))?;
        validate_envelope(&envelope, cluster_id, cluster_incarnation)
            .map_err(|error| RedbStateMachineError::Corrupt(error.to_string()))?;
        let persisted_snapshot = read_persisted_snapshot(&state_machine.db)
            .map_err(|error| RedbStateMachineError::Corrupt(error.to_string()))?;
        if let Some(cached) = &persisted_snapshot {
            validate_cached_snapshot(cached, cluster_id, cluster_incarnation, &envelope)
                .map_err(|error| RedbStateMachineError::Corrupt(error.to_string()))?;
        }
        if let Some(purge_fence) = &state_machine.purge_fence {
            let durable_fence = purge_fence.current().map_err(|error| {
                RedbStateMachineError::Corrupt(format!(
                    "durable snapshot purge-fence read failed: {error}"
                ))
            })?;
            let imported_marker = purge_fence.imported_marker().map_err(|error| {
                RedbStateMachineError::Corrupt(format!(
                    "durable imported-snapshot marker read failed: {error}"
                ))
            })?;
            validate_log_publication_binding(
                persisted_snapshot.as_ref(),
                durable_fence.as_ref(),
                imported_marker.as_ref(),
            )
            .map_err(|error| RedbStateMachineError::Corrupt(error.to_string()))?;
        }
        if let (Some(purge_fence), Some(cached)) = (&state_machine.purge_fence, &persisted_snapshot)
        {
            // A process can crash after the state database commits a snapshot
            // and before the separate raft.redb fence transaction commits.
            // Once the snapshot has passed all validation above, replay the
            // monotonic publication step during reopen. Imported snapshots
            // carry a state-durable proof because their last-applied LogId may
            // never have existed in this follower's local log.
            let publication = cached.publication.clone();
            let publication_result = match publication.source {
                SnapshotSource::Local => purge_fence.advance(publication.marker.last_applied),
                SnapshotSource::Imported => purge_fence.publish_imported(publication.marker),
            };
            publication_result.map_err(|error| {
                RedbStateMachineError::Corrupt(format!(
                    "durable snapshot purge-fence reconciliation failed: {error}"
                ))
            })?;
        }
        state_machine.current_snapshot = Arc::new(RwLock::new(persisted_snapshot));
        Ok(state_machine)
    }

    pub fn cluster_id(&self) -> [u8; 16] {
        self.cluster_id
    }

    pub fn cluster_incarnation(&self) -> u64 {
        self.cluster_incarnation
    }

    pub fn state_data(&self) -> Result<StateData, RedbStateMachineError> {
        self.read_envelope()
            .map(|envelope| envelope.state)
            .map_err(|error| RedbStateMachineError::Corrupt(error.to_string()))
    }

    pub fn state_snapshot(&self) -> Result<StateSnapshot, RedbStateMachineError> {
        let data = self.state_data()?;
        MemoryStateStore::from_data(data)
            .snapshot()
            .map_err(|error| RedbStateMachineError::Corrupt(error.to_string()))
    }

    pub fn exact_membership(
        &self,
    ) -> Result<StoredMembership<u64, BasicNode>, RedbStateMachineError> {
        self.read_envelope()
            .map(|envelope| envelope.membership)
            .map_err(|error| RedbStateMachineError::Corrupt(error.to_string()))
    }

    fn lock_writes(&self) -> io::Result<MutexGuard<'_, ()>> {
        self.write_lock
            .lock()
            .map_err(|_| io_other("state-machine write lock is poisoned"))
    }

    fn read_envelope(&self) -> io::Result<DurableStateEnvelope> {
        read_envelope(&self.db)
    }

    fn commit_envelope(&self, envelope: &DurableStateEnvelope) -> io::Result<()> {
        validate_envelope(envelope, self.cluster_id, self.cluster_incarnation)?;
        write_envelope(&self.db, envelope)
    }

    fn apply_batch(
        &self,
        entries: Vec<openraft::Entry<ChorusRaftConfig>>,
    ) -> io::Result<Vec<ApplyResult>> {
        if entries.is_empty() {
            return Ok(Vec::new());
        }
        let _guard = self.lock_writes()?;
        let mut envelope = self.read_envelope()?;
        let mut memory = MemoryStateStore::from_data(envelope.state.clone());
        let mut responses = Vec::with_capacity(entries.len());

        for entry in entries {
            let expected_index = match &envelope.last_applied {
                Some(previous) => previous
                    .index
                    .checked_add(1)
                    .ok_or_else(|| io_other("state-machine log index exhausted"))?,
                None => 0,
            };
            if entry.log_id.index != expected_index {
                return Err(io_other(format!(
                    "state-machine log gap: expected index {expected_index}, got {}",
                    entry.log_id.index
                )));
            }
            if envelope
                .last_applied
                .as_ref()
                .is_some_and(|previous| entry.log_id.leader_id < previous.leader_id)
            {
                return Err(io_other("state-machine log term regressed"));
            }

            let chorus_log_id = to_chorus_log_id(&entry.log_id);
            let (command, new_membership) = match entry.payload {
                EntryPayload::Blank => (ReplicatedCommandV1::Noop, None),
                EntryPayload::Normal(command) => (command, None),
                EntryPayload::Membership(membership) => {
                    let command = membership_command(&membership);
                    let stored = StoredMembership::new(Some(entry.log_id), membership);
                    (command, Some(stored))
                }
            };

            let response = if expected_index == 0 {
                if !matches!(
                    &command,
                    ReplicatedCommandV1::Noop | ReplicatedCommandV1::Membership { .. }
                ) {
                    return Err(io_other(
                        "the first OpenRaft entry may only initialize membership or be blank",
                    ));
                }
                let mut data = memory.data();
                data.last_applied = chorus_log_id;
                if let ReplicatedCommandV1::Membership { voters, learners } = &command {
                    data.membership = ChorusMembership {
                        log_id: chorus_log_id,
                        voters: voters.clone(),
                        learners: learners.clone(),
                    };
                }
                memory = MemoryStateStore::from_data(data);
                ApplyResult::Noop
            } else {
                memory
                    .apply(chorus_log_id, &command)
                    .map_err(|error| io_other(format!("state-machine apply failed: {error}")))?
            };

            if matches!(response, ApplyResult::Rejected(_)) && new_membership.is_some() {
                return Err(io_other("OpenRaft membership projection was rejected"));
            }
            if let Some(membership) = new_membership {
                envelope.membership = membership;
            }
            envelope.last_applied = Some(entry.log_id);
            responses.push(response);
        }

        envelope.state = memory.data();
        self.commit_envelope(&envelope)?;
        Ok(responses)
    }

    fn build_snapshot_record(&self) -> io::Result<CachedSnapshot> {
        let _guard = self.lock_writes()?;
        let envelope = self.read_envelope()?;
        let last_applied = envelope
            .last_applied
            .clone()
            .ok_or_else(|| io_other("cannot snapshot an unapplied state machine"))?;
        let memory = MemoryStateStore::from_data(envelope.state.clone());
        let logical_state = snapshot_from_store(&memory)
            .map_err(|error| io_other(format!("logical snapshot build failed: {error}")))?;
        let payload = LogicalRaftSnapshot {
            format_version: SNAPSHOT_FORMAT_VERSION,
            cluster_id: self.cluster_id,
            cluster_incarnation: self.cluster_incarnation,
            last_applied: last_applied.clone(),
            membership: envelope.membership.clone(),
            logical_state,
        };
        let bytes = encode_bounded(&payload, MAX_SNAPSHOT_BYTES)?;
        let digest = payload.logical_state.header.digest;
        let meta = SnapshotMeta {
            last_log_id: Some(last_applied.clone()),
            last_membership: envelope.membership,
            snapshot_id: format!(
                "chorus-{}-{}-{}",
                last_applied.leader_id.term,
                last_applied.index,
                hex_prefix(&digest)
            ),
        };
        let cached = CachedSnapshot {
            meta,
            bytes,
            publication: SnapshotPublication {
                source: SnapshotSource::Local,
                marker: snapshot_marker(&payload)?,
            },
        };
        persist_snapshot(&self.db, &cached)?;
        if let Some(purge_fence) = &self.purge_fence {
            // The state snapshot is already committed with redb's Immediate
            // durability before this second durable transaction can move the
            // log purge fence.  If this fails, return an error and leave the
            // in-memory publication cache unchanged; the persisted snapshot
            // is intentionally recoverable while the log remains retained.
            purge_fence.advance(last_applied).map_err(|error| {
                io_other(format!("snapshot purge-fence advance failed: {error}"))
            })?;
        }
        *self
            .current_snapshot
            .write()
            .map_err(|_| io_other("snapshot cache lock is poisoned"))? = Some(cached.clone());
        Ok(cached)
    }

    fn install_snapshot_record(
        &self,
        meta: &SnapshotMeta<u64, BasicNode>,
        bytes: Vec<u8>,
    ) -> io::Result<()> {
        let payload =
            decode_and_validate_snapshot(meta, &bytes, self.cluster_id, self.cluster_incarnation)?;

        let memory = MemoryStateStore::with_cluster(self.cluster_id, self.cluster_incarnation);
        memory
            .install(&payload.logical_state)
            .map_err(|error| io_other(format!("logical snapshot install failed: {error}")))?;

        let _guard = self.lock_writes()?;
        let current = self.read_envelope()?;
        if let Some(current_applied) = &current.last_applied {
            if payload.last_applied.index < current_applied.index
                || (payload.last_applied.index == current_applied.index
                    && payload.last_applied != *current_applied)
            {
                return Err(io_other(
                    "snapshot is older than or conflicts with durable state",
                ));
            }
            if payload.last_applied == *current_applied {
                let current_memory = MemoryStateStore::from_data(current.state.clone());
                if current.membership != payload.membership
                    || current_memory.state_hash().map_err(to_io)?
                        != memory.state_hash().map_err(to_io)?
                {
                    return Err(io_other(
                        "snapshot conflicts with durable state at the same applied log",
                    ));
                }
            }
        }

        let publication = SnapshotPublication {
            source: SnapshotSource::Imported,
            marker: snapshot_marker(&payload)?,
        };
        let envelope = DurableStateEnvelope {
            format_version: STATE_FORMAT_VERSION,
            cluster_id: self.cluster_id,
            cluster_incarnation: self.cluster_incarnation,
            state: memory.data(),
            last_applied: Some(payload.last_applied.clone()),
            membership: payload.membership.clone(),
        };
        validate_envelope(&envelope, self.cluster_id, self.cluster_incarnation)?;
        let cached = CachedSnapshot {
            meta: meta.clone(),
            bytes,
            publication,
        };
        validate_cached_snapshot(
            &cached,
            self.cluster_id,
            self.cluster_incarnation,
            &envelope,
        )?;
        write_envelope_and_snapshot(&self.db, &envelope, &cached)?;
        if let Some(purge_fence) = &self.purge_fence {
            // The complete state and its imported-snapshot proof are already
            // durable. Only now may raft.redb publish the corresponding
            // virtual log boundary and authorize purge.
            purge_fence
                .publish_imported(cached.publication.marker.clone())
                .map_err(|error| {
                    io_other(format!("imported snapshot publication failed: {error}"))
                })?;
        }
        *self
            .current_snapshot
            .write()
            .map_err(|_| io_other("snapshot cache lock is poisoned"))? = Some(cached);
        Ok(())
    }
}

#[derive(Clone)]
pub struct RedbSnapshotBuilder {
    state_machine: RedbStateMachine,
}

impl RaftSnapshotBuilder<ChorusRaftConfig> for RedbSnapshotBuilder {
    async fn build_snapshot(&mut self) -> Result<Snapshot<ChorusRaftConfig>, StorageError<u64>> {
        let cached = self
            .state_machine
            .build_snapshot_record()
            .map_err(state_machine_read_error)?;
        Ok(Snapshot {
            meta: cached.meta,
            snapshot: Box::new(
                BoundedSnapshotData::from_bytes(cached.bytes).map_err(state_machine_read_error)?,
            ),
        })
    }
}

impl RaftStateMachine<ChorusRaftConfig> for RedbStateMachine {
    type SnapshotBuilder = RedbSnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<u64>>, StoredMembership<u64, BasicNode>), StorageError<u64>> {
        let envelope = self.read_envelope().map_err(state_machine_read_error)?;
        Ok((envelope.last_applied, envelope.membership))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<ApplyResult>, StorageError<u64>>
    where
        I: IntoIterator<Item = openraft::Entry<ChorusRaftConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let mut iterator = entries.into_iter();
        let entries: Vec<_> = iterator.by_ref().take(MAX_APPLY_ENTRIES + 1).collect();
        if entries.len() > MAX_APPLY_ENTRIES {
            return Err(state_machine_write_error(io_other(
                "state-machine apply batch exceeds entry-count limit",
            )));
        }
        self.apply_batch(entries).map_err(state_machine_write_error)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        RedbSnapshotBuilder {
            state_machine: self.clone(),
        }
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<BoundedSnapshotData>, StorageError<u64>> {
        Ok(Box::new(BoundedSnapshotData::empty()))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, BasicNode>,
        snapshot: Box<BoundedSnapshotData>,
    ) -> Result<(), StorageError<u64>> {
        self.install_snapshot_record(meta, snapshot.into_inner())
            .map_err(state_machine_write_error)
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<ChorusRaftConfig>>, StorageError<u64>> {
        let cached = self
            .current_snapshot
            .read()
            .map_err(|_| state_machine_read_error(io_other("snapshot cache lock is poisoned")))?
            .clone();
        match cached {
            Some(cached) => Ok(Some(Snapshot {
                meta: cached.meta,
                snapshot: Box::new(
                    BoundedSnapshotData::from_bytes(cached.bytes)
                        .map_err(state_machine_read_error)?,
                ),
            })),
            None => Ok(None),
        }
    }
}

fn initialize_or_validate(
    db: &Database,
    cluster_id: [u8; 16],
    cluster_incarnation: u64,
) -> Result<(), RedbStateMachineError> {
    let mut transaction = db.begin_write().map_err(state_redb_error)?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(state_redb_error)?;
    let created = {
        let mut table = transaction
            .open_table(STATE_META)
            .map_err(state_redb_error)?;
        for record in table.iter().map_err(state_redb_error)? {
            let (key, _) = record.map_err(state_redb_error)?;
            let key = key.value();
            if key != KEY_STATE
                && key != KEY_SNAPSHOT_META
                && key != KEY_SNAPSHOT_DATA
                && key != KEY_SNAPSHOT_PUBLICATION
            {
                return Err(RedbStateMachineError::Corrupt(
                    "state storage contains an unknown metadata key".into(),
                ));
            }
        }
        let stored = table
            .get(KEY_STATE)
            .map_err(state_redb_error)?
            .map(|value| value.value().to_vec());
        match stored {
            Some(bytes) => {
                let envelope: DurableStateEnvelope =
                    decode_bounded(&bytes, MAX_STATE_ENVELOPE_BYTES)
                        .map_err(|error| RedbStateMachineError::Corrupt(error.to_string()))?;
                if envelope.cluster_id != cluster_id
                    || envelope.cluster_incarnation != cluster_incarnation
                {
                    return Err(RedbStateMachineError::InvalidIdentity(
                        "stored state-machine identity does not match requested cluster".into(),
                    ));
                }
                validate_envelope(&envelope, cluster_id, cluster_incarnation)
                    .map_err(|error| RedbStateMachineError::Corrupt(error.to_string()))?;
                false
            }
            None => {
                if table.len().map_err(state_redb_error)? != 0 {
                    return Err(RedbStateMachineError::Corrupt(
                        "state envelope is missing from nonempty state storage".into(),
                    ));
                }
                let envelope = initial_envelope(cluster_id, cluster_incarnation);
                let bytes = encode_bounded(&envelope, MAX_STATE_ENVELOPE_BYTES)
                    .map_err(|error| RedbStateMachineError::Corrupt(error.to_string()))?;
                table
                    .insert(KEY_STATE, bytes.as_slice())
                    .map_err(state_redb_error)?;
                true
            }
        }
    };
    if created {
        transaction.commit().map_err(state_redb_error)
    } else {
        transaction.abort().map_err(state_redb_error)
    }
}

fn initial_envelope(cluster_id: [u8; 16], cluster_incarnation: u64) -> DurableStateEnvelope {
    let memory = MemoryStateStore::with_cluster(cluster_id, cluster_incarnation);
    let mut state = memory.data();
    state.membership = ChorusMembership {
        log_id: ChorusLogId::ZERO,
        voters: Vec::new(),
        learners: Vec::new(),
    };
    DurableStateEnvelope {
        format_version: STATE_FORMAT_VERSION,
        cluster_id,
        cluster_incarnation,
        state,
        last_applied: None,
        membership: StoredMembership::default(),
    }
}

fn read_envelope(db: &Database) -> io::Result<DurableStateEnvelope> {
    let transaction = db.begin_read().map_err(to_io)?;
    let table = transaction.open_table(STATE_META).map_err(to_io)?;
    let bytes = table
        .get(KEY_STATE)
        .map_err(to_io)?
        .map(|value| value.value().to_vec())
        .ok_or_else(|| io_other("durable state envelope is missing"))?;
    decode_bounded(&bytes, MAX_STATE_ENVELOPE_BYTES)
}

fn write_envelope(db: &Database, envelope: &DurableStateEnvelope) -> io::Result<()> {
    let bytes = encode_bounded(envelope, MAX_STATE_ENVELOPE_BYTES)?;
    let mut transaction = db.begin_write().map_err(to_io)?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(to_io)?;
    {
        let mut table = transaction.open_table(STATE_META).map_err(to_io)?;
        table.insert(KEY_STATE, bytes.as_slice()).map_err(to_io)?;
    }
    transaction.commit().map_err(to_io)
}

fn read_persisted_snapshot(db: &Database) -> io::Result<Option<CachedSnapshot>> {
    let transaction = db.begin_read().map_err(to_io)?;
    let table = transaction.open_table(STATE_META).map_err(to_io)?;
    let meta = table
        .get(KEY_SNAPSHOT_META)
        .map_err(to_io)?
        .map(|value| value.value().to_vec());
    let bytes = table
        .get(KEY_SNAPSHOT_DATA)
        .map_err(to_io)?
        .map(|value| value.value().to_vec());
    let publication = table
        .get(KEY_SNAPSHOT_PUBLICATION)
        .map_err(to_io)?
        .map(|value| value.value().to_vec());
    match (meta, bytes, publication) {
        (None, None, None) => Ok(None),
        (Some(meta), Some(bytes), Some(publication)) => {
            if bytes.is_empty() || bytes.len() > MAX_SNAPSHOT_BYTES {
                return Err(io_other("durable snapshot payload has an invalid size"));
            }
            let meta = decode_bounded(&meta, MAX_SNAPSHOT_META_BYTES)?;
            let publication = decode_bounded(&publication, MAX_SNAPSHOT_META_BYTES)?;
            Ok(Some(CachedSnapshot {
                meta,
                bytes,
                publication,
            }))
        }
        _ => Err(io_other("durable snapshot metadata is incomplete")),
    }
}

fn persist_snapshot(db: &Database, snapshot: &CachedSnapshot) -> io::Result<()> {
    let meta = encode_bounded(&snapshot.meta, MAX_SNAPSHOT_META_BYTES)?;
    let publication = encode_bounded(&snapshot.publication, MAX_SNAPSHOT_META_BYTES)?;
    if snapshot.bytes.is_empty() || snapshot.bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(io_other("snapshot payload has an invalid size"));
    }
    let mut transaction = db.begin_write().map_err(to_io)?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(to_io)?;
    {
        let mut table = transaction.open_table(STATE_META).map_err(to_io)?;
        table
            .insert(KEY_SNAPSHOT_META, meta.as_slice())
            .map_err(to_io)?;
        table
            .insert(KEY_SNAPSHOT_DATA, snapshot.bytes.as_slice())
            .map_err(to_io)?;
        table
            .insert(KEY_SNAPSHOT_PUBLICATION, publication.as_slice())
            .map_err(to_io)?;
    }
    transaction.commit().map_err(to_io)
}

fn write_envelope_and_snapshot(
    db: &Database,
    envelope: &DurableStateEnvelope,
    snapshot: &CachedSnapshot,
) -> io::Result<()> {
    let state = encode_bounded(envelope, MAX_STATE_ENVELOPE_BYTES)?;
    let meta = encode_bounded(&snapshot.meta, MAX_SNAPSHOT_META_BYTES)?;
    let publication = encode_bounded(&snapshot.publication, MAX_SNAPSHOT_META_BYTES)?;
    if snapshot.bytes.is_empty() || snapshot.bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(io_other("snapshot payload has an invalid size"));
    }
    let mut transaction = db.begin_write().map_err(to_io)?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(to_io)?;
    {
        let mut table = transaction.open_table(STATE_META).map_err(to_io)?;
        table.insert(KEY_STATE, state.as_slice()).map_err(to_io)?;
        table
            .insert(KEY_SNAPSHOT_META, meta.as_slice())
            .map_err(to_io)?;
        table
            .insert(KEY_SNAPSHOT_DATA, snapshot.bytes.as_slice())
            .map_err(to_io)?;
        table
            .insert(KEY_SNAPSHOT_PUBLICATION, publication.as_slice())
            .map_err(to_io)?;
    }
    transaction.commit().map_err(to_io)
}

fn decode_and_validate_snapshot(
    meta: &SnapshotMeta<u64, BasicNode>,
    bytes: &[u8],
    cluster_id: [u8; 16],
    cluster_incarnation: u64,
) -> io::Result<LogicalRaftSnapshot> {
    let payload: LogicalRaftSnapshot = decode_bounded(bytes, MAX_SNAPSHOT_BYTES)?;
    if payload.format_version != SNAPSHOT_FORMAT_VERSION
        || payload.cluster_id != cluster_id
        || payload.cluster_incarnation != cluster_incarnation
    {
        return Err(io_other(
            "snapshot identity or format does not match state machine",
        ));
    }
    if meta.last_log_id.as_ref() != Some(&payload.last_applied)
        || &meta.last_membership != &payload.membership
    {
        return Err(io_other(
            "snapshot payload does not match OpenRaft metadata",
        ));
    }
    payload
        .logical_state
        .validate()
        .map_err(|error| io_other(format!("logical snapshot validation failed: {error}")))?;
    if payload.logical_state.header.cluster_id != cluster_id
        || payload.logical_state.header.cluster_incarnation != cluster_incarnation
        || payload.logical_state.header.last_included != to_chorus_log_id(&payload.last_applied)
    {
        return Err(io_other(
            "logical snapshot header does not match OpenRaft metadata",
        ));
    }
    validate_exact_membership(&payload.membership)?;
    if payload
        .membership
        .log_id()
        .as_ref()
        .is_some_and(|membership_log| membership_log > &payload.last_applied)
    {
        return Err(io_other(
            "snapshot StoredMembership is ahead of the applied log",
        ));
    }
    validate_logical_membership(&payload)?;
    Ok(payload)
}

fn snapshot_marker(payload: &LogicalRaftSnapshot) -> io::Result<DurableSnapshotMarker<u64>> {
    let membership = encode_bounded(&payload.membership, MAX_SNAPSHOT_META_BYTES)?;
    let domain = b"CHORUS-IMPORTED-SNAPSHOT-MEMBERSHIP-V1\0";
    let capacity = domain
        .len()
        .checked_add(membership.len())
        .ok_or_else(|| io_other("snapshot membership digest input overflow"))?;
    let mut digest_input = Vec::with_capacity(capacity);
    digest_input.extend_from_slice(domain);
    digest_input.extend_from_slice(&membership);

    Ok(DurableSnapshotMarker {
        format_version: SNAPSHOT_MARKER_FORMAT_VERSION,
        cluster_id: payload.cluster_id,
        cluster_incarnation: payload.cluster_incarnation,
        last_applied: payload.last_applied.clone(),
        membership_log_id: payload.membership.log_id().clone(),
        membership_digest: hash32(&digest_input),
        logical_digest: payload.logical_state.header.digest,
    })
}

fn validate_snapshot_publication(
    publication: &SnapshotPublication,
    payload: &LogicalRaftSnapshot,
    cluster_id: [u8; 16],
    cluster_incarnation: u64,
) -> io::Result<()> {
    publication
        .marker
        .validate_identity(cluster_id, cluster_incarnation)
        .map_err(io_other)?;
    let expected = snapshot_marker(payload)?;
    if publication.marker != expected {
        return Err(io_other(
            "snapshot publication proof does not match its applied state or membership",
        ));
    }
    Ok(())
}

fn validate_log_publication_binding(
    snapshot: Option<&CachedSnapshot>,
    durable_fence: Option<&LogId<u64>>,
    imported_marker: Option<&DurableSnapshotMarker<u64>>,
) -> io::Result<()> {
    if let Some(fence) = durable_fence {
        let snapshot = snapshot.ok_or_else(|| {
            io_other("raft purge fence exists without a durable state snapshot publication")
        })?;
        let applied = &snapshot.publication.marker.last_applied;
        if applied.index < fence.index || (applied.index == fence.index && applied != fence) {
            return Err(io_other(
                "durable state snapshot is behind or conflicts with the raft purge fence",
            ));
        }
    }
    if let Some(imported) = imported_marker {
        let snapshot = snapshot.ok_or_else(|| {
            io_other("raft import marker exists without a durable state snapshot publication")
        })?;
        let state_marker = &snapshot.publication.marker;
        if state_marker.last_applied.index < imported.last_applied.index
            || (state_marker.last_applied.index == imported.last_applied.index
                && state_marker != imported)
        {
            return Err(io_other(
                "durable state publication is behind or conflicts with the raft import marker",
            ));
        }
    }
    Ok(())
}

fn validate_cached_snapshot(
    snapshot: &CachedSnapshot,
    cluster_id: [u8; 16],
    cluster_incarnation: u64,
    envelope: &DurableStateEnvelope,
) -> io::Result<()> {
    let payload = decode_and_validate_snapshot(
        &snapshot.meta,
        &snapshot.bytes,
        cluster_id,
        cluster_incarnation,
    )?;
    validate_snapshot_publication(
        &snapshot.publication,
        &payload,
        cluster_id,
        cluster_incarnation,
    )?;
    let applied = envelope
        .last_applied
        .as_ref()
        .ok_or_else(|| io_other("durable snapshot exists before any applied log"))?;
    if payload.last_applied.index > applied.index
        || (payload.last_applied.index == applied.index && payload.last_applied != *applied)
    {
        return Err(io_other("durable snapshot is ahead of applied state"));
    }
    if payload.last_applied == *applied {
        let snapshot_memory = MemoryStateStore::with_cluster(cluster_id, cluster_incarnation);
        snapshot_memory
            .install(&payload.logical_state)
            .map_err(|error| io_other(format!("logical snapshot install failed: {error}")))?;
        let current_memory = MemoryStateStore::from_data(envelope.state.clone());
        if payload.membership != envelope.membership
            || snapshot_memory.state_hash().map_err(to_io)?
                != current_memory.state_hash().map_err(to_io)?
        {
            return Err(io_other(
                "durable snapshot conflicts with state at the same applied log",
            ));
        }
    }
    Ok(())
}

fn validate_envelope(
    envelope: &DurableStateEnvelope,
    cluster_id: [u8; 16],
    cluster_incarnation: u64,
) -> io::Result<()> {
    if envelope.format_version != STATE_FORMAT_VERSION
        || envelope.cluster_id != cluster_id
        || envelope.cluster_incarnation != cluster_incarnation
        || envelope.state.cluster_id != cluster_id
        || envelope.state.cluster_incarnation != cluster_incarnation
    {
        return Err(io_other(
            "state envelope identity or format is inconsistent",
        ));
    }
    match &envelope.last_applied {
        None => {
            if envelope.state.last_applied != ChorusLogId::ZERO
                || envelope.membership.log_id().is_some()
            {
                return Err(io_other("fresh state envelope has applied metadata"));
            }
        }
        Some(applied) => {
            if envelope.state.last_applied != to_chorus_log_id(applied) {
                return Err(io_other("OpenRaft and Chorus applied cursors disagree"));
            }
            if envelope
                .membership
                .log_id()
                .as_ref()
                .is_some_and(|membership_log| membership_log > applied)
            {
                return Err(io_other("stored membership is ahead of applied state"));
            }
        }
    }
    validate_exact_membership(&envelope.membership)?;
    validate_flat_membership(envelope)?;
    let memory = MemoryStateStore::from_data(envelope.state.clone());
    memory
        .state_hash()
        .map_err(|error| io_other(format!("state envelope hash validation failed: {error}")))?;
    if !memory.status().healthy {
        return Err(io_other("state envelope reports unhealthy logical state"));
    }
    Ok(())
}

fn validate_exact_membership(stored: &StoredMembership<u64, BasicNode>) -> io::Result<()> {
    let membership = stored.membership();
    match stored.log_id() {
        None => {
            if !membership.get_joint_config().is_empty() || membership.nodes().next().is_some() {
                return Err(io_other(
                    "unapplied StoredMembership contains membership data",
                ));
            }
        }
        Some(_) => {
            let configs = membership.get_joint_config();
            if configs.is_empty() || configs.iter().any(|config| config.is_empty()) {
                return Err(io_other("StoredMembership contains an empty voter config"));
            }
            let voters: Vec<_> = membership.voter_ids().collect();
            let learners: Vec<_> = membership.learner_ids().collect();
            if voters.len().saturating_add(learners.len()) > 10_000
                || voters.iter().chain(&learners).any(|node_id| *node_id == 0)
                || voters
                    .iter()
                    .any(|node_id| membership.get_node(node_id).is_none())
            {
                return Err(io_other("StoredMembership contains invalid node data"));
            }
        }
    }
    Ok(())
}

fn validate_flat_membership(envelope: &DurableStateEnvelope) -> io::Result<()> {
    match envelope.membership.log_id() {
        None => {
            if !envelope.state.membership.voters.is_empty()
                || !envelope.state.membership.learners.is_empty()
            {
                return Err(io_other(
                    "logical membership exists without StoredMembership",
                ));
            }
        }
        Some(log_id) => {
            let (voters, learners) = flat_membership(envelope.membership.membership());
            if envelope.state.membership.log_id != to_chorus_log_id(log_id)
                || envelope.state.membership.voters != voters
                || envelope.state.membership.learners != learners
            {
                return Err(io_other("logical membership projection is inconsistent"));
            }
        }
    }
    Ok(())
}

fn validate_logical_membership(payload: &LogicalRaftSnapshot) -> io::Result<()> {
    let (voters, learners) = flat_membership(payload.membership.membership());
    let membership_log_id = payload
        .membership
        .log_id()
        .as_ref()
        .map(to_chorus_log_id)
        .unwrap_or(ChorusLogId::ZERO);
    if payload.logical_state.header.membership_log_id != membership_log_id
        || payload.logical_state.header.voters != voters
        || payload.logical_state.header.learners != learners
    {
        return Err(io_other(
            "logical snapshot membership projection is inconsistent",
        ));
    }
    Ok(())
}

fn membership_command(membership: &openraft::Membership<u64, BasicNode>) -> ReplicatedCommandV1 {
    let (voters, learners) = flat_membership(membership);
    ReplicatedCommandV1::Membership { voters, learners }
}

fn flat_membership(membership: &openraft::Membership<u64, BasicNode>) -> (Vec<u64>, Vec<u64>) {
    (
        membership.voter_ids().collect(),
        membership.learner_ids().collect(),
    )
}

fn to_chorus_log_id(log_id: &LogId<u64>) -> ChorusLogId {
    ChorusLogId {
        term: log_id.leader_id.term,
        index: log_id.index,
    }
}

fn hex_prefix(digest: &[u8; 32]) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(16);
    for byte in &digest[..8] {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn encode_bounded<T: Serialize>(value: &T, maximum: usize) -> io::Result<Vec<u8>> {
    let encoded = serde_json::to_vec(value).map_err(to_io)?;
    let total = encoded
        .len()
        .checked_add(1)
        .ok_or_else(|| io_other("encoded state value length overflow"))?;
    if total > maximum {
        return Err(io_other("encoded state value exceeds configured bound"));
    }
    let mut bytes = Vec::with_capacity(total);
    bytes.push(VALUE_VERSION);
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

fn decode_bounded<T: DeserializeOwned>(bytes: &[u8], maximum: usize) -> io::Result<T> {
    if bytes.len() > maximum {
        return Err(io_other("encoded state value exceeds configured bound"));
    }
    let (version, payload) = bytes
        .split_first()
        .ok_or_else(|| io_other("encoded state value is empty"))?;
    if *version != VALUE_VERSION {
        return Err(io_other(format!(
            "unsupported state value version {version}"
        )));
    }
    serde_json::from_slice(payload).map_err(to_io)
}

fn state_machine_read_error(error: io::Error) -> StorageError<u64> {
    StorageError::from_io_error(ErrorSubject::StateMachine, ErrorVerb::Read, error)
}

fn state_machine_write_error(error: io::Error) -> StorageError<u64> {
    StorageError::from_io_error(ErrorSubject::StateMachine, ErrorVerb::Write, error)
}

fn io_other(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

fn to_io(error: impl std::fmt::Display) -> io::Error {
    io_other(error.to_string())
}

fn state_redb_error(error: impl std::fmt::Display) -> RedbStateMachineError {
    RedbStateMachineError::Redb(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use chorus_codec::ActivateOriginV1;
    use chorus_common::OriginId;
    use openraft::{CommittedLeaderId, Entry, Membership};
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};

    use super::*;

    const CLUSTER_ID: [u8; 16] = [9; 16];
    const INCARNATION: u64 = 17;

    fn log_id(term: u64, index: u64) -> LogId<u64> {
        LogId::new(CommittedLeaderId::new(term, 1), index)
    }

    fn joint_membership() -> Membership<u64, BasicNode> {
        let configs = vec![BTreeSet::from([1, 2]), BTreeSet::from([2, 3])];
        let nodes = BTreeMap::from([
            (1, BasicNode::new("node-1")),
            (2, BasicNode::new("node-2")),
            (3, BasicNode::new("node-3")),
            (4, BasicNode::new("learner-4")),
        ]);
        Membership::new(configs, nodes)
    }

    fn membership_entry() -> Entry<ChorusRaftConfig> {
        Entry {
            // OpenRaft initialization uses `LogId::default()` at index zero;
            // the durable Option cursor distinguishes it from fresh state.
            log_id: LogId::default(),
            payload: EntryPayload::Membership(joint_membership()),
        }
    }

    fn activate_entry(index: u64, origin: OriginId) -> Entry<ChorusRaftConfig> {
        Entry {
            log_id: log_id(1, index),
            payload: EntryPayload::Normal(ReplicatedCommandV1::ActivateOrigin(ActivateOriginV1 {
                origin,
            })),
        }
    }

    fn noop_entry(index: u64) -> Entry<ChorusRaftConfig> {
        Entry {
            log_id: log_id(1, index),
            payload: EntryPayload::Normal(ReplicatedCommandV1::Noop),
        }
    }

    async fn applied(
        state_machine: &mut RedbStateMachine,
    ) -> (Option<LogId<u64>>, StoredMembership<u64, BasicNode>) {
        <RedbStateMachine as RaftStateMachine<ChorusRaftConfig>>::applied_state(state_machine)
            .await
            .unwrap()
    }

    async fn apply<I>(
        state_machine: &mut RedbStateMachine,
        entries: I,
    ) -> Result<Vec<ApplyResult>, StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<ChorusRaftConfig>> + Send,
        I::IntoIter: Send,
    {
        <RedbStateMachine as RaftStateMachine<ChorusRaftConfig>>::apply(state_machine, entries)
            .await
    }

    #[tokio::test]
    async fn exact_joint_membership_and_applied_cursor_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.redb");
        let origin = OriginId {
            node_id: 2,
            boot_nonce: [3; 16],
        };
        let expected_membership = joint_membership();
        let mut state_machine = RedbStateMachine::open(&path, CLUSTER_ID, INCARNATION).unwrap();

        assert_eq!(
            vec![ApplyResult::Noop, ApplyResult::Activated],
            apply(
                &mut state_machine,
                [membership_entry(), activate_entry(1, origin)]
            )
            .await
            .unwrap()
        );
        let (last_applied, stored) = applied(&mut state_machine).await;
        assert_eq!(Some(log_id(1, 1)), last_applied);
        assert_eq!(&Some(LogId::default()), stored.log_id());
        assert_eq!(&expected_membership, stored.membership());
        assert_eq!(
            origin,
            state_machine.state_data().unwrap().origins[&2].active_origin
        );
        drop(state_machine);

        let mut reopened = RedbStateMachine::open(&path, CLUSTER_ID, INCARNATION).unwrap();
        let (last_applied, stored) = applied(&mut reopened).await;
        assert_eq!(Some(log_id(1, 1)), last_applied);
        assert_eq!(&expected_membership, stored.membership());
        assert_eq!(
            origin,
            reopened.state_data().unwrap().origins[&2].active_origin
        );
        drop(reopened);

        assert!(matches!(
            RedbStateMachine::open(&path, [8; 16], INCARNATION),
            Err(RedbStateMachineError::InvalidIdentity(_))
        ));

        {
            let db = redb::Builder::new()
                .set_cache_size(STATE_CACHE_BYTES)
                .open(&path)
                .unwrap();
            let mut transaction = db.begin_write().unwrap();
            transaction.set_durability(Durability::Immediate).unwrap();
            {
                let mut table = transaction.open_table(STATE_META).unwrap();
                table
                    .insert(b"unknown".as_slice(), b"value".as_slice())
                    .unwrap();
            }
            transaction.commit().unwrap();
        }
        assert!(matches!(
            RedbStateMachine::open(&path, CLUSTER_ID, INCARNATION),
            Err(RedbStateMachineError::Corrupt(_))
        ));
    }

    #[tokio::test]
    async fn failed_batch_does_not_publish_staged_state_or_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.redb");
        let origin = OriginId {
            node_id: 8,
            boot_nonce: [4; 16],
        };
        let mut state_machine = RedbStateMachine::open(&path, CLUSTER_ID, INCARNATION).unwrap();
        apply(&mut state_machine, [membership_entry()])
            .await
            .unwrap();

        assert!(
            apply(
                &mut state_machine,
                [activate_entry(1, origin), noop_entry(3)]
            )
            .await
            .is_err()
        );
        let (last_applied, stored) = applied(&mut state_machine).await;
        assert_eq!(Some(LogId::default()), last_applied);
        assert_eq!(&Some(LogId::default()), stored.log_id());
        assert!(!state_machine.state_data().unwrap().origins.contains_key(&8));
        drop(state_machine);

        let mut reopened = RedbStateMachine::open(&path, CLUSTER_ID, INCARNATION).unwrap();
        assert_eq!(Some(LogId::default()), applied(&mut reopened).await.0);
        assert!(!reopened.state_data().unwrap().origins.contains_key(&8));

        let fresh_path = dir.path().join("fresh.redb");
        let mut fresh = RedbStateMachine::open(&fresh_path, CLUSTER_ID, INCARNATION).unwrap();
        assert!(
            apply(&mut fresh, [activate_entry(0, origin)])
                .await
                .is_err()
        );
        assert_eq!(None, applied(&mut fresh).await.0);
    }

    #[tokio::test]
    async fn logical_snapshot_is_durable_and_installs_atomically() {
        let source_dir = tempfile::tempdir().unwrap();
        let source_path = source_dir.path().join("state.redb");
        let origin = OriginId {
            node_id: 2,
            boot_nonce: [5; 16],
        };
        let mut source = RedbStateMachine::open(&source_path, CLUSTER_ID, INCARNATION).unwrap();
        apply(&mut source, [membership_entry(), activate_entry(1, origin)])
            .await
            .unwrap();
        let mut builder =
            <RedbStateMachine as RaftStateMachine<ChorusRaftConfig>>::get_snapshot_builder(
                &mut source,
            )
            .await;
        let snapshot = builder.build_snapshot().await.unwrap();
        let expected_meta = snapshot.meta.clone();
        let expected_bytes = snapshot.snapshot.into_inner();
        drop(builder);
        drop(source);

        let mut reopened = RedbStateMachine::open(&source_path, CLUSTER_ID, INCARNATION).unwrap();
        let durable =
            <RedbStateMachine as RaftStateMachine<ChorusRaftConfig>>::get_current_snapshot(
                &mut reopened,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(expected_meta, durable.meta);
        assert_eq!(expected_bytes, durable.snapshot.into_inner());

        let mut forged_payload: LogicalRaftSnapshot =
            decode_bounded(&expected_bytes, MAX_SNAPSHOT_BYTES).unwrap();
        let forged_membership = StoredMembership::new(Some(log_id(2, 1)), joint_membership());
        forged_payload.membership = forged_membership.clone();
        forged_payload.logical_state.header.membership_log_id = ChorusLogId { term: 2, index: 1 };
        let forged_bytes = encode_bounded(&forged_payload, MAX_SNAPSHOT_BYTES).unwrap();
        let mut forged_meta = expected_meta.clone();
        forged_meta.last_membership = forged_membership;
        assert!(
            decode_and_validate_snapshot(&forged_meta, &forged_bytes, CLUSTER_ID, INCARNATION)
                .is_err()
        );
        let forged_dir = tempfile::tempdir().unwrap();
        let mut forged_destination = RedbStateMachine::open(
            forged_dir.path().join("state.redb"),
            CLUSTER_ID,
            INCARNATION,
        )
        .unwrap();
        assert!(
            <RedbStateMachine as RaftStateMachine<ChorusRaftConfig>>::install_snapshot(
                &mut forged_destination,
                &forged_meta,
                Box::new(BoundedSnapshotData::from_bytes(forged_bytes).unwrap()),
            )
            .await
            .is_err()
        );
        assert_eq!(None, applied(&mut forged_destination).await.0);

        let destination_dir = tempfile::tempdir().unwrap();
        let destination_path = destination_dir.path().join("state.redb");
        let mut destination =
            RedbStateMachine::open(&destination_path, CLUSTER_ID, INCARNATION).unwrap();
        <RedbStateMachine as RaftStateMachine<ChorusRaftConfig>>::install_snapshot(
            &mut destination,
            &expected_meta,
            Box::new(BoundedSnapshotData::from_bytes(expected_bytes.clone()).unwrap()),
        )
        .await
        .unwrap();
        assert_eq!(Some(log_id(1, 1)), applied(&mut destination).await.0);
        assert_eq!(
            origin,
            destination.state_data().unwrap().origins[&2].active_origin
        );
        assert_eq!(
            reopened.exact_membership().unwrap(),
            destination.exact_membership().unwrap()
        );
        drop(destination);

        let mut destination =
            RedbStateMachine::open(&destination_path, CLUSTER_ID, INCARNATION).unwrap();
        assert_eq!(Some(log_id(1, 1)), applied(&mut destination).await.0);
        assert!(
            <RedbStateMachine as RaftStateMachine<ChorusRaftConfig>>::get_current_snapshot(
                &mut destination,
            )
            .await
            .unwrap()
            .is_some()
        );

        apply(&mut destination, [noop_entry(2)]).await.unwrap();
        assert!(
            <RedbStateMachine as RaftStateMachine<ChorusRaftConfig>>::install_snapshot(
                &mut destination,
                &expected_meta,
                Box::new(BoundedSnapshotData::from_bytes(expected_bytes).unwrap()),
            )
            .await
            .is_err()
        );
        assert_eq!(Some(log_id(1, 2)), applied(&mut destination).await.0);

        let mut bounded = BoundedSnapshotData::empty();
        assert!(
            bounded
                .seek(SeekFrom::Start(MAX_SNAPSHOT_BYTES as u64 + 1))
                .await
                .is_err()
        );
        bounded
            .seek(SeekFrom::Start(MAX_SNAPSHOT_BYTES as u64))
            .await
            .unwrap();
        assert!(bounded.write_all(&[1]).await.is_err());
        assert!(bounded.into_inner().is_empty());
    }

    #[tokio::test]
    async fn durable_snapshot_publication_is_complete_identity_and_membership_bound() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.redb");
        let mut state = RedbStateMachine::open(&path, CLUSTER_ID, INCARNATION).unwrap();
        apply(&mut state, [membership_entry(), noop_entry(1)])
            .await
            .unwrap();
        state
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .unwrap();
        drop(state);

        let original = {
            let db = redb::Builder::new().open(&path).unwrap();
            let tx = db.begin_read().unwrap();
            let table = tx.open_table(STATE_META).unwrap();
            table
                .get(KEY_SNAPSHOT_PUBLICATION)
                .unwrap()
                .unwrap()
                .value()
                .to_vec()
        };

        {
            let db = redb::Builder::new().open(&path).unwrap();
            let mut tx = db.begin_write().unwrap();
            tx.set_durability(Durability::Immediate).unwrap();
            tx.open_table(STATE_META)
                .unwrap()
                .remove(KEY_SNAPSHOT_PUBLICATION)
                .unwrap();
            tx.commit().unwrap();
        }
        assert!(matches!(
            RedbStateMachine::open(&path, CLUSTER_ID, INCARNATION),
            Err(RedbStateMachineError::Corrupt(_))
        ));

        let mut forged: SnapshotPublication =
            decode_bounded(&original, MAX_SNAPSHOT_META_BYTES).unwrap();
        forged.marker.membership_digest[0] ^= 0xff;
        let forged = encode_bounded(&forged, MAX_SNAPSHOT_META_BYTES).unwrap();
        {
            let db = redb::Builder::new().open(&path).unwrap();
            let mut tx = db.begin_write().unwrap();
            tx.set_durability(Durability::Immediate).unwrap();
            tx.open_table(STATE_META)
                .unwrap()
                .insert(KEY_SNAPSHOT_PUBLICATION, forged.as_slice())
                .unwrap();
            tx.commit().unwrap();
        }
        assert!(matches!(
            RedbStateMachine::open(&path, CLUSTER_ID, INCARNATION),
            Err(RedbStateMachineError::Corrupt(_))
        ));

        let mut forged: SnapshotPublication =
            decode_bounded(&original, MAX_SNAPSHOT_META_BYTES).unwrap();
        forged.marker.cluster_id = [0x71; 16];
        let forged = encode_bounded(&forged, MAX_SNAPSHOT_META_BYTES).unwrap();
        {
            let db = redb::Builder::new().open(&path).unwrap();
            let mut tx = db.begin_write().unwrap();
            tx.set_durability(Durability::Immediate).unwrap();
            tx.open_table(STATE_META)
                .unwrap()
                .insert(KEY_SNAPSHOT_PUBLICATION, forged.as_slice())
                .unwrap();
            tx.commit().unwrap();
        }
        assert!(matches!(
            RedbStateMachine::open(&path, CLUSTER_ID, INCARNATION),
            Err(RedbStateMachineError::Corrupt(_))
        ));
    }
}
