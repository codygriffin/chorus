#![forbid(unsafe_code)]

//! Durable OpenRaft log storage backed by redb.
//!
//! This crate implements the durable log/vote and state-machine sides of
//! OpenRaft's storage-v2 boundary. Locally-built snapshots can opt into an
//! identity-bound publication handle so the durable purge fence advances only
//! after the logical snapshot is recoverable.

pub mod purge_fence;
pub mod state_machine;

pub use purge_fence::PurgeFenceHandle;
pub use state_machine::{
    BoundedSnapshotData, ChorusRaftConfig, RedbStateMachine, RedbStateMachineError,
};

use std::fmt::Debug;
use std::io;
use std::marker::PhantomData;
use std::ops::{Bound, RangeBounds};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use openraft::storage::{LogFlushed, RaftLogStorage};
use openraft::{
    ErrorSubject, ErrorVerb, LogId, LogState, NodeId, OptionalSend, RaftLogId, RaftLogReader,
    RaftTypeConfig, StorageError, Vote,
};
use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::purge_fence::DurableSnapshotMarker;

const DEFAULT_RAFT_CACHE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ENCODED_VALUE_BYTES: usize = 8 * 1024 * 1024;
const MAX_APPEND_ENTRIES: usize = 4096;
const MAX_APPEND_BYTES: usize = 64 * 1024 * 1024;
const MAX_READ_ENTRIES: usize = 65_536;
const MAX_READ_BYTES: usize = 64 * 1024 * 1024;
const VALUE_VERSION: u8 = 1;
const IDENTITY_FORMAT_VERSION: u16 = 1;

const META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("meta");
const LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("log");

const KEY_IDENTITY: &[u8] = b"identity";
const KEY_VOTE: &[u8] = b"vote";
const KEY_COMMITTED: &[u8] = b"committed";
const KEY_PURGED: &[u8] = b"purged";
const KEY_PURGE_FENCE: &[u8] = b"purge_fence";
const KEY_IMPORTED_SNAPSHOT: &[u8] = b"imported_snapshot";

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
struct StoredIdentity {
    format_version: u16,
    cluster_id: [u8; 16],
    cluster_incarnation: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum RedbRaftError {
    #[error("invalid cluster identity: {0}")]
    InvalidIdentity(String),
    #[error("redb error: {0}")]
    Redb(String),
    #[error("corrupt raft storage: {0}")]
    Corrupt(String),
}

/// Durable OpenRaft log/vote storage.
///
/// All mutations use one redb transaction with `Durability::Immediate` and
/// are serialized with `write_lock`, including vote and log writes as required
/// by OpenRaft's storage-v2 contract.
pub struct RedbRaftLogStore<C: RaftTypeConfig> {
    db: Arc<Database>,
    write_lock: Arc<Mutex<()>>,
    cluster_id: [u8; 16],
    cluster_incarnation: u64,
    _config: PhantomData<C>,
}

impl<C: RaftTypeConfig> Clone for RedbRaftLogStore<C> {
    fn clone(&self) -> Self {
        Self {
            db: Arc::clone(&self.db),
            write_lock: Arc::clone(&self.write_lock),
            cluster_id: self.cluster_id,
            cluster_incarnation: self.cluster_incarnation,
            _config: PhantomData,
        }
    }
}

impl<C: RaftTypeConfig> RedbRaftLogStore<C> {
    pub fn open(
        path: impl AsRef<Path>,
        cluster_id: [u8; 16],
        cluster_incarnation: u64,
    ) -> Result<Self, RedbRaftError> {
        if cluster_id == [0; 16] || cluster_incarnation == 0 {
            return Err(RedbRaftError::InvalidIdentity(
                "cluster id and incarnation must be nonzero".into(),
            ));
        }

        let db = redb::Builder::new()
            .set_cache_size(DEFAULT_RAFT_CACHE_BYTES)
            .create(path)
            .map_err(redb_error)?;
        initialize_or_validate_identity(&db, cluster_id, cluster_incarnation)?;

        let store = Self {
            db: Arc::new(db),
            write_lock: Arc::new(Mutex::new(())),
            cluster_id,
            cluster_incarnation,
            _config: PhantomData,
        };
        store
            .validate_on_open()
            .map_err(|e| RedbRaftError::Corrupt(e.to_string()))?;
        Ok(store)
    }

    pub fn cluster_id(&self) -> [u8; 16] {
        self.cluster_id
    }

    pub fn cluster_incarnation(&self) -> u64 {
        self.cluster_incarnation
    }

    /// Return the encoded bytes retained in the physical Raft log.
    ///
    /// This is deliberately the bounded on-disk value payload total rather
    /// than a filesystem-size estimate: it is the quantity used by the
    /// runtime's configured `snapshot_log_bytes` trigger.  The read is
    /// consistent with one redb transaction and never materializes entries.
    pub fn retained_log_bytes(&self) -> Result<u64, RedbRaftError> {
        let tx = self.db.begin_read().map_err(redb_error)?;
        let table = tx.open_table(LOG).map_err(redb_error)?;
        let mut total = 0u64;
        for item in table.iter().map_err(redb_error)? {
            let (_index, value) = item.map_err(redb_error)?;
            total = total
                .checked_add(value.value().len() as u64)
                .ok_or_else(|| RedbRaftError::Corrupt("raft log byte count overflow".into()))?;
        }
        Ok(total)
    }

    /// Return an explicit capability for state/snapshot publication to
    /// advance this store's durable purge fence.
    pub fn purge_fence_handle(&self) -> PurgeFenceHandle<C> {
        PurgeFenceHandle::from_store(self)
    }

    /// Advance the durable proof through which log entries may be purged.
    ///
    /// This method must only be called after the state machine or a logical
    /// snapshot is durably recoverable through `log_id`. Merely committing a
    /// Raft entry is not sufficient to advance this fence.
    pub fn advance_purge_fence(
        &self,
        log_id: LogId<C::NodeId>,
    ) -> Result<(), StorageError<C::NodeId>> {
        self.with_write(ErrorSubject::Store, |db| {
            let committed = read_meta::<LogId<C::NodeId>>(db, KEY_COMMITTED)?
                .ok_or_else(|| io_other("cannot advance purge fence without a committed log id"))?;
            if log_id > committed {
                return Err(io_other("purge fence is ahead of the committed log id"));
            }
            let current = read_meta::<LogId<C::NodeId>>(db, KEY_PURGE_FENCE)?;
            if current.as_ref().is_some_and(|old| log_id < *old) {
                return Err(io_other("purge fence cannot regress"));
            }
            validate_known_log_id::<C>(db, &log_id)?;
            write_meta(db, KEY_PURGE_FENCE, &log_id)
        })
    }

    pub(crate) fn read_purge_fence(
        &self,
    ) -> Result<Option<LogId<C::NodeId>>, StorageError<C::NodeId>> {
        read_meta::<LogId<C::NodeId>>(&self.db, KEY_PURGE_FENCE)
            .map_err(|e| storage_error(ErrorSubject::Store, ErrorVerb::Read, e))
    }

    pub(crate) fn read_imported_snapshot_marker(
        &self,
    ) -> Result<Option<DurableSnapshotMarker<C::NodeId>>, StorageError<C::NodeId>> {
        read_meta::<DurableSnapshotMarker<C::NodeId>>(&self.db, KEY_IMPORTED_SNAPSHOT)
            .map_err(|e| storage_error(ErrorSubject::Store, ErrorVerb::Read, e))
    }

    pub(crate) fn publish_imported_snapshot(
        &self,
        marker: DurableSnapshotMarker<C::NodeId>,
    ) -> Result<(), StorageError<C::NodeId>> {
        self.with_write(ErrorSubject::Store, |db| {
            publish_imported_snapshot_immediate::<C>(
                db,
                self.cluster_id,
                self.cluster_incarnation,
                &marker,
            )
        })
    }

    fn lock_writes(&self) -> io::Result<MutexGuard<'_, ()>> {
        self.write_lock
            .lock()
            .map_err(|_| io_other("raft storage write lock is poisoned"))
    }

    fn with_write<T>(
        &self,
        subject: ErrorSubject<C::NodeId>,
        operation: impl FnOnce(&Database) -> io::Result<T>,
    ) -> Result<T, StorageError<C::NodeId>> {
        let _guard = self
            .lock_writes()
            .map_err(|e| storage_error(subject.clone(), ErrorVerb::Write, e))?;
        operation(&self.db).map_err(|e| storage_error(subject, ErrorVerb::Write, e))
    }

    fn validate_on_open(&self) -> io::Result<()> {
        let tx = self.db.begin_read().map_err(to_io)?;
        let meta = tx.open_table(META).map_err(to_io)?;
        for item in meta.iter().map_err(to_io)? {
            let (key, _) = item.map_err(to_io)?;
            let key = key.value();
            if ![
                KEY_IDENTITY,
                KEY_VOTE,
                KEY_COMMITTED,
                KEY_PURGED,
                KEY_PURGE_FENCE,
                KEY_IMPORTED_SNAPSHOT,
            ]
            .contains(&key)
            {
                return Err(io_other(format!(
                    "unknown raft metadata key {:?}",
                    String::from_utf8_lossy(key)
                )));
            }
        }
        drop(meta);

        let identity = read_meta_from_tx::<StoredIdentity>(&tx, KEY_IDENTITY)?
            .ok_or_else(|| io_other("raft identity metadata is missing"))?;
        if identity.format_version != IDENTITY_FORMAT_VERSION
            || identity.cluster_id != self.cluster_id
            || identity.cluster_incarnation != self.cluster_incarnation
        {
            return Err(io_other(
                "raft identity metadata does not match this installation",
            ));
        }

        let committed = read_meta_from_tx::<LogId<C::NodeId>>(&tx, KEY_COMMITTED)?;
        let purged = read_meta_from_tx::<LogId<C::NodeId>>(&tx, KEY_PURGED)?;
        let fence = read_meta_from_tx::<LogId<C::NodeId>>(&tx, KEY_PURGE_FENCE)?;
        let imported =
            read_meta_from_tx::<DurableSnapshotMarker<C::NodeId>>(&tx, KEY_IMPORTED_SNAPSHOT)?;
        let _vote = read_meta_from_tx::<Vote<C::NodeId>>(&tx, KEY_VOTE)?;

        if let (Some(purged), Some(fence)) = (&purged, &fence)
            && purged > fence
        {
            return Err(io_other("last purged log id is ahead of its durable fence"));
        }
        if let (Some(fence), Some(committed)) = (&fence, &committed)
            && fence > committed
        {
            return Err(io_other("purge fence is ahead of committed log id"));
        }
        if (purged.is_some() || fence.is_some()) && committed.is_none() {
            return Err(io_other("purge metadata exists without committed metadata"));
        }
        if let Some(marker) = &imported {
            marker
                .validate_identity(self.cluster_id, self.cluster_incarnation)
                .map_err(io_other)?;
            validate_cursor_at_or_after(
                committed.as_ref(),
                &marker.last_applied,
                "committed metadata",
            )?;
            validate_cursor_at_or_after(fence.as_ref(), &marker.last_applied, "purge fence")?;
        }

        let log = tx.open_table(LOG).map_err(to_io)?;
        let mut previous: Option<LogId<C::NodeId>> = purged.clone();
        for item in log.iter().map_err(to_io)? {
            let (index, value) = item.map_err(to_io)?;
            let entry: C::Entry = decode_value(value.value())?;
            let entry_id = entry.get_log_id().clone();
            if entry_id.index != index.value() {
                return Err(io_other("raft log key does not match encoded log id"));
            }
            if let Some(prior) = &previous {
                let expected = prior
                    .index
                    .checked_add(1)
                    .ok_or_else(|| io_other("raft log index exhausted"))?;
                if entry_id.index != expected {
                    return Err(io_other("raft log contains a physical index gap"));
                }
                if entry_id.leader_id < prior.leader_id {
                    return Err(io_other("raft log term regresses"));
                }
            } else if entry_id.index != 0 {
                return Err(io_other("initial raft log must begin at index 0"));
            }
            previous = Some(entry_id);
        }
        drop(log);

        if let Some(committed) = &committed {
            validate_known_log_id_in_tx::<C>(&tx, committed)?;
        }
        if let Some(fence) = &fence {
            validate_known_log_id_in_tx::<C>(&tx, fence)?;
        }
        if let Some(marker) = &imported {
            let covered_by_purge = purged.as_ref().is_some_and(|purged| {
                purged.index > marker.last_applied.index || purged == &marker.last_applied
            });
            if !covered_by_purge {
                validate_known_log_id_in_tx::<C>(&tx, &marker.last_applied)?;
            }
        }
        Ok(())
    }

    fn read_entries<RB>(&self, range: RB) -> io::Result<Vec<C::Entry>>
    where
        RB: RangeBounds<u64> + Clone + Debug,
    {
        let tx = self.db.begin_read().map_err(to_io)?;
        let table = tx.open_table(LOG).map_err(to_io)?;
        let bounds = owned_bounds(&range);
        let mut entries = Vec::new();
        let mut previous_index = None;
        let mut previous_leader_id = None;
        let mut encoded_bytes = 0usize;
        for item in table.range(bounds).map_err(to_io)? {
            let (index, value) = item.map_err(to_io)?;
            let index = index.value();
            if let Some(previous) = previous_index
                && index != previous + 1
            {
                return Err(io_other("raft log read encountered an index gap"));
            }
            encoded_bytes = encoded_bytes
                .checked_add(value.value().len())
                .ok_or_else(|| io_other("raft log read byte count overflow"))?;
            if encoded_bytes > MAX_READ_BYTES || entries.len() >= MAX_READ_ENTRIES {
                return Err(io_other("raft log read exceeds bounded result size"));
            }
            let entry: C::Entry = decode_value(value.value())?;
            if entry.get_log_id().index != index {
                return Err(io_other("raft log key does not match encoded log id"));
            }
            if previous_leader_id
                .as_ref()
                .is_some_and(|previous| entry.get_log_id().leader_id < *previous)
            {
                return Err(io_other("raft log read encountered a term regression"));
            }
            previous_leader_id = Some(entry.get_log_id().leader_id.clone());
            entries.push(entry);
            previous_index = Some(index);
        }
        Ok(entries)
    }
}

impl<C: RaftTypeConfig> RaftLogReader<C> for RedbRaftLogStore<C> {
    async fn try_get_log_entries<RB>(
        &mut self,
        range: RB,
    ) -> Result<Vec<C::Entry>, StorageError<C::NodeId>>
    where
        RB: RangeBounds<u64> + Clone + Debug + OptionalSend,
    {
        self.read_entries(range)
            .map_err(|e| storage_error(ErrorSubject::Logs, ErrorVerb::Read, e))
    }
}

impl<C: RaftTypeConfig> RaftLogStorage<C> for RedbRaftLogStore<C> {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<C>, StorageError<C::NodeId>> {
        let tx = self
            .db
            .begin_read()
            .map_err(|e| storage_error(ErrorSubject::Logs, ErrorVerb::Read, to_io(e)))?;
        let last_purged_log_id = read_meta_from_tx::<LogId<C::NodeId>>(&tx, KEY_PURGED)
            .map_err(|e| storage_error(ErrorSubject::Logs, ErrorVerb::Read, e))?;
        let table = tx
            .open_table(LOG)
            .map_err(|e| storage_error(ErrorSubject::Logs, ErrorVerb::Read, to_io(e)))?;
        let last_log_id = match table
            .last()
            .map_err(|e| storage_error(ErrorSubject::Logs, ErrorVerb::Read, to_io(e)))?
        {
            Some((_key, value)) => Some(
                decode_value::<C::Entry>(value.value())
                    .map_err(|e| storage_error(ErrorSubject::Logs, ErrorVerb::Read, e))?
                    .get_log_id()
                    .clone(),
            ),
            None => last_purged_log_id.clone(),
        };
        Ok(LogState {
            last_purged_log_id,
            last_log_id,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<C::NodeId>) -> Result<(), StorageError<C::NodeId>> {
        self.with_write(ErrorSubject::Vote, |db| {
            if let Some(current) = read_meta::<Vote<C::NodeId>>(db, KEY_VOTE)?
                && current
                    .partial_cmp(vote)
                    .is_none_or(|ordering| ordering.is_gt())
            {
                return Err(io_other("raft vote cannot regress or change incompatibly"));
            }
            write_meta(db, KEY_VOTE, vote)
        })
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<C::NodeId>>, StorageError<C::NodeId>> {
        read_meta::<Vote<C::NodeId>>(&self.db, KEY_VOTE)
            .map_err(|e| storage_error(ErrorSubject::Vote, ErrorVerb::Read, e))
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<C::NodeId>>,
    ) -> Result<(), StorageError<C::NodeId>> {
        self.with_write(ErrorSubject::Store, |db| {
            let current = read_meta::<LogId<C::NodeId>>(db, KEY_COMMITTED)?;
            match (&current, &committed) {
                (Some(_), None) => return Err(io_other("committed log id cannot be cleared")),
                (Some(old), Some(new)) if new < old => {
                    return Err(io_other("committed log id cannot regress"));
                }
                (_, Some(new)) => validate_known_log_id::<C>(db, new)?,
                _ => {}
            }
            match committed {
                Some(value) => write_meta(db, KEY_COMMITTED, &value),
                None => Ok(()),
            }
        })
    }

    async fn read_committed(
        &mut self,
    ) -> Result<Option<LogId<C::NodeId>>, StorageError<C::NodeId>> {
        read_meta::<LogId<C::NodeId>>(&self.db, KEY_COMMITTED)
            .map_err(|e| storage_error(ErrorSubject::Store, ErrorVerb::Read, e))
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<C>,
    ) -> Result<(), StorageError<C::NodeId>>
    where
        I: IntoIterator<Item = C::Entry> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let mut iterator = entries.into_iter();
        let entries: Vec<C::Entry> = iterator.by_ref().take(MAX_APPEND_ENTRIES + 1).collect();
        let result = if entries.len() > MAX_APPEND_ENTRIES {
            Err(io_other("raft append exceeds entry-count limit"))
        } else {
            self.append_immediate(entries)
        };
        match result {
            Ok(()) => {
                callback.log_io_completed(Ok(()));
                Ok(())
            }
            Err(error) => {
                callback.log_io_completed(Err(io::Error::new(error.kind(), error.to_string())));
                Err(storage_error(ErrorSubject::Logs, ErrorVerb::Write, error))
            }
        }
    }

    async fn truncate(&mut self, log_id: LogId<C::NodeId>) -> Result<(), StorageError<C::NodeId>> {
        self.with_write(ErrorSubject::Logs, |db| {
            truncate_immediate::<C>(db, log_id.index)
        })
    }

    async fn purge(&mut self, log_id: LogId<C::NodeId>) -> Result<(), StorageError<C::NodeId>> {
        self.with_write(ErrorSubject::Logs, |db| purge_immediate::<C>(db, &log_id))
    }
}

impl<C: RaftTypeConfig> RedbRaftLogStore<C> {
    fn append_immediate(&self, entries: Vec<C::Entry>) -> io::Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let encoded = entries
            .iter()
            .map(encode_value)
            .collect::<io::Result<Vec<_>>>()?;
        let total_encoded = encoded.iter().try_fold(0usize, |total, value| {
            total
                .checked_add(value.len())
                .ok_or_else(|| io_other("raft append byte count overflow"))
        })?;
        if total_encoded > MAX_APPEND_BYTES {
            return Err(io_other("raft append exceeds byte limit"));
        }
        for pair in entries.windows(2) {
            let expected = pair[0]
                .get_log_id()
                .index
                .checked_add(1)
                .ok_or_else(|| io_other("raft log index exhausted"))?;
            if pair[1].get_log_id().index != expected {
                return Err(io_other("appended raft entries are not contiguous"));
            }
            if pair[1].get_log_id().leader_id < pair[0].get_log_id().leader_id {
                return Err(io_other("appended raft entry term regresses"));
            }
        }

        let _guard = self.lock_writes()?;
        let mut tx = self.db.begin_write().map_err(to_io)?;
        tx.set_durability(Durability::Immediate).map_err(to_io)?;
        {
            let mut table = tx.open_table(LOG).map_err(to_io)?;
            let tail = table
                .last()
                .map_err(to_io)?
                .map(|(key, value)| {
                    let entry: C::Entry = decode_value(value.value())?;
                    if entry.get_log_id().index != key.value() {
                        return Err(io_other("raft log tail key does not match encoded log id"));
                    }
                    Ok(entry.get_log_id().clone())
                })
                .transpose()?;
            let purged = read_meta_from_write::<LogId<C::NodeId>>(&tx, KEY_PURGED)?;
            let durable_tail = tail.as_ref().or(purged.as_ref());
            let expected_first = match durable_tail {
                Some(log_id) => log_id
                    .index
                    .checked_add(1)
                    .ok_or_else(|| io_other("raft log index exhausted"))?,
                None => entries[0].get_log_id().index,
            };
            if entries[0].get_log_id().index != expected_first
                || (tail.is_none() && purged.is_none() && expected_first != 0)
            {
                return Err(io_other(
                    "appended raft entries do not continue the durable tail",
                ));
            }
            if durable_tail.is_some_and(|prior| entries[0].get_log_id().leader_id < prior.leader_id)
            {
                return Err(io_other(
                    "appended raft entry term regresses from durable tail",
                ));
            }
            for (entry, bytes) in entries.iter().zip(encoded.iter()) {
                if table
                    .get(entry.get_log_id().index)
                    .map_err(to_io)?
                    .is_some()
                {
                    return Err(io_other("raft append would overwrite an existing entry"));
                }
                table
                    .insert(entry.get_log_id().index, bytes.as_slice())
                    .map_err(to_io)?;
            }
        }
        tx.commit().map_err(to_io)
    }
}

fn initialize_or_validate_identity(
    db: &Database,
    cluster_id: [u8; 16],
    cluster_incarnation: u64,
) -> Result<(), RedbRaftError> {
    let mut tx = db.begin_write().map_err(redb_error)?;
    tx.set_durability(Durability::Immediate)
        .map_err(redb_error)?;
    let created = {
        let mut meta = tx.open_table(META).map_err(redb_error)?;
        let log = tx.open_table(LOG).map_err(redb_error)?;
        let stored = meta
            .get(KEY_IDENTITY)
            .map_err(redb_error)?
            .map(|value| value.value().to_vec());
        match stored {
            Some(bytes) => {
                let identity: StoredIdentity =
                    decode_value(&bytes).map_err(|e| RedbRaftError::Corrupt(e.to_string()))?;
                if identity.format_version != IDENTITY_FORMAT_VERSION
                    || identity.cluster_id != cluster_id
                    || identity.cluster_incarnation != cluster_incarnation
                {
                    return Err(RedbRaftError::InvalidIdentity(
                        "stored identity does not match requested cluster".into(),
                    ));
                }
                false
            }
            None => {
                if meta.len().map_err(redb_error)? != 0 || log.len().map_err(redb_error)? != 0 {
                    return Err(RedbRaftError::Corrupt(
                        "identity is missing from nonempty raft storage".into(),
                    ));
                }
                let bytes = encode_value(&StoredIdentity {
                    format_version: IDENTITY_FORMAT_VERSION,
                    cluster_id,
                    cluster_incarnation,
                })
                .map_err(|e| RedbRaftError::Corrupt(e.to_string()))?;
                meta.insert(KEY_IDENTITY, bytes.as_slice())
                    .map_err(redb_error)?;
                true
            }
        }
    };
    if created {
        tx.commit().map_err(redb_error)
    } else {
        tx.abort().map_err(redb_error)
    }
}

fn validate_cursor_at_or_after<NID: NodeId>(
    current: Option<&LogId<NID>>,
    expected: &LogId<NID>,
    label: &str,
) -> io::Result<()> {
    let current = current.ok_or_else(|| io_other(format!("{label} is missing")))?;
    if current.index < expected.index || (current.index == expected.index && current != expected) {
        return Err(io_other(format!(
            "{label} is behind or conflicts with the imported snapshot"
        )));
    }
    Ok(())
}

fn cursor_needs_advance<NID: NodeId>(
    current: Option<&LogId<NID>>,
    incoming: &LogId<NID>,
    label: &str,
) -> io::Result<bool> {
    if let Some(current) = current
        && current.index == incoming.index
        && current != incoming
    {
        return Err(io_other(format!(
            "{label} conflicts with the imported snapshot at the same index"
        )));
    }
    Ok(current.is_none_or(|current| current.index < incoming.index))
}

fn publish_imported_snapshot_immediate<C: RaftTypeConfig>(
    db: &Database,
    cluster_id: [u8; 16],
    cluster_incarnation: u64,
    marker: &DurableSnapshotMarker<C::NodeId>,
) -> io::Result<()> {
    marker
        .validate_identity(cluster_id, cluster_incarnation)
        .map_err(io_other)?;
    let encoded_marker = encode_value(marker)?;
    let mut tx = db.begin_write().map_err(to_io)?;
    tx.set_durability(Durability::Immediate).map_err(to_io)?;

    let existing =
        read_meta_from_write::<DurableSnapshotMarker<C::NodeId>>(&tx, KEY_IMPORTED_SNAPSHOT)?;
    let committed = read_meta_from_write::<LogId<C::NodeId>>(&tx, KEY_COMMITTED)?;
    let fence = read_meta_from_write::<LogId<C::NodeId>>(&tx, KEY_PURGE_FENCE)?;
    let purged = read_meta_from_write::<LogId<C::NodeId>>(&tx, KEY_PURGED)?;

    if existing.as_ref() == Some(marker) {
        validate_cursor_at_or_after(
            committed.as_ref(),
            &marker.last_applied,
            "committed metadata",
        )?;
        validate_cursor_at_or_after(fence.as_ref(), &marker.last_applied, "purge fence")?;
        tx.abort().map_err(to_io)?;
        return Ok(());
    }
    if let Some(existing) = &existing {
        if existing.last_applied.index > marker.last_applied.index
            || (existing.last_applied.index == marker.last_applied.index && existing != marker)
        {
            return Err(io_other(
                "imported snapshot marker cannot regress or conflict",
            ));
        }
    }
    let advance_committed = cursor_needs_advance(
        committed.as_ref(),
        &marker.last_applied,
        "committed metadata",
    )?;
    let advance_fence = cursor_needs_advance(fence.as_ref(), &marker.last_applied, "purge fence")?;
    let advance_purged =
        cursor_needs_advance(purged.as_ref(), &marker.last_applied, "purged metadata")?;

    let covered_by_purge = purged.as_ref().is_some_and(|purged| {
        purged.index > marker.last_applied.index || purged == &marker.last_applied
    });

    let exact_log_retained = !covered_by_purge && {
        let table = tx.open_table(LOG).map_err(to_io)?;
        match table.get(marker.last_applied.index).map_err(to_io)? {
            Some(value) => {
                let entry: C::Entry = decode_value(value.value())?;
                entry.get_log_id() == &marker.last_applied
            }
            None => false,
        }
    };

    if !covered_by_purge
        && !exact_log_retained
        && [committed.as_ref(), fence.as_ref(), purged.as_ref()]
            .into_iter()
            .flatten()
            .any(|cursor| cursor.index > marker.last_applied.index)
    {
        return Err(io_other(
            "raft metadata is ahead of an imported snapshot absent from local history",
        ));
    }

    {
        let mut log = tx.open_table(LOG).map_err(to_io)?;
        if !covered_by_purge && !exact_log_retained {
            // Raft may retain a suffix after snapshot installation only when
            // the local entry at last_applied matches exactly. With no such
            // entry, every local entry may belong to a divergent history.
            let indexes = log
                .iter()
                .map_err(to_io)?
                .map(|item| item.map(|(key, _)| key.value()).map_err(to_io))
                .collect::<io::Result<Vec<_>>>()?;
            for index in indexes {
                log.remove(index).map_err(to_io)?;
            }
        }
    }

    {
        let mut meta = tx.open_table(META).map_err(to_io)?;
        let encoded_applied = encode_value(&marker.last_applied)?;
        meta.insert(KEY_IMPORTED_SNAPSHOT, encoded_marker.as_slice())
            .map_err(to_io)?;
        if advance_committed {
            meta.insert(KEY_COMMITTED, encoded_applied.as_slice())
                .map_err(to_io)?;
        }
        if advance_fence {
            meta.insert(KEY_PURGE_FENCE, encoded_applied.as_slice())
                .map_err(to_io)?;
        }
        if !exact_log_retained && advance_purged {
            meta.insert(KEY_PURGED, encoded_applied.as_slice())
                .map_err(to_io)?;
        }
    }
    tx.commit().map_err(to_io)
}

fn truncate_immediate<C: RaftTypeConfig>(db: &Database, from: u64) -> io::Result<()> {
    let committed = read_meta::<LogId<C::NodeId>>(db, KEY_COMMITTED)?;
    if committed.as_ref().is_some_and(|value| from <= value.index) {
        return Err(io_other("cannot truncate a committed raft entry"));
    }
    let purged = read_meta::<LogId<C::NodeId>>(db, KEY_PURGED)?;
    if purged.as_ref().is_some_and(|value| from <= value.index) {
        return Err(io_other("cannot truncate a purged raft entry"));
    }

    let mut tx = db.begin_write().map_err(to_io)?;
    tx.set_durability(Durability::Immediate).map_err(to_io)?;
    {
        let mut table = tx.open_table(LOG).map_err(to_io)?;
        let indexes = table
            .range(from..)
            .map_err(to_io)?
            .map(|item| item.map(|(key, _)| key.value()).map_err(to_io))
            .collect::<io::Result<Vec<_>>>()?;
        for index in indexes {
            table.remove(index).map_err(to_io)?;
        }
    }
    tx.commit().map_err(to_io)
}

fn purge_immediate<C: RaftTypeConfig>(db: &Database, through: &LogId<C::NodeId>) -> io::Result<()> {
    let fence = read_meta::<LogId<C::NodeId>>(db, KEY_PURGE_FENCE)?
        .ok_or_else(|| io_other("cannot purge without a durable state/snapshot fence"))?;
    if through > &fence {
        return Err(io_other(
            "raft purge is ahead of durable state/snapshot fence",
        ));
    }
    if let Some(current) = read_meta::<LogId<C::NodeId>>(db, KEY_PURGED)? {
        if through < &current {
            return Err(io_other("last purged log id cannot regress"));
        }
        if through == &current {
            return Ok(());
        }
    }
    validate_known_log_id::<C>(db, through)?;

    let mut tx = db.begin_write().map_err(to_io)?;
    tx.set_durability(Durability::Immediate).map_err(to_io)?;
    {
        let mut table = tx.open_table(LOG).map_err(to_io)?;
        let indexes = table
            .range(..=through.index)
            .map_err(to_io)?
            .map(|item| item.map(|(key, _)| key.value()).map_err(to_io))
            .collect::<io::Result<Vec<_>>>()?;
        for index in indexes {
            table.remove(index).map_err(to_io)?;
        }
        drop(table);
        let mut meta = tx.open_table(META).map_err(to_io)?;
        let bytes = encode_value(through)?;
        meta.insert(KEY_PURGED, bytes.as_slice()).map_err(to_io)?;
    }
    tx.commit().map_err(to_io)
}

fn read_meta<T: DeserializeOwned>(db: &Database, key: &[u8]) -> io::Result<Option<T>> {
    let tx = db.begin_read().map_err(to_io)?;
    read_meta_from_tx(&tx, key)
}

fn read_meta_from_tx<T: DeserializeOwned>(
    tx: &redb::ReadTransaction,
    key: &[u8],
) -> io::Result<Option<T>> {
    let table = tx.open_table(META).map_err(to_io)?;
    let bytes = table
        .get(key)
        .map_err(to_io)?
        .map(|value| value.value().to_vec());
    bytes.map(|value| decode_value(&value)).transpose()
}

fn read_meta_from_write<T: DeserializeOwned>(
    tx: &redb::WriteTransaction,
    key: &[u8],
) -> io::Result<Option<T>> {
    let table = tx.open_table(META).map_err(to_io)?;
    let bytes = table
        .get(key)
        .map_err(to_io)?
        .map(|value| value.value().to_vec());
    bytes.map(|value| decode_value(&value)).transpose()
}

fn write_meta<T: Serialize>(db: &Database, key: &[u8], value: &T) -> io::Result<()> {
    let bytes = encode_value(value)?;
    let mut tx = db.begin_write().map_err(to_io)?;
    tx.set_durability(Durability::Immediate).map_err(to_io)?;
    {
        let mut table = tx.open_table(META).map_err(to_io)?;
        table.insert(key, bytes.as_slice()).map_err(to_io)?;
    }
    tx.commit().map_err(to_io)
}

fn validate_known_log_id<C: RaftTypeConfig>(
    db: &Database,
    expected: &LogId<C::NodeId>,
) -> io::Result<()> {
    let tx = db.begin_read().map_err(to_io)?;
    validate_known_log_id_in_tx::<C>(&tx, expected)
}

fn validate_known_log_id_in_tx<C: RaftTypeConfig>(
    tx: &redb::ReadTransaction,
    expected: &LogId<C::NodeId>,
) -> io::Result<()> {
    if let Some(purged) = read_meta_from_tx::<LogId<C::NodeId>>(tx, KEY_PURGED)?
        && expected == &purged
    {
        return Ok(());
    }
    let table = tx.open_table(LOG).map_err(to_io)?;
    let bytes = table
        .get(expected.index)
        .map_err(to_io)?
        .map(|value| value.value().to_vec())
        .ok_or_else(|| io_other("metadata refers to a missing raft log entry"))?;
    let entry: C::Entry = decode_value(&bytes)?;
    if entry.get_log_id() != expected {
        return Err(io_other("metadata log id does not match stored raft entry"));
    }
    Ok(())
}

fn encode_value<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    let encoded = serde_json::to_vec(value).map_err(to_io)?;
    let total = encoded
        .len()
        .checked_add(1)
        .ok_or_else(|| io_other("encoded raft value length overflow"))?;
    if total > MAX_ENCODED_VALUE_BYTES {
        return Err(io_other("encoded raft value exceeds 8 MiB"));
    }
    let mut bytes = Vec::with_capacity(total);
    bytes.push(VALUE_VERSION);
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

fn decode_value<T: DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    if bytes.len() > MAX_ENCODED_VALUE_BYTES {
        return Err(io_other("encoded raft value exceeds 8 MiB"));
    }
    let (version, payload) = bytes
        .split_first()
        .ok_or_else(|| io_other("encoded raft value is empty"))?;
    if *version != VALUE_VERSION {
        return Err(io_other(format!(
            "unsupported raft value version {version}"
        )));
    }
    serde_json::from_slice(payload).map_err(to_io)
}

fn owned_bounds<R: RangeBounds<u64>>(range: &R) -> (Bound<u64>, Bound<u64>) {
    let start = match range.start_bound() {
        Bound::Included(value) => Bound::Included(*value),
        Bound::Excluded(value) => Bound::Excluded(*value),
        Bound::Unbounded => Bound::Unbounded,
    };
    let end = match range.end_bound() {
        Bound::Included(value) => Bound::Included(*value),
        Bound::Excluded(value) => Bound::Excluded(*value),
        Bound::Unbounded => Bound::Unbounded,
    };
    (start, end)
}

fn storage_error<NID: openraft::NodeId>(
    subject: ErrorSubject<NID>,
    verb: ErrorVerb,
    error: io::Error,
) -> StorageError<NID> {
    StorageError::from_io_error(subject, verb, error)
}

fn io_other(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

fn to_io(error: impl std::fmt::Display) -> io::Error {
    io_other(error.to_string())
}

fn redb_error(error: impl std::fmt::Display) -> RedbRaftError {
    RedbRaftError::Redb(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use openraft::entry::EntryPayload;
    use openraft::storage::{RaftLogStorage, RaftLogStorageExt};
    use openraft::{BasicNode, CommittedLeaderId, Entry, LogId, RaftLogReader, Vote};
    use redb::Durability;

    use super::*;

    openraft::declare_raft_types!(
        TestConfig:
            D = String,
            R = String,
            NodeId = u64,
            Node = BasicNode,
            Entry = Entry<Self>,
            SnapshotData = Cursor<Vec<u8>>,
            AsyncRuntime = openraft::TokioRuntime,
            Responder = openraft::impls::OneshotResponder<Self>,
    );

    type Store = RedbRaftLogStore<TestConfig>;

    const CLUSTER_ID: [u8; 16] = [7; 16];
    const INCARNATION: u64 = 11;

    fn log_id(term: u64, index: u64) -> LogId<u64> {
        LogId::new(CommittedLeaderId::new(term, 1), index)
    }

    fn entry(term: u64, index: u64, value: &str) -> Entry<TestConfig> {
        Entry {
            log_id: log_id(term, index),
            payload: EntryPayload::Normal(value.to_owned()),
        }
    }

    async fn append<I>(store: &mut Store, entries: I)
    where
        I: IntoIterator<Item = Entry<TestConfig>> + Send,
        I::IntoIter: Send,
    {
        store.blocking_append(entries).await.unwrap();
    }

    fn raw_database(path: &Path) -> Database {
        redb::Builder::new()
            .set_cache_size(DEFAULT_RAFT_CACHE_BYTES)
            .create(path)
            .unwrap()
    }

    #[tokio::test]
    async fn identity_vote_and_full_committed_id_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("raft.redb");
        let mut store = Store::open(&path, CLUSTER_ID, INCARNATION).unwrap();
        assert_eq!(0, store.retained_log_bytes().unwrap());
        assert!(
            store
                .blocking_append([entry(1, 1, "missing-zero")])
                .await
                .is_err()
        );
        assert_eq!(None, store.get_log_state().await.unwrap().last_log_id);
        append(&mut store, [entry(1, 0, "zero"), entry(1, 1, "one")]).await;
        assert!(store.retained_log_bytes().unwrap() > 0);

        let vote = Vote::new_committed(3, 9);
        store.save_vote(&vote).await.unwrap();
        store.save_committed(Some(log_id(1, 1))).await.unwrap();
        drop(store);

        let mut reopened = Store::open(&path, CLUSTER_ID, INCARNATION).unwrap();
        assert_eq!(Some(vote), reopened.read_vote().await.unwrap());
        assert!(reopened.read_vote().await.unwrap().unwrap().is_committed());
        assert_eq!(Some(log_id(1, 1)), reopened.read_committed().await.unwrap());
        assert!(reopened.retained_log_bytes().unwrap() > 0);
        assert!(reopened.save_committed(None).await.is_err());
        drop(reopened);

        assert!(matches!(
            Store::open(&path, [8; 16], INCARNATION),
            Err(RedbRaftError::InvalidIdentity(_))
        ));
        assert!(matches!(
            Store::open(&path, CLUSTER_ID, INCARNATION + 1),
            Err(RedbRaftError::InvalidIdentity(_))
        ));
    }

    #[test]
    fn missing_partial_and_malformed_identity_fail_closed() {
        let partial_dir = tempfile::tempdir().unwrap();
        let partial_path = partial_dir.path().join("raft.redb");
        {
            let db = raw_database(&partial_path);
            let mut tx = db.begin_write().unwrap();
            tx.set_durability(Durability::Immediate).unwrap();
            {
                let mut meta = tx.open_table(META).unwrap();
                let vote = encode_value(&Vote::<u64>::new(1, 1)).unwrap();
                meta.insert(KEY_VOTE, vote.as_slice()).unwrap();
                let _log = tx.open_table(LOG).unwrap();
            }
            tx.commit().unwrap();
        }
        assert!(matches!(
            Store::open(&partial_path, CLUSTER_ID, INCARNATION),
            Err(RedbRaftError::Corrupt(_))
        ));

        let malformed_dir = tempfile::tempdir().unwrap();
        let malformed_path = malformed_dir.path().join("raft.redb");
        {
            let db = raw_database(&malformed_path);
            let mut tx = db.begin_write().unwrap();
            tx.set_durability(Durability::Immediate).unwrap();
            {
                let mut meta = tx.open_table(META).unwrap();
                meta.insert(KEY_IDENTITY, b"\x01{".as_slice()).unwrap();
                let _log = tx.open_table(LOG).unwrap();
            }
            tx.commit().unwrap();
        }
        assert!(matches!(
            Store::open(&malformed_path, CLUSTER_ID, INCARNATION),
            Err(RedbRaftError::Corrupt(_))
        ));
    }

    #[tokio::test]
    async fn append_is_immediately_visible_contiguous_and_durable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("raft.redb");
        let mut store = Store::open(&path, CLUSTER_ID, INCARNATION).unwrap();
        append(&mut store, [entry(1, 0, "zero"), entry(1, 1, "one")]).await;

        let entries = store.try_get_log_entries(0..2).await.unwrap();
        assert_eq!(2, entries.len());
        assert_eq!(EntryPayload::Normal("one".into()), entries[1].payload);

        assert!(store.blocking_append([entry(1, 3, "gap")]).await.is_err());
        assert!(
            store
                .blocking_append([entry(0, 2, "term-regression")])
                .await
                .is_err()
        );
        assert_eq!(2, store.try_get_log_entries(..).await.unwrap().len());
        drop(store);

        let mut reopened = Store::open(&path, CLUSTER_ID, INCARNATION).unwrap();
        let state = reopened.get_log_state().await.unwrap();
        assert_eq!(None, state.last_purged_log_id);
        assert_eq!(Some(log_id(1, 1)), state.last_log_id);
        assert_eq!(2, reopened.try_get_log_entries(..).await.unwrap().len());
    }

    #[tokio::test]
    async fn truncate_is_inclusive_and_never_removes_committed_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("raft.redb");
        let mut store = Store::open(&path, CLUSTER_ID, INCARNATION).unwrap();
        append(
            &mut store,
            [
                entry(1, 0, "zero"),
                entry(1, 1, "one"),
                entry(1, 2, "old-two"),
            ],
        )
        .await;
        store.save_committed(Some(log_id(1, 1))).await.unwrap();

        assert!(store.truncate(log_id(1, 1)).await.is_err());
        store.truncate(log_id(2, 2)).await.unwrap();
        assert_eq!(
            Some(log_id(1, 1)),
            store.get_log_state().await.unwrap().last_log_id
        );
        append(&mut store, [entry(2, 2, "new-two")]).await;
        let entries = store.try_get_log_entries(2..3).await.unwrap();
        assert_eq!(EntryPayload::Normal("new-two".into()), entries[0].payload);
    }

    #[tokio::test]
    async fn purge_requires_monotonic_durable_fence_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("raft.redb");
        let mut store = Store::open(&path, CLUSTER_ID, INCARNATION).unwrap();
        append(
            &mut store,
            [entry(1, 0, "zero"), entry(1, 1, "one"), entry(1, 2, "two")],
        )
        .await;
        store.save_committed(Some(log_id(1, 2))).await.unwrap();

        assert!(store.purge(log_id(1, 0)).await.is_err());
        store.advance_purge_fence(log_id(1, 1)).unwrap();
        assert!(store.purge(log_id(1, 2)).await.is_err());
        store.purge(log_id(1, 1)).await.unwrap();
        assert!(store.advance_purge_fence(log_id(1, 0)).is_err());

        let state = store.get_log_state().await.unwrap();
        assert_eq!(Some(log_id(1, 1)), state.last_purged_log_id);
        assert_eq!(Some(log_id(1, 2)), state.last_log_id);
        let remaining = store.try_get_log_entries(..).await.unwrap();
        assert_eq!(
            vec![log_id(1, 2)],
            remaining
                .iter()
                .map(|e| *e.get_log_id())
                .collect::<Vec<_>>()
        );
        drop(store);

        let mut reopened = Store::open(&path, CLUSTER_ID, INCARNATION).unwrap();
        assert_eq!(
            Some(log_id(1, 1)),
            reopened.get_log_state().await.unwrap().last_purged_log_id
        );
        reopened.advance_purge_fence(log_id(1, 2)).unwrap();
        reopened.purge(log_id(1, 2)).await.unwrap();
        let state = reopened.get_log_state().await.unwrap();
        assert_eq!(Some(log_id(1, 2)), state.last_purged_log_id);
        assert_eq!(Some(log_id(1, 2)), state.last_log_id);
    }

    #[tokio::test]
    async fn truncated_encoded_frame_is_rejected_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("raft.redb");
        let mut store = Store::open(&path, CLUSTER_ID, INCARNATION).unwrap();
        append(&mut store, [entry(1, 0, "zero")]).await;
        drop(store);

        {
            let db = redb::Builder::new()
                .set_cache_size(DEFAULT_RAFT_CACHE_BYTES)
                .open(&path)
                .unwrap();
            let mut tx = db.begin_write().unwrap();
            tx.set_durability(Durability::Immediate).unwrap();
            {
                let mut log = tx.open_table(LOG).unwrap();
                log.insert(0, b"\x01{".as_slice()).unwrap();
            }
            tx.commit().unwrap();
        }

        assert!(matches!(
            Store::open(&path, CLUSTER_ID, INCARNATION),
            Err(RedbRaftError::Corrupt(_))
        ));
    }
}
