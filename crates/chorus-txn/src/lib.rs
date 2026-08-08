#![forbid(unsafe_code)]

//! Snapshot/overlay transactions and the per-origin commit sequencer.

use chorus_codec::{
    ApplyResult, CommitTransactionV1, KvMutationV1, SchemaCommandV1, SchemaOperationV1,
    payload_hash,
};
use chorus_common::{ChorusError, Limits, LogId, OriginId, RequestId, Result, unix_now_us};
use chorus_storage::{MemoryStateStore, StateSnapshot, StateStore};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

pub trait Committer: Send + Sync {
    fn read_barrier(&self) -> Result<StateSnapshot>;
    fn submit(&self, command: CommitTransactionV1) -> Result<ApplyResult>;
    fn submit_schema(&self, command: SchemaCommandV1) -> Result<ApplyResult>;
    fn origin(&self) -> OriginId;
}

/// Direct single-process committer. It is useful for development, tests and
/// the standalone node; consensus adapters implement the same trait.
pub struct LocalCommitter {
    store: Arc<dyn StateStore>,
    origin: OriginId,
    next_log: Mutex<u64>,
}

impl LocalCommitter {
    pub fn new(store: Arc<dyn StateStore>, origin: OriginId) -> Result<Self> {
        let log = store.snapshot()?.last_applied().index;
        let committer = Self {
            store,
            origin,
            next_log: Mutex::new(log),
        };
        let activate =
            chorus_codec::ReplicatedCommandV1::ActivateOrigin(chorus_codec::ActivateOriginV1 {
                origin,
            });
        let idx = committer.next_log();
        let _ = committer.store.apply(
            LogId {
                term: 1,
                index: idx,
            },
            &activate,
        )?;
        Ok(committer)
    }
    fn next_log(&self) -> u64 {
        let mut n = self.next_log.lock().expect("log lock poisoned");
        *n += 1;
        *n
    }
    pub fn store(&self) -> &Arc<dyn StateStore> {
        &self.store
    }
}

impl Committer for LocalCommitter {
    fn read_barrier(&self) -> Result<StateSnapshot> {
        self.store.snapshot()
    }
    fn submit(&self, command: CommitTransactionV1) -> Result<ApplyResult> {
        let id = self.next_log();
        self.store.apply(
            LogId { term: 1, index: id },
            &chorus_codec::ReplicatedCommandV1::CommitTransaction(command),
        )
    }
    fn submit_schema(&self, command: SchemaCommandV1) -> Result<ApplyResult> {
        let id = self.next_log();
        self.store.apply(
            LogId { term: 1, index: id },
            &chorus_codec::ReplicatedCommandV1::SchemaChange(command),
        )
    }
    fn origin(&self) -> OriginId {
        self.origin
    }
}

#[derive(Clone, Debug)]
pub struct Overlay {
    values: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    bytes: usize,
    max_bytes: usize,
    max_mutations: usize,
}

impl Overlay {
    pub fn new(limits: &Limits) -> Self {
        Self {
            values: BTreeMap::new(),
            bytes: 0,
            max_bytes: limits.max_transaction_bytes,
            max_mutations: limits.max_mutations,
        }
    }
    pub fn get<'a>(&'a self, snapshot: &'a StateSnapshot, key: &[u8]) -> Option<Option<&'a [u8]>> {
        if let Some(v) = self.values.get(key) {
            return Some(v.as_deref());
        }
        snapshot.get(key).map(Some)
    }
    pub fn contains_key(&self, key: &[u8]) -> bool {
        self.values.contains_key(key)
    }
    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        self.insert(key, Some(value))
    }
    pub fn delete(&mut self, key: Vec<u8>) -> Result<()> {
        self.insert(key, None)
    }
    fn insert(&mut self, key: Vec<u8>, value: Option<Vec<u8>>) -> Result<()> {
        let old = self
            .values
            .get(&key)
            .map(|v| v.as_ref().map(Vec::len).unwrap_or(0))
            .unwrap_or(0);
        let new = value.as_ref().map(Vec::len).unwrap_or(0);
        let projected = self
            .bytes
            .saturating_sub(key.len() + old)
            .saturating_add(key.len() + new);
        if projected > self.max_bytes {
            return Err(ChorusError::Limit(
                "transaction mutation bytes exceed limit".into(),
            ));
        }
        if !self.values.contains_key(&key) && self.values.len() >= self.max_mutations {
            return Err(ChorusError::Limit(
                "transaction mutation count exceeds limit".into(),
            ));
        }
        self.bytes = projected;
        self.values.insert(key, value);
        Ok(())
    }
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    pub fn len(&self) -> usize {
        self.values.len()
    }
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&Vec<u8>, &Option<Vec<u8>>)> {
        self.values.iter()
    }
    pub fn clear(&mut self) {
        self.values.clear();
        self.bytes = 0;
    }
    pub fn checkpoint(&self) -> Self {
        self.clone()
    }
    pub fn restore(&mut self, checkpoint: Self) {
        *self = checkpoint;
    }
    /// Merge a base ordered range with overlay keys. Deleted values are hidden.
    pub fn scan<'a>(
        &'a self,
        snapshot: &'a StateSnapshot,
        start: &[u8],
        end: Option<&[u8]>,
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut merged = BTreeMap::new();
        for (k, v) in snapshot.scan(start, end) {
            merged.insert(k.clone(), v.clone());
        }
        for (k, v) in self.values.range(start.to_vec()..) {
            if end.map(|e| k.as_slice() >= e).unwrap_or(false) {
                break;
            }
            match v {
                Some(v) => {
                    merged.insert(k.clone(), v.clone());
                }
                None => {
                    merged.remove(k);
                }
            }
        }
        merged.into_iter().collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionStatus {
    Active,
    Failed,
    Committed,
    Aborted,
}

pub struct Transaction {
    pub transaction_id: [u8; 16],
    pub snapshot: StateSnapshot,
    pub base_epoch: u64,
    pub base_log_id: LogId,
    pub overlay: Overlay,
    pub transaction_timestamp_us: i64,
    pub statement_timestamp_us: i64,
    pub statement_ordinal: u32,
    pub started_at: Instant,
    pub limits: Limits,
    pub status: TransactionStatus,
    pub read_only: bool,
}

impl Transaction {
    pub fn begin(snapshot: StateSnapshot, limits: Limits) -> Self {
        let now = unix_now_us();
        Self {
            transaction_id: *Uuid::new_v4().as_bytes(),
            base_epoch: snapshot.db_epoch(),
            base_log_id: snapshot.last_applied(),
            snapshot,
            overlay: Overlay::new(&limits),
            transaction_timestamp_us: now,
            statement_timestamp_us: now,
            statement_ordinal: 0,
            started_at: Instant::now(),
            limits,
            status: TransactionStatus::Active,
            read_only: true,
        }
    }
    pub fn with_id(snapshot: StateSnapshot, limits: Limits, id: [u8; 16]) -> Self {
        let mut t = Self::begin(snapshot, limits);
        t.transaction_id = id;
        t
    }
    pub fn set_statement_time(&mut self) {
        self.statement_timestamp_us = unix_now_us();
        self.statement_ordinal = self.statement_ordinal.saturating_add(1);
    }
    pub fn check_age(&self) -> Result<()> {
        if self.started_at.elapsed() > Duration::from_millis(self.limits.max_transaction_age_ms) {
            return Err(ChorusError::Limit(
                "transaction exceeded maximum age".into(),
            ));
        }
        if self.status == TransactionStatus::Failed {
            return Err(ChorusError::Sql(
                chorus_common::SqlError::failed_transaction(),
            ));
        }
        if self.status != TransactionStatus::Active {
            return Err(ChorusError::Sql(chorus_common::SqlError::new(
                "25000",
                "transaction is not active",
            )));
        }
        Ok(())
    }
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.overlay
            .get(&self.snapshot, key)
            .and_then(|v| v.map(ToOwned::to_owned))
    }
    pub fn scan(&self, start: &[u8], end: Option<&[u8]>) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.overlay.scan(&self.snapshot, start, end)
    }
    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        self.check_age()?;
        self.read_only = false;
        self.overlay.put(key, value)
    }
    pub fn delete(&mut self, key: Vec<u8>) -> Result<()> {
        self.check_age()?;
        self.read_only = false;
        self.overlay.delete(key)
    }
    pub fn fail(&mut self) {
        self.status = TransactionStatus::Failed;
        self.overlay.clear();
    }
    pub fn rollback(&mut self) {
        self.overlay.clear();
        self.status = TransactionStatus::Aborted;
    }
    pub fn is_read_only(&self) -> bool {
        self.overlay.is_empty()
    }

    pub fn commit(
        &mut self,
        committer: &dyn Committer,
        sequencer: &CommitSequencer,
    ) -> Result<ApplyResult> {
        self.check_age()?;
        if self.overlay.is_empty() {
            self.status = TransactionStatus::Committed;
            return Ok(ApplyResult::Noop);
        }
        let mutations: Vec<_> = self
            .overlay
            .iter()
            .map(|(key, value)| match value {
                Some(value) => KvMutationV1::Put {
                    key: key.clone(),
                    value: value.clone(),
                },
                None => KvMutationV1::Delete { key: key.clone() },
            })
            .collect();
        let canonical = canonical_mutations(&mutations);
        let seq = sequencer.next_sequence()?;
        let id = RequestId::new(sequencer.origin(), seq);
        let hash = payload_hash(1, &id, self.base_epoch, &canonical);
        let command = CommitTransactionV1 {
            request_id: id,
            payload_hash: hash,
            base_epoch: self.base_epoch,
            mutations,
        };
        let result = sequencer.submit(committer, command)?;
        match result {
            ApplyResult::Committed { .. } | ApplyResult::Duplicate(_) => {
                self.status = TransactionStatus::Committed;
                self.overlay.clear();
                Ok(result)
            }
            ApplyResult::SerializationFailure { .. } => {
                self.status = TransactionStatus::Aborted;
                Err(ChorusError::Sql(chorus_common::SqlError::serialization(
                    "could not serialize access due to concurrent update",
                )))
            }
            ApplyResult::StaleOrigin => {
                self.status = TransactionStatus::Aborted;
                Err(ChorusError::Sql(
                    chorus_common::SqlError::cluster_unavailable("node origin has been fenced"),
                ))
            }
            ApplyResult::Rejected(message) | ApplyResult::ProtocolError(message) => {
                self.status = TransactionStatus::Aborted;
                Err(ChorusError::Internal(message))
            }
            other => {
                self.status = TransactionStatus::Aborted;
                Ok(other)
            }
        }
    }
}

pub fn canonical_mutations(mutations: &[KvMutationV1]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for m in mutations {
        bytes.extend_from_slice(m.key());
        bytes.push(match m {
            KvMutationV1::Put { .. } => 1,
            KvMutationV1::Delete { .. } => 2,
        });
        if let KvMutationV1::Put { value, .. } = m {
            bytes.extend_from_slice(value);
        }
    }
    bytes
}

pub struct CommitSequencer {
    origin: OriginId,
    state: Mutex<SequencerState>,
}
struct SequencerState {
    next: u64,
    unresolved: bool,
}
impl CommitSequencer {
    pub fn new(origin: OriginId) -> Self {
        Self {
            origin,
            state: Mutex::new(SequencerState {
                next: 1,
                unresolved: false,
            }),
        }
    }
    pub fn origin(&self) -> OriginId {
        self.origin
    }
    fn next_sequence(&self) -> Result<u64> {
        let mut s = self
            .state
            .lock()
            .map_err(|_| ChorusError::Internal("commit sequencer lock poisoned".into()))?;
        if s.unresolved {
            return Err(ChorusError::Protocol(
                "one unresolved command is already in flight for this origin".into(),
            ));
        }
        s.unresolved = true;
        Ok(s.next)
    }
    fn submit(
        &self,
        committer: &dyn Committer,
        command: CommitTransactionV1,
    ) -> Result<ApplyResult> {
        let result = committer.submit(command);
        let mut s = self
            .state
            .lock()
            .map_err(|_| ChorusError::Internal("commit sequencer lock poisoned".into()))?;
        if result.is_ok() {
            s.next = s
                .next
                .checked_add(1)
                .ok_or_else(|| ChorusError::Limit("request sequence exhausted".into()))?;
            s.unresolved = false;
        } else {
            s.unresolved = false;
        }
        result
    }
    pub fn submit_schema(
        &self,
        committer: &dyn Committer,
        base_epoch: u64,
        operation: SchemaOperationV1,
    ) -> Result<ApplyResult> {
        let sequence = self.next_sequence()?;
        let request_id = RequestId::new(self.origin, sequence);
        let payload = serde_json::to_vec(&operation)
            .map_err(|e| ChorusError::Serialization(e.to_string()))?;
        let payload_hash = payload_hash(1, &request_id, base_epoch, &payload);
        let command = SchemaCommandV1 {
            request_id,
            payload_hash,
            base_epoch,
            operation,
        };
        let result = committer.submit_schema(command);
        let mut s = self
            .state
            .lock()
            .map_err(|_| ChorusError::Internal("commit sequencer lock poisoned".into()))?;
        if result.is_ok() {
            s.next = s
                .next
                .checked_add(1)
                .ok_or_else(|| ChorusError::Limit("request sequence exhausted".into()))?;
        }
        s.unresolved = false;
        result
    }
    pub fn next_sequence_hint(&self) -> u64 {
        self.state.lock().map(|s| s.next).unwrap_or(0)
    }
}

#[derive(Clone, Debug)]
pub enum SessionTxnState {
    Idle,
    InTransaction,
    FailedTransaction,
}

pub struct TransactionManager {
    committer: Arc<dyn Committer>,
    limits: Limits,
    pub sequencer: Arc<CommitSequencer>,
}
impl TransactionManager {
    pub fn new(committer: Arc<dyn Committer>, origin: OriginId, limits: Limits) -> Self {
        Self {
            committer,
            limits,
            sequencer: Arc::new(CommitSequencer::new(origin)),
        }
    }
    pub fn begin(&self) -> Result<Transaction> {
        let snapshot = self.committer.read_barrier()?;
        Ok(Transaction::begin(snapshot, self.limits.clone()))
    }
    pub fn committer(&self) -> &Arc<dyn Committer> {
        &self.committer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overlay_merges_and_tombstones() {
        let store: Arc<dyn StateStore> = Arc::new(MemoryStateStore::new());
        let origin = OriginId::new(1);
        let c = Arc::new(LocalCommitter::new(store.clone(), origin).unwrap());
        let manager = TransactionManager::new(c.clone(), origin, Limits::default());
        let mut t = manager.begin().unwrap();
        t.put(b"a".to_vec(), b"1".to_vec()).unwrap();
        assert_eq!(t.get(b"a"), Some(b"1".to_vec()));
        t.delete(b"a".to_vec()).unwrap();
        assert_eq!(t.get(b"a"), None);
    }
    #[test]
    fn transaction_commit_advances_epoch() {
        let store: Arc<dyn StateStore> = Arc::new(MemoryStateStore::new());
        let origin = OriginId::new(1);
        let c = Arc::new(LocalCommitter::new(store.clone(), origin).unwrap());
        let manager = TransactionManager::new(c.clone(), origin, Limits::default());
        let mut t = manager.begin().unwrap();
        t.put(b"a".to_vec(), b"1".to_vec()).unwrap();
        assert!(matches!(
            t.commit(c.as_ref(), &manager.sequencer).unwrap(),
            ApplyResult::Committed { epoch: 1, .. }
        ));
    }
}
