#![forbid(unsafe_code)]

//! Snapshot/overlay transactions and the per-origin commit sequencer.

use chorus_codec::{
    ApplyResult, CommitTransactionV1, KvMutationV1, ReplicatedCommandV1, SchemaCommandV1,
    SchemaOperationV1, canonical_mutations as encode_canonical_mutations, encode_command,
    payload_hash,
};
use chorus_common::{ChorusError, Limits, LogId, OriginId, RequestId, Result, unix_now_us};
#[cfg(test)]
use chorus_storage::MemoryStateStore;
use chorus_storage::{StateSnapshot, StateStore};
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

/// The size charged for one mutation in the versioned command envelope.
/// Keep this in lock-step with `KvMutationV1::encoded_len`; unlike a plain
/// key/value sum it accounts for the operation and length fields too.
fn mutation_size(key_len: usize, value: Option<&[u8]>) -> Result<usize> {
    let base = 1usize
        .checked_add(4)
        .and_then(|n| n.checked_add(key_len))
        .ok_or_else(|| ChorusError::Limit("transaction mutation bytes exhausted".into()))?;
    match value {
        Some(value) => base
            .checked_add(4)
            .and_then(|n| n.checked_add(value.len()))
            .ok_or_else(|| ChorusError::Limit("transaction mutation bytes exhausted".into())),
        None => Ok(base),
    }
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
    max_key_bytes: usize,
    max_row_bytes: usize,
}

impl Overlay {
    pub fn new(limits: &Limits) -> Self {
        Self {
            values: BTreeMap::new(),
            bytes: 0,
            max_bytes: limits.max_transaction_bytes,
            max_mutations: limits.max_mutations,
            max_key_bytes: limits.max_key_bytes,
            max_row_bytes: limits.max_row_bytes,
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
        if key.len() > self.max_key_bytes {
            return Err(ChorusError::Limit(
                "physical key exceeds configured limit".into(),
            ));
        }
        if value.as_ref().is_some_and(|v| v.len() > self.max_row_bytes) {
            return Err(ChorusError::Limit(
                "row value exceeds configured limit".into(),
            ));
        }
        let old_bytes = match self.values.get(&key) {
            Some(old) => mutation_size(key.len(), old.as_deref())?,
            None => 0,
        };
        let new_bytes = mutation_size(key.len(), value.as_deref())?;
        let projected = self
            .bytes
            .checked_sub(old_bytes)
            .ok_or_else(|| ChorusError::Internal("overlay byte accounting underflow".into()))?
            .checked_add(new_bytes)
            .ok_or_else(|| ChorusError::Limit("transaction mutation bytes exhausted".into()))?;
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
            read_only: false,
        }
    }
    pub fn with_id(snapshot: StateSnapshot, limits: Limits, id: [u8; 16]) -> Self {
        let mut t = Self::begin(snapshot, limits);
        t.transaction_id = id;
        t
    }
    pub fn set_statement_time(&mut self) -> Result<()> {
        let ordinal = match self.statement_ordinal.checked_add(1) {
            Some(ordinal) => ordinal,
            None => {
                self.status = TransactionStatus::Aborted;
                self.overlay.clear();
                return Err(ChorusError::Limit("statement ordinal exhausted".into()));
            }
        };
        self.statement_timestamp_us = unix_now_us();
        self.statement_ordinal = ordinal;
        Ok(())
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
    fn check_age_for_write(&mut self) -> Result<()> {
        match self.check_age() {
            Err(error @ ChorusError::Limit(_)) => {
                self.status = TransactionStatus::Aborted;
                self.overlay.clear();
                Err(error)
            }
            other => other,
        }
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
        self.check_age_for_write()?;
        if self.read_only {
            return Err(ChorusError::Sql(chorus_common::SqlError::new(
                "25006",
                "cannot execute write in a read-only transaction",
            )));
        }
        self.read_only = false;
        self.overlay.put(key, value)
    }
    pub fn delete(&mut self, key: Vec<u8>) -> Result<()> {
        self.check_age_for_write()?;
        if self.read_only {
            return Err(ChorusError::Sql(chorus_common::SqlError::new(
                "25006",
                "cannot execute write in a read-only transaction",
            )));
        }
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
        self.check_age_for_write()?;
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
        // An uncertain submit leaves an exact command pending.  Reusing its
        // sequence is intentional; the sequencer compares the encoded
        // command before retrying and rejects any changed payload.
        let seq = match sequencer.pending_sequence() {
            Some(sequence) => sequence,
            None => sequencer.next_sequence()?,
        };
        let id = RequestId::new(sequencer.origin(), seq);
        let hash = payload_hash(1, &id, self.base_epoch, &canonical);
        let command = CommitTransactionV1 {
            request_id: id,
            payload_hash: hash,
            base_epoch: self.base_epoch,
            mutations,
        };
        let result = match sequencer.submit(committer, command) {
            Ok(result) => result,
            Err(error) => {
                // A committer/transport error is retryable and leaves this
                // transaction active.  A sequencer protocol error means the
                // pending request belongs to a different transaction or the
                // command changed, so this transaction cannot safely proceed.
                if matches!(error, ChorusError::Protocol(_)) {
                    self.status = TransactionStatus::Aborted;
                }
                return Err(error);
            }
        };
        let outcome = validate_apply_result(&result);
        if let Err(error) = outcome {
            self.status = TransactionStatus::Aborted;
            return Err(error);
        }
        match result {
            ApplyResult::Committed { .. } | ApplyResult::Duplicate(_) => {
                self.status = TransactionStatus::Committed;
                self.overlay.clear();
                Ok(result)
            }
            // `validate_apply_result` rejects every other terminal outcome.
            _ => unreachable!("non-success apply result passed validation"),
        }
    }
}

/// Convert a replicated terminal result into the transaction-layer outcome.
/// A duplicate is only successful when the cached result was successful; a
/// cached serialization failure or rejection must retain its original error
/// semantics rather than being mistaken for a committed transaction.
fn validate_apply_result(result: &ApplyResult) -> Result<()> {
    match result {
        ApplyResult::Committed { .. } => Ok(()),
        ApplyResult::Duplicate(inner) => validate_apply_result(inner),
        ApplyResult::SerializationFailure { .. } => {
            Err(ChorusError::Sql(chorus_common::SqlError::serialization(
                "could not serialize access due to concurrent update",
            )))
        }
        ApplyResult::StaleOrigin => Err(ChorusError::Sql(
            chorus_common::SqlError::cluster_unavailable("node origin has been fenced"),
        )),
        ApplyResult::Rejected(message) | ApplyResult::ProtocolError(message) => {
            Err(ChorusError::Internal(message.clone()))
        }
        ApplyResult::AlreadyProcessed => Err(ChorusError::Protocol(
            "request outcome is no longer available for retry".into(),
        )),
        ApplyResult::Noop | ApplyResult::Activated => Err(ChorusError::Internal(
            "committer returned a non-terminal transaction result".into(),
        )),
    }
}

pub fn canonical_mutations(mutations: &[KvMutationV1]) -> Vec<u8> {
    encode_canonical_mutations(mutations).unwrap_or_default()
}

#[derive(Clone)]
pub struct CommitSequencer {
    origin: OriginId,
    // Cloning a sequencer shares the per-origin state.  A process should keep
    // one clone at the engine/session boundary so sessions cannot reuse a
    // sequence number concurrently.
    state: Arc<Mutex<SequencerState>>,
}

#[derive(Clone)]
enum PendingCommand {
    Transaction {
        command: CommitTransactionV1,
        encoded: Vec<u8>,
    },
    Schema {
        command: SchemaCommandV1,
        encoded: Vec<u8>,
    },
}

struct SequencerState {
    next: u64,
    // `reserved` closes the small gap between allocating a sequence and
    // recording the exact command.  `pending` then remains populated across
    // an uncertain committer error so a retry is byte-for-byte identical.
    reserved: bool,
    pending: Option<PendingCommand>,
}

impl CommitSequencer {
    pub fn new(origin: OriginId) -> Self {
        Self {
            origin,
            state: Arc::new(Mutex::new(SequencerState {
                next: 1,
                reserved: false,
                pending: None,
            })),
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
        if s.reserved || s.pending.is_some() {
            return Err(ChorusError::Protocol(
                "one unresolved command is already in flight for this origin".into(),
            ));
        }
        // A sequence at u64::MAX cannot be followed by another contiguous
        // sequence, so fail closed before reserving it.
        if s.next == u64::MAX {
            return Err(ChorusError::Limit("request sequence exhausted".into()));
        }
        s.reserved = true;
        Ok(s.next)
    }

    /// Returns the sequence of an exact command awaiting a retry.  It is
    /// intentionally read-only; callers still pass the full command to
    /// `submit`, which verifies its encoded bytes against the pending copy.
    pub fn pending_sequence(&self) -> Option<u64> {
        let state = self.state.lock().ok()?;
        match state.pending.as_ref() {
            Some(PendingCommand::Transaction { command, .. }) => Some(command.request_id.sequence),
            Some(PendingCommand::Schema { command, .. }) => Some(command.request_id.sequence),
            None => None,
        }
    }

    fn submit(
        &self,
        committer: &dyn Committer,
        command: CommitTransactionV1,
    ) -> Result<ApplyResult> {
        let encoded = match encode_command(&ReplicatedCommandV1::CommitTransaction(command.clone()))
        {
            Ok(encoded) => encoded,
            Err(error) => {
                self.release_reservation(command.request_id.sequence)?;
                return Err(ChorusError::Serialization(error.to_string()));
            }
        };
        let command = {
            let mut s = self
                .state
                .lock()
                .map_err(|_| ChorusError::Internal("commit sequencer lock poisoned".into()))?;
            match s.pending.as_ref() {
                Some(PendingCommand::Transaction {
                    command: pending,
                    encoded: pending_encoded,
                }) if pending_encoded == &encoded => pending.clone(),
                Some(PendingCommand::Transaction { .. }) => {
                    return Err(ChorusError::Protocol(
                        "retry payload differs from the unresolved transaction command".into(),
                    ));
                }
                Some(PendingCommand::Schema { .. }) => {
                    return Err(ChorusError::Protocol(
                        "a schema command is unresolved for this origin".into(),
                    ));
                }
                None => {
                    if !s.reserved
                        || command.request_id.origin != self.origin
                        || command.request_id.sequence != s.next
                    {
                        return Err(ChorusError::Protocol(
                            "transaction command sequence is not reserved for this origin".into(),
                        ));
                    }
                    s.pending = Some(PendingCommand::Transaction {
                        command: command.clone(),
                        encoded,
                    });
                    command
                }
            }
        };
        let result = committer.submit(command);
        self.finish(result.is_ok())?;
        result
    }

    fn release_reservation(&self, sequence: u64) -> Result<()> {
        let mut s = self
            .state
            .lock()
            .map_err(|_| ChorusError::Internal("commit sequencer lock poisoned".into()))?;
        if s.pending.is_none() && s.reserved && sequence == s.next {
            s.reserved = false;
        }
        Ok(())
    }

    fn finish(&self, result_ok: bool) -> Result<()> {
        let mut s = self
            .state
            .lock()
            .map_err(|_| ChorusError::Internal("commit sequencer lock poisoned".into()))?;
        if result_ok {
            s.pending = None;
            s.reserved = false;
            // Keep MAX as a permanent exhausted sentinel.  The command at
            // MAX is already terminal and must not be replayed with a reused
            // sequence, while no subsequent sequence may be allocated.
            if s.next != u64::MAX {
                s.next = s
                    .next
                    .checked_add(1)
                    .ok_or_else(|| ChorusError::Limit("request sequence exhausted".into()))?;
            }
        }
        // An Err is deliberately left pending: the command may have reached
        // a quorum even though the caller observed a transport error.
        Ok(())
    }

    pub fn submit_schema(
        &self,
        committer: &dyn Committer,
        base_epoch: u64,
        operation: SchemaOperationV1,
    ) -> Result<ApplyResult> {
        // Serialize before reserving a sequence so a local encoding failure
        // cannot strand an unresolved reservation.
        let payload = serde_json::to_vec(&operation)
            .map_err(|e| ChorusError::Serialization(e.to_string()))?;
        let sequence = match self.pending_sequence() {
            Some(sequence) => sequence,
            None => self.next_sequence()?,
        };
        let request_id = RequestId::new(self.origin, sequence);
        let payload_hash = payload_hash(1, &request_id, base_epoch, &payload);
        let command = SchemaCommandV1 {
            request_id,
            payload_hash,
            base_epoch,
            operation,
        };
        let encoded = match encode_command(&ReplicatedCommandV1::SchemaChange(command.clone())) {
            Ok(encoded) => encoded,
            Err(error) => {
                self.release_reservation(command.request_id.sequence)?;
                return Err(ChorusError::Serialization(error.to_string()));
            }
        };
        let command = {
            let mut s = self
                .state
                .lock()
                .map_err(|_| ChorusError::Internal("commit sequencer lock poisoned".into()))?;
            match s.pending.as_ref() {
                Some(PendingCommand::Schema {
                    command: pending,
                    encoded: pending_encoded,
                }) if pending_encoded == &encoded => pending.clone(),
                Some(PendingCommand::Schema { .. }) => {
                    return Err(ChorusError::Protocol(
                        "retry payload differs from the unresolved schema command".into(),
                    ));
                }
                Some(PendingCommand::Transaction { .. }) => {
                    return Err(ChorusError::Protocol(
                        "a transaction command is unresolved for this origin".into(),
                    ));
                }
                None => {
                    if !s.reserved
                        || command.request_id.origin != self.origin
                        || command.request_id.sequence != s.next
                    {
                        return Err(ChorusError::Protocol(
                            "schema command sequence is not reserved for this origin".into(),
                        ));
                    }
                    s.pending = Some(PendingCommand::Schema {
                        command: command.clone(),
                        encoded,
                    });
                    command
                }
            }
        };
        let result = committer.submit_schema(command);
        self.finish(result.is_ok())?;
        result
    }

    /// Resolve the command left by an ambiguous transport response.  The
    /// caller need not reconstruct its payload; the encoded pending copy is
    /// submitted exactly as it was first sent.
    pub fn retry_pending(&self, committer: &dyn Committer) -> Result<ApplyResult> {
        let pending = self
            .state
            .lock()
            .map_err(|_| ChorusError::Internal("commit sequencer lock poisoned".into()))?
            .pending
            .clone()
            .ok_or_else(|| ChorusError::Protocol("no unresolved command".into()))?;
        let result = match pending {
            PendingCommand::Transaction { command, .. } => committer.submit(command),
            PendingCommand::Schema { command, .. } => committer.submit_schema(command),
        };
        self.finish(result.is_ok())?;
        result
    }

    /// Retry the retained command if one exists, preserving a poisoned-state
    /// error instead of treating it as an empty sequencer.  Shutdown callers
    /// use this single check-and-retry operation after all sessions drain.
    pub fn retry_pending_if_any(&self, committer: &dyn Committer) -> Result<Option<ApplyResult>> {
        let pending = self
            .state
            .lock()
            .map_err(|_| ChorusError::Internal("commit sequencer lock poisoned".into()))?
            .pending
            .clone();
        let Some(pending) = pending else {
            return Ok(None);
        };
        let result = match pending {
            PendingCommand::Transaction { command, .. } => committer.submit(command),
            PendingCommand::Schema { command, .. } => committer.submit_schema(command),
        };
        self.finish(result.is_ok())?;
        result.map(Some)
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

    #[test]
    fn encoding_failure_releases_reserved_sequence() {
        let store: Arc<dyn StateStore> = Arc::new(MemoryStateStore::new());
        let origin = OriginId::new(1);
        let c = Arc::new(LocalCommitter::new(store, origin).unwrap());
        let sequencer = CommitSequencer::new(origin);
        let sequence = sequencer.next_sequence().unwrap();
        let command = CommitTransactionV1 {
            request_id: RequestId::new(origin, sequence),
            payload_hash: [0; 32],
            base_epoch: 0,
            // JSON encodes bytes as an array; this exceeds the 4 MiB command
            // envelope even though the raw value itself is modest.
            mutations: vec![KvMutationV1::Put {
                key: b"oversized".to_vec(),
                value: vec![u8::MAX; 1_100_000],
            }],
        };
        assert!(sequencer.submit(c.as_ref(), command).is_err());
        assert_eq!(sequencer.next_sequence().unwrap(), sequence);
    }
}
