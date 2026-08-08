#![forbid(unsafe_code)]

//! Deterministic fault injection and recovery helpers for Chorus storage
//! integration tests.
//!
//! The testkit deliberately wraps the public [`chorus_storage::StateStore`]
//! contract.  It does not reach into storage internals or add a runtime
//! dependency to production crates.  A scheduled fault is keyed by the
//! one-based apply-call number, so a test can reproduce the same boundary on
//! every run without timing or thread scheduling assumptions.

use chorus_codec::{ApplyResult, LogicalSnapshot, ReplicatedCommandV1};
use chorus_common::{ChorusError, LogId, Result};
use chorus_storage::{FileStateStore, StateSnapshot, StateStore, StoreStatus};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FaultPoint {
    /// Return an injected error without invoking the wrapped store.
    BeforeApply,
    /// Invoke the wrapped store successfully, then return an injected error
    /// to model a lost response or process crash after durable publication.
    AfterApply,
}

#[derive(Debug, Default)]
struct FaultState {
    apply_calls: u64,
    scheduled: BTreeSet<(u64, FaultPoint)>,
}

/// A deterministic, one-shot fault schedule.
#[derive(Clone, Debug, Default)]
pub struct FaultPlan {
    state: Arc<Mutex<FaultState>>,
}

impl FaultPlan {
    pub fn new() -> Self {
        Self::default()
    }

    /// Schedule one fault at a one-based `apply` call number.
    pub fn fail_once_at(&self, apply_call: u64, point: FaultPoint) -> Result<()> {
        if apply_call == 0 {
            return Err(ChorusError::Limit(
                "fault apply call number must be nonzero".into(),
            ));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ChorusError::Internal("fault plan lock poisoned".into()))?;
        state.scheduled.insert((apply_call, point));
        Ok(())
    }

    /// Remove all scheduled faults and restart deterministic call numbering.
    pub fn reset(&self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ChorusError::Internal("fault plan lock poisoned".into()))?;
        state.apply_calls = 0;
        state.scheduled.clear();
        Ok(())
    }

    pub fn apply_calls(&self) -> Result<u64> {
        Ok(self
            .state
            .lock()
            .map_err(|_| ChorusError::Internal("fault plan lock poisoned".into()))?
            .apply_calls)
    }

    fn begin_apply(&self) -> Result<u64> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ChorusError::Internal("fault plan lock poisoned".into()))?;
        state.apply_calls = state
            .apply_calls
            .checked_add(1)
            .ok_or_else(|| ChorusError::Limit("fault apply call counter exhausted".into()))?;
        Ok(state.apply_calls)
    }

    fn take_fault(&self, apply_call: u64, point: FaultPoint) -> Result<bool> {
        Ok(self
            .state
            .lock()
            .map_err(|_| ChorusError::Internal("fault plan lock poisoned".into()))?
            .scheduled
            .remove(&(apply_call, point)))
    }
}

/// Public [`StateStore`] decorator that applies a deterministic fault plan.
pub struct FaultingStore {
    inner: Arc<dyn StateStore>,
    plan: FaultPlan,
}

impl FaultingStore {
    pub fn new(inner: Arc<dyn StateStore>, plan: FaultPlan) -> Self {
        Self { inner, plan }
    }

    pub fn plan(&self) -> &FaultPlan {
        &self.plan
    }

    pub fn inner(&self) -> &Arc<dyn StateStore> {
        &self.inner
    }

    fn injected(point: FaultPoint, apply_call: u64) -> ChorusError {
        ChorusError::Storage(format!(
            "testkit fault at {point:?} on apply call {apply_call}"
        ))
    }
}

impl StateStore for FaultingStore {
    fn snapshot(&self) -> Result<StateSnapshot> {
        self.inner.snapshot()
    }

    fn apply(&self, log_id: LogId, command: &ReplicatedCommandV1) -> Result<ApplyResult> {
        let apply_call = self.plan.begin_apply()?;
        if self.plan.take_fault(apply_call, FaultPoint::BeforeApply)? {
            return Err(Self::injected(FaultPoint::BeforeApply, apply_call));
        }
        let result = self.inner.apply(log_id, command)?;
        if self.plan.take_fault(apply_call, FaultPoint::AfterApply)? {
            return Err(Self::injected(FaultPoint::AfterApply, apply_call));
        }
        Ok(result)
    }

    fn install(&self, snapshot: &LogicalSnapshot) -> Result<()> {
        self.inner.install(snapshot)
    }

    fn rollback(&self, snapshot: &LogicalSnapshot) -> Result<()> {
        self.inner.rollback(snapshot)
    }

    fn state_hash(&self) -> Result<[u8; 32]> {
        self.inner.state_hash()
    }

    fn status(&self) -> StoreStatus {
        self.inner.status()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryFingerprint {
    pub state_hash: [u8; 32],
    pub db_epoch: u64,
    pub catalog_epoch: u64,
    pub last_applied: LogId,
}

pub fn fingerprint(store: &dyn StateStore) -> Result<RecoveryFingerprint> {
    let snapshot = store.snapshot()?;
    Ok(RecoveryFingerprint {
        state_hash: snapshot.state_hash(),
        db_epoch: snapshot.db_epoch(),
        catalog_epoch: snapshot.catalog_epoch(),
        last_applied: snapshot.last_applied(),
    })
}

/// Reopen a file-backed store and return its deterministic logical state
/// fingerprint.  `FileStateStore::open` performs framed recovery-log replay
/// before this helper observes the snapshot.
pub fn recover_file_store(path: impl AsRef<Path>) -> Result<Arc<FileStateStore>> {
    Ok(Arc::new(FileStateStore::open(path)?))
}

pub fn recover_fingerprint(path: impl AsRef<Path>) -> Result<RecoveryFingerprint> {
    let store = recover_file_store(path)?;
    fingerprint(store.as_ref())
}
