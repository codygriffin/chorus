use chorus_codec::{ApplyResult, LogicalSnapshot, ReplicatedCommandV1};
use chorus_common::{ChorusError, LogId, Result};
use chorus_raft_contract::state_machine::{ReplayProgress, StateMachineAdapter};
use chorus_raft_contract::{InternalRaftLog, entry};
use chorus_storage::{MemoryStateStore, StateSnapshot, StateStore, StoreStatus};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const CLUSTER: [u8; 16] = [0x51; 16];
const INCARNATION: u64 = 12;

struct FaultingCountingStore {
    inner: Arc<MemoryStateStore>,
    fail_once_at: Mutex<Option<u64>>,
    attempts: Mutex<Vec<LogId>>,
    successes: Mutex<Vec<LogId>>,
}

impl FaultingCountingStore {
    fn new(inner: Arc<MemoryStateStore>, fail_once_at: Option<u64>) -> Self {
        Self {
            inner,
            fail_once_at: Mutex::new(fail_once_at),
            attempts: Mutex::new(Vec::new()),
            successes: Mutex::new(Vec::new()),
        }
    }

    fn attempts_at(&self, index: u64) -> usize {
        self.attempts
            .lock()
            .unwrap()
            .iter()
            .filter(|log_id| log_id.index == index)
            .count()
    }

    fn successes_at(&self, index: u64) -> usize {
        self.successes
            .lock()
            .unwrap()
            .iter()
            .filter(|log_id| log_id.index == index)
            .count()
    }
}

impl StateStore for FaultingCountingStore {
    fn snapshot(&self) -> Result<StateSnapshot> {
        self.inner.snapshot()
    }

    fn apply(&self, log_id: LogId, command: &ReplicatedCommandV1) -> Result<ApplyResult> {
        self.attempts.lock().unwrap().push(log_id);
        let should_fail = {
            let mut fault = self.fail_once_at.lock().unwrap();
            if *fault == Some(log_id.index) {
                *fault = None;
                true
            } else {
                false
            }
        };
        if should_fail {
            return Err(ChorusError::Storage(format!(
                "injected apply failure at index {}",
                log_id.index
            )));
        }
        let result = self.inner.apply(log_id, command)?;
        self.successes.lock().unwrap().push(log_id);
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

fn temp_path(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "chorus-state-machine-contract-{}-{}-{label}.log",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn clean(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("hard"));
}

#[test]
fn reconciles_apply_before_hard_marker_without_duplicate_apply() {
    let path = temp_path("apply-before-marker");
    clean(&path);
    let membership = ReplicatedCommandV1::Membership {
        voters: vec![1, 2, 3],
        learners: vec![4],
    };
    let first = entry(CLUSTER, INCARNATION, 1, 1, membership.clone());
    let second = entry(CLUSTER, INCARNATION, 1, 2, ReplicatedCommandV1::Noop);
    {
        let log = InternalRaftLog::open(&path, CLUSTER, INCARNATION).unwrap();
        log.save_vote(1, Some(1)).unwrap();
        log.append(&[first.clone(), second]).unwrap();
        log.commit(2).unwrap();
    }

    let memory = Arc::new(MemoryStateStore::with_cluster(CLUSTER, INCARNATION));
    let counted = Arc::new(FaultingCountingStore::new(memory, None));
    counted.apply(first.log_id, &membership).unwrap();

    let reopened = InternalRaftLog::open(&path, CLUSTER, INCARNATION).unwrap();
    assert_eq!(reopened.hard_state().unwrap().last_applied, LogId::ZERO);
    let adapter = StateMachineAdapter::new(reopened.clone(), counted.clone());
    assert_eq!(
        adapter.replay_committed().unwrap(),
        ReplayProgress {
            reconciled_hard_cursor: true,
            entries_applied: 1,
        }
    );
    assert_eq!(counted.successes_at(1), 1);
    assert_eq!(counted.attempts_at(1), 1);
    assert_eq!(counted.successes_at(2), 1);
    assert_eq!(counted.snapshot().unwrap().last_applied().index, 2);
    assert_eq!(reopened.hard_state().unwrap().last_applied.index, 2);
    let stored_membership = adapter.membership().unwrap();
    assert_eq!(stored_membership.log_id, first.log_id);
    assert_eq!(stored_membership.voters, vec![1, 2, 3]);
    assert_eq!(stored_membership.learners, vec![4]);
    clean(&path);
}

#[test]
fn apply_failure_leaves_marker_and_retry_resumes_once() {
    let path = temp_path("apply-failure");
    clean(&path);
    let log = InternalRaftLog::open(&path, CLUSTER, INCARNATION).unwrap();
    log.save_vote(1, Some(1)).unwrap();
    log.append(&[
        entry(CLUSTER, INCARNATION, 1, 1, ReplicatedCommandV1::Noop),
        entry(CLUSTER, INCARNATION, 1, 2, ReplicatedCommandV1::Noop),
    ])
    .unwrap();
    log.commit(2).unwrap();

    let memory = Arc::new(MemoryStateStore::with_cluster(CLUSTER, INCARNATION));
    let counted = Arc::new(FaultingCountingStore::new(memory, Some(2)));
    let adapter = StateMachineAdapter::new(log.clone(), counted.clone());
    assert!(matches!(
        adapter.replay_committed(),
        Err(ChorusError::Storage(message)) if message.contains("injected apply failure")
    ));
    assert_eq!(counted.snapshot().unwrap().last_applied().index, 1);
    assert_eq!(log.hard_state().unwrap().last_applied.index, 1);
    assert_eq!(counted.successes_at(1), 1);
    assert_eq!(counted.attempts_at(2), 1);

    assert_eq!(
        adapter.replay_committed().unwrap(),
        ReplayProgress {
            reconciled_hard_cursor: false,
            entries_applied: 1,
        }
    );
    assert_eq!(counted.snapshot().unwrap().last_applied().index, 2);
    assert_eq!(log.hard_state().unwrap().last_applied.index, 2);
    assert_eq!(counted.successes_at(2), 1);
    assert_eq!(counted.attempts_at(2), 2);
    clean(&path);
}
