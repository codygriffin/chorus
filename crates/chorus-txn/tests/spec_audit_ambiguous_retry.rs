use chorus_codec::{ApplyResult, CommitTransactionV1, SchemaCommandV1};
use chorus_common::{ChorusError, Limits, OriginId, Result};
use chorus_storage::{MemoryStateStore, StateSnapshot, StateStore};
use chorus_txn::{Committer, LocalCommitter, TransactionManager};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

struct ApplyThenLoseResponse {
    inner: Arc<LocalCommitter>,
    first: AtomicBool,
}

impl Committer for ApplyThenLoseResponse {
    fn read_barrier(&self) -> Result<StateSnapshot> {
        self.inner.read_barrier()
    }

    fn submit(&self, command: CommitTransactionV1) -> Result<ApplyResult> {
        let result = self.inner.submit(command);
        if self.first.swap(false, Ordering::SeqCst) {
            // Simulate a process/network failure after the state machine has
            // durably applied the command but before the client saw a reply.
            return Err(ChorusError::Consensus("response lost after apply".into()));
        }
        result
    }

    fn submit_schema(&self, command: SchemaCommandV1) -> Result<ApplyResult> {
        self.inner.submit_schema(command)
    }

    fn origin(&self) -> OriginId {
        self.inner.origin()
    }
}

#[test]
fn retry_after_ambiguous_apply_reuses_the_same_request_identity() {
    let store = Arc::new(MemoryStateStore::new()) as Arc<dyn StateStore>;
    // MemoryStateStore starts with the deterministic bootstrap membership
    // containing node 1; use that authorized origin for this local retry
    // exercise rather than relying on an unreplicated activation.
    let origin = OriginId::new(1);
    let local = Arc::new(LocalCommitter::new(store.clone(), origin).unwrap());
    let committer = ApplyThenLoseResponse {
        inner: local.clone(),
        first: AtomicBool::new(true),
    };
    let manager = TransactionManager::new(Arc::new(committer), origin, Limits::default());
    let mut txn = manager.begin().unwrap();
    // Short metadata keys are valid for this storage-level transaction test;
    // table row keys require a catalog entry that is outside this gate.
    txn.put(b"a".to_vec(), b"once".to_vec()).unwrap();

    assert!(
        txn.commit(manager.committer().as_ref(), &manager.sequencer)
            .is_err()
    );
    assert_eq!(store.snapshot().unwrap().get(b"a"), Some(&b"once"[..]));

    // A retry must resolve the original request as a duplicate and must not
    // allocate a fresh sequence/request that could apply the mutation twice.
    assert!(matches!(
        txn.commit(manager.committer().as_ref(), &manager.sequencer),
        Ok(ApplyResult::Duplicate(_))
    ));
    assert_eq!(store.snapshot().unwrap().db_epoch(), 1);
    assert_eq!(manager.sequencer.next_sequence_hint(), 2);
}
