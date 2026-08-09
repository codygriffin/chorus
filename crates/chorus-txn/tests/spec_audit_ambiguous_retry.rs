use chorus_codec::{ApplyResult, CommitTransactionV1, SchemaCommandV1, SchemaOperationV1};
use chorus_common::{ChorusError, Limits, LogId, OriginId, Result};
use chorus_storage::{MemoryStateStore, StateSnapshot, StateStore};
use chorus_txn::{CommitSequencer, Committer, LocalCommitter, TransactionManager};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
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

    assert!(matches!(
        txn.commit(manager.committer().as_ref(), &manager.sequencer),
        Err(ChorusError::OutcomeUnknown(_))
    ));
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

struct FixedResultCommitter {
    store: Arc<dyn StateStore>,
    origin: OriginId,
    result: ApplyResult,
    calls: AtomicUsize,
}

impl Committer for FixedResultCommitter {
    fn read_barrier(&self) -> Result<StateSnapshot> {
        self.store.snapshot()
    }

    fn submit(&self, _command: CommitTransactionV1) -> Result<ApplyResult> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Ok(self.result.clone())
    }

    fn submit_schema(&self, _command: SchemaCommandV1) -> Result<ApplyResult> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Ok(self.result.clone())
    }

    fn origin(&self) -> OriginId {
        self.origin
    }
}

#[test]
fn non_consuming_apply_results_do_not_skip_the_pending_sequence() {
    for result in [
        ApplyResult::StaleOrigin,
        ApplyResult::AlreadyProcessed,
        ApplyResult::ProtocolError("request sequence gap".into()),
        ApplyResult::Noop,
    ] {
        let store = Arc::new(MemoryStateStore::new()) as Arc<dyn StateStore>;
        let origin = OriginId::new(1);
        let committer = Arc::new(FixedResultCommitter {
            store,
            origin,
            result,
            calls: AtomicUsize::new(0),
        });
        let manager = TransactionManager::new(
            committer.clone() as Arc<dyn Committer>,
            origin,
            Limits::default(),
        );
        let mut first = manager.begin().unwrap();
        first.put(b"a".to_vec(), b"first".to_vec()).unwrap();
        assert!(
            first
                .commit(manager.committer().as_ref(), &manager.sequencer)
                .is_err()
        );
        assert_eq!(Some(1), manager.sequencer.pending_sequence());
        assert_eq!(1, manager.sequencer.next_sequence_hint());

        // A different transaction cannot steal sequence 1 or make the local
        // sequencer jump over the command which the state machine rejected
        // without consuming.
        let mut second = manager.begin().unwrap();
        second.put(b"b".to_vec(), b"second".to_vec()).unwrap();
        assert!(matches!(
            second.commit(manager.committer().as_ref(), &manager.sequencer),
            Err(ChorusError::Protocol(_))
        ));
        assert_eq!(1, committer.calls.load(Ordering::Acquire));
        assert_eq!(Some(1), manager.sequencer.pending_sequence());
        assert_eq!(1, manager.sequencer.next_sequence_hint());
    }
}

#[test]
fn recorded_terminal_failures_consume_exactly_one_sequence() {
    for result in [
        ApplyResult::SerializationFailure {
            expected: 0,
            actual: 1,
        },
        ApplyResult::Rejected("deterministic limit rejection".into()),
    ] {
        let store = Arc::new(MemoryStateStore::new()) as Arc<dyn StateStore>;
        let origin = OriginId::new(1);
        let committer = Arc::new(FixedResultCommitter {
            store,
            origin,
            result,
            calls: AtomicUsize::new(0),
        });
        let manager = TransactionManager::new(
            committer.clone() as Arc<dyn Committer>,
            origin,
            Limits::default(),
        );
        let mut transaction = manager.begin().unwrap();
        transaction
            .put(b"a".to_vec(), b"recorded".to_vec())
            .unwrap();
        assert!(
            transaction
                .commit(manager.committer().as_ref(), &manager.sequencer)
                .is_err()
        );
        assert_eq!(1, committer.calls.load(Ordering::Acquire));
        assert_eq!(None, manager.sequencer.pending_sequence());
        assert_eq!(2, manager.sequencer.next_sequence_hint());
    }
}

struct AmbiguousSchemaCommitter {
    store: Arc<dyn StateStore>,
    origin: OriginId,
    fail_once: AtomicBool,
    commands: Mutex<Vec<SchemaCommandV1>>,
}

impl Committer for AmbiguousSchemaCommitter {
    fn read_barrier(&self) -> Result<StateSnapshot> {
        self.store.snapshot()
    }

    fn submit(&self, _command: CommitTransactionV1) -> Result<ApplyResult> {
        unreachable!("schema test does not submit a transaction")
    }

    fn submit_schema(&self, command: SchemaCommandV1) -> Result<ApplyResult> {
        self.commands.lock().unwrap().push(command);
        if self.fail_once.swap(false, Ordering::AcqRel) {
            Err(ChorusError::Storage(
                "schema reply lost after durable apply".into(),
            ))
        } else {
            Ok(ApplyResult::Committed {
                epoch: 1,
                log_id: LogId { term: 1, index: 1 },
            })
        }
    }

    fn origin(&self) -> OriginId {
        self.origin
    }
}

#[test]
fn pending_schema_command_rejects_a_different_ddl_and_retries_exactly() {
    let store = Arc::new(MemoryStateStore::new()) as Arc<dyn StateStore>;
    let origin = OriginId::new(1);
    let committer = AmbiguousSchemaCommitter {
        store,
        origin,
        fail_once: AtomicBool::new(true),
        commands: Mutex::new(Vec::new()),
    };
    let sequencer = CommitSequencer::new(origin);
    let pending = SchemaOperationV1::DropTable {
        table_id: 7,
        expected_version: 2,
    };
    assert!(matches!(
        sequencer.submit_schema(&committer, 0, pending.clone()),
        Err(ChorusError::OutcomeUnknown(_))
    ));
    assert_eq!(Some(1), sequencer.pending_sequence());

    let different = SchemaOperationV1::DropTable {
        table_id: 8,
        expected_version: 2,
    };
    assert!(matches!(
        sequencer.submit_schema(&committer, 0, different),
        Err(ChorusError::Protocol(_))
    ));
    assert_eq!(1, committer.commands.lock().unwrap().len());
    assert_eq!(Some(1), sequencer.pending_sequence());

    assert!(matches!(
        sequencer.submit_schema(&committer, 0, pending),
        Ok(ApplyResult::Committed { .. })
    ));
    let commands = committer.commands.lock().unwrap();
    assert_eq!(2, commands.len());
    assert_eq!(commands[0], commands[1]);
    assert_eq!(None, sequencer.pending_sequence());
    assert_eq!(2, sequencer.next_sequence_hint());
}
