use chorus_codec::{
    CommitTransactionV1, KvMutationV1, ReplicatedCommandV1, canonical_mutations, payload_hash,
};
use chorus_common::{ChorusError, LogId, OriginId, RequestId};
use chorus_consensus::{Consensus, InMemoryCluster};
use chorus_storage::{MemoryStateStore, StateSnapshot, StateStore, StoreStatus};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

struct FailingApplyStore {
    inner: Arc<MemoryStateStore>,
    fail: Arc<AtomicBool>,
}

impl StateStore for FailingApplyStore {
    fn snapshot(&self) -> chorus_common::Result<StateSnapshot> {
        self.inner.snapshot()
    }

    fn apply(
        &self,
        log_id: LogId,
        command: &ReplicatedCommandV1,
    ) -> chorus_common::Result<chorus_codec::ApplyResult> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(ChorusError::Storage("injected apply failure".into()));
        }
        self.inner.apply(log_id, command)
    }

    fn install(&self, snapshot: &chorus_codec::LogicalSnapshot) -> chorus_common::Result<()> {
        self.inner.install(snapshot)
    }

    fn state_hash(&self) -> chorus_common::Result<[u8; 32]> {
        self.inner.state_hash()
    }

    fn status(&self) -> StoreStatus {
        self.inner.status()
    }
}

fn put_command(origin: OriginId) -> CommitTransactionV1 {
    let request_id = RequestId::new(origin, 1);
    let mutation = KvMutationV1::Put {
        key: b"quorum-leak".to_vec(),
        value: b"must-not-leak".to_vec(),
    };
    let canonical = canonical_mutations(std::slice::from_ref(&mutation)).unwrap();
    CommitTransactionV1 {
        request_id,
        payload_hash: payload_hash(1, &request_id, 0, &canonical),
        base_epoch: 0,
        mutations: vec![mutation],
    }
}

#[test]
fn failed_replication_does_not_ack_or_leave_a_local_state_leak() {
    let first = Arc::new(MemoryStateStore::new()) as Arc<dyn StateStore>;
    let flaky_inner = Arc::new(MemoryStateStore::new());
    let fail = Arc::new(AtomicBool::new(false));
    let flaky = Arc::new(FailingApplyStore {
        inner: flaky_inner,
        fail: fail.clone(),
    }) as Arc<dyn StateStore>;
    let third = Arc::new(MemoryStateStore::new()) as Arc<dyn StateStore>;
    let cluster = InMemoryCluster::new(vec![
        (1, first.clone()),
        (2, flaky.clone()),
        (3, third.clone()),
    ]);
    let adapter = cluster.adapter(1);
    let origin = OriginId::new(1);
    adapter.activate_origin(origin).unwrap();
    fail.store(true, Ordering::SeqCst);

    // The first replica currently applies before the second replica reports
    // failure.  The command is therefore unacknowledged, but the state
    // machine must roll back/reconcile every participant instead of leaking
    // the write into a minority of stores.
    assert!(adapter.submit(put_command(origin)).is_err());
    for store in [&first, &flaky, &third] {
        assert!(store.snapshot().unwrap().get(b"quorum-leak").is_none());
    }
    assert_eq!(first.state_hash().unwrap(), third.state_hash().unwrap());
}
