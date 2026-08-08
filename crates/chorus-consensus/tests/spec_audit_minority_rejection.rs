use chorus_codec::{CommitTransactionV1, KvMutationV1, canonical_mutations, payload_hash};
use chorus_common::{ChorusError, OriginId, RequestId};
use chorus_consensus::{Consensus, InMemoryCluster};
use chorus_storage::{MemoryStateStore, StateStore};
use std::sync::Arc;

fn put_command(origin: OriginId) -> CommitTransactionV1 {
    let request_id = RequestId::new(origin, 1);
    let mutation = KvMutationV1::Put {
        key: b"minority-key".to_vec(),
        value: b"value".to_vec(),
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
fn isolated_node_cannot_read_or_commit_using_the_majority_adapter() {
    let stores: Vec<Arc<dyn StateStore>> = (0..3)
        .map(|_| Arc::new(MemoryStateStore::new()) as Arc<dyn StateStore>)
        .collect();
    let cluster = InMemoryCluster::new(vec![
        (1, stores[0].clone()),
        (2, stores[1].clone()),
        (3, stores[2].clone()),
    ]);
    let adapter = cluster.adapter(1);
    let origin = OriginId::new(1);
    adapter.activate_origin(origin).unwrap();

    // Node 1 is now the isolated minority.  A strict transaction bound to
    // that node must not silently fail over to a different replica or append
    // directly through the cluster-wide helper.
    cluster.set_healthy(1, false);
    assert!(matches!(
        adapter.read_barrier(),
        Err(ChorusError::Consensus(_))
    ));
    assert!(matches!(
        adapter.submit(put_command(origin)),
        Err(ChorusError::Consensus(_))
    ));

    for store in &stores {
        assert!(store.snapshot().unwrap().get(b"minority-key").is_none());
    }
}
