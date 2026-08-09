use std::sync::Arc;

use chorus_codec::{
    ApplyResult, CommitTransactionV1, KvMutationV1, ReplicatedCommandV1, canonical_mutations,
    payload_hash,
};
use chorus_common::{LogId, OriginId, RequestId};
use chorus_consensus::{Consensus, OpenRaftConsensus};
use chorus_redb::{ChorusRaftConfig, RedbStateMachine};
use openraft::storage::RaftStateMachine;

const CLUSTER_ID: [u8; 16] = [0x63; 16];
const INCARNATION: u64 = 7;

fn open(root: &std::path::Path, initialize: bool) -> chorus_common::Result<Arc<OpenRaftConsensus>> {
    OpenRaftConsensus::open(
        1,
        root.join("raft.redb"),
        root.join("state.redb"),
        CLUSTER_ID,
        INCARNATION,
        initialize,
    )
}

fn put(
    origin: OriginId,
    sequence: u64,
    base_epoch: u64,
    key: &[u8],
    value: &[u8],
) -> CommitTransactionV1 {
    let request_id = RequestId::new(origin, sequence);
    let mutation = KvMutationV1::Put {
        key: key.to_vec(),
        value: value.to_vec(),
    };
    let canonical = canonical_mutations(std::slice::from_ref(&mutation)).unwrap();
    CommitTransactionV1 {
        request_id,
        payload_hash: payload_hash(1, &request_id, base_epoch, &canonical),
        base_epoch,
        mutations: vec![mutation],
    }
}

#[test]
fn empty_group_requires_explicit_initialization() {
    let root = tempfile::tempdir().unwrap();
    let error = match open(root.path(), false) {
        Ok(_) => panic!("empty group opened without explicit initialization"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("explicit initialization"));

    let consensus = open(root.path(), true).unwrap();
    assert_eq!(Some(1), consensus.status().leader_id);
    assert!(consensus.status().quorum);
    drop(consensus);
}

#[test]
fn committed_state_is_linearizable_read_only_and_durable_across_reopen() {
    let root = tempfile::tempdir().unwrap();
    let origin = OriginId {
        node_id: 1,
        boot_nonce: [9; 16],
    };
    let consensus = open(root.path(), true).unwrap();
    consensus.activate_origin(origin).unwrap();

    let first = consensus.submit(put(origin, 1, 0, b"k", b"v1")).unwrap();
    let first_log = match first {
        ApplyResult::Committed { epoch: 1, log_id } => log_id,
        other => panic!("unexpected first apply result: {other:?}"),
    };
    consensus.wait_applied(first_log).unwrap();
    let barrier = consensus.read_barrier().unwrap();
    assert_eq!(Some(&b"v1"[..]), barrier.get(b"k"));

    let store = consensus.store();
    assert_eq!(Some(&b"v1"[..]), store.snapshot().unwrap().get(b"k"));
    let error = store
        .apply(
            LogId {
                term: 99,
                index: 99,
            },
            &ReplicatedCommandV1::Noop,
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("submit the command through OpenRaft")
    );
    drop(store);
    consensus.checkpoint().unwrap();
    drop(consensus);

    let state_machine =
        RedbStateMachine::open(root.path().join("state.redb"), CLUSTER_ID, INCARNATION).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let snapshot = runtime.block_on(async move {
        let mut state_machine = state_machine;
        <RedbStateMachine as RaftStateMachine<ChorusRaftConfig>>::get_current_snapshot(
            &mut state_machine,
        )
        .await
        .unwrap()
    });
    let snapshot = snapshot.expect("checkpoint must publish a durable snapshot");
    assert!(snapshot.meta.last_log_id.is_some_and(|log_id| {
        log_id.index >= first_log.index && log_id.leader_id.term >= first_log.term
    }));

    let reopened = open(root.path(), false).unwrap();
    assert_eq!(Some(&b"v1"[..]), reopened.read_barrier().unwrap().get(b"k"));
    let second = reopened.submit(put(origin, 2, 1, b"k", b"v2")).unwrap();
    assert!(matches!(second, ApplyResult::Committed { epoch: 2, .. }));
    assert_eq!(Some(&b"v2"[..]), reopened.read_barrier().unwrap().get(b"k"));
}
