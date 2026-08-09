//! Snapshot publication and Raft-log purge ordering gates.
//!
//! These tests cover the local durable-snapshot path only. Snapshot import on
//! a follower that does not retain the snapshot's LogId remains a separate
//! adapter milestone.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chorus_codec::{ApplyResult, ReplicatedCommandV1};
use chorus_redb::{ChorusRaftConfig, RedbRaftLogStore, RedbStateMachine};
use openraft::entry::EntryPayload;
use openraft::error::{InstallSnapshotError, RPCError, RaftError, Unreachable};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::storage::{RaftLogStorage, RaftLogStorageExt, RaftStateMachine};
use openraft::{
    BasicNode, CommittedLeaderId, Config, Entry, LogId, Raft, RaftSnapshotBuilder, SnapshotPolicy,
};

type LogStore = RedbRaftLogStore<ChorusRaftConfig>;

const CLUSTER_ID: [u8; 16] = [0x51; 16];
const INCARNATION: u64 = 29;
const WAIT_TIMEOUT: Duration = Duration::from_secs(8);

fn log_id(term: u64, index: u64) -> LogId<u64> {
    LogId::new(CommittedLeaderId::new(term, 1), index)
}

fn membership_entry() -> Entry<ChorusRaftConfig> {
    Entry {
        log_id: LogId::default(),
        payload: EntryPayload::Membership(openraft::Membership::new(
            vec![BTreeSet::from([1])],
            BTreeMap::from([(1, BasicNode::new("in-process://1"))]),
        )),
    }
}

fn blank_entry() -> Entry<ChorusRaftConfig> {
    Entry {
        log_id: log_id(1, 1),
        payload: EntryPayload::Blank,
    }
}

fn unreachable<N, E>(message: &str) -> RPCError<u64, N, E>
where
    N: openraft::Node,
    E: std::error::Error,
{
    let error = io::Error::new(io::ErrorKind::NotConnected, message);
    RPCError::Unreachable(Unreachable::new(&error))
}

#[derive(Clone, Default)]
struct NoNetwork;

impl RaftNetworkFactory<ChorusRaftConfig> for NoNetwork {
    type Network = NoNetwork;

    async fn new_client(&mut self, _target: u64, _node: &BasicNode) -> Self::Network {
        NoNetwork
    }
}

impl RaftNetwork<ChorusRaftConfig> for NoNetwork {
    async fn append_entries(
        &mut self,
        _rpc: AppendEntriesRequest<ChorusRaftConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        Err(unreachable("single-node harness has no remote peers"))
    }

    async fn install_snapshot(
        &mut self,
        _rpc: InstallSnapshotRequest<ChorusRaftConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<u64>,
        RPCError<u64, BasicNode, RaftError<u64, InstallSnapshotError>>,
    > {
        Err(unreachable("single-node harness has no remote peers"))
    }

    async fn vote(
        &mut self,
        _rpc: VoteRequest<u64>,
        _option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        Err(unreachable("single-node harness has no remote peers"))
    }
}

#[tokio::test]
async fn persisted_snapshot_without_fence_retains_logs_then_reconciles_on_reopen() {
    let root = tempfile::tempdir().unwrap();
    let raft_path = root.path().join("raft.redb");
    let state_path = root.path().join("state.redb");
    let mut log_store = LogStore::open(&raft_path, CLUSTER_ID, INCARNATION).unwrap();
    let fence = log_store.purge_fence_handle();
    let mut state = RedbStateMachine::open(&state_path, CLUSTER_ID, INCARNATION).unwrap();
    let entries = vec![membership_entry(), blank_entry()];

    log_store.blocking_append(entries.clone()).await.unwrap();
    log_store.save_committed(Some(log_id(1, 1))).await.unwrap();
    let responses = state.apply(entries).await.unwrap();
    assert_eq!(vec![ApplyResult::Noop, ApplyResult::Noop], responses);
    let mut builder = state.get_snapshot_builder().await;
    let snapshot = builder.build_snapshot().await.unwrap();
    assert_eq!(Some(log_id(1, 1)), snapshot.meta.last_log_id);
    drop(builder);

    assert_eq!(None, fence.current().unwrap());
    assert!(log_store.purge(log_id(1, 1)).await.is_err());
    assert_eq!(
        None,
        log_store.get_log_state().await.unwrap().last_purged_log_id
    );

    drop(state);
    let mut reopened = RedbStateMachine::open_with_purge_fence(
        &state_path,
        CLUSTER_ID,
        INCARNATION,
        fence.clone(),
    )
    .unwrap();
    assert_eq!(Some(log_id(1, 1)), fence.current().unwrap());
    assert!(reopened.get_current_snapshot().await.unwrap().is_some());
    log_store.purge(log_id(1, 1)).await.unwrap();
    assert_eq!(
        Some(log_id(1, 1)),
        log_store.get_log_state().await.unwrap().last_purged_log_id
    );

    let mismatched_state_path = root.path().join("mismatched-state.redb");
    assert!(
        RedbStateMachine::open_with_purge_fence(
            &mismatched_state_path,
            [0x52; 16],
            INCARNATION,
            fence,
        )
        .is_err()
    );
    assert!(!mismatched_state_path.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openraft_automatic_snapshot_advances_fence_before_purge_and_survives_restart() {
    let root = tempfile::tempdir().unwrap();
    let raft_path = root.path().join("raft.redb");
    let state_path = root.path().join("state.redb");
    let log_store = LogStore::open(&raft_path, CLUSTER_ID, INCARNATION).unwrap();
    let mut log_observer = log_store.clone();
    let fence = log_store.purge_fence_handle();
    let state = RedbStateMachine::open_with_purge_fence(
        &state_path,
        CLUSTER_ID,
        INCARNATION,
        fence.clone(),
    )
    .unwrap();
    let mut state_observer = state.clone();
    let config = Arc::new(
        Config {
            cluster_name: "chorus-snapshot-purge".into(),
            election_timeout_min: 200,
            election_timeout_max: 400,
            heartbeat_interval: 50,
            snapshot_policy: SnapshotPolicy::LogsSinceLast(2),
            max_in_snapshot_log_to_keep: 0,
            purge_batch_size: 1,
            ..Config::default()
        }
        .validate()
        .unwrap(),
    );
    let raft = Raft::<ChorusRaftConfig>::new(1, config, NoNetwork, log_store, state)
        .await
        .unwrap();
    raft.initialize(BTreeMap::from([(1, BasicNode::new("in-process://1"))]))
        .await
        .unwrap();

    let deadline = Instant::now() + WAIT_TIMEOUT;
    loop {
        let metrics = raft.metrics().borrow().clone();
        if metrics.current_leader == Some(1) && metrics.state == openraft::ServerState::Leader {
            break;
        }
        assert!(Instant::now() < deadline, "single-node election timed out");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for _ in 0..6 {
        let response = raft.client_write(ReplicatedCommandV1::Noop).await.unwrap();
        assert_eq!(ApplyResult::Noop, response.data);
    }

    let deadline = Instant::now() + WAIT_TIMEOUT;
    let (snapshot_log_id, purged_log_id) = loop {
        let metrics = raft.metrics().borrow().clone();
        if let (Some(snapshot), Some(purged)) = (metrics.snapshot, metrics.purged) {
            break (snapshot, purged);
        }
        assert!(
            Instant::now() < deadline,
            "automatic snapshot/purge timed out"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert!(purged_log_id <= snapshot_log_id);
    assert!(
        fence
            .current()
            .unwrap()
            .is_some_and(|id| id >= purged_log_id)
    );
    let durable_log_state = log_observer.get_log_state().await.unwrap();
    assert_eq!(Some(purged_log_id), durable_log_state.last_purged_log_id);
    let current_snapshot = state_observer
        .get_current_snapshot()
        .await
        .unwrap()
        .unwrap();
    assert!(current_snapshot.meta.last_log_id >= Some(purged_log_id));

    raft.shutdown().await.unwrap();
    drop(raft);
    drop(state_observer);
    drop(log_observer);
    drop(fence);

    // OpenRaft's state-machine worker observes its command channel closing
    // asynchronously after the core joins. A real process restart has no
    // lingering handles; in-process, wait boundedly for those handles to drop.
    let reopen_deadline = Instant::now() + Duration::from_secs(2);
    let mut reopened_log = loop {
        match LogStore::open(&raft_path, CLUSTER_ID, INCARNATION) {
            Ok(store) => break store,
            Err(error) => {
                assert!(
                    Instant::now() < reopen_deadline,
                    "raft store did not close after shutdown: {error}"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    };
    let reopened_fence = reopened_log.purge_fence_handle();
    let mut reopened_state = RedbStateMachine::open_with_purge_fence(
        &state_path,
        CLUSTER_ID,
        INCARNATION,
        reopened_fence.clone(),
    )
    .unwrap();
    let reopened_log_state = reopened_log.get_log_state().await.unwrap();
    assert_eq!(Some(purged_log_id), reopened_log_state.last_purged_log_id);
    assert!(
        reopened_fence
            .current()
            .unwrap()
            .is_some_and(|id| id >= purged_log_id)
    );
    let reopened_snapshot = reopened_state
        .get_current_snapshot()
        .await
        .unwrap()
        .unwrap();
    assert!(reopened_snapshot.meta.last_log_id >= Some(purged_log_id));
}
