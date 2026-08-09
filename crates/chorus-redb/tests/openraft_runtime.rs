//! Test-only in-process OpenRaft runtime boundary.
//!
//! This harness deliberately does not provide a production transport or wire
//! `chorus-node` to OpenRaft. It exercises the real durable log and state
//! adapters through OpenRaft's public runtime API.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use chorus_codec::{ActivateOriginV1, ApplyResult, ReplicatedCommandV1};
use chorus_common::OriginId;
use chorus_redb::{ChorusRaftConfig, RedbRaftLogStore, RedbStateMachine};
use openraft::error::{InstallSnapshotError, RPCError, RaftError, RemoteError, Unreachable};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, ClientWriteResponse, InstallSnapshotRequest,
    InstallSnapshotResponse, VoteRequest, VoteResponse,
};
use openraft::{BasicNode, Config, Raft, SnapshotPolicy};

type RuntimeRaft = Raft<ChorusRaftConfig>;
type RuntimeLogStore = RedbRaftLogStore<ChorusRaftConfig>;

const CLUSTER_ID: [u8; 16] = [0x42; 16];
const INCARNATION: u64 = 23;
const WAIT_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Default)]
struct NetworkState {
    nodes: RwLock<BTreeMap<u64, RuntimeRaft>>,
    blocked: RwLock<BTreeSet<(u64, u64)>>,
}

impl NetworkState {
    fn register(&self, node_id: u64, raft: RuntimeRaft) {
        self.nodes.write().unwrap().insert(node_id, raft);
    }

    fn unregister(&self, node_id: u64) {
        self.nodes.write().unwrap().remove(&node_id);
    }

    fn partition(&self, left: u64, right: u64) {
        let mut blocked = self.blocked.write().unwrap();
        blocked.insert((left, right));
        blocked.insert((right, left));
    }

    fn heal_all(&self) {
        self.blocked.write().unwrap().clear();
    }

    fn target<E>(
        &self,
        source: u64,
        target: u64,
    ) -> Result<RuntimeRaft, RPCError<u64, BasicNode, E>>
    where
        E: std::error::Error,
    {
        if self.blocked.read().unwrap().contains(&(source, target)) {
            return Err(unreachable(format!(
                "link {source}->{target} is partitioned"
            )));
        }
        self.nodes
            .read()
            .unwrap()
            .get(&target)
            .cloned()
            .ok_or_else(|| unreachable(format!("node {target} is offline")))
    }
}

fn unreachable<N, E>(message: String) -> RPCError<u64, N, E>
where
    N: openraft::Node,
    E: std::error::Error,
{
    let error = io::Error::new(io::ErrorKind::NotConnected, message);
    RPCError::Unreachable(Unreachable::new(&error))
}

#[derive(Clone)]
struct InProcessNetworkFactory {
    source: u64,
    state: Arc<NetworkState>,
}

struct InProcessNetwork {
    source: u64,
    target: u64,
    target_node: BasicNode,
    state: Arc<NetworkState>,
}

impl RaftNetworkFactory<ChorusRaftConfig> for InProcessNetworkFactory {
    type Network = InProcessNetwork;

    async fn new_client(&mut self, target: u64, node: &BasicNode) -> Self::Network {
        InProcessNetwork {
            source: self.source,
            target,
            target_node: node.clone(),
            state: Arc::clone(&self.state),
        }
    }
}

impl RaftNetwork<ChorusRaftConfig> for InProcessNetwork {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<ChorusRaftConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        let target = self.state.target(self.source, self.target)?;
        target.append_entries(rpc).await.map_err(|error| {
            RPCError::RemoteError(RemoteError::new_with_node(
                self.target,
                self.target_node.clone(),
                error,
            ))
        })
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<ChorusRaftConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<u64>,
        RPCError<u64, BasicNode, RaftError<u64, InstallSnapshotError>>,
    > {
        let target = self.state.target(self.source, self.target)?;
        target.install_snapshot(rpc).await.map_err(|error| {
            RPCError::RemoteError(RemoteError::new_with_node(
                self.target,
                self.target_node.clone(),
                error,
            ))
        })
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<u64>,
        _option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        let target = self.state.target(self.source, self.target)?;
        target.vote(rpc).await.map_err(|error| {
            RPCError::RemoteError(RemoteError::new_with_node(
                self.target,
                self.target_node.clone(),
                error,
            ))
        })
    }
}

struct NodeHandle {
    raft: RuntimeRaft,
    state: RedbStateMachine,
}

async fn start_node(
    node_id: u64,
    root: &Path,
    config: Arc<Config>,
    network: Arc<NetworkState>,
) -> NodeHandle {
    let node_dir = root.join(format!("node-{node_id}"));
    std::fs::create_dir_all(&node_dir).unwrap();
    let raft_path = node_dir.join("raft.redb");
    let state_path = node_dir.join("state.redb");
    let log_store = RuntimeLogStore::open(&raft_path, CLUSTER_ID, INCARNATION).unwrap();
    let state_machine = RedbStateMachine::open(&state_path, CLUSTER_ID, INCARNATION).unwrap();
    let state = state_machine.clone();
    let factory = InProcessNetworkFactory {
        source: node_id,
        state: Arc::clone(&network),
    };
    let raft = RuntimeRaft::new(node_id, config, factory, log_store, state_machine)
        .await
        .unwrap();
    network.register(node_id, raft.clone());
    NodeHandle { raft, state }
}

fn test_config() -> Arc<Config> {
    Arc::new(
        Config {
            cluster_name: "chorus-in-process-runtime".into(),
            election_timeout_min: 250,
            election_timeout_max: 500,
            heartbeat_interval: 50,
            snapshot_policy: SnapshotPolicy::LogsSinceLast(10_000),
            max_in_snapshot_log_to_keep: 10_000,
            ..Config::default()
        }
        .validate()
        .unwrap(),
    )
}

fn initial_members() -> BTreeMap<u64, BasicNode> {
    (1..=3)
        .map(|node_id| (node_id, BasicNode::new(format!("in-process://{node_id}"))))
        .collect()
}

async fn wait_for_leader(nodes: &BTreeMap<u64, NodeHandle>) -> u64 {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    loop {
        let metrics: Vec<_> = nodes
            .values()
            .map(|node| node.raft.metrics().borrow().clone())
            .collect();
        let agreed = metrics
            .first()
            .and_then(|first| first.current_leader)
            .filter(|leader_id| {
                metrics
                    .iter()
                    .all(|metric| metric.current_leader == Some(*leader_id))
                    && metrics.iter().any(|metric| {
                        metric.id == *leader_id && metric.state == openraft::ServerState::Leader
                    })
            });
        if let Some(leader_id) = agreed {
            return leader_id;
        }
        assert!(Instant::now() < deadline, "leader election timed out");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_applied(nodes: &BTreeMap<u64, NodeHandle>, index: u64) {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    loop {
        if nodes
            .values()
            .all(|node| node.state.state_data().unwrap().last_applied.index >= index)
        {
            return;
        }
        assert!(Instant::now() < deadline, "state-machine apply timed out");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn write_with_healthy_quorum(
    nodes: &BTreeMap<u64, NodeHandle>,
    command: ReplicatedCommandV1,
) -> (u64, ClientWriteResponse<ChorusRaftConfig>) {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    loop {
        let leader_id = wait_for_leader(nodes).await;
        match tokio::time::timeout(
            Duration::from_secs(2),
            nodes[&leader_id].raft.client_write(command.clone()),
        )
        .await
        {
            Ok(Ok(response)) => return (leader_id, response),
            _ => {
                assert!(
                    Instant::now() < deadline,
                    "healthy-quorum client write timed out during leadership churn"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
}

async fn shutdown_all(network: &NetworkState, nodes: &BTreeMap<u64, NodeHandle>) {
    for node_id in nodes.keys() {
        network.unregister(*node_id);
    }
    for node in nodes.values() {
        node.raft.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn initialize_write_and_linearizable_read_use_real_durable_adapters() {
    let root = tempfile::tempdir().unwrap();
    let network = Arc::new(NetworkState::default());
    let config = test_config();
    let mut nodes = BTreeMap::new();
    for node_id in 1..=3 {
        nodes.insert(
            node_id,
            start_node(
                node_id,
                root.path(),
                Arc::clone(&config),
                Arc::clone(&network),
            )
            .await,
        );
    }

    nodes[&1].raft.initialize(initial_members()).await.unwrap();
    let origin = OriginId {
        node_id: 77,
        boot_nonce: [7; 16],
    };
    let (leader_id, response) = write_with_healthy_quorum(
        &nodes,
        ReplicatedCommandV1::ActivateOrigin(ActivateOriginV1 { origin }),
    )
    .await;
    assert_eq!(ApplyResult::Activated, response.data);
    wait_for_applied(&nodes, response.log_id.index).await;
    assert!(nodes[&leader_id].raft.ensure_linearizable().await.is_ok());
    for node in nodes.values() {
        assert_eq!(
            origin,
            node.state.state_data().unwrap().origins[&origin.node_id].active_origin
        );
    }

    // Isolate the incumbent leader from both other voters. The remaining
    // pair may elect a replacement, but a write submitted to the isolated
    // minority must neither acknowledge nor become state-machine-visible.
    for follower_id in nodes.keys().copied().filter(|id| *id != leader_id) {
        network.partition(leader_id, follower_id);
    }
    let minority_origin = OriginId {
        node_id: 88,
        boot_nonce: [8; 16],
    };
    let minority_write = tokio::time::timeout(
        Duration::from_millis(750),
        nodes[&leader_id]
            .raft
            .client_write(ReplicatedCommandV1::ActivateOrigin(ActivateOriginV1 {
                origin: minority_origin,
            })),
    )
    .await;
    assert!(
        minority_write.is_err(),
        "minority write unexpectedly completed"
    );
    for node in nodes.values() {
        assert!(
            !node
                .state
                .state_data()
                .unwrap()
                .origins
                .contains_key(&minority_origin.node_id),
            "minority write became visible"
        );
    }
    let minority_read = tokio::time::timeout(
        Duration::from_secs(2),
        nodes[&leader_id].raft.ensure_linearizable(),
    )
    .await;
    assert!(
        !matches!(minority_read, Ok(Ok(_))),
        "isolated leader passed a quorum read barrier"
    );

    network.heal_all();
    let healed_origin = OriginId {
        node_id: 99,
        boot_nonce: [9; 16],
    };
    let (healed_leader_id, healed_response) = write_with_healthy_quorum(
        &nodes,
        ReplicatedCommandV1::ActivateOrigin(ActivateOriginV1 {
            origin: healed_origin,
        }),
    )
    .await;
    wait_for_applied(&nodes, healed_response.log_id.index).await;

    // Restart a follower from the same raft.redb/state.redb files, commit a
    // write while it is offline, then require log/state catch-up after reopen.
    let restart_id = *nodes
        .keys()
        .find(|node_id| **node_id != healed_leader_id)
        .unwrap();
    network.unregister(restart_id);
    let stopped = nodes.remove(&restart_id).unwrap();
    stopped.raft.shutdown().await.unwrap();
    drop(stopped);

    let restart_origin = OriginId {
        node_id: 100,
        boot_nonce: [10; 16],
    };
    let (_, restart_response) = write_with_healthy_quorum(
        &nodes,
        ReplicatedCommandV1::ActivateOrigin(ActivateOriginV1 {
            origin: restart_origin,
        }),
    )
    .await;

    let restarted = start_node(
        restart_id,
        root.path(),
        Arc::clone(&config),
        Arc::clone(&network),
    )
    .await;
    assert_eq!(
        healed_origin,
        restarted.state.state_data().unwrap().origins[&healed_origin.node_id].active_origin,
        "durable state was not recovered before catch-up"
    );
    nodes.insert(restart_id, restarted);
    wait_for_applied(&nodes, restart_response.log_id.index).await;
    let final_leader_id = wait_for_leader(&nodes).await;
    assert!(
        nodes[&final_leader_id]
            .raft
            .ensure_linearizable()
            .await
            .is_ok()
    );
    for node in nodes.values() {
        assert_eq!(
            restart_origin,
            node.state.state_data().unwrap().origins[&restart_origin.node_id].active_origin
        );
        assert!(
            !node
                .state
                .state_data()
                .unwrap()
                .origins
                .contains_key(&minority_origin.node_id)
        );
    }

    shutdown_all(&network, &nodes).await;
}
