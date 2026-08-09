//! Single-node production bridge from Chorus's synchronous consensus boundary
//! to the durable OpenRaft/redb adapters.
//!
//! This module intentionally has no peer transport. It is useful only when
//! the configured voter set is exactly the local node; multi-node serving
//! remains blocked on the authenticated Tonic/Rustls transport.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc as std_mpsc};
use std::thread;
use std::time::Duration;

use chorus_codec::{
    ActivateOriginV1, ApplyResult, CommitTransactionV1, LogicalSnapshot, ReplicatedCommandV1,
    SchemaCommandV1,
};
use chorus_common::{ChorusError, LogId as ChorusLogId, OriginId, Result};
use chorus_redb::{ChorusRaftConfig, RedbRaftLogStore, RedbStateMachine};
use chorus_storage::{StateSnapshot, StateStore, StoreStatus};
use openraft::error::{InstallSnapshotError, RPCError, RaftError, Unreachable};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::storage::RaftLogStorage;
use openraft::{BasicNode, Config, Raft, ServerState, SnapshotPolicy};
use tokio::runtime::Builder;
use tokio::sync::mpsc;

use crate::{Consensus, ConsensusStatus};

const REQUEST_QUEUE_CAPACITY: usize = 128;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(8);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

type ChorusRaft = Raft<ChorusRaftConfig>;

/// A synchronous `Consensus` implementation backed by one real OpenRaft
/// runtime on a dedicated thread.
pub struct OpenRaftConsensus {
    node_id: u64,
    sender: Mutex<Option<mpsc::Sender<RuntimeRequest>>>,
    runtime_thread: Mutex<Option<thread::JoinHandle<()>>>,
    store: Arc<RedbReadStore>,
}

impl OpenRaftConsensus {
    /// Open a durable single-node Raft group.
    ///
    /// `initialize` is an explicit administrative intent. Passing `false`
    /// for an empty store fails closed; ordinary reopen never initializes a
    /// new cluster merely because no peer can be reached.
    pub fn open(
        node_id: u64,
        raft_path: impl AsRef<Path>,
        state_path: impl AsRef<Path>,
        cluster_id: [u8; 16],
        cluster_incarnation: u64,
        initialize: bool,
    ) -> Result<Arc<Self>> {
        if node_id == 0 {
            return Err(ChorusError::Consensus(
                "Raft node id must be nonzero".into(),
            ));
        }

        let log_store =
            RedbRaftLogStore::<ChorusRaftConfig>::open(raft_path, cluster_id, cluster_incarnation)
                .map_err(|error| ChorusError::Storage(error.to_string()))?;
        let state_machine = RedbStateMachine::open_with_purge_fence(
            state_path,
            cluster_id,
            cluster_incarnation,
            log_store.purge_fence_handle(),
        )
        .map_err(|error| ChorusError::Storage(error.to_string()))?;

        let stored_membership = state_machine
            .exact_membership()
            .map_err(|error| ChorusError::Storage(error.to_string()))?;
        let state_initialized = stored_membership.log_id().is_some();
        if state_initialized {
            let voters: Vec<_> = stored_membership.voter_ids().collect();
            let learners: Vec<_> = stored_membership.membership().learner_ids().collect();
            if voters != [node_id] || !learners.is_empty() {
                return Err(ChorusError::Consensus(
                    "single-node adapter refuses durable multi-node or foreign-node membership"
                        .into(),
                ));
            }
        }

        let read_store = Arc::new(RedbReadStore {
            inner: state_machine.clone(),
        });
        let (sender, receiver) = mpsc::channel(REQUEST_QUEUE_CAPACITY);
        let (startup_tx, startup_rx) = std_mpsc::sync_channel(1);
        let thread_state = state_machine;
        let runtime_thread = thread::Builder::new()
            .name(format!("chorus-raft-{node_id}"))
            .spawn(move || {
                let runtime = match Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_time()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = startup_tx
                            .send(Err(format!("could not build OpenRaft runtime: {error}")));
                        return;
                    }
                };
                runtime.block_on(run_runtime(
                    node_id,
                    log_store,
                    thread_state,
                    initialize,
                    state_initialized,
                    receiver,
                    startup_tx,
                ));
            })
            .map_err(|error| {
                ChorusError::Consensus(format!("could not start OpenRaft runtime: {error}"))
            })?;

        match startup_rx.recv_timeout(OPERATION_TIMEOUT + Duration::from_secs(1)) {
            Ok(Ok(())) => Ok(Arc::new(Self {
                node_id,
                sender: Mutex::new(Some(sender)),
                runtime_thread: Mutex::new(Some(runtime_thread)),
                store: read_store,
            })),
            Ok(Err(error)) => {
                let _ = runtime_thread.join();
                Err(ChorusError::Consensus(error))
            }
            Err(error) => {
                drop(sender);
                let _ = runtime_thread.join();
                Err(ChorusError::Consensus(format!(
                    "OpenRaft startup did not complete: {error}"
                )))
            }
        }
    }

    fn send<T>(
        &self,
        build: impl FnOnce(std_mpsc::SyncSender<Result<T>>) -> RuntimeRequest,
    ) -> Result<T> {
        let sender = self
            .sender
            .lock()
            .map_err(|_| ChorusError::Consensus("OpenRaft sender lock is poisoned".into()))?
            .as_ref()
            .cloned()
            .ok_or_else(|| ChorusError::Consensus("OpenRaft runtime is stopped".into()))?;
        let (response_tx, response_rx) = std_mpsc::sync_channel(1);
        sender
            .try_send(build(response_tx))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    ChorusError::Consensus("OpenRaft request queue is full".into())
                }
                mpsc::error::TrySendError::Closed(_) => {
                    ChorusError::Consensus("OpenRaft runtime is stopped".into())
                }
            })?;
        response_rx
            .recv_timeout(OPERATION_TIMEOUT + Duration::from_secs(1))
            .map_err(|error| {
                ChorusError::Consensus(format!("OpenRaft request did not complete: {error}"))
            })?
    }

    fn write(&self, command: ReplicatedCommandV1) -> Result<ApplyResult> {
        self.send(|response| RuntimeRequest::Write { command, response })
    }

    fn status_result(&self) -> Result<ConsensusStatus> {
        self.send(|response| RuntimeRequest::Status { response })
    }
}

impl Consensus for OpenRaftConsensus {
    fn activate_origin(&self, origin: OriginId) -> Result<()> {
        self.write(ReplicatedCommandV1::ActivateOrigin(ActivateOriginV1 {
            origin,
        }))?;
        Ok(())
    }

    fn read_barrier(&self) -> Result<StateSnapshot> {
        self.send(|response| RuntimeRequest::ReadBarrier { response })
    }

    fn submit(&self, command: CommitTransactionV1) -> Result<ApplyResult> {
        self.write(ReplicatedCommandV1::CommitTransaction(command))
    }

    fn submit_schema(&self, command: SchemaCommandV1) -> Result<ApplyResult> {
        self.write(ReplicatedCommandV1::SchemaChange(command))
    }

    fn bootstrap(&self) -> Result<()> {
        Err(ChorusError::Consensus(
            "this OpenRaft group is initialized only by explicit open intent".into(),
        ))
    }

    fn change_membership(&self, voters: Vec<u64>, learners: Vec<u64>) -> Result<()> {
        if voters == [self.node_id] && learners.is_empty() {
            return Ok(());
        }
        Err(ChorusError::Consensus(
            "multi-node membership requires the authenticated OpenRaft transport".into(),
        ))
    }

    fn wait_applied(&self, log_id: ChorusLogId) -> Result<()> {
        self.send(|response| RuntimeRequest::WaitApplied { log_id, response })
    }

    fn status(&self) -> ConsensusStatus {
        self.status_result().unwrap_or_else(|_| {
            let status = self.store.status();
            ConsensusStatus {
                node_id: self.node_id,
                leader_id: None,
                term: status.last_applied.term,
                commit_index: status.last_applied.index,
                applied_index: status.last_applied.index,
                quorum: false,
                voters: vec![self.node_id],
                learners: Vec::new(),
            }
        })
    }

    fn store(&self) -> Arc<dyn StateStore> {
        self.store.clone()
    }
}

impl Drop for OpenRaftConsensus {
    fn drop(&mut self) {
        let sender = self.sender.get_mut().ok().and_then(|sender| sender.take());
        if let Some(sender) = sender {
            let (response_tx, response_rx) = std_mpsc::sync_channel(1);
            let _ = sender.try_send(RuntimeRequest::Shutdown {
                response: response_tx,
            });
            drop(sender);
            let _ = response_rx.recv_timeout(SHUTDOWN_TIMEOUT + Duration::from_secs(1));
        }
        if let Some(handle) = self
            .runtime_thread
            .get_mut()
            .ok()
            .and_then(|thread| thread.take())
        {
            let _ = handle.join();
        }
    }
}

enum RuntimeRequest {
    Write {
        command: ReplicatedCommandV1,
        response: std_mpsc::SyncSender<Result<ApplyResult>>,
    },
    ReadBarrier {
        response: std_mpsc::SyncSender<Result<StateSnapshot>>,
    },
    WaitApplied {
        log_id: ChorusLogId,
        response: std_mpsc::SyncSender<Result<()>>,
    },
    Status {
        response: std_mpsc::SyncSender<Result<ConsensusStatus>>,
    },
    Shutdown {
        response: std_mpsc::SyncSender<()>,
    },
}

async fn run_runtime(
    node_id: u64,
    log_store: RedbRaftLogStore<ChorusRaftConfig>,
    state_machine: RedbStateMachine,
    initialize: bool,
    state_initialized: bool,
    mut receiver: mpsc::Receiver<RuntimeRequest>,
    startup: std_mpsc::SyncSender<std::result::Result<(), String>>,
) {
    let mut log_store = log_store;
    let committed = match log_store.read_committed().await {
        Ok(committed) => committed,
        Err(error) => {
            let _ = startup.send(Err(format!(
                "could not read OpenRaft commit state: {error}"
            )));
            return;
        }
    };
    let log_state = match log_store.get_log_state().await {
        Ok(log_state) => log_state,
        Err(error) => {
            let _ = startup.send(Err(format!("could not read OpenRaft log state: {error}")));
            return;
        }
    };
    let log_nonempty = log_state.last_log_id.is_some() || log_state.last_purged_log_id.is_some();
    if initialize && (state_initialized || committed.is_some() || log_nonempty) {
        let _ = startup.send(Err(
            "OpenRaft durable state is already initialized or nonempty".into(),
        ));
        return;
    }
    if !initialize && !state_initialized && committed.is_none() {
        let message = if log_nonempty {
            "OpenRaft log is nonempty without committed membership; recovery is required"
        } else {
            "empty OpenRaft state requires explicit initialization"
        };
        let _ = startup.send(Err(message.into()));
        return;
    }
    if state_initialized && committed.is_none() {
        let _ = startup.send(Err(
            "OpenRaft state membership exists without durable commit metadata".into(),
        ));
        return;
    }

    let config = match single_node_config() {
        Ok(config) => config,
        Err(error) => {
            let _ = startup.send(Err(error));
            return;
        }
    };
    let raft = match ChorusRaft::new(
        node_id,
        config,
        NoNetworkFactory,
        log_store,
        state_machine.clone(),
    )
    .await
    {
        Ok(raft) => raft,
        Err(error) => {
            let _ = startup.send(Err(format!("could not open OpenRaft node: {error}")));
            return;
        }
    };

    if initialize {
        let members =
            BTreeMap::from([(node_id, BasicNode::new(format!("single-node://{node_id}")))]);
        match tokio::time::timeout(OPERATION_TIMEOUT, raft.initialize(members)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let _ = startup.send(Err(format!("OpenRaft initialization failed: {error}")));
                let _ = raft.shutdown().await;
                return;
            }
            Err(_) => {
                let _ = startup.send(Err("OpenRaft initialization timed out".into()));
                let _ = raft.shutdown().await;
                return;
            }
        }
    }

    // Whether freshly initialized or reopened, do not publish the adapter
    // until the one-member group has elected this process.
    match raft
        .wait(Some(OPERATION_TIMEOUT))
        .current_leader(node_id, "single-node OpenRaft leader")
        .await
    {
        Ok(_) => {
            let _ = startup.send(Ok(()));
        }
        Err(error) => {
            let _ = startup.send(Err(format!("OpenRaft leader startup failed: {error}")));
            let _ = raft.shutdown().await;
            return;
        }
    }

    while let Some(request) = receiver.recv().await {
        match request {
            RuntimeRequest::Write { command, response } => {
                let result =
                    match tokio::time::timeout(OPERATION_TIMEOUT, raft.client_write(command)).await
                    {
                        Ok(Ok(result)) => Ok(result.data),
                        Ok(Err(error)) => Err(ChorusError::Consensus(error.to_string())),
                        Err(_) => Err(ChorusError::Consensus("OpenRaft write timed out".into())),
                    };
                let _ = response.send(result);
            }
            RuntimeRequest::ReadBarrier { response } => {
                let result =
                    match tokio::time::timeout(OPERATION_TIMEOUT, raft.ensure_linearizable()).await
                    {
                        Ok(Ok(_)) => state_machine
                            .state_snapshot()
                            .map_err(|error| ChorusError::Storage(error.to_string())),
                        Ok(Err(error)) => Err(ChorusError::Consensus(error.to_string())),
                        Err(_) => Err(ChorusError::Consensus(
                            "OpenRaft read barrier timed out".into(),
                        )),
                    };
                let _ = response.send(result);
            }
            RuntimeRequest::WaitApplied { log_id, response } => {
                let result = match raft
                    .wait(Some(OPERATION_TIMEOUT))
                    .applied_index_at_least(Some(log_id.index), "Chorus wait_applied")
                    .await
                {
                    Ok(_) => state_machine
                        .state_snapshot()
                        .map_err(|error| ChorusError::Storage(error.to_string()))
                        .and_then(|snapshot| {
                            if snapshot.last_applied() >= log_id {
                                Ok(())
                            } else {
                                Err(ChorusError::Consensus(
                                    "state machine applied index has an unexpected term".into(),
                                ))
                            }
                        }),
                    Err(error) => Err(ChorusError::Consensus(error.to_string())),
                };
                let _ = response.send(result);
            }
            RuntimeRequest::Status { response } => {
                let metrics = raft.metrics().borrow().clone();
                let voters = metrics.membership_config.voter_ids().collect();
                let learners = metrics
                    .membership_config
                    .membership()
                    .learner_ids()
                    .collect();
                let applied_index = metrics
                    .last_applied
                    .as_ref()
                    .map(|log_id| log_id.index)
                    .unwrap_or(0);
                let _ = response.send(Ok(ConsensusStatus {
                    node_id,
                    leader_id: metrics.current_leader,
                    term: metrics.current_term,
                    commit_index: applied_index,
                    applied_index,
                    quorum: metrics.current_leader == Some(node_id)
                        && metrics.state == ServerState::Leader,
                    voters,
                    learners,
                }));
            }
            RuntimeRequest::Shutdown { response } => {
                let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, raft.shutdown()).await;
                let _ = response.send(());
                return;
            }
        }
    }
    let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, raft.shutdown()).await;
}

fn single_node_config() -> std::result::Result<Arc<Config>, String> {
    Config {
        cluster_name: "chorus-single-node".into(),
        heartbeat_interval: 100,
        election_timeout_min: 300,
        election_timeout_max: 600,
        snapshot_policy: SnapshotPolicy::LogsSinceLast(50_000),
        max_in_snapshot_log_to_keep: 10_000,
        ..Config::default()
    }
    .validate()
    .map(Arc::new)
    .map_err(|error| format!("invalid OpenRaft configuration: {error}"))
}

#[derive(Clone, Copy)]
struct NoNetworkFactory;

struct NoNetwork {
    target: u64,
}

impl RaftNetworkFactory<ChorusRaftConfig> for NoNetworkFactory {
    type Network = NoNetwork;

    async fn new_client(&mut self, target: u64, _node: &BasicNode) -> Self::Network {
        NoNetwork { target }
    }
}

impl RaftNetwork<ChorusRaftConfig> for NoNetwork {
    async fn append_entries(
        &mut self,
        _rpc: AppendEntriesRequest<ChorusRaftConfig>,
        _option: RPCOption,
    ) -> std::result::Result<AppendEntriesResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>>
    {
        Err(no_transport(self.target))
    }

    async fn install_snapshot(
        &mut self,
        _rpc: InstallSnapshotRequest<ChorusRaftConfig>,
        _option: RPCOption,
    ) -> std::result::Result<
        InstallSnapshotResponse<u64>,
        RPCError<u64, BasicNode, RaftError<u64, InstallSnapshotError>>,
    > {
        Err(no_transport(self.target))
    }

    async fn vote(
        &mut self,
        _rpc: VoteRequest<u64>,
        _option: RPCOption,
    ) -> std::result::Result<VoteResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        Err(no_transport(self.target))
    }
}

fn no_transport<N, E>(target: u64) -> RPCError<u64, N, E>
where
    N: openraft::Node,
    E: std::error::Error,
{
    let error = io::Error::new(
        io::ErrorKind::NotConnected,
        format!("no authenticated OpenRaft transport for node {target}"),
    );
    RPCError::Unreachable(Unreachable::new(&error))
}

/// Read-only `StateStore` view over the same durable state machine that
/// OpenRaft applies. Direct mutation is rejected so callers cannot bypass
/// quorum/commit ordering.
struct RedbReadStore {
    inner: RedbStateMachine,
}

impl StateStore for RedbReadStore {
    fn snapshot(&self) -> Result<StateSnapshot> {
        self.inner
            .state_snapshot()
            .map_err(|error| ChorusError::Storage(error.to_string()))
    }

    fn apply(&self, _log_id: ChorusLogId, _command: &ReplicatedCommandV1) -> Result<ApplyResult> {
        Err(direct_mutation_error())
    }

    fn install(&self, _snapshot: &LogicalSnapshot) -> Result<()> {
        Err(direct_mutation_error())
    }

    fn rollback(&self, _snapshot: &LogicalSnapshot) -> Result<()> {
        Err(direct_mutation_error())
    }

    fn state_hash(&self) -> Result<[u8; 32]> {
        self.snapshot()?.try_state_hash()
    }

    fn status(&self) -> StoreStatus {
        match self.snapshot() {
            Ok(snapshot) => StoreStatus {
                db_epoch: snapshot.db_epoch(),
                catalog_epoch: snapshot.catalog_epoch(),
                last_applied: snapshot.last_applied(),
                state_hash: snapshot.try_state_hash().unwrap_or([0; 32]),
                healthy: snapshot.try_state_hash().is_ok(),
            },
            Err(_) => StoreStatus {
                db_epoch: 0,
                catalog_epoch: 0,
                last_applied: ChorusLogId::ZERO,
                state_hash: [0; 32],
                healthy: false,
            },
        }
    }
}

fn direct_mutation_error() -> ChorusError {
    ChorusError::Storage(
        "direct state mutation is forbidden; submit the command through OpenRaft".into(),
    )
}
