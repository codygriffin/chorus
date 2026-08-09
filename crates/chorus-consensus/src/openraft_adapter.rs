//! Production bridge from Chorus's synchronous consensus boundary to durable
//! OpenRaft/redb adapters. The legacy constructor remains single-node; the
//! authenticated constructor owns a bounded Tonic/Rustls server and network
//! factory on the same dedicated Tokio runtime as OpenRaft.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::SocketAddr;
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
use openraft::error::{
    CheckIsLeaderError, ClientWriteError, InstallSnapshotError, RPCError, RaftError, Unreachable,
};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::storage::RaftLogStorage;
use openraft::{BasicNode, ChangeMembers, Config, Raft, SnapshotPolicy, metrics::Metric};
use tokio::runtime::Builder;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::TcpListenerStream;

use crate::openraft_transport::{
    AuthenticatedNetworkFactory, AuthenticatedRaftService, ChangeMembershipIntent,
    ClientWriteGatewayResponse, ReadBarrierGatewayResponse, TransportTlsIdentity,
    authenticated_server_builder, bounded_transport_server,
};
use crate::{Consensus, ConsensusStatus};

const REQUEST_QUEUE_CAPACITY: usize = 128;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(8);
const STATUS_METADATA_TIMEOUT: Duration = Duration::from_millis(250);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_GATEWAY_REDIRECTS: usize = 3;

type ChorusRaft = Raft<ChorusRaftConfig>;

/// Convert the durable OpenRaft commit cursor into the public status index.
///
/// This intentionally does not clamp to `applied_index`: commit and apply
/// are distinct progress points, and a healthy runtime may briefly expose a
/// committed entry while its local state machine is still catching up.
fn durable_commit_index(committed: Option<openraft::LogId<u64>>) -> u64 {
    committed.map_or(0, |log_id| log_id.index)
}

#[derive(Clone, Debug)]
pub struct OpenRaftRuntimeOptions {
    pub listen: SocketAddr,
    pub heartbeat_ms: u64,
    pub election_timeout_min_ms: u64,
    pub election_timeout_max_ms: u64,
    pub snapshot_entries: u64,
}

enum RuntimeMode {
    SingleNode,
    Authenticated {
        identity: Arc<TransportTlsIdentity>,
        initial_voters: BTreeMap<u64, BasicNode>,
        options: OpenRaftRuntimeOptions,
    },
}

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
        Self::open_inner(
            node_id,
            raft_path,
            state_path,
            cluster_id,
            cluster_incarnation,
            initialize,
            RuntimeMode::SingleNode,
        )
    }

    /// Open one member of an authenticated static OpenRaft group.
    ///
    /// Only the lowest configured voter may pass `initialize=true`. Empty
    /// non-bootstrap members are allowed to start their authenticated RPC
    /// server and wait for that explicit bootstrap; ordinary startup never
    /// calls `Raft::initialize` on its own.
    pub fn open_authenticated(
        node_id: u64,
        raft_path: impl AsRef<Path>,
        state_path: impl AsRef<Path>,
        cluster_id: [u8; 16],
        cluster_incarnation: u64,
        initialize: bool,
        identity: Arc<TransportTlsIdentity>,
        initial_voters: BTreeMap<u64, String>,
        options: OpenRaftRuntimeOptions,
    ) -> Result<Arc<Self>> {
        if identity.node_id != node_id
            || identity.cluster_id != cluster_id
            || identity.cluster_incarnation != cluster_incarnation
        {
            return Err(ChorusError::Consensus(
                "authenticated transport identity does not match the durable node identity".into(),
            ));
        }
        identity
            .validate()
            .map_err(|error| ChorusError::Consensus(error.to_string()))?;
        if initial_voters.len() < 3 || initial_voters.len() > 5 || initial_voters.len() % 2 == 0 {
            return Err(ChorusError::Consensus(
                "authenticated static bootstrap requires 3 or 5 voters".into(),
            ));
        }
        if options.listen.port() == 0 {
            return Err(ChorusError::Consensus(
                "authenticated OpenRaft listen port must be nonzero".into(),
            ));
        }
        let unknown_voter = initial_voters
            .keys()
            .copied()
            .find(|peer| *peer != node_id && !identity.peers.contains_key(peer));
        if let Some(unknown_voter) = unknown_voter {
            return Err(ChorusError::Consensus(format!(
                "authenticated initial voter {unknown_voter} is absent from the signed peer manifest"
            )));
        }
        if identity.peers.iter().any(|(peer_id, peer)| {
            initial_voters
                .get(peer_id)
                .is_some_and(|endpoint| endpoint != &peer.endpoint)
        }) {
            return Err(ChorusError::Consensus(
                "authenticated peer endpoints do not match the static voter directory".into(),
            ));
        }
        let bootstrap = initial_voters
            .keys()
            .next()
            .copied()
            .ok_or_else(|| ChorusError::Consensus("authenticated voter set is empty".into()))?;
        if initialize && node_id != bootstrap {
            return Err(ChorusError::Consensus(format!(
                "only deterministic bootstrap voter {bootstrap} may initialize the cluster"
            )));
        }
        let initial_voters = initial_voters
            .into_iter()
            .map(|(node_id, endpoint)| (node_id, BasicNode::new(endpoint)))
            .collect();
        Self::open_inner(
            node_id,
            raft_path,
            state_path,
            cluster_id,
            cluster_incarnation,
            initialize,
            RuntimeMode::Authenticated {
                identity,
                initial_voters,
                options,
            },
        )
    }

    fn open_inner(
        node_id: u64,
        raft_path: impl AsRef<Path>,
        state_path: impl AsRef<Path>,
        cluster_id: [u8; 16],
        cluster_incarnation: u64,
        initialize: bool,
        mode: RuntimeMode,
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
            match &mode {
                RuntimeMode::SingleNode if voters != [node_id] || !learners.is_empty() => {
                    return Err(ChorusError::Consensus(
                        "single-node adapter refuses durable multi-node or foreign-node membership"
                            .into(),
                    ));
                }
                RuntimeMode::Authenticated { identity, .. } => {
                    let membership = stored_membership.membership();
                    if membership.get_node(&node_id).is_none() {
                        return Err(ChorusError::Consensus(format!(
                            "local node {node_id} is absent from its durable OpenRaft membership"
                        )));
                    }
                    for (member_id, node) in membership.nodes() {
                        if *member_id == node_id {
                            continue;
                        }
                        let peer = identity.peers.get(member_id).ok_or_else(|| {
                            ChorusError::Consensus(format!(
                                "durable member {member_id} is absent from the signed peer manifest"
                            ))
                        })?;
                        if node.addr != peer.endpoint {
                            return Err(ChorusError::Consensus(format!(
                                "durable member {member_id} endpoint does not match the signed peer manifest"
                            )));
                        }
                    }
                }
                _ => {}
            }
        }

        let read_store = Arc::new(RedbReadStore {
            inner: state_machine.clone(),
        });
        // OpenRaft owns the primary log-store handle after startup, but the
        // status path must read the durable commit cursor independently of
        // the in-memory last-applied metric.  RedbRaftLogStore is a cheap
        // handle clone over the same durable database.
        let status_log_store = log_store.clone();
        let (sender, receiver) = mpsc::channel(REQUEST_QUEUE_CAPACITY);
        let (startup_tx, startup_rx) = std_mpsc::sync_channel(1);
        let thread_state = state_machine;
        let runtime_thread = thread::Builder::new()
            .name(format!("chorus-raft-{node_id}"))
            .spawn(move || {
                let runtime = match Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_io()
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
                    status_log_store,
                    thread_state,
                    initialize,
                    state_initialized,
                    mode,
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

    /// Force a bounded durable state-machine checkpoint before an orderly
    /// shutdown.  This triggers OpenRaft's snapshot builder and waits until
    /// the snapshot metadata reaches the last applied cursor.  Leader
    /// transfer is intentionally not implied: OpenRaft 0.9.25 exposes no
    /// public transfer-leadership API.
    pub fn checkpoint(&self) -> Result<()> {
        self.send(|response| RuntimeRequest::Checkpoint { response })
    }
}

impl Consensus for OpenRaftConsensus {
    fn activate_origin(&self, origin: OriginId) -> Result<()> {
        let result = self.write(ReplicatedCommandV1::ActivateOrigin(ActivateOriginV1 {
            origin,
        }))?;
        crate::validate_activation_result(result)
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
        self.send(|response| RuntimeRequest::ChangeMembership {
            voters,
            learners,
            response,
        })
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
    ChangeMembership {
        voters: Vec<u64>,
        learners: Vec<u64>,
        response: std_mpsc::SyncSender<Result<()>>,
    },
    Checkpoint {
        response: std_mpsc::SyncSender<Result<()>>,
    },
    Shutdown {
        response: std_mpsc::SyncSender<()>,
    },
}

async fn run_runtime(
    node_id: u64,
    log_store: RedbRaftLogStore<ChorusRaftConfig>,
    mut status_log_store: RedbRaftLogStore<ChorusRaftConfig>,
    state_machine: RedbStateMachine,
    initialize: bool,
    state_initialized: bool,
    mode: RuntimeMode,
    mut receiver: mpsc::Receiver<RuntimeRequest>,
    startup: std_mpsc::SyncSender<std::result::Result<(), String>>,
) {
    let authenticated = matches!(mode, RuntimeMode::Authenticated { .. });
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
    if !initialize && !state_initialized && committed.is_none() && !authenticated {
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

    let mut server_shutdown = None;
    let mut server_task = None;
    let (raft, initial_members, wait_for_self_leader, gateway, authorized_nodes) = match mode {
        RuntimeMode::SingleNode => {
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
            (
                raft,
                BTreeMap::from([(node_id, BasicNode::new(format!("single-node://{node_id}")))]),
                true,
                None,
                BTreeMap::new(),
            )
        }
        RuntimeMode::Authenticated {
            identity,
            initial_voters,
            options,
        } => {
            let authorized_nodes: BTreeMap<u64, BasicNode> = identity
                .peers
                .iter()
                .map(|(peer_id, peer)| (*peer_id, BasicNode::new(&peer.endpoint)))
                .collect();
            let listener = match tokio::net::TcpListener::bind(options.listen).await {
                Ok(listener) => listener,
                Err(error) => {
                    let _ = startup.send(Err(format!(
                        "could not bind authenticated OpenRaft listener {}: {error}",
                        options.listen
                    )));
                    return;
                }
            };
            let config = match authenticated_config(&options) {
                Ok(config) => config,
                Err(error) => {
                    let _ = startup.send(Err(error));
                    return;
                }
            };
            let network = match AuthenticatedNetworkFactory::new(Arc::clone(&identity)) {
                Ok(network) => network,
                Err(error) => {
                    let _ = startup.send(Err(error.to_string()));
                    return;
                }
            };
            let gateway = network.clone();
            let raft =
                match ChorusRaft::new(node_id, config, network, log_store, state_machine.clone())
                    .await
                {
                    Ok(raft) => raft,
                    Err(error) => {
                        let _ = startup.send(Err(format!("could not open OpenRaft node: {error}")));
                        return;
                    }
                };
            let service = match AuthenticatedRaftService::new_with_control(
                raft.clone(),
                Arc::clone(&identity),
                authorized_nodes.clone(),
                Some(gateway.clone()),
            ) {
                Ok(service) => service,
                Err(error) => {
                    let _ = startup.send(Err(error.to_string()));
                    let _ = raft.shutdown().await;
                    return;
                }
            };
            let tls = match identity.server_tls_config() {
                Ok(tls) => tls,
                Err(error) => {
                    let _ = startup.send(Err(error.to_string()));
                    let _ = raft.shutdown().await;
                    return;
                }
            };
            let mut server = match authenticated_server_builder().tls_config(tls) {
                Ok(server) => server,
                Err(error) => {
                    let _ = startup.send(Err(format!(
                        "could not configure authenticated OpenRaft TLS server: {error}"
                    )));
                    let _ = raft.shutdown().await;
                    return;
                }
            };
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let incoming = TcpListenerStream::new(listener);
            let task = tokio::spawn(async move {
                server
                    .add_service(bounded_transport_server(service))
                    .serve_with_incoming_shutdown(incoming, async {
                        let _ = shutdown_rx.await;
                    })
                    .await
                    .map_err(|error| error.to_string())
            });
            server_shutdown = Some(shutdown_tx);
            server_task = Some(task);
            (
                raft,
                initial_voters,
                initialize,
                Some(gateway),
                authorized_nodes,
            )
        }
    };

    if initialize {
        match tokio::time::timeout(OPERATION_TIMEOUT, raft.initialize(initial_members)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let _ = startup.send(Err(format!("OpenRaft initialization failed: {error}")));
                stop_transport_server(&mut server_shutdown, &mut server_task).await;
                let _ = raft.shutdown().await;
                return;
            }
            Err(_) => {
                let _ = startup.send(Err("OpenRaft initialization timed out".into()));
                stop_transport_server(&mut server_shutdown, &mut server_task).await;
                let _ = raft.shutdown().await;
                return;
            }
        }
    }

    if wait_for_self_leader {
        match raft
            .wait(Some(OPERATION_TIMEOUT))
            .current_leader(node_id, "OpenRaft bootstrap leader")
            .await
        {
            Ok(_) => {}
            Err(error) => {
                let _ = startup.send(Err(format!("OpenRaft leader startup failed: {error}")));
                stop_transport_server(&mut server_shutdown, &mut server_task).await;
                let _ = raft.shutdown().await;
                return;
            }
        }
    }
    let _ = startup.send(Ok(()));

    loop {
        let request = if let Some(task) = server_task.as_mut() {
            tokio::select! {
                request = receiver.recv() => request,
                result = task => {
                    server_task = None;
                    let message = match result {
                        Ok(Ok(())) => "authenticated OpenRaft server stopped unexpectedly".into(),
                        Ok(Err(error)) => format!("authenticated OpenRaft server failed: {error}"),
                        Err(error) => format!("authenticated OpenRaft server task failed: {error}"),
                    };
                    eprintln!("{message}");
                    break;
                }
            }
        } else {
            receiver.recv().await
        };
        let Some(request) = request else {
            break;
        };
        match request {
            RuntimeRequest::Write { command, response } => {
                let result = match tokio::time::timeout(
                    OPERATION_TIMEOUT,
                    write_with_forwarding(&raft, gateway.as_ref(), &state_machine, command),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err(ChorusError::Consensus("OpenRaft write timed out".into())),
                };
                let _ = response.send(result);
            }
            RuntimeRequest::ReadBarrier { response } => {
                let result = match tokio::time::timeout(
                    OPERATION_TIMEOUT,
                    read_barrier_with_forwarding(&raft, gateway.as_ref(), &state_machine),
                )
                .await
                {
                    Ok(result) => result,
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
                // Status is deliberately diagnostic: a failed or timed-out
                // barrier must not make the whole status request fail.  Probe
                // the current barrier first, so the durable commit cursor is
                // read only after any local follower catch-up it requires.
                let quorum = tokio::time::timeout_at(
                    tokio::time::Instant::now() + OPERATION_TIMEOUT,
                    read_barrier_with_forwarding(&raft, gateway.as_ref(), &state_machine),
                )
                .await
                .is_ok_and(|result| result.is_ok());
                // The metadata read gets its own short local bound.  If it
                // fails, return an error so the public status fallback stays
                // conservative rather than fabricating a commit cursor.
                let committed = tokio::time::timeout(
                    STATUS_METADATA_TIMEOUT,
                    status_log_store.read_committed(),
                )
                .await
                .map_err(|_| {
                    ChorusError::Consensus("OpenRaft durable status read timed out".into())
                })
                .and_then(|result| {
                    result.map_err(|error| {
                        ChorusError::Storage(format!(
                            "could not read durable OpenRaft status: {error}"
                        ))
                    })
                });
                let committed = match committed {
                    Ok(committed) => committed,
                    Err(error) => {
                        let _ = response.send(Err(error));
                        continue;
                    }
                };
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
                    commit_index: durable_commit_index(committed),
                    applied_index,
                    quorum,
                    voters,
                    learners,
                }));
            }
            RuntimeRequest::ChangeMembership {
                voters,
                learners,
                response,
            } => {
                let result = tokio::time::timeout(
                    OPERATION_TIMEOUT,
                    apply_bounded_membership_change(&raft, &authorized_nodes, voters, learners),
                )
                .await
                .map_err(|_| ChorusError::Consensus("OpenRaft membership change timed out".into()))
                .and_then(|result| result);
                let _ = response.send(result);
            }
            RuntimeRequest::Checkpoint { response } => {
                let result = checkpoint_runtime(&raft).await;
                let _ = response.send(result);
            }
            RuntimeRequest::Shutdown { response } => {
                let checkpoint = tokio::time::timeout(SHUTDOWN_TIMEOUT, checkpoint_runtime(&raft))
                    .await
                    .map_err(|_| {
                        ChorusError::Consensus("OpenRaft shutdown checkpoint timed out".into())
                    })
                    .and_then(|result| result);
                if let Err(error) = checkpoint {
                    eprintln!("OpenRaft checkpoint before shutdown failed: {error}");
                }
                stop_transport_server(&mut server_shutdown, &mut server_task).await;
                let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, raft.shutdown()).await;
                let _ = response.send(());
                return;
            }
        }
    }
    if let Err(error) = checkpoint_runtime(&raft).await {
        eprintln!("OpenRaft checkpoint before runtime exit failed: {error}");
    }
    stop_transport_server(&mut server_shutdown, &mut server_task).await;
    let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, raft.shutdown()).await;
}

async fn checkpoint_runtime(raft: &ChorusRaft) -> Result<()> {
    let target = raft.metrics().borrow().last_applied;
    let Some(target) = target else {
        return Ok(());
    };
    let current_snapshot = raft.metrics().borrow().snapshot;
    if current_snapshot.is_some_and(|snapshot| snapshot >= target) {
        return Ok(());
    }
    tokio::time::timeout(OPERATION_TIMEOUT, async {
        raft.trigger()
            .snapshot()
            .await
            .map_err(|error| ChorusError::Consensus(error.to_string()))?;
        raft.wait(Some(OPERATION_TIMEOUT))
            .ge(
                Metric::Snapshot(Some(target)),
                "OpenRaft durable checkpoint",
            )
            .await
            .map_err(|error| ChorusError::Consensus(error.to_string()))?;
        Ok::<(), ChorusError>(())
    })
    .await
    .map_err(|_| ChorusError::Consensus("OpenRaft checkpoint timed out".into()))??;
    Ok(())
}

/// Bounded live-membership support. A leader may add one pre-provisioned
/// learner, or replace exactly one nonleader voter with exactly one caught-up
/// learner while retaining the former voter as a learner, or remove exactly
/// one already-demoted learner. Voter removal, multi-node changes, leader
/// demotion and peer-directory rotation fail closed.
pub(crate) async fn apply_bounded_membership_change(
    raft: &ChorusRaft,
    authorized_nodes: &BTreeMap<u64, BasicNode>,
    voters: Vec<u64>,
    learners: Vec<u64>,
) -> Result<()> {
    apply_bounded_membership_change_with_intent(raft, authorized_nodes, voters, learners, None)
        .await
}

pub(crate) async fn apply_bounded_membership_change_with_intent(
    raft: &ChorusRaft,
    authorized_nodes: &BTreeMap<u64, BasicNode>,
    voters: Vec<u64>,
    learners: Vec<u64>,
    intent: Option<&ChangeMembershipIntent>,
) -> Result<()> {
    if voters.iter().chain(&learners).any(|node_id| *node_id == 0) {
        return Err(ChorusError::Consensus(
            "OpenRaft membership node ids must be nonzero".into(),
        ));
    }
    let requested_voters: BTreeSet<_> = voters.iter().copied().collect();
    let requested_learners: BTreeSet<_> = learners.iter().copied().collect();
    if requested_voters.len() != voters.len() || requested_learners.len() != learners.len() {
        return Err(ChorusError::Consensus(
            "OpenRaft membership request contains duplicate node ids".into(),
        ));
    }
    if requested_voters.is_empty()
        || requested_voters
            .iter()
            .any(|node_id| requested_learners.contains(node_id))
    {
        return Err(ChorusError::Consensus(
            "OpenRaft voter set must be nonempty and voters/learners must be disjoint".into(),
        ));
    }

    let metrics = raft.metrics().borrow().clone();
    let current_voters: BTreeSet<_> = metrics.membership_config.voter_ids().collect();
    let current_learners: BTreeSet<_> = metrics
        .membership_config
        .membership()
        .learner_ids()
        .collect();
    if metrics.current_leader != Some(metrics.id) {
        return Err(ChorusError::Consensus(
            "OpenRaft membership changes must be submitted to the current leader".into(),
        ));
    }
    if metrics
        .membership_config
        .membership()
        .get_joint_config()
        .len()
        != 1
    {
        return Err(ChorusError::Consensus(
            "OpenRaft membership is still joint; wait for recovery before another change".into(),
        ));
    }

    if let Some(intent) = intent {
        validate_membership_intent(
            intent,
            &current_voters,
            &current_learners,
            &requested_voters,
            &requested_learners,
        )?;
        if requested_voters == current_voters && requested_learners == current_learners {
            match intent {
                ChangeMembershipIntent::AddLearner { node_id } => {
                    let node = authorized_nodes.get(node_id).cloned().ok_or_else(|| {
                        ChorusError::Consensus(format!(
                            "learner {node_id} is absent from the signed peer manifest"
                        ))
                    })?;
                    raft.add_learner(*node_id, node, true)
                        .await
                        .map_err(|error| {
                            ChorusError::Consensus(format!(
                                "OpenRaft learner {node_id} catch-up retry failed: {error}"
                            ))
                        })?;
                }
                ChangeMembershipIntent::ReplaceVoter { .. }
                | ChangeMembershipIntent::RemoveLearner { .. } => {}
            }
            return verify_uniform_membership(raft, &requested_voters, &requested_learners);
        }
    }

    if requested_voters != current_voters {
        return replace_one_voter(
            raft,
            authorized_nodes,
            &current_voters,
            &current_learners,
            &requested_voters,
            &requested_learners,
            metrics.current_leader,
        )
        .await;
    }
    let removed: Vec<_> = current_learners
        .difference(&requested_learners)
        .copied()
        .collect();
    let added: Vec<_> = requested_learners
        .difference(&current_learners)
        .copied()
        .collect();
    if !removed.is_empty() {
        if !added.is_empty() {
            return Err(ChorusError::Consensus(
                "bounded membership cannot add and remove learners in one request".into(),
            ));
        }
        let target = match removed.as_slice() {
            [target] => *target,
            _ => {
                return Err(ChorusError::Consensus(
                    "bounded membership removes exactly one learner per request".into(),
                ));
            }
        };
        return remove_one_learner(
            raft,
            &current_voters,
            &requested_voters,
            &requested_learners,
            target,
        )
        .await;
    }
    let target = match added.as_slice() {
        [target] => *target,
        [] if requested_learners.is_empty() => return Ok(()),
        // A retry after an ambiguous response re-adds the sole learner with
        // `blocking=true`, preserving the catch-up guarantee.
        [] if requested_learners.len() == 1 => *requested_learners.iter().next().unwrap(),
        [] => {
            return Err(ChorusError::Consensus(
                "bounded membership cannot revalidate multiple learners".into(),
            ));
        }
        _ => {
            return Err(ChorusError::Consensus(
                "bounded membership adds exactly one learner per request".into(),
            ));
        }
    };
    let node = authorized_nodes.get(&target).cloned().ok_or_else(|| {
        ChorusError::Consensus(format!(
            "learner {target} is absent from the signed peer manifest"
        ))
    })?;

    raft.add_learner(target, node, true)
        .await
        .map_err(|error| ChorusError::Consensus(format!("OpenRaft add learner failed: {error}")))?;
    verify_uniform_membership(raft, &requested_voters, &requested_learners)
}

fn validate_membership_intent(
    intent: &ChangeMembershipIntent,
    current_voters: &BTreeSet<u64>,
    current_learners: &BTreeSet<u64>,
    requested_voters: &BTreeSet<u64>,
    requested_learners: &BTreeSet<u64>,
) -> Result<()> {
    match intent {
        ChangeMembershipIntent::AddLearner { node_id } => {
            if current_voters.contains(node_id) {
                return Err(ChorusError::Consensus(format!(
                    "learner {node_id} is already a voter"
                )));
            }
            let mut expected = current_learners.clone();
            expected.insert(*node_id);
            if requested_voters != current_voters
                || (requested_learners != &expected
                    && !(current_learners.contains(node_id)
                        && requested_learners == current_learners))
            {
                return Err(ChorusError::Consensus(
                    "add-learner intent does not match the requested one-node delta".into(),
                ));
            }
        }
        ChangeMembershipIntent::ReplaceVoter { promoted, demoted } => {
            if *promoted == 0 || *demoted == 0 || promoted == demoted {
                return Err(ChorusError::Consensus(
                    "voter replacement intent has invalid node ids".into(),
                ));
            }
            let already_applied = current_voters.contains(promoted)
                && !current_voters.contains(demoted)
                && current_learners.contains(demoted)
                && !current_learners.contains(promoted)
                && requested_voters == current_voters
                && requested_learners == current_learners;
            let mut expected_voters = current_voters.clone();
            expected_voters.remove(demoted);
            expected_voters.insert(*promoted);
            let mut expected_learners = current_learners.clone();
            expected_learners.remove(promoted);
            expected_learners.insert(*demoted);
            if !already_applied
                && (requested_voters != &expected_voters
                    || requested_learners != &expected_learners)
            {
                return Err(ChorusError::Consensus(
                    "voter replacement intent does not match the requested one-for-one delta"
                        .into(),
                ));
            }
        }
        ChangeMembershipIntent::RemoveLearner { node_id } => {
            let already_applied = !current_voters.contains(node_id)
                && !current_learners.contains(node_id)
                && requested_voters == current_voters
                && requested_learners == current_learners;
            let mut expected_learners = current_learners.clone();
            expected_learners.remove(node_id);
            if !already_applied
                && (requested_voters != current_voters || requested_learners != &expected_learners)
            {
                return Err(ChorusError::Consensus(
                    "learner removal intent does not match the requested one-node delta".into(),
                ));
            }
        }
    }
    Ok(())
}

async fn remove_one_learner(
    raft: &ChorusRaft,
    current_voters: &BTreeSet<u64>,
    requested_voters: &BTreeSet<u64>,
    requested_learners: &BTreeSet<u64>,
    target: u64,
) -> Result<()> {
    if !matches!(current_voters.len(), 3 | 5) || requested_voters != current_voters {
        return Err(ChorusError::Consensus(
            "learner removal must preserve an existing 3- or 5-voter set".into(),
        ));
    }
    raft.change_membership(ChangeMembers::RemoveNodes(BTreeSet::from([target])), false)
        .await
        .map_err(|error| {
            ChorusError::Consensus(format!("OpenRaft learner {target} removal failed: {error}"))
        })?;
    verify_uniform_membership(raft, requested_voters, requested_learners)
}

async fn replace_one_voter(
    raft: &ChorusRaft,
    authorized_nodes: &BTreeMap<u64, BasicNode>,
    current_voters: &BTreeSet<u64>,
    current_learners: &BTreeSet<u64>,
    requested_voters: &BTreeSet<u64>,
    requested_learners: &BTreeSet<u64>,
    current_leader: Option<u64>,
) -> Result<()> {
    if !matches!(current_voters.len(), 3 | 5) || requested_voters.len() != current_voters.len() {
        return Err(ChorusError::Consensus(
            "voter replacement must preserve an existing 3- or 5-voter set".into(),
        ));
    }
    let promoted: Vec<_> = requested_voters
        .difference(current_voters)
        .copied()
        .collect();
    let demoted: Vec<_> = current_voters
        .difference(requested_voters)
        .copied()
        .collect();
    let (promoted, demoted) = match (promoted.as_slice(), demoted.as_slice()) {
        ([promoted], [demoted]) => (*promoted, *demoted),
        _ => {
            return Err(ChorusError::Consensus(
                "bounded voter replacement requires exactly one promotion and one demotion".into(),
            ));
        }
    };
    if !current_learners.contains(&promoted) {
        return Err(ChorusError::Consensus(format!(
            "replacement voter {promoted} is not a current learner"
        )));
    }
    if current_leader == Some(demoted) {
        return Err(ChorusError::Consensus(
            "bounded voter replacement cannot demote the current leader without leader transfer"
                .into(),
        ));
    }
    let mut expected_learners = current_learners.clone();
    expected_learners.remove(&promoted);
    expected_learners.insert(demoted);
    if requested_learners != &expected_learners {
        return Err(ChorusError::Consensus(
            "voter replacement must retain the demoted voter and every other learner".into(),
        ));
    }
    let node = authorized_nodes.get(&promoted).cloned().ok_or_else(|| {
        ChorusError::Consensus(format!(
            "replacement voter {promoted} is absent from the signed peer manifest"
        ))
    })?;

    // Re-adding an existing learner with `blocking=true` is OpenRaft's
    // explicit line-rate/catch-up gate immediately before promotion.
    raft.add_learner(promoted, node, true)
        .await
        .map_err(|error| {
            ChorusError::Consensus(format!(
                "OpenRaft replacement learner catch-up failed: {error}"
            ))
        })?;
    raft.change_membership(requested_voters.clone(), true)
        .await
        .map_err(|error| {
            ChorusError::Consensus(format!("OpenRaft voter replacement failed: {error}"))
        })?;
    verify_uniform_membership(raft, requested_voters, requested_learners)
}

fn verify_uniform_membership(
    raft: &ChorusRaft,
    requested_voters: &BTreeSet<u64>,
    requested_learners: &BTreeSet<u64>,
) -> Result<()> {
    let membership = raft.metrics().borrow().membership_config.clone();
    let observed_voters: BTreeSet<_> = membership.voter_ids().collect();
    let observed_learners: BTreeSet<_> = membership.membership().learner_ids().collect();
    if membership.membership().get_joint_config().len() != 1
        || &observed_voters != requested_voters
        || &observed_learners != requested_learners
    {
        return Err(ChorusError::Consensus(
            "OpenRaft did not publish the requested uniform exact membership".into(),
        ));
    }
    Ok(())
}

async fn write_with_forwarding(
    raft: &ChorusRaft,
    gateway: Option<&AuthenticatedNetworkFactory>,
    state_machine: &RedbStateMachine,
    command: ReplicatedCommandV1,
) -> Result<ApplyResult> {
    let mut target = match raft.client_write(command.clone()).await {
        Ok(response) => return Ok(response.data),
        Err(RaftError::APIError(ClientWriteError::ForwardToLeader(forward))) => forward
            .leader_id
            .or_else(|| raft.metrics().borrow().current_leader),
        Err(error) => return Err(ChorusError::Consensus(error.to_string())),
    };
    let gateway = gateway.ok_or_else(|| {
        ChorusError::Consensus("OpenRaft has no authenticated follower gateway".into())
    })?;
    let mut visited = BTreeSet::new();
    for _ in 0..MAX_GATEWAY_REDIRECTS {
        let leader = target.ok_or_else(|| {
            ChorusError::Consensus("OpenRaft follower does not know the current leader".into())
        })?;
        if !visited.insert(leader) {
            return Err(ChorusError::Consensus(
                "OpenRaft follower gateway detected a redirect loop".into(),
            ));
        }
        match gateway
            .forward_client_write(leader, command.clone(), OPERATION_TIMEOUT)
            .await
            .map_err(|error| ChorusError::Consensus(error.to_string()))?
        {
            ClientWriteGatewayResponse::Applied { log_id, result } => {
                snapshot_after_read_cursor(raft, state_machine, Some(log_id)).await?;
                return Ok(result);
            }
            ClientWriteGatewayResponse::ForwardToLeader { leader_id } => target = leader_id,
            ClientWriteGatewayResponse::Failed(error) => {
                return Err(ChorusError::Consensus(format!(
                    "OpenRaft leader rejected forwarded write: {error}"
                )));
            }
        }
    }
    Err(ChorusError::Consensus(
        "OpenRaft follower gateway exceeded its redirect limit".into(),
    ))
}

async fn read_barrier_with_forwarding(
    raft: &ChorusRaft,
    gateway: Option<&AuthenticatedNetworkFactory>,
    state_machine: &RedbStateMachine,
) -> Result<StateSnapshot> {
    let mut target = match raft.ensure_linearizable().await {
        Ok(read_log_id) => {
            return snapshot_after_read_cursor(raft, state_machine, read_log_id).await;
        }
        Err(RaftError::APIError(CheckIsLeaderError::ForwardToLeader(forward))) => forward
            .leader_id
            .or_else(|| raft.metrics().borrow().current_leader),
        Err(error) => return Err(ChorusError::Consensus(error.to_string())),
    };
    let gateway = gateway.ok_or_else(|| {
        ChorusError::Consensus("OpenRaft has no authenticated follower gateway".into())
    })?;
    let mut visited = BTreeSet::new();
    for _ in 0..MAX_GATEWAY_REDIRECTS {
        let leader = target.ok_or_else(|| {
            ChorusError::Consensus("OpenRaft follower does not know the current leader".into())
        })?;
        if !visited.insert(leader) {
            return Err(ChorusError::Consensus(
                "OpenRaft follower gateway detected a redirect loop".into(),
            ));
        }
        match gateway
            .forward_read_barrier(leader, OPERATION_TIMEOUT)
            .await
            .map_err(|error| ChorusError::Consensus(error.to_string()))?
        {
            ReadBarrierGatewayResponse::Confirmed { read_log_id } => {
                return snapshot_after_read_cursor(raft, state_machine, read_log_id).await;
            }
            ReadBarrierGatewayResponse::ForwardToLeader { leader_id } => target = leader_id,
            ReadBarrierGatewayResponse::Failed(error) => {
                return Err(ChorusError::Consensus(format!(
                    "OpenRaft leader rejected forwarded read barrier: {error}"
                )));
            }
        }
    }
    Err(ChorusError::Consensus(
        "OpenRaft follower gateway exceeded its redirect limit".into(),
    ))
}

async fn snapshot_after_read_cursor(
    raft: &ChorusRaft,
    state_machine: &RedbStateMachine,
    read_log_id: Option<openraft::LogId<u64>>,
) -> Result<StateSnapshot> {
    if let Some(read_log_id) = read_log_id {
        raft.wait(Some(OPERATION_TIMEOUT))
            .applied_index_at_least(Some(read_log_id.index), "Chorus follower read barrier")
            .await
            .map_err(|error| ChorusError::Consensus(error.to_string()))?;
        let snapshot = state_machine
            .state_snapshot()
            .map_err(|error| ChorusError::Storage(error.to_string()))?;
        let applied = snapshot.last_applied();
        if applied.index < read_log_id.index
            || (applied.index == read_log_id.index && applied.term != read_log_id.leader_id.term)
        {
            return Err(ChorusError::Consensus(
                "local state does not match the confirmed OpenRaft read cursor".into(),
            ));
        }
        Ok(snapshot)
    } else {
        state_machine
            .state_snapshot()
            .map_err(|error| ChorusError::Storage(error.to_string()))
    }
}

async fn stop_transport_server(
    shutdown: &mut Option<oneshot::Sender<()>>,
    task: &mut Option<tokio::task::JoinHandle<std::result::Result<(), String>>>,
) {
    if let Some(shutdown) = shutdown.take() {
        let _ = shutdown.send(());
    }
    if let Some(mut task) = task.take() {
        if tokio::time::timeout(SHUTDOWN_TIMEOUT, &mut task)
            .await
            .is_err()
        {
            task.abort();
            let _ = task.await;
        }
    }
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

fn authenticated_config(
    options: &OpenRaftRuntimeOptions,
) -> std::result::Result<Arc<Config>, String> {
    Config {
        cluster_name: "chorus-authenticated".into(),
        heartbeat_interval: options.heartbeat_ms,
        election_timeout_min: options.election_timeout_min_ms,
        election_timeout_max: options.election_timeout_max_ms,
        snapshot_policy: SnapshotPolicy::LogsSinceLast(options.snapshot_entries),
        snapshot_max_chunk_size: crate::openraft_transport::MAX_SNAPSHOT_CHUNK_BYTES as u64,
        max_payload_entries: crate::openraft_transport::MAX_APPEND_ENTRIES as u64,
        max_in_snapshot_log_to_keep: options.snapshot_entries.min(10_000),
        ..Config::default()
    }
    .validate()
    .map(Arc::new)
    .map_err(|error| format!("invalid authenticated OpenRaft configuration: {error}"))
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

#[cfg(test)]
mod tests {
    use openraft::{CommittedLeaderId, LogId};

    use super::durable_commit_index;

    #[test]
    fn durable_commit_index_is_not_fabricated_from_applied_index() {
        let committed = Some(LogId::new(CommittedLeaderId::new(7, 1), 9));
        let applied_index = 3;

        let commit_index = durable_commit_index(committed);
        assert_eq!(9, commit_index);
        assert!(commit_index > applied_index);
        assert_eq!(0, durable_commit_index(None));
    }
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
