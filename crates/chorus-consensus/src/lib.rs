#![forbid(unsafe_code)]

//! Consensus boundary.  The release baseline keeps OpenRaft types out of SQL
//! and exposes a synchronous adapter that can be backed by OpenRaft or the
//! deterministic in-process cluster used by tests and local development.

use chorus_codec::{
    ApplyResult, CommitTransactionV1, LogicalSnapshot, ReplicatedCommandV1, SchemaCommandV1,
};
use chorus_common::{ChorusError, LogId, Result};
use chorus_storage::{StateSnapshot, StateStore, StoreStatus, snapshot_from_store};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusStatus {
    pub node_id: u64,
    pub leader_id: Option<u64>,
    pub term: u64,
    pub commit_index: u64,
    pub applied_index: u64,
    pub quorum: bool,
    pub voters: Vec<u64>,
    pub learners: Vec<u64>,
}

pub trait Consensus: Send + Sync {
    /// Install the process boot origin before accepting SQL writes.  Network
    /// and in-memory adapters replicate this idempotent command; test/fake
    /// adapters may keep the default no-op.
    fn activate_origin(&self, _origin: chorus_common::OriginId) -> Result<()> {
        Ok(())
    }
    fn read_barrier(&self) -> Result<StateSnapshot>;
    fn submit(&self, command: CommitTransactionV1) -> Result<ApplyResult>;
    fn submit_schema(&self, command: SchemaCommandV1) -> Result<ApplyResult>;
    /// Bootstrap the configured initial membership.  Implementations that do
    /// not own a multi-node transport (for example a test committer) may
    /// retain the default rejection.  Bootstrap is deliberately explicit;
    /// ordinary SQL readiness must never create a new cluster as a side
    /// effect of an unreachable peer set.
    fn bootstrap(&self) -> Result<()> {
        Err(ChorusError::Consensus(
            "explicit bootstrap is not supported by this adapter".into(),
        ))
    }
    /// Submit an explicit membership change.  Membership is part of the
    /// replicated state machine and is therefore never changed by a local
    /// liveness timeout.
    fn change_membership(&self, _voters: Vec<u64>, _learners: Vec<u64>) -> Result<()> {
        Err(ChorusError::Consensus(
            "membership changes are not supported by this adapter".into(),
        ))
    }
    fn wait_applied(&self, log_id: LogId) -> Result<()>;
    fn status(&self) -> ConsensusStatus;
    fn store(&self) -> Arc<dyn StateStore>;
}

/// Adapter used by the SQL gateway.  It keeps `Consensus` and transaction
/// contracts separate while allowing either OpenRaft or the in-memory test
/// cluster to drive exactly the same SQL executor.
pub struct ConsensusCommitter {
    inner: Arc<dyn Consensus>,
    origin: chorus_common::OriginId,
}
impl ConsensusCommitter {
    pub fn new(inner: Arc<dyn Consensus>, origin: chorus_common::OriginId) -> Arc<Self> {
        Arc::new(Self { inner, origin })
    }
    pub fn new_activated(
        inner: Arc<dyn Consensus>,
        origin: chorus_common::OriginId,
    ) -> Result<Arc<Self>> {
        inner.activate_origin(origin)?;
        Ok(Self::new(inner, origin))
    }
}
impl chorus_txn::Committer for ConsensusCommitter {
    fn read_barrier(&self) -> Result<StateSnapshot> {
        self.inner.read_barrier()
    }
    fn submit(&self, command: CommitTransactionV1) -> Result<ApplyResult> {
        self.inner.submit(command)
    }
    fn submit_schema(&self, command: SchemaCommandV1) -> Result<ApplyResult> {
        self.inner.submit_schema(command)
    }
    fn origin(&self) -> chorus_common::OriginId {
        self.origin
    }
}

pub struct StandaloneConsensus {
    node_id: u64,
    store: Arc<dyn StateStore>,
    leader: Mutex<bool>,
    term: Mutex<u64>,
}
impl StandaloneConsensus {
    pub fn new(node_id: u64, store: Arc<dyn StateStore>) -> Self {
        Self {
            node_id,
            store,
            leader: Mutex::new(true),
            term: Mutex::new(1),
        }
    }
    pub fn set_quorum(&self, available: bool) {
        *self.leader.lock().unwrap() = available;
    }
}
impl Consensus for StandaloneConsensus {
    fn activate_origin(&self, origin: chorus_common::OriginId) -> Result<()> {
        let snapshot = self.store.snapshot()?;
        if snapshot
            .origins()
            .get(&origin.node_id)
            .is_some_and(|state| state.active_origin == origin)
        {
            return Ok(());
        }
        let index = snapshot.last_applied().index + 1;
        self.store.apply(
            LogId {
                term: *self.term.lock().unwrap(),
                index,
            },
            &ReplicatedCommandV1::ActivateOrigin(chorus_codec::ActivateOriginV1 { origin }),
        )?;
        Ok(())
    }
    fn read_barrier(&self) -> Result<StateSnapshot> {
        if !*self.leader.lock().unwrap() {
            return Err(ChorusError::Consensus("no quorum".into()));
        }
        self.store.snapshot()
    }
    fn submit(&self, c: CommitTransactionV1) -> Result<ApplyResult> {
        if !*self.leader.lock().unwrap() {
            return Err(ChorusError::Consensus("no quorum".into()));
        }
        let i = self.store.snapshot()?.last_applied().index + 1;
        self.store.apply(
            LogId {
                term: *self.term.lock().unwrap(),
                index: i,
            },
            &ReplicatedCommandV1::CommitTransaction(c),
        )
    }
    fn submit_schema(&self, c: SchemaCommandV1) -> Result<ApplyResult> {
        if !*self.leader.lock().unwrap() {
            return Err(ChorusError::Consensus("no quorum".into()));
        }
        let i = self.store.snapshot()?.last_applied().index + 1;
        self.store.apply(
            LogId {
                term: *self.term.lock().unwrap(),
                index: i,
            },
            &ReplicatedCommandV1::SchemaChange(c),
        )
    }
    fn wait_applied(&self, log_id: LogId) -> Result<()> {
        if self.store.snapshot()?.last_applied().index >= log_id.index {
            Ok(())
        } else {
            Err(ChorusError::Consensus(
                "state machine has not caught up".into(),
            ))
        }
    }
    fn status(&self) -> ConsensusStatus {
        let s = self.store.status();
        ConsensusStatus {
            node_id: self.node_id,
            leader_id: if *self.leader.lock().unwrap() {
                Some(self.node_id)
            } else {
                None
            },
            term: *self.term.lock().unwrap(),
            commit_index: s.last_applied.index,
            applied_index: s.last_applied.index,
            quorum: *self.leader.lock().unwrap(),
            voters: vec![self.node_id],
            learners: Vec::new(),
        }
    }
    fn store(&self) -> Arc<dyn StateStore> {
        self.store.clone()
    }
}

/// Small static-bootstrap peer transport used when a node is configured with
/// more than one initial member.  It deliberately keeps the wire contract
/// versioned and synchronous so the SQL/transaction layer remains independent
/// of transport details.  The transport is a bring-up implementation: the
/// lowest reachable voter is the deterministic leader, and committed entries
/// are applied to every reachable replica before acknowledgement.
pub struct NetworkConsensus {
    node_id: u64,
    voters: Vec<u64>,
    learners: Vec<u64>,
    endpoints: BTreeMap<u64, String>,
    local_endpoint: String,
    store: Arc<dyn StateStore>,
    term: Mutex<u64>,
    /// Only one proposal may be in the locally observed leader's commit
    /// window at a time.  Without this gate two concurrent gateways could
    /// both derive the same next log index and acknowledge different
    /// commands for one slot.
    proposal_lock: Mutex<()>,
    /// A command that was applied locally but did not yet reach a quorum is
    /// retained until a later proposal retries it.  This closes the most
    /// dangerous failure window in this small transport: an unacknowledged
    /// local apply must not be silently skipped by the next log index.
    pending: Mutex<Option<PendingEntry>>,
    cluster_id: [u8; 16],
    cluster_incarnation: u64,
}

#[derive(Clone, Debug)]
struct PendingEntry {
    log_id: LogId,
    command: ReplicatedCommandV1,
    result: Option<ApplyResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum PeerRequest {
    Ping {
        from: u64,
        cluster_id: [u8; 16],
        cluster_incarnation: u64,
    },
    Status {
        from: u64,
        cluster_id: [u8; 16],
        cluster_incarnation: u64,
    },
    ReadBarrier {
        from: u64,
        cluster_id: [u8; 16],
        cluster_incarnation: u64,
    },
    Snapshot {
        from: u64,
        cluster_id: [u8; 16],
        cluster_incarnation: u64,
    },
    Prepare {
        from: u64,
        cluster_id: [u8; 16],
        cluster_incarnation: u64,
        log_id: LogId,
        command: ReplicatedCommandV1,
    },
    Propose {
        from: u64,
        cluster_id: [u8; 16],
        cluster_incarnation: u64,
        command: ReplicatedCommandV1,
    },
    Apply {
        from: u64,
        leader_id: u64,
        cluster_id: [u8; 16],
        cluster_incarnation: u64,
        log_id: LogId,
        command: ReplicatedCommandV1,
    },
    Install {
        from: u64,
        leader_id: u64,
        cluster_id: [u8; 16],
        cluster_incarnation: u64,
        snapshot: LogicalSnapshot,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum PeerResponse {
    Pong,
    Status(PeerStatus),
    Barrier { log_id: LogId },
    Snapshot(LogicalSnapshot),
    Prepared,
    Installed,
    NeedCatchUp { expected: LogId, actual: LogId },
    Applied(ApplyResult),
    Error(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PeerStatus {
    node_id: u64,
    last_applied: LogId,
    healthy: bool,
}

impl NetworkConsensus {
    pub fn new(
        node_id: u64,
        voters: Vec<u64>,
        learners: Vec<u64>,
        endpoints: BTreeMap<u64, String>,
        store: Arc<dyn StateStore>,
    ) -> Arc<Self> {
        let (cluster_id, cluster_incarnation) = store
            .snapshot()
            .map(|snapshot| {
                (
                    snapshot.cluster_id(),
                    snapshot.to_data().cluster_incarnation,
                )
            })
            .unwrap_or(([0; 16], 1));
        Self::new_with_identity(
            node_id,
            voters,
            learners,
            endpoints,
            cluster_id,
            cluster_incarnation,
            store,
        )
    }

    /// Construct a network adapter with the signed cluster identity from the
    /// bootstrap manifest.  The old `new` constructor remains available for
    /// local development and tests; production callers should use this
    /// constructor so a node cannot accidentally talk to another cluster or
    /// incarnation that happens to share an endpoint.
    pub fn new_with_identity(
        node_id: u64,
        voters: Vec<u64>,
        learners: Vec<u64>,
        endpoints: BTreeMap<u64, String>,
        cluster_id: [u8; 16],
        cluster_incarnation: u64,
        store: Arc<dyn StateStore>,
    ) -> Arc<Self> {
        let local_endpoint = endpoints.get(&node_id).cloned().unwrap_or_default();
        let mut voters = voters;
        voters.sort_unstable();
        voters.dedup();
        let mut learners = learners;
        learners.sort_unstable();
        learners.dedup();
        Arc::new(Self {
            node_id,
            voters,
            learners,
            endpoints,
            local_endpoint,
            store,
            term: Mutex::new(1),
            proposal_lock: Mutex::new(()),
            pending: Mutex::new(None),
            cluster_id,
            cluster_incarnation,
        })
    }

    pub fn start(self: &Arc<Self>) -> std::io::Result<()> {
        let listener = TcpListener::bind(&self.local_endpoint)?;
        listener.set_nonblocking(true)?;
        let this = Arc::clone(self);
        thread::spawn(move || {
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let peer = Arc::clone(&this);
                        thread::spawn(move || {
                            let _ = peer.handle_stream(stream);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(())
    }

    fn identity_ok(&self, cluster_id: [u8; 16], cluster_incarnation: u64) -> Result<()> {
        if cluster_id != self.cluster_id || cluster_incarnation != self.cluster_incarnation {
            return Err(ChorusError::Protocol(
                "peer cluster identity or incarnation mismatch".into(),
            ));
        }
        Ok(())
    }

    fn known_peer(&self, node_id: u64) -> bool {
        self.voters.contains(&node_id) || self.learners.contains(&node_id)
    }

    fn validate_request(&self, request: &PeerRequest) -> Result<()> {
        let (from, cluster_id, cluster_incarnation) = match request {
            PeerRequest::Ping {
                from,
                cluster_id,
                cluster_incarnation,
            }
            | PeerRequest::Status {
                from,
                cluster_id,
                cluster_incarnation,
            }
            | PeerRequest::ReadBarrier {
                from,
                cluster_id,
                cluster_incarnation,
            }
            | PeerRequest::Snapshot {
                from,
                cluster_id,
                cluster_incarnation,
            }
            | PeerRequest::Prepare {
                from,
                cluster_id,
                cluster_incarnation,
                ..
            }
            | PeerRequest::Propose {
                from,
                cluster_id,
                cluster_incarnation,
                ..
            }
            | PeerRequest::Apply {
                from,
                cluster_id,
                cluster_incarnation,
                ..
            }
            | PeerRequest::Install {
                from,
                cluster_id,
                cluster_incarnation,
                ..
            } => (*from, *cluster_id, *cluster_incarnation),
        };
        self.identity_ok(cluster_id, cluster_incarnation)?;
        if !self.known_peer(from) {
            return Err(ChorusError::Protocol(
                "requester is not a cluster member".into(),
            ));
        }
        Ok(())
    }

    fn membership(&self) -> Result<(Vec<u64>, Vec<u64>)> {
        let snapshot = self.store.snapshot()?;
        // A zero membership log id denotes the unbootstrapped local store.
        // Until the explicit Membership entry is committed, use only the
        // signed static manifest for quorum calculations.
        if snapshot.membership().log_id != LogId::ZERO {
            Ok((
                snapshot.membership().voters.clone(),
                snapshot.membership().learners.clone(),
            ))
        } else {
            Ok((self.voters.clone(), self.learners.clone()))
        }
    }

    fn local_peer_status(&self) -> Result<PeerStatus> {
        let snapshot = self.store.snapshot()?;
        Ok(PeerStatus {
            node_id: self.node_id,
            last_applied: snapshot.last_applied(),
            healthy: self.store.status().healthy,
        })
    }

    fn observe(&self) -> Result<(Vec<u64>, Vec<u64>, Vec<PeerStatus>, u64, LogId)> {
        let (voters, learners) = self.membership()?;
        if voters.is_empty()
            || voters.iter().any(|id| *id == 0)
            || voters.iter().any(|id| learners.binary_search(id).is_ok())
        {
            return Err(ChorusError::Protocol(
                "invalid replicated membership".into(),
            ));
        }
        let mut statuses = Vec::with_capacity(voters.len() + learners.len());
        if self.known_peer(self.node_id) {
            statuses.push(self.local_peer_status()?);
        }
        for node_id in voters.iter().chain(learners.iter()) {
            if *node_id == self.node_id {
                continue;
            }
            let Some(endpoint) = self.endpoints.get(node_id) else {
                continue;
            };
            let request = PeerRequest::Status {
                from: self.node_id,
                cluster_id: self.cluster_id,
                cluster_incarnation: self.cluster_incarnation,
            };
            if let Ok(PeerResponse::Status(status)) = self.rpc(endpoint, &request) {
                if status.healthy {
                    statuses.push(status);
                }
            }
        }
        let reachable_voters = statuses
            .iter()
            .filter(|status| voters.binary_search(&status.node_id).is_ok())
            .count();
        if reachable_voters <= voters.len() / 2 {
            return Err(ChorusError::Consensus("no majority is reachable".into()));
        }
        // This transport has no OpenRaft election object yet.  Select the
        // freshest member observed by a quorum, with node id as a stable tie
        // breaker.  A stale local replica can therefore never win a read
        // barrier merely because it is the caller.
        let leader = statuses
            .iter()
            .filter(|status| voters.binary_search(&status.node_id).is_ok())
            .max_by(|a, b| {
                a.last_applied
                    .index
                    .cmp(&b.last_applied.index)
                    .then_with(|| a.last_applied.term.cmp(&b.last_applied.term))
                    .then_with(|| b.node_id.cmp(&a.node_id))
            })
            .ok_or_else(|| ChorusError::Consensus("no leader is reachable".into()))?;
        let leader_id = leader.node_id;
        let leader_log = leader.last_applied;
        Ok((voters, learners, statuses, leader_id, leader_log))
    }

    fn leader_id(&self) -> Option<u64> {
        self.observe().ok().map(|(_, _, _, leader, _)| leader)
    }

    fn quorum(&self) -> bool {
        self.observe().is_ok()
    }

    fn ping(&self, node_id: u64) -> bool {
        let Some(endpoint) = self.endpoints.get(&node_id) else {
            return false;
        };
        if node_id == self.node_id {
            return self.local_peer_status().is_ok_and(|status| status.healthy);
        }
        matches!(
            self.rpc(
                endpoint,
                &PeerRequest::Ping {
                    from: self.node_id,
                    cluster_id: self.cluster_id,
                    cluster_incarnation: self.cluster_incarnation,
                },
            ),
            Ok(PeerResponse::Pong)
        )
    }

    fn snapshot_from_leader(&self, leader: u64) -> Result<StateSnapshot> {
        if leader == self.node_id {
            return self.store.snapshot();
        }
        let endpoint = self
            .endpoints
            .get(&leader)
            .ok_or_else(|| ChorusError::Consensus("leader endpoint is missing".into()))?;
        let response = self.rpc(
            endpoint,
            &PeerRequest::Snapshot {
                from: self.node_id,
                cluster_id: self.cluster_id,
                cluster_incarnation: self.cluster_incarnation,
            },
        )?;
        let PeerResponse::Snapshot(snapshot) = response else {
            return Err(ChorusError::Protocol("invalid snapshot response".into()));
        };
        let remote_log = snapshot.header.last_included;
        let local_log = self.store.snapshot()?.last_applied();
        if remote_log.index < local_log.index {
            return Err(ChorusError::Consensus(
                "leader snapshot is older than local state".into(),
            ));
        }
        self.store.install(&snapshot)?;
        self.store.snapshot()
    }

    fn barrier_local(&self) -> Result<LogId> {
        let (_, _, _, leader, log_id) = self.observe()?;
        if leader != self.node_id {
            return Err(ChorusError::Consensus("not the quorum leader".into()));
        }
        Ok(log_id)
    }

    fn append(&self, command: ReplicatedCommandV1) -> Result<ApplyResult> {
        self.append_from(self.node_id, command)
    }

    fn append_from(&self, requester: u64, command: ReplicatedCommandV1) -> Result<ApplyResult> {
        self.identity_ok(self.cluster_id, self.cluster_incarnation)?;
        match &command {
            ReplicatedCommandV1::ActivateOrigin(a) if a.origin.node_id != requester => {
                return Err(ChorusError::Protocol(
                    "origin activation is not authorized by its node".into(),
                ));
            }
            ReplicatedCommandV1::CommitTransaction(c)
                if c.request_id.origin.node_id != requester =>
            {
                return Err(ChorusError::Protocol(
                    "request origin is not authorized by its node".into(),
                ));
            }
            ReplicatedCommandV1::SchemaChange(c) if c.request_id.origin.node_id != requester => {
                return Err(ChorusError::Protocol(
                    "request origin is not authorized by its node".into(),
                ));
            }
            _ => {}
        }
        let (_, _, _, leader, _) = self.observe()?;
        if leader != self.node_id {
            let endpoint = self
                .endpoints
                .get(&leader)
                .ok_or_else(|| ChorusError::Consensus("leader endpoint is missing".into()))?;
            return match self.rpc(
                endpoint,
                &PeerRequest::Propose {
                    from: requester,
                    cluster_id: self.cluster_id,
                    cluster_incarnation: self.cluster_incarnation,
                    command,
                },
            )? {
                PeerResponse::Applied(result) => Ok(result),
                PeerResponse::Error(message) => Err(ChorusError::Consensus(message)),
                _ => Err(ChorusError::Protocol("invalid proposal response".into())),
            };
        }
        self.append_as_leader(command)
    }

    fn append_as_leader(&self, command: ReplicatedCommandV1) -> Result<ApplyResult> {
        let _proposal_guard = self
            .proposal_lock
            .lock()
            .map_err(|_| ChorusError::Consensus("proposal lock poisoned".into()))?;
        // A previous proposal may have reached this state machine but lost
        // its quorum response.  Finish that exact entry before allocating a
        // new index; this is the local equivalent of retrying an OpenRaft
        // proposal with the same request id and bytes.
        if let Some(pending) = self
            .pending
            .lock()
            .map_err(|_| ChorusError::Consensus("pending proposal lock poisoned".into()))?
            .clone()
        {
            self.reapply_pending_locally(&pending)?;
            if pending.command != command {
                let result = self.replicate_entry(&pending)?;
                self.pending
                    .lock()
                    .map_err(|_| ChorusError::Consensus("pending proposal lock poisoned".into()))?
                    .take();
                let _ = result;
            } else {
                return self.replicate_entry(&pending);
            }
        }
        let (_, _, _, leader, _) = self.observe()?;
        if leader != self.node_id {
            return Err(ChorusError::Consensus(
                "leadership changed during proposal".into(),
            ));
        }
        let snapshot = self.store.snapshot()?;
        let log_id = LogId {
            term: (*self.term.lock().unwrap()).max(snapshot.last_applied().term),
            index: snapshot.last_applied().index.saturating_add(1),
        };
        let before_snapshot = snapshot_from_store(self.store.as_ref())?;
        let prepared = PendingEntry {
            log_id,
            command: command.clone(),
            result: None,
        };
        // Do not mutate the local state machine until a quorum has accepted
        // the exact next entry for preparation.  If the network disappears
        // here, the proposal fails without a visible local mutation.
        self.prepare_quorum(&prepared)?;
        *self
            .pending
            .lock()
            .map_err(|_| ChorusError::Consensus("pending proposal lock poisoned".into()))? =
            Some(prepared);
        let local_result = match self.store.apply(log_id, &command) {
            Ok(result) => result,
            Err(error) => {
                let _ = self.pending.lock().map(|mut pending| pending.take());
                return Err(error);
            }
        };
        if let Ok(mut pending) = self.pending.lock() {
            if let Some(entry) = pending.as_mut() {
                entry.result = Some(local_result.clone());
            }
        }
        let result = self.replicate_entry(&PendingEntry {
            log_id,
            command,
            result: Some(local_result),
        });
        if result.is_err() {
            // Keep the exact pending command for a retry, but hide an
            // unacknowledged local state-machine apply.  `rollback` is a
            // separate monotonicity escape hatch used only for this window.
            let _ = self.store.rollback(&before_snapshot);
        }
        result
    }

    fn reapply_pending_locally(&self, pending: &PendingEntry) -> Result<()> {
        let current = self.store.snapshot()?.last_applied();
        if current < pending.log_id {
            let result = self.store.apply(pending.log_id, &pending.command)?;
            if let Ok(mut slot) = self.pending.lock() {
                if let Some(existing) = slot.as_mut() {
                    existing.result = Some(result);
                }
            }
        } else if current.index > pending.log_id.index {
            return Err(ChorusError::Consensus(
                "pending proposal is behind the local state machine".into(),
            ));
        }
        Ok(())
    }

    fn prepare_quorum(&self, pending: &PendingEntry) -> Result<()> {
        let (voters, learners, statuses, leader, _) = self.observe()?;
        if leader != self.node_id {
            return Err(ChorusError::Consensus("not the quorum leader".into()));
        }
        let quorum = voters.len() / 2 + 1;
        let mut prepared_voters = 1usize;
        for node_id in voters.iter().chain(learners.iter()) {
            if *node_id == self.node_id {
                continue;
            }
            let Some(endpoint) = self.endpoints.get(node_id) else {
                continue;
            };
            let peer_status = statuses
                .iter()
                .find(|status| status.node_id == *node_id)
                .map(|status| status.last_applied);
            if peer_status.is_some_and(|last| {
                last.index < pending.log_id.index
                    && last.index.saturating_add(1) < pending.log_id.index
            }) {
                let snapshot = snapshot_from_store(self.store.as_ref())?;
                if !matches!(
                    self.rpc(
                        endpoint,
                        &PeerRequest::Install {
                            from: self.node_id,
                            leader_id: self.node_id,
                            cluster_id: self.cluster_id,
                            cluster_incarnation: self.cluster_incarnation,
                            snapshot,
                        },
                    ),
                    Ok(PeerResponse::Installed)
                ) {
                    continue;
                }
            }
            if matches!(
                self.rpc(
                    endpoint,
                    &PeerRequest::Prepare {
                        from: self.node_id,
                        cluster_id: self.cluster_id,
                        cluster_incarnation: self.cluster_incarnation,
                        log_id: pending.log_id,
                        command: pending.command.clone(),
                    },
                ),
                Ok(PeerResponse::Prepared)
            ) && voters.binary_search(node_id).is_ok()
            {
                prepared_voters += 1;
            }
        }
        if prepared_voters < quorum {
            return Err(ChorusError::Consensus(
                "proposal was not durably prepared on a quorum".into(),
            ));
        }
        Ok(())
    }

    fn replicate_entry(&self, pending: &PendingEntry) -> Result<ApplyResult> {
        let (voters, learners, statuses, leader, _) = self.observe()?;
        if leader != self.node_id {
            return Err(ChorusError::Consensus(
                "leadership changed during replication".into(),
            ));
        }
        let quorum = voters.len() / 2 + 1;
        self.prepare_quorum(pending)?;

        let local_result = pending
            .result
            .clone()
            .ok_or_else(|| ChorusError::Consensus("leader apply result is missing".into()))?;
        let mut applied_voters = 1usize;
        for node_id in voters.iter().chain(learners.iter()) {
            if *node_id == self.node_id {
                continue;
            }
            let Some(endpoint) = self.endpoints.get(node_id) else {
                continue;
            };
            let peer_status = statuses
                .iter()
                .find(|status| status.node_id == *node_id)
                .map(|status| status.last_applied);
            // A follower with a gap must be repaired from a logical snapshot
            // before it receives this entry.  Applying a future log id
            // directly would skip committed entries and permanently diverge
            // its state machine.
            if peer_status.is_some_and(|last| {
                last < pending.log_id && last.index.saturating_add(1) < pending.log_id.index
            }) {
                let snapshot = snapshot_from_store(self.store.as_ref())?;
                match self.rpc(
                    endpoint,
                    &PeerRequest::Install {
                        from: self.node_id,
                        leader_id: self.node_id,
                        cluster_id: self.cluster_id,
                        cluster_incarnation: self.cluster_incarnation,
                        snapshot,
                    },
                ) {
                    Ok(PeerResponse::Installed) => {}
                    _ => continue,
                }
            }
            let mut response = self.rpc(
                endpoint,
                &PeerRequest::Apply {
                    from: self.node_id,
                    leader_id: self.node_id,
                    cluster_id: self.cluster_id,
                    cluster_incarnation: self.cluster_incarnation,
                    log_id: pending.log_id,
                    command: pending.command.clone(),
                },
            );
            if matches!(response, Ok(PeerResponse::NeedCatchUp { .. })) {
                if let Ok(PeerResponse::Installed) = self.rpc(
                    endpoint,
                    &PeerRequest::Install {
                        from: self.node_id,
                        leader_id: self.node_id,
                        cluster_id: self.cluster_id,
                        cluster_incarnation: self.cluster_incarnation,
                        snapshot: snapshot_from_store(self.store.as_ref())?,
                    },
                ) {
                    response = self.rpc(
                        endpoint,
                        &PeerRequest::Apply {
                            from: self.node_id,
                            leader_id: self.node_id,
                            cluster_id: self.cluster_id,
                            cluster_incarnation: self.cluster_incarnation,
                            log_id: pending.log_id,
                            command: pending.command.clone(),
                        },
                    );
                }
            }
            let applied = matches!(response, Ok(PeerResponse::Applied(_)));
            if applied && voters.binary_search(node_id).is_ok() {
                applied_voters += 1;
            }
        }
        if applied_voters < quorum {
            return Err(ChorusError::Consensus(
                "replication quorum failed after local apply".into(),
            ));
        }
        self.pending
            .lock()
            .map_err(|_| ChorusError::Consensus("pending proposal lock poisoned".into()))?
            .take();
        Ok(local_result)
    }

    fn rpc(&self, endpoint: &str, request: &PeerRequest) -> Result<PeerResponse> {
        let mut stream = TcpStream::connect_timeout(
            &endpoint
                .parse()
                .map_err(|e: std::net::AddrParseError| ChorusError::Consensus(e.to_string()))?,
            Duration::from_millis(250),
        )
        .map_err(|e| ChorusError::Consensus(e.to_string()))?;
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .map_err(|e| ChorusError::Consensus(e.to_string()))?;
        stream
            .set_write_timeout(Some(Duration::from_millis(500)))
            .map_err(|e| ChorusError::Consensus(e.to_string()))?;
        write_frame(&mut stream, request)?;
        read_frame(&mut stream)
    }

    fn handle_stream(&self, mut stream: TcpStream) -> Result<()> {
        let request: PeerRequest = read_frame(&mut stream)?;
        self.validate_request(&request)?;
        let response = match request {
            PeerRequest::Ping { .. } => PeerResponse::Pong,
            PeerRequest::Status { .. } => PeerResponse::Status(self.local_peer_status()?),
            PeerRequest::ReadBarrier { .. } => match self.barrier_local() {
                Ok(log_id) => PeerResponse::Barrier { log_id },
                Err(error) => PeerResponse::Error(error.to_string()),
            },
            PeerRequest::Snapshot { .. } => {
                PeerResponse::Snapshot(snapshot_from_store(self.store.as_ref())?)
            }
            PeerRequest::Prepare { log_id, .. } => {
                if !self.store.status().healthy {
                    PeerResponse::Error("state store is unhealthy".into())
                } else {
                    let current = self.store.snapshot()?.last_applied();
                    if log_id.index > current.index.saturating_add(1) {
                        PeerResponse::NeedCatchUp {
                            expected: LogId {
                                term: current.term,
                                index: current.index.saturating_add(1),
                            },
                            actual: log_id,
                        }
                    } else {
                        PeerResponse::Prepared
                    }
                }
            }
            PeerRequest::Propose { from, command, .. } => match self.append_from(from, command) {
                Ok(result) => PeerResponse::Applied(result),
                Err(error) => PeerResponse::Error(error.to_string()),
            },
            PeerRequest::Apply {
                from,
                leader_id,
                log_id,
                command,
                ..
            } => {
                if from != leader_id {
                    PeerResponse::Error("apply sender is not the declared leader".into())
                } else {
                    let current = self.store.snapshot()?.last_applied();
                    if log_id.index > current.index.saturating_add(1) {
                        PeerResponse::NeedCatchUp {
                            expected: LogId {
                                term: current.term,
                                index: current.index.saturating_add(1),
                            },
                            actual: log_id,
                        }
                    } else {
                        match self.store.apply(log_id, &command) {
                            Ok(result) => PeerResponse::Applied(result),
                            Err(error) => PeerResponse::Error(error.to_string()),
                        }
                    }
                }
            }
            PeerRequest::Install {
                from,
                leader_id,
                snapshot,
                ..
            } => {
                if from != leader_id {
                    PeerResponse::Error("snapshot sender is not the declared leader".into())
                } else {
                    match self.store.install(&snapshot) {
                        Ok(()) => PeerResponse::Installed,
                        Err(error) => PeerResponse::Error(error.to_string()),
                    }
                }
            }
        };
        write_frame(&mut stream, &response)
    }
}

impl Consensus for NetworkConsensus {
    fn activate_origin(&self, origin: chorus_common::OriginId) -> Result<()> {
        if origin.node_id != self.node_id {
            return Err(ChorusError::Protocol(
                "origin activation must use this node's identity".into(),
            ));
        }
        self.append(ReplicatedCommandV1::ActivateOrigin(
            chorus_codec::ActivateOriginV1 { origin },
        ))
        .map(|_| ())
    }
    fn read_barrier(&self) -> Result<StateSnapshot> {
        if self
            .pending
            .lock()
            .map_err(|_| ChorusError::Consensus("pending proposal lock poisoned".into()))?
            .is_some()
        {
            return Err(ChorusError::Consensus(
                "an unacknowledged proposal is awaiting quorum recovery".into(),
            ));
        }
        let (_, _, _, leader, observed_log) = self.observe()?;
        let barrier = if leader == self.node_id {
            observed_log
        } else {
            let endpoint = self
                .endpoints
                .get(&leader)
                .ok_or_else(|| ChorusError::Consensus("leader endpoint is missing".into()))?;
            match self.rpc(
                endpoint,
                &PeerRequest::ReadBarrier {
                    from: self.node_id,
                    cluster_id: self.cluster_id,
                    cluster_incarnation: self.cluster_incarnation,
                },
            )? {
                PeerResponse::Barrier { log_id } => log_id,
                PeerResponse::Error(message) => return Err(ChorusError::Consensus(message)),
                _ => {
                    return Err(ChorusError::Protocol(
                        "invalid read barrier response".into(),
                    ));
                }
            }
        };
        let local = self.store.snapshot()?;
        if local.last_applied().index < barrier.index {
            let synced = self.snapshot_from_leader(leader)?;
            if synced.last_applied().index < barrier.index {
                return Err(ChorusError::Consensus(
                    "local state did not catch up to read barrier".into(),
                ));
            }
        }
        self.store.snapshot()
    }
    fn submit(&self, command: CommitTransactionV1) -> Result<ApplyResult> {
        self.append(ReplicatedCommandV1::CommitTransaction(command))
    }
    fn submit_schema(&self, command: SchemaCommandV1) -> Result<ApplyResult> {
        self.append(ReplicatedCommandV1::SchemaChange(command))
    }
    fn wait_applied(&self, log_id: LogId) -> Result<()> {
        let snapshot = self.read_barrier()?;
        if snapshot.last_applied().index >= log_id.index {
            Ok(())
        } else {
            Err(ChorusError::Consensus("replica lagging".into()))
        }
    }
    fn status(&self) -> ConsensusStatus {
        let state = self.store.status();
        let observed = self.observe().ok();
        ConsensusStatus {
            node_id: self.node_id,
            leader_id: observed.as_ref().map(|(_, _, _, leader, _)| *leader),
            term: *self.term.lock().unwrap(),
            commit_index: state.last_applied.index,
            applied_index: state.last_applied.index,
            quorum: observed.is_some(),
            voters: observed
                .as_ref()
                .map(|(voters, _, _, _, _)| voters.clone())
                .unwrap_or_else(|| self.voters.clone()),
            learners: observed
                .as_ref()
                .map(|(_, learners, _, _, _)| learners.clone())
                .unwrap_or_else(|| self.learners.clone()),
        }
    }
    fn bootstrap(&self) -> Result<()> {
        let (voters, learners) = self.membership()?;
        if self.node_id
            != *voters
                .first()
                .ok_or_else(|| ChorusError::Consensus("bootstrap voter set is empty".into()))?
        {
            return Err(ChorusError::Consensus(
                "only the lowest initial voter may bootstrap".into(),
            ));
        }
        let snapshot = self.store.snapshot()?;
        if snapshot.last_applied() != LogId::ZERO
            || snapshot.db_epoch() != 0
            || !snapshot.kv().is_empty()
            || !snapshot.origins().is_empty()
            || !snapshot.catalog().tables.is_empty()
        {
            return Err(ChorusError::Protocol(
                "cannot bootstrap a non-empty durable state".into(),
            ));
        }
        let result = self.append(ReplicatedCommandV1::Membership { voters, learners })?;
        if !matches!(result, ApplyResult::Noop) {
            return Err(ChorusError::Protocol(
                "membership bootstrap returned an unexpected result".into(),
            ));
        }
        Ok(())
    }
    fn change_membership(&self, mut voters: Vec<u64>, mut learners: Vec<u64>) -> Result<()> {
        voters.sort_unstable();
        voters.dedup();
        learners.sort_unstable();
        learners.dedup();
        if voters.is_empty()
            || voters.contains(&0)
            || learners.contains(&0)
            || voters.iter().any(|id| learners.binary_search(id).is_ok())
        {
            return Err(ChorusError::Protocol("invalid membership change".into()));
        }
        let result = self.append(ReplicatedCommandV1::Membership { voters, learners })?;
        if matches!(result, ApplyResult::Noop) {
            Ok(())
        } else {
            Err(ChorusError::Consensus(
                "membership change was not applied".into(),
            ))
        }
    }
    fn store(&self) -> Arc<dyn StateStore> {
        self.store.clone()
    }
}

fn write_frame<T: Serialize>(stream: &mut TcpStream, value: &T) -> Result<()> {
    const MAX_PEER_FRAME: usize = 8 * 1024 * 1024;
    let bytes = serde_json::to_vec(value).map_err(|e| ChorusError::Serialization(e.to_string()))?;
    if bytes.len() > MAX_PEER_FRAME {
        return Err(ChorusError::Limit("peer message exceeds 8 MiB".into()));
    }
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| stream.write_all(&bytes))
        .map_err(|e| ChorusError::Consensus(e.to_string()))
}

fn read_frame<T: for<'de> Deserialize<'de>>(stream: &mut TcpStream) -> Result<T> {
    const MAX_PEER_FRAME: usize = 8 * 1024 * 1024;
    let mut length = [0; 4];
    stream
        .read_exact(&mut length)
        .map_err(|e| ChorusError::Consensus(e.to_string()))?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_PEER_FRAME {
        return Err(ChorusError::Protocol("peer message exceeds 8 MiB".into()));
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .map_err(|e| ChorusError::Consensus(e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| ChorusError::Serialization(e.to_string()))
}

struct Replica {
    id: u64,
    store: Arc<dyn StateStore>,
    healthy: bool,
    learner: bool,
}
pub struct InMemoryCluster {
    replicas: Mutex<Vec<Replica>>,
    term: Mutex<u64>,
    next_index: Mutex<u64>,
}
impl InMemoryCluster {
    pub fn new(replicas: Vec<(u64, Arc<dyn StateStore>)>) -> Arc<Self> {
        let max = replicas
            .iter()
            .filter_map(|(_, s)| s.snapshot().ok().map(|x| x.last_applied().index))
            .max()
            .unwrap_or(0);
        Arc::new(Self {
            replicas: Mutex::new(
                replicas
                    .into_iter()
                    .map(|(id, store)| Replica {
                        id,
                        store,
                        healthy: true,
                        learner: false,
                    })
                    .collect(),
            ),
            term: Mutex::new(1),
            next_index: Mutex::new(max),
        })
    }
    pub fn set_healthy(&self, node_id: u64, healthy: bool) {
        if let Some(r) = self
            .replicas
            .lock()
            .unwrap()
            .iter_mut()
            .find(|r| r.id == node_id)
        {
            r.healthy = healthy;
        }
    }
    pub fn promote(&self, node_id: u64) {
        if let Some(r) = self
            .replicas
            .lock()
            .unwrap()
            .iter_mut()
            .find(|r| r.id == node_id)
        {
            r.learner = false;
        }
    }
    pub fn leader(&self) -> Option<u64> {
        if !self.quorum() {
            return None;
        }
        self.replicas
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.healthy && !r.learner)
            .map(|r| r.id)
            .min()
    }
    pub fn adapter(self: &Arc<Self>, node_id: u64) -> ClusterConsensus {
        ClusterConsensus {
            cluster: self.clone(),
            node_id,
        }
    }
    fn quorum(&self) -> bool {
        let r = self.replicas.lock().unwrap();
        let voters = r.iter().filter(|x| !x.learner).count();
        r.iter().filter(|x| x.healthy && !x.learner).count() > voters / 2
    }
    fn append(&self, command: ReplicatedCommandV1) -> Result<ApplyResult> {
        if !self.quorum() {
            return Err(ChorusError::Consensus("no majority is reachable".into()));
        }
        let mut i = self.next_index.lock().unwrap();
        let previous_index = *i;
        *i = i.saturating_add(1);
        let log = LogId {
            term: *self.term.lock().unwrap(),
            index: *i,
        };
        let mut replicas = self.replicas.lock().unwrap();
        let mut before = Vec::new();
        for replica in replicas.iter().filter(|replica| replica.healthy) {
            before.push((replica.id, snapshot_from_store(replica.store.as_ref())?));
        }
        let mut result = None;
        for r in replicas.iter().filter(|r| r.healthy) {
            let x = match r.store.apply(log, &command) {
                Ok(result) => result,
                Err(error) => {
                    // A state-machine apply is atomic, but earlier healthy
                    // replicas may already have applied this entry.  Roll
                    // every participant back to its exact pre-entry logical
                    // snapshot before exposing the error to the proposer.
                    for (id, snapshot) in &before {
                        if let Some(previous) = replicas.iter().find(|r| r.id == *id) {
                            let _ = previous.store.rollback(snapshot);
                        }
                    }
                    *i = previous_index;
                    return Err(error);
                }
            };
            if result.is_none() {
                result = Some(x);
            }
        }
        Ok(result.unwrap_or(ApplyResult::Noop))
    }
}

pub struct ClusterConsensus {
    cluster: Arc<InMemoryCluster>,
    node_id: u64,
}
impl Consensus for ClusterConsensus {
    fn activate_origin(&self, origin: chorus_common::OriginId) -> Result<()> {
        self.local_store_if_healthy()?;
        let _ = self.cluster.append(ReplicatedCommandV1::ActivateOrigin(
            chorus_codec::ActivateOriginV1 { origin },
        ))?;
        Ok(())
    }
    fn read_barrier(&self) -> Result<StateSnapshot> {
        if !self.cluster.quorum() {
            return Err(ChorusError::Consensus("no quorum".into()));
        }
        let (local_store, leader_store) = {
            let r = self.cluster.replicas.lock().unwrap();
            let local = r
                .iter()
                .find(|x| x.id == self.node_id && x.healthy)
                .ok_or_else(|| ChorusError::Consensus("node unavailable".into()))?;
            let leader_id = r
                .iter()
                .filter(|x| x.healthy && !x.learner)
                .map(|x| x.id)
                .min()
                .ok_or_else(|| ChorusError::Consensus("no leader is reachable".into()))?;
            let leader = r
                .iter()
                .find(|x| x.id == leader_id)
                .ok_or_else(|| ChorusError::Consensus("leader is unavailable".into()))?;
            (local.store.clone(), leader.store.clone())
        };
        let local_snapshot = local_store.snapshot()?;
        let leader_snapshot = leader_store.snapshot()?;
        if local_snapshot.last_applied() < leader_snapshot.last_applied() {
            local_store.install(&snapshot_from_store(leader_store.as_ref())?)?;
        }
        let snapshot = local_store.snapshot()?;
        if snapshot.last_applied() < leader_snapshot.last_applied() {
            return Err(ChorusError::Consensus("replica lagging".into()));
        }
        Ok(snapshot)
    }
    fn submit(&self, c: CommitTransactionV1) -> Result<ApplyResult> {
        self.local_store_if_healthy()?;
        self.cluster
            .append(ReplicatedCommandV1::CommitTransaction(c))
    }
    fn submit_schema(&self, c: SchemaCommandV1) -> Result<ApplyResult> {
        self.local_store_if_healthy()?;
        self.cluster.append(ReplicatedCommandV1::SchemaChange(c))
    }
    fn wait_applied(&self, log_id: LogId) -> Result<()> {
        let s = self.read_barrier()?;
        if s.last_applied().index >= log_id.index {
            Ok(())
        } else {
            Err(ChorusError::Consensus("replica lagging".into()))
        }
    }
    fn status(&self) -> ConsensusStatus {
        let s = self
            .cluster
            .replicas
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == self.node_id)
            .map(|r| r.store.status());
        let st = s.unwrap_or(StoreStatus {
            db_epoch: 0,
            catalog_epoch: 0,
            last_applied: LogId::ZERO,
            state_hash: [0; 32],
            healthy: false,
        });
        let leader = self.cluster.leader();
        let voters = self
            .cluster
            .replicas
            .lock()
            .unwrap()
            .iter()
            .filter(|r| !r.learner)
            .map(|r| r.id)
            .collect();
        let learners = self
            .cluster
            .replicas
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.learner)
            .map(|r| r.id)
            .collect();
        ConsensusStatus {
            node_id: self.node_id,
            leader_id: leader,
            term: *self.cluster.term.lock().unwrap(),
            commit_index: *self.cluster.next_index.lock().unwrap(),
            applied_index: st.last_applied.index,
            quorum: self.cluster.quorum(),
            voters,
            learners,
        }
    }
    fn store(&self) -> Arc<dyn StateStore> {
        self.cluster
            .replicas
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == self.node_id)
            .map(|r| r.store.clone())
            .expect("cluster node exists")
    }
}

impl ClusterConsensus {
    fn local_store_if_healthy(&self) -> Result<Arc<dyn StateStore>> {
        self.cluster
            .replicas
            .lock()
            .map_err(|_| ChorusError::Consensus("replica lock poisoned".into()))?
            .iter()
            .find(|replica| replica.id == self.node_id && replica.healthy)
            .map(|replica| replica.store.clone())
            .ok_or_else(|| ChorusError::Consensus("node unavailable".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chorus_codec::{KvMutationV1, canonical_mutations, payload_hash};
    use chorus_common::{OriginId, RequestId};
    use chorus_storage::MemoryStateStore;

    #[test]
    fn three_node_quorum_rejects_minority_and_replicates() {
        let stores: Vec<_> = (0..3)
            .map(|_| Arc::new(MemoryStateStore::new()) as Arc<dyn StateStore>)
            .collect();
        let cluster = InMemoryCluster::new(vec![
            (1, stores[0].clone()),
            (2, stores[1].clone()),
            (3, stores[2].clone()),
        ]);
        let origin = OriginId::new(2);
        let adapter = cluster.adapter(2);
        Consensus::activate_origin(&adapter, origin).unwrap();
        let id = RequestId::new(origin, 1);
        let mutation = KvMutationV1::Put {
            key: b"k".to_vec(),
            value: b"v".to_vec(),
        };
        let canonical = canonical_mutations(std::slice::from_ref(&mutation)).unwrap();
        let command = CommitTransactionV1 {
            request_id: id,
            payload_hash: payload_hash(1, &id, 0, &canonical),
            base_epoch: 0,
            mutations: vec![mutation],
        };
        assert!(matches!(
            adapter.submit(command),
            Ok(ApplyResult::Committed { epoch: 1, .. })
        ));
        assert_eq!(stores[0].snapshot().unwrap().get(b"k"), Some(&b"v"[..]));
        assert_eq!(stores[1].snapshot().unwrap().get(b"k"), Some(&b"v"[..]));
        assert_eq!(stores[2].snapshot().unwrap().get(b"k"), Some(&b"v"[..]));
        cluster.set_healthy(1, false);
        cluster.set_healthy(3, false);
        assert!(adapter.read_barrier().is_err());
        assert_eq!(cluster.leader(), None);
        cluster.set_healthy(3, true);
        assert_eq!(cluster.leader(), Some(2));
        assert!(adapter.read_barrier().is_ok());
    }

    #[test]
    fn static_network_transport_replicates_a_command() {
        let ports = [19_501u16, 19_502, 19_503];
        let endpoints: BTreeMap<_, _> = (1..=3)
            .zip(ports)
            .map(|(id, port)| (id, format!("127.0.0.1:{port}")))
            .collect();
        let mut nodes = Vec::new();
        for id in 1..=3 {
            let store = Arc::new(MemoryStateStore::new()) as Arc<dyn StateStore>;
            let node = NetworkConsensus::new(
                id,
                vec![1, 2, 3],
                Vec::new(),
                endpoints.clone(),
                store.clone(),
            );
            match node.start() {
                Ok(()) => {}
                // Some hermetic test runners disallow loopback listeners. The
                // transport remains covered by integration deployments; keep
                // the unit suite portable when the OS rejects bind(2).
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
                Err(error) => panic!("failed to start peer: {error}"),
            }
            nodes.push((node, store));
        }
        thread::sleep(Duration::from_millis(50));
        let origin = OriginId::new(1);
        nodes[0].0.activate_origin(origin).unwrap();
        let id = RequestId::new(origin, 1);
        let mutation = KvMutationV1::Put {
            key: b"network-key".to_vec(),
            value: b"network-value".to_vec(),
        };
        let canonical = canonical_mutations(std::slice::from_ref(&mutation)).unwrap();
        let command = CommitTransactionV1 {
            request_id: id,
            payload_hash: payload_hash(1, &id, 0, &canonical),
            base_epoch: 0,
            mutations: vec![mutation],
        };
        assert!(matches!(
            nodes[2].0.submit(command),
            Ok(ApplyResult::Committed { .. })
        ));
        for (_, store) in &nodes {
            assert_eq!(
                store.snapshot().unwrap().get(b"network-key"),
                Some(&b"network-value"[..])
            );
        }
    }
}
