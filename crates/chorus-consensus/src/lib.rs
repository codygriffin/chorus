#![forbid(unsafe_code)]

//! Consensus boundary.  The release baseline keeps OpenRaft types out of SQL
//! and exposes a synchronous adapter that can be backed by OpenRaft or the
//! deterministic in-process cluster used by tests and local development.

use chorus_codec::{ApplyResult, CommitTransactionV1, ReplicatedCommandV1, SchemaCommandV1};
use chorus_common::{ChorusError, LogId, Result};
use chorus_storage::{StateSnapshot, StateStore, StoreStatus};
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
        if self.store.snapshot()?.last_applied() >= log_id {
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum PeerRequest {
    Ping,
    Propose {
        command: ReplicatedCommandV1,
    },
    Apply {
        log_id: LogId,
        command: ReplicatedCommandV1,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum PeerResponse {
    Pong,
    Applied(ApplyResult),
    Error(String),
}

impl NetworkConsensus {
    pub fn new(
        node_id: u64,
        voters: Vec<u64>,
        learners: Vec<u64>,
        endpoints: BTreeMap<u64, String>,
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

    fn leader_id(&self) -> Option<u64> {
        let mut reachable = self
            .voters
            .iter()
            .copied()
            .filter(|id| *id == self.node_id || self.ping(*id));
        reachable.next()
    }

    fn quorum(&self) -> bool {
        let voters = self.voters.len();
        let reachable = self
            .voters
            .iter()
            .filter(|id| **id == self.node_id || self.ping(**id))
            .count();
        reachable > voters / 2
    }

    fn ping(&self, node_id: u64) -> bool {
        let Some(endpoint) = self.endpoints.get(&node_id) else {
            return false;
        };
        if node_id == self.node_id {
            return true;
        }
        matches!(
            self.rpc(endpoint, &PeerRequest::Ping),
            Ok(PeerResponse::Pong)
        )
    }

    fn append(&self, command: ReplicatedCommandV1) -> Result<ApplyResult> {
        if !self.quorum() {
            return Err(ChorusError::Consensus("no majority is reachable".into()));
        }
        let leader = self
            .leader_id()
            .ok_or_else(|| ChorusError::Consensus("no leader is reachable".into()))?;
        if leader != self.node_id {
            let endpoint = self
                .endpoints
                .get(&leader)
                .ok_or_else(|| ChorusError::Consensus("leader endpoint is missing".into()))?;
            return match self.rpc(endpoint, &PeerRequest::Propose { command })? {
                PeerResponse::Applied(result) => Ok(result),
                PeerResponse::Error(message) => Err(ChorusError::Consensus(message)),
                _ => Err(ChorusError::Protocol("invalid proposal response".into())),
            };
        }
        let snapshot = self.store.snapshot()?;
        let log_id = LogId {
            term: *self.term.lock().unwrap(),
            index: snapshot.last_applied().index.saturating_add(1),
        };
        // Preflight the voter set so a transient connection loss does not
        // acknowledge an entry that never reached a majority.
        let voters_reachable = self
            .voters
            .iter()
            .filter(|id| **id == self.node_id || self.ping(**id))
            .count();
        if voters_reachable <= self.voters.len() / 2 {
            return Err(ChorusError::Consensus("quorum disappeared".into()));
        }
        let local_result = self.store.apply(log_id, &command)?;
        let mut applied_voters = 1usize;
        for node_id in self.voters.iter().chain(self.learners.iter()) {
            if *node_id == self.node_id {
                continue;
            }
            let Some(endpoint) = self.endpoints.get(node_id) else {
                continue;
            };
            if let Ok(PeerResponse::Applied(_)) = self.rpc(
                endpoint,
                &PeerRequest::Apply {
                    log_id,
                    command: command.clone(),
                },
            ) {
                if self.voters.contains(node_id) {
                    applied_voters += 1;
                }
            }
        }
        if applied_voters <= self.voters.len() / 2 {
            return Err(ChorusError::Consensus("replication quorum failed".into()));
        }
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
        let response = match request {
            PeerRequest::Ping => PeerResponse::Pong,
            PeerRequest::Propose { command } => match self.append(command) {
                Ok(result) => PeerResponse::Applied(result),
                Err(error) => PeerResponse::Error(error.to_string()),
            },
            PeerRequest::Apply { log_id, command } => match self.store.apply(log_id, &command) {
                Ok(result) => PeerResponse::Applied(result),
                Err(error) => PeerResponse::Error(error.to_string()),
            },
        };
        write_frame(&mut stream, &response)
    }
}

impl Consensus for NetworkConsensus {
    fn activate_origin(&self, origin: chorus_common::OriginId) -> Result<()> {
        self.append(ReplicatedCommandV1::ActivateOrigin(
            chorus_codec::ActivateOriginV1 { origin },
        ))
        .map(|_| ())
    }
    fn read_barrier(&self) -> Result<StateSnapshot> {
        if !self.quorum() {
            return Err(ChorusError::Consensus("no quorum".into()));
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
        if self.store.snapshot()?.last_applied() >= log_id {
            Ok(())
        } else {
            Err(ChorusError::Consensus("replica lagging".into()))
        }
    }
    fn status(&self) -> ConsensusStatus {
        let state = self.store.status();
        ConsensusStatus {
            node_id: self.node_id,
            leader_id: if self.quorum() {
                self.leader_id()
            } else {
                None
            },
            term: *self.term.lock().unwrap(),
            commit_index: state.last_applied.index,
            applied_index: state.last_applied.index,
            quorum: self.quorum(),
            voters: self.voters.clone(),
            learners: self.learners.clone(),
        }
    }
    fn store(&self) -> Arc<dyn StateStore> {
        self.store.clone()
    }
}

fn write_frame<T: Serialize>(stream: &mut TcpStream, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|e| ChorusError::Serialization(e.to_string()))?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(ChorusError::Limit("peer message exceeds 16 MiB".into()));
    }
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| stream.write_all(&bytes))
        .map_err(|e| ChorusError::Consensus(e.to_string()))
}

fn read_frame<T: for<'de> Deserialize<'de>>(stream: &mut TcpStream) -> Result<T> {
    let mut length = [0; 4];
    stream
        .read_exact(&mut length)
        .map_err(|e| ChorusError::Consensus(e.to_string()))?;
    let length = u32::from_be_bytes(length) as usize;
    if length > 16 * 1024 * 1024 {
        return Err(ChorusError::Protocol("peer message exceeds 16 MiB".into()));
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
        *i += 1;
        let log = LogId {
            term: *self.term.lock().unwrap(),
            index: *i,
        };
        let mut result = None;
        for r in self.replicas.lock().unwrap().iter().filter(|r| r.healthy) {
            let x = r.store.apply(log, &command)?;
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
        let _ = self.cluster.append(ReplicatedCommandV1::ActivateOrigin(
            chorus_codec::ActivateOriginV1 { origin },
        ))?;
        Ok(())
    }
    fn read_barrier(&self) -> Result<StateSnapshot> {
        if !self.cluster.quorum() {
            return Err(ChorusError::Consensus("no quorum".into()));
        }
        let r = self.cluster.replicas.lock().unwrap();
        let node = r
            .iter()
            .find(|x| x.id == self.node_id && x.healthy)
            .or_else(|| r.iter().find(|x| x.healthy))
            .ok_or_else(|| ChorusError::Consensus("node unavailable".into()))?;
        node.store.snapshot()
    }
    fn submit(&self, c: CommitTransactionV1) -> Result<ApplyResult> {
        self.cluster
            .append(ReplicatedCommandV1::CommitTransaction(c))
    }
    fn submit_schema(&self, c: SchemaCommandV1) -> Result<ApplyResult> {
        self.cluster.append(ReplicatedCommandV1::SchemaChange(c))
    }
    fn wait_applied(&self, log_id: LogId) -> Result<()> {
        let s = self.read_barrier()?;
        if s.last_applied() >= log_id {
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

#[cfg(test)]
mod tests {
    use super::*;
    use chorus_codec::{KvMutationV1, payload_hash};
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
        let mut canonical = Vec::new();
        canonical.extend_from_slice(mutation.key());
        canonical.push(1);
        canonical.extend_from_slice(b"v");
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
        let mut canonical = Vec::new();
        canonical.extend_from_slice(mutation.key());
        canonical.push(1);
        canonical.extend_from_slice(b"network-value");
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
