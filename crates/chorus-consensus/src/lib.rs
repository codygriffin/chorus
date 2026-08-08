#![forbid(unsafe_code)]

//! Consensus boundary.  The release baseline keeps OpenRaft types out of SQL
//! and exposes a synchronous adapter that can be backed by OpenRaft or the
//! deterministic in-process cluster used by tests and local development.

use chorus_codec::{ApplyResult, CommitTransactionV1, ReplicatedCommandV1, SchemaCommandV1};
use chorus_common::{ChorusError, LogId, Result};
use chorus_storage::{StateSnapshot, StateStore, StoreStatus};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

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
