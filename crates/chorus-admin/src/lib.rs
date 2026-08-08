#![forbid(unsafe_code)]

//! Configuration, status and operational helpers shared by the binary and
//! tests.  Correctness-affecting values are validated before a node opens its
//! listeners.

use chorus_common::{ClusterId, Limits};
use chorus_consensus::ConsensusStatus;
use chorus_storage::{FileStateStore, StateStore, StoreStatus};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub cluster_id: String,
    pub cluster_incarnation: u64,
    pub node_id: u64,
    pub data_dir: PathBuf,
    #[serde(default)]
    pub postgres: PostgresConfig,
    #[serde(default)]
    pub raft: RaftConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub initial_nodes: Vec<InitialNode>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostgresConfig {
    pub unix_socket_dir: Option<PathBuf>,
    pub listen: Option<String>,
    pub remote_listen: Option<String>,
    pub max_connections: usize,
}
impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            unix_socket_dir: Some("/run/chorus".into()),
            listen: Some("127.0.0.1:5432".into()),
            remote_listen: None,
            max_connections: 32,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RaftConfig {
    pub listen: String,
    pub heartbeat_ms: u64,
    pub election_timeout_min_ms: u64,
    pub election_timeout_max_ms: u64,
    pub snapshot_entries: u64,
    pub snapshot_log_bytes: u64,
}
impl Default for RaftConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:7001".into(),
            heartbeat_ms: 250,
            election_timeout_min_ms: 1200,
            election_timeout_max_ms: 2400,
            snapshot_entries: 50_000,
            snapshot_log_bytes: 128 * 1024 * 1024,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageConfig {
    pub state_cache_bytes: usize,
    pub raft_cache_bytes: usize,
    pub state_apply_durability: String,
    pub checkpoint_interval_ms: u64,
    pub checkpoint_commits: u64,
}
impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            state_cache_bytes: 32 * 1024 * 1024,
            raft_cache_bytes: 8 * 1024 * 1024,
            state_apply_durability: "immediate".into(),
            checkpoint_interval_ms: 250,
            checkpoint_commits: 128,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitialNode {
    pub node_id: u64,
    pub endpoint: String,
    pub voter: bool,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("I/O: {0}")]
    Io(String),
    #[error("configuration: {0}")]
    Parse(String),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}
impl Config {
    pub fn defaults(data_dir: impl Into<PathBuf>, node_id: u64) -> Self {
        Self {
            cluster_id: "chorus-local".into(),
            cluster_incarnation: 1,
            node_id,
            data_dir: data_dir.into(),
            postgres: PostgresConfig::default(),
            raft: RaftConfig::default(),
            storage: StorageConfig::default(),
            limits: Limits::default(),
            initial_nodes: vec![InitialNode {
                node_id,
                endpoint: "127.0.0.1:7001".into(),
                voter: true,
            }],
        }
    }
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
        let c: Self = toml::from_str(&text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        c.validate()?;
        Ok(c)
    }
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), ConfigError> {
        self.validate()?;
        let text = toml::to_string_pretty(self).map_err(|e| ConfigError::Parse(e.to_string()))?;
        fs::write(path, text).map_err(|e| ConfigError::Io(e.to_string()))
    }
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.cluster_id.trim().is_empty() {
            return Err(ConfigError::Invalid("cluster_id is empty".into()));
        }
        if self.cluster_incarnation == 0 {
            return Err(ConfigError::Invalid(
                "cluster_incarnation must be nonzero".into(),
            ));
        }
        if self.node_id == 0 {
            return Err(ConfigError::Invalid("node_id must be nonzero".into()));
        }
        if self.raft.heartbeat_ms == 0
            || self.raft.election_timeout_min_ms <= self.raft.heartbeat_ms
            || self.raft.election_timeout_min_ms >= self.raft.election_timeout_max_ms
        {
            return Err(ConfigError::Invalid(
                "raft timing values are invalid".into(),
            ));
        }
        if self.limits.query_workers == 0
            || self.limits.max_active_queries == 0
            || self.limits.max_connections == 0
        {
            return Err(ConfigError::Invalid(
                "resource limits must be positive".into(),
            ));
        }
        if self.storage.state_apply_durability != "immediate"
            && self.storage.state_apply_durability != "raft-backed"
        {
            return Err(ConfigError::Invalid(
                "state_apply_durability must be immediate or raft-backed".into(),
            ));
        }
        Ok(())
    }
    pub fn cluster_id(&self) -> ClusterId {
        ClusterId::from_name(&self.cluster_id)
    }
    pub fn state_path(&self) -> PathBuf {
        self.data_dir.join("state").join("active.json")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeStatus {
    pub config_node_id: u64,
    pub cluster_id: String,
    pub cluster_incarnation: u64,
    pub storage: StoreStatus,
    pub consensus: Option<ConsensusStatus>,
    pub strict_ready: bool,
}
pub fn status(
    config: &Config,
    store: &dyn StateStore,
    consensus: Option<&dyn chorus_consensus::Consensus>,
) -> NodeStatus {
    let s = store.status();
    let c = consensus.map(|x| x.status());
    let ready = s.healthy && c.as_ref().map(|x| x.quorum).unwrap_or(true);
    NodeStatus {
        config_node_id: config.node_id,
        cluster_id: config.cluster_id.clone(),
        cluster_incarnation: config.cluster_incarnation,
        storage: s,
        strict_ready: ready,
        consensus: c,
    }
}
pub fn open_store(config: &Config) -> Result<FileStateStore, ConfigError> {
    let store =
        FileStateStore::open(config.state_path()).map_err(|e| ConfigError::Io(e.to_string()))?;
    store
        .initialize_cluster(config.cluster_id().0, config.cluster_incarnation)
        .map_err(|e| ConfigError::Io(e.to_string()))?;
    Ok(store)
}
pub fn render_status(status: &NodeStatus) -> String {
    serde_json::to_string_pretty(status).unwrap_or_else(|_| "{}".into())
}
