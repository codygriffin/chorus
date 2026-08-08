#![forbid(unsafe_code)]

//! Configuration, status and operational helpers shared by the binary and
//! tests.  Correctness-affecting values are validated before a node opens its
//! listeners.

use chorus_codec::LogicalSnapshot;
use chorus_common::{ClusterId, Limits};
use chorus_consensus::ConsensusStatus;
use chorus_storage::{FileStateStore, StateStore, StoreStatus};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use thiserror::Error;

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_CLUSTER_ID_BYTES: usize = 128;
const MAX_REPLICAS: usize = 16;
const MAX_VOTERS: usize = 5;
const MAX_CONNECTIONS: usize = 1024;
const MAX_QUERY_WORKERS: usize = 64;
const MAX_ROW_BYTES: usize = 1024 * 1024;
const MAX_TRANSACTION_BYTES: usize = 64 * 1024 * 1024;
const MAX_SQL_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_RETURNING_BYTES: usize = 64 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES: u64 = 10 * 1024 * 1024 * 1024;

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
    pub tls: TlsConfig,
    /// Development-only escape hatch for the current plaintext peer adapter.
    /// It is intentionally false by default and must never be used for a
    /// production deployment.
    #[serde(default)]
    pub allow_insecure_dev: bool,
    #[serde(default)]
    pub initial_nodes: Vec<InitialNode>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct PostgresConfig {
    pub unix_socket_dir: Option<PathBuf>,
    pub listen: Option<String>,
    pub remote_listen: Option<String>,
    pub auth_file: Option<PathBuf>,
    pub max_connections: usize,
}
impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            unix_socket_dir: Some("/run/chorus".into()),
            listen: Some("127.0.0.1:5432".into()),
            remote_listen: None,
            auth_file: None,
            max_connections: 32,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct RaftConfig {
    pub listen: String,
    pub heartbeat_ms: u64,
    pub election_timeout_min_ms: u64,
    pub election_timeout_max_ms: u64,
    pub snapshot_entries: u64,
    pub snapshot_log_bytes: u64,
    pub max_message_bytes: usize,
    pub rpc_queue_capacity: usize,
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
            max_message_bytes: 8 * 1024 * 1024,
            rpc_queue_capacity: 128,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub state_cache_bytes: usize,
    pub raft_cache_bytes: usize,
    pub state_apply_durability: String,
    pub checkpoint_interval_ms: u64,
    pub checkpoint_commits: u64,
    pub snapshot_chunk_bytes: usize,
    pub snapshot_bandwidth_bytes_per_sec: usize,
    pub data_dir_budget_bytes: u64,
    pub low_space_watermark_bytes: u64,
    pub low_space_watermark_percent: u8,
}
impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            state_cache_bytes: 32 * 1024 * 1024,
            raft_cache_bytes: 8 * 1024 * 1024,
            state_apply_durability: "immediate".into(),
            checkpoint_interval_ms: 250,
            checkpoint_commits: 128,
            snapshot_chunk_bytes: 1024 * 1024,
            snapshot_bandwidth_bytes_per_sec: 20 * 1024 * 1024,
            data_dir_budget_bytes: 4 * 1024 * 1024 * 1024,
            low_space_watermark_bytes: 512 * 1024 * 1024,
            low_space_watermark_percent: 10,
        }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    pub ca: Option<PathBuf>,
    pub certificate: Option<PathBuf>,
    pub private_key: Option<PathBuf>,
}

impl TlsConfig {
    pub fn configured(&self) -> bool {
        self.ca.is_some() || self.certificate.is_some() || self.private_key.is_some()
    }

    pub fn complete(&self) -> bool {
        self.ca.is_some() && self.certificate.is_some() && self.private_key.is_some()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
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
            tls: TlsConfig::default(),
            allow_insecure_dev: false,
            initial_nodes: vec![InitialNode {
                node_id,
                endpoint: "127.0.0.1:7001".into(),
                voter: true,
            }],
        }
    }
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let metadata = fs::metadata(path).map_err(|e| ConfigError::Io(e.to_string()))?;
        if metadata.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::Invalid(format!(
                "configuration exceeds {} bytes",
                MAX_CONFIG_BYTES
            )));
        }
        let text = fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
        // `Limits` predates the config loader and does not carry serde field
        // defaults. Merge only nested option tables so a config containing,
        // for example, just `[limits].query_workers` remains compatible with
        // the documented TOML while required top-level identity fields still
        // have to be present.
        let mut value: toml::Value =
            toml::from_str(&text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        let defaults = toml::Value::try_from(Self::defaults(".", 1))
            .map_err(|e| ConfigError::Parse(e.to_string()))?;
        for section in ["postgres", "raft", "storage", "limits", "tls"] {
            merge_toml_table(&mut value, &defaults, section);
        }
        let c: Self = value
            .try_into()
            .map_err(|e: toml::de::Error| ConfigError::Parse(e.to_string()))?;
        c.validate()?;
        Ok(c)
    }
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), ConfigError> {
        self.validate()?;
        let text = toml::to_string_pretty(self).map_err(|e| ConfigError::Parse(e.to_string()))?;
        let path = path.as_ref();
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|e| ConfigError::Io(e.to_string()))?;
        }
        let tmp = path.with_extension("tmp");
        let mut file = fs::File::create(&tmp).map_err(|e| ConfigError::Io(e.to_string()))?;
        file.write_all(text.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|e| ConfigError::Io(e.to_string()))?;
        harden_file_permissions(&tmp, false)?;
        fs::rename(&tmp, path).map_err(|e| ConfigError::Io(e.to_string()))?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.cluster_id.trim().is_empty() {
            return Err(ConfigError::Invalid("cluster_id is empty".into()));
        }
        if self.cluster_id.len() > MAX_CLUSTER_ID_BYTES {
            return Err(ConfigError::Invalid(format!(
                "cluster_id exceeds {MAX_CLUSTER_ID_BYTES} bytes"
            )));
        }
        if self.cluster_incarnation == 0 {
            return Err(ConfigError::Invalid(
                "cluster_incarnation must be nonzero".into(),
            ));
        }
        if self.node_id == 0 {
            return Err(ConfigError::Invalid("node_id must be nonzero".into()));
        }
        if self.data_dir.as_os_str().is_empty() {
            return Err(ConfigError::Invalid("data_dir is empty".into()));
        }

        let mut ids = std::collections::BTreeSet::new();
        let mut endpoints = std::collections::BTreeSet::new();
        let mut voters = 0usize;
        if self.initial_nodes.is_empty() {
            return Err(ConfigError::Invalid(
                "initial_nodes must contain at least the local node".into(),
            ));
        }
        if self.initial_nodes.len() > MAX_REPLICAS {
            return Err(ConfigError::Invalid(format!(
                "initial_nodes exceeds the {MAX_REPLICAS}-replica limit"
            )));
        }
        for node in &self.initial_nodes {
            if node.node_id == 0 {
                return Err(ConfigError::Invalid(
                    "initial_nodes contains node_id 0".into(),
                ));
            }
            if !ids.insert(node.node_id) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate initial node id {}",
                    node.node_id
                )));
            }
            let endpoint: SocketAddr = node.endpoint.parse().map_err(|_| {
                ConfigError::Invalid(format!(
                    "initial node {} endpoint is not a socket address",
                    node.node_id
                ))
            })?;
            if !endpoints.insert(endpoint) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate initial node endpoint {}",
                    node.endpoint
                )));
            }
            if node.voter {
                voters += 1;
            }
        }
        if !ids.contains(&self.node_id) {
            return Err(ConfigError::Invalid(
                "node_id must be present in initial_nodes".into(),
            ));
        }
        if voters == 0 || voters > MAX_VOTERS || (voters > 1 && voters % 2 == 0) {
            return Err(ConfigError::Invalid(
                "voting membership must have 1, 3, or 5 voters".into(),
            ));
        }

        let raft_listen: SocketAddr = self
            .raft
            .listen
            .parse()
            .map_err(|_| ConfigError::Invalid("raft.listen is not a socket address".into()))?;
        if raft_listen.port() == 0 {
            return Err(ConfigError::Invalid(
                "raft.listen port must be nonzero".into(),
            ));
        }
        if self.postgres.max_connections == 0 || self.postgres.max_connections > MAX_CONNECTIONS {
            return Err(ConfigError::Invalid(format!(
                "postgres.max_connections must be between 1 and {MAX_CONNECTIONS}"
            )));
        }
        if self.postgres.max_connections != self.limits.max_connections {
            return Err(ConfigError::Invalid(
                "postgres.max_connections must equal limits.max_connections".into(),
            ));
        }
        if let Some(listen) = self.postgres.listen.as_deref().filter(|x| !x.is_empty()) {
            let address: SocketAddr = listen.parse().map_err(|_| {
                ConfigError::Invalid("postgres.listen is not a socket address".into())
            })?;
            if address.port() == 0 {
                return Err(ConfigError::Invalid(
                    "postgres.listen port must be nonzero".into(),
                ));
            }
            if !address.ip().is_loopback() {
                return Err(ConfigError::Invalid(
                    "remote PostgreSQL TCP requires TLS/authentication; non-loopback listen is unsupported".into(),
                ));
            }
        }
        if let Some(remote) = self
            .postgres
            .remote_listen
            .as_deref()
            .filter(|x| !x.is_empty())
        {
            let _: SocketAddr = remote.parse().map_err(|_| {
                ConfigError::Invalid("postgres.remote_listen is not a socket address".into())
            })?;
            return Err(ConfigError::Invalid(
                "postgres remote TCP is unsupported until TLS and authentication are implemented"
                    .into(),
            ));
        }
        if self.postgres.auth_file.is_some() {
            return Err(ConfigError::Invalid(
                "postgres authentication configuration is unsupported by the current trust-only gateway".into(),
            ));
        }
        if let Some(dir) = &self.postgres.unix_socket_dir {
            if dir.as_os_str().is_empty() {
                return Err(ConfigError::Invalid(
                    "postgres.unix_socket_dir is empty".into(),
                ));
            }
            // Linux sockaddr_un paths are limited to 108 bytes, and the
            // gateway appends .s.PGSQL.5432.
            if dir.as_os_str().len() > 90 {
                return Err(ConfigError::Invalid(
                    "postgres.unix_socket_dir is too long for a Unix socket".into(),
                ));
            }
        }
        if self.raft.heartbeat_ms == 0
            || self.raft.election_timeout_min_ms <= self.raft.heartbeat_ms
            || self.raft.election_timeout_min_ms >= self.raft.election_timeout_max_ms
        {
            return Err(ConfigError::Invalid(
                "raft timing values are invalid".into(),
            ));
        }
        if self.raft.snapshot_entries == 0
            || self.raft.snapshot_log_bytes == 0
            || self.raft.max_message_bytes == 0
            || self.raft.max_message_bytes > MAX_SQL_MESSAGE_BYTES
            || self.raft.rpc_queue_capacity == 0
            || self.raft.rpc_queue_capacity > 4096
        {
            return Err(ConfigError::Invalid(
                "raft snapshot/message/queue limits are invalid".into(),
            ));
        }
        let l = &self.limits;
        if l.query_workers == 0
            || l.query_workers > MAX_QUERY_WORKERS
            || l.max_active_queries == 0
            || l.max_active_queries > l.max_connections
            || l.max_connections == 0
            || l.max_connections > MAX_CONNECTIONS
            || l.max_transaction_age_ms == 0
            || l.idle_in_transaction_timeout_ms == 0
            || l.idle_in_transaction_timeout_ms > l.max_transaction_age_ms
            || l.max_transaction_bytes == 0
            || l.max_transaction_bytes > MAX_TRANSACTION_BYTES
            || l.max_mutations == 0
            || l.max_row_bytes == 0
            || l.max_row_bytes > MAX_ROW_BYTES
            || l.max_sql_message_bytes == 0
            || l.max_sql_message_bytes > MAX_SQL_MESSAGE_BYTES
            || l.max_returning_bytes == 0
            || l.max_returning_bytes > MAX_RETURNING_BYTES
            || l.max_key_bytes == 0
            || l.max_indexed_value_bytes == 0
            || l.query_work_mem_bytes == 0
            || l.global_work_mem_bytes == 0
            || l.query_work_mem_bytes > l.global_work_mem_bytes
        {
            return Err(ConfigError::Invalid(
                "resource limits must be positive".into(),
            ));
        }
        if self.storage.state_cache_bytes == 0
            || self.storage.raft_cache_bytes == 0
            || self.storage.checkpoint_interval_ms == 0
            || self.storage.checkpoint_commits == 0
            || self.storage.snapshot_chunk_bytes == 0
            || self.storage.snapshot_chunk_bytes > self.raft.max_message_bytes
            || self.storage.snapshot_bandwidth_bytes_per_sec == 0
            || self.storage.data_dir_budget_bytes == 0
            || self.storage.low_space_watermark_bytes >= self.storage.data_dir_budget_bytes
            || self.storage.low_space_watermark_percent == 0
            || self.storage.low_space_watermark_percent >= 100
        {
            return Err(ConfigError::Invalid(
                "storage cache/checkpoint/snapshot/disk limits are invalid".into(),
            ));
        }
        if self.storage.state_apply_durability != "immediate" {
            return Err(ConfigError::Invalid(
                "state_apply_durability=raft-backed is not supported until crash/replay gates pass; use immediate".into(),
            ));
        }
        if self.tls.configured() && !self.tls.complete() {
            return Err(ConfigError::Invalid(
                "tls.ca, tls.certificate, and tls.private_key must be configured together".into(),
            ));
        }
        if self.tls.complete() {
            validate_tls_file(self.tls.ca.as_deref(), "tls.ca", false)?;
            validate_tls_file(self.tls.certificate.as_deref(), "tls.certificate", false)?;
            validate_tls_file(self.tls.private_key.as_deref(), "tls.private_key", true)?;
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
    pub local_ready: bool,
    pub strict_ready: bool,
    pub role: String,
    pub replication_lag: u64,
    pub state_file_bytes: Option<u64>,
    pub data_dir_budget_bytes: u64,
    pub disk_write_admission: bool,
    pub identity_ok: bool,
    pub warnings: Vec<String>,
}
pub fn status(
    config: &Config,
    store: &dyn StateStore,
    consensus: Option<&dyn chorus_consensus::Consensus>,
) -> NodeStatus {
    let s = store.status();
    let c = consensus.map(|x| x.status());
    let snapshot = store.snapshot().ok();
    let identity_ok = snapshot.as_ref().is_some_and(|snapshot| {
        snapshot.cluster_id() == config.cluster_id().0
            && snapshot.to_data().cluster_incarnation == config.cluster_incarnation
    });
    let local_ready = s.healthy && identity_ok;
    // A local state file is not enough for strict readiness: it requires a
    // live consensus adapter to prove a leader/majority read barrier.
    let strict_ready = local_ready
        && c.as_ref().is_some_and(|x| {
            x.quorum && x.leader_id.is_some() && x.commit_index <= x.applied_index
        });
    let (role, replication_lag) = match c.as_ref() {
        Some(c) => {
            let role = if c.leader_id == Some(config.node_id) {
                "leader"
            } else if c.learners.contains(&config.node_id) {
                "learner"
            } else {
                "follower"
            };
            (
                role.to_string(),
                c.commit_index.saturating_sub(c.applied_index),
            )
        }
        None => ("unknown".into(), 0),
    };
    let state_file = config.state_path();
    let state_file_bytes = fs::metadata(&state_file).ok().map(|m| m.len());
    let disk_write_admission = state_file_bytes.is_none_or(|size| {
        let percentage = config
            .storage
            .data_dir_budget_bytes
            .saturating_mul(config.storage.low_space_watermark_percent as u64)
            / 100;
        size.saturating_add(config.storage.low_space_watermark_bytes.max(percentage))
            <= config.storage.data_dir_budget_bytes
    });
    let mut warnings = Vec::new();
    if !identity_ok {
        warnings.push("persisted state identity does not match configuration".into());
    }
    if c.is_none() {
        warnings.push("strict readiness is unknown: consensus barrier is unavailable".into());
    } else if !strict_ready {
        warnings.push("strict readiness is false: quorum/leader barrier is unavailable".into());
    }
    if !disk_write_admission {
        warnings.push("data-directory budget is below the write-admission watermark".into());
    }
    NodeStatus {
        config_node_id: config.node_id,
        cluster_id: config.cluster_id.clone(),
        cluster_incarnation: config.cluster_incarnation,
        storage: s,
        consensus: c,
        local_ready,
        strict_ready,
        role,
        replication_lag,
        state_file_bytes,
        data_dir_budget_bytes: config.storage.data_dir_budget_bytes,
        disk_write_admission,
        identity_ok,
        warnings,
    }
}
pub fn open_store(config: &Config) -> Result<FileStateStore, ConfigError> {
    config.validate()?;
    ensure_private_dir(&config.data_dir)?;
    let state_path = config.state_path();
    if fs::symlink_metadata(&state_path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(ConfigError::Invalid(
            "state path must not be a symbolic link".into(),
        ));
    }
    let store = FileStateStore::open(&state_path).map_err(|e| ConfigError::Io(e.to_string()))?;
    store
        .initialize_cluster(config.cluster_id().0, config.cluster_incarnation)
        .map_err(|e| ConfigError::Io(e.to_string()))?;
    let snapshot = store
        .snapshot()
        .map_err(|e| ConfigError::Io(e.to_string()))?;
    if snapshot.cluster_id() != config.cluster_id().0 {
        return Err(ConfigError::Invalid(
            "persisted cluster_id does not match configuration".into(),
        ));
    }
    if snapshot.to_data().cluster_incarnation != config.cluster_incarnation {
        return Err(ConfigError::Invalid(
            "persisted cluster_incarnation does not match configuration".into(),
        ));
    }
    harden_file_permissions(&state_path, false)?;
    Ok(store)
}
pub fn render_status(status: &NodeStatus) -> String {
    serde_json::to_string_pretty(status).unwrap_or_else(|_| "{}".into())
}

/// Build a cluster-independent logical backup. Unlike an OpenRaft recovery
/// snapshot, this excludes source identity, membership, and request-origin
/// deduplication state. Restore binds it to the target cluster.
pub fn logical_backup_from_store(store: &dyn StateStore) -> Result<LogicalSnapshot, ConfigError> {
    let snapshot = store
        .snapshot()
        .map_err(|e| ConfigError::Io(e.to_string()))?;
    let mut data = snapshot.to_data();
    data.cluster_id = [0; 16];
    // Logical backups intentionally omit the source identity, but the
    // versioned snapshot envelope still needs a nonzero sentinel incarnation
    // so it can be validated before restore rebinding.
    data.cluster_incarnation = 1;
    data.last_applied = chorus_common::LogId::ZERO;
    data.membership = chorus_storage::Membership::default();
    data.membership.log_id = chorus_common::LogId::ZERO;
    data.origins.clear();
    let mut meta = std::collections::BTreeMap::new();
    meta.insert("backup_kind".into(), b"chorus-logical-backup-v1".to_vec());
    meta.insert(
        "state".into(),
        serde_json::to_vec(&data).map_err(|e| ConfigError::Parse(e.to_string()))?,
    );
    Ok(LogicalSnapshot::new(
        [0; 16],
        1,
        chorus_common::LogId::ZERO,
        chorus_common::LogId::ZERO,
        Vec::new(),
        Vec::new(),
        snapshot.db_epoch(),
        snapshot.catalog_epoch(),
        meta,
        snapshot
            .kv()
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    ))
}

pub fn is_logical_backup(snapshot: &LogicalSnapshot) -> bool {
    snapshot
        .meta
        .get("backup_kind")
        .is_some_and(|kind| kind.as_slice() == b"chorus-logical-backup-v1")
}

pub fn snapshot_file_within_limit(path: impl AsRef<Path>) -> Result<(), ConfigError> {
    let size = fs::metadata(path)
        .map_err(|e| ConfigError::Io(e.to_string()))?
        .len();
    if size > MAX_SNAPSHOT_BYTES {
        return Err(ConfigError::Invalid(format!(
            "snapshot exceeds {} bytes",
            MAX_SNAPSHOT_BYTES
        )));
    }
    Ok(())
}

fn ensure_private_dir(path: &Path) -> Result<(), ConfigError> {
    if fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(ConfigError::Invalid(format!(
            "data directory {} must not be a symbolic link",
            path.display()
        )));
    }
    fs::create_dir_all(path).map_err(|e| ConfigError::Io(e.to_string()))?;
    harden_file_permissions(path, true)
}

fn validate_tls_file(path: Option<&Path>, name: &str, private: bool) -> Result<(), ConfigError> {
    let path = path.ok_or_else(|| ConfigError::Invalid(format!("{name} is missing")))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| ConfigError::Invalid(format!("{name} cannot be read: {e}")))?;
    if !metadata.is_file() {
        return Err(ConfigError::Invalid(format!(
            "{name} is not a regular file"
        )));
    }
    if metadata.len() == 0 {
        return Err(ConfigError::Invalid(format!("{name} is empty")));
    }
    if private {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(ConfigError::Invalid(format!(
                    "{name} must not be group/world-readable"
                )));
            }
        }
    }
    Ok(())
}

fn harden_file_permissions(path: &Path, directory: bool) -> Result<(), ConfigError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if directory { 0o700 } else { 0o600 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|e| ConfigError::Io(e.to_string()))?;
    }
    Ok(())
}

fn merge_toml_table(value: &mut toml::Value, defaults: &toml::Value, section: &str) {
    let Some(defaults) = defaults.get(section).and_then(toml::Value::as_table) else {
        return;
    };
    let Some(table) = value
        .as_table_mut()
        .and_then(|root| root.get_mut(section))
        .and_then(toml::Value::as_table_mut)
    else {
        return;
    };
    for (key, default) in defaults {
        table.entry(key.clone()).or_insert_with(|| default.clone());
    }
}
