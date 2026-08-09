#![forbid(unsafe_code)]

//! Configuration, status and operational helpers shared by the binary and
//! tests.  Correctness-affecting values are validated before a node opens its
//! listeners.

use chorus_codec::LogicalSnapshot;
use chorus_common::{ClusterId, Limits};
use chorus_consensus::ConsensusStatus;
use chorus_storage::{FileStateStore, StateStore, StoreStatus};
use ring::digest::{SHA256, digest};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
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
const IDENTITY_FILE_NAME: &str = "identity.toml";
const IDENTITY_VERSION: u32 = 1;
const MAX_IDENTITY_BYTES: u64 = 4096;
const MAX_TLS_FILE_BYTES: u64 = 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_MANIFEST_CANONICAL_BYTES: usize = 64 * 1024;
const MAX_MANIFEST_KEY_BYTES: u64 = 64;
const MAX_MANIFEST_BINDING_BYTES: u64 = 4096;
const MANIFEST_FORMAT_VERSION: u16 = 1;
const MANIFEST_BINDING_VERSION: u16 = 1;
const MANIFEST_DOMAIN: &[u8] = b"chorus/openraft-bootstrap-manifest/v1\0";
const MANIFEST_BINDING_FILE_NAME: &str = "bootstrap-manifest.lock";
static NEXT_IDENTITY_TEMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

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
    /// Signature metadata for the shared authenticated OpenRaft bootstrap
    /// manifest. Node-local paths and `node_id` are deliberately excluded
    /// from the signed projection so every initial node uses the same
    /// signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_manifest: Option<BootstrapManifestSignature>,
    /// In-memory proof that `bootstrap_manifest` was verified against an
    /// external trust key and its immutable installation binding. This is
    /// deliberately never serialized: parsing a configuration must not be
    /// able to manufacture authorization to open durable state.
    #[serde(skip)]
    verified_bootstrap_manifest: Option<VerifiedOpenRaftManifest>,
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
    /// Legacy mode accepts a bare socket address. Authenticated OpenRaft
    /// requires an `https://IP:PORT` seed from the operator-provisioned
    /// manifest.
    pub endpoint: String,
    pub voter: bool,
    /// DNS SAN expected in this node's cluster-issued leaf certificate.
    pub tls_dns_name: Option<String>,
    /// Lower- or upper-case hexadecimal SHA-256 of the leaf DER certificate.
    pub tls_leaf_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapManifestSignature {
    pub format_version: u16,
    pub algorithm: String,
    pub generation: u64,
    /// Lower-case SHA-256 of the raw 32-byte Ed25519 public key.
    pub key_id: String,
    /// Lower-case SHA-256 of the canonical DER CA trust set.
    pub ca_sha256: String,
    /// Lower-case hexadecimal 64-byte Ed25519 signature. This field alone is
    /// excluded from the canonical signed bytes.
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedOpenRaftManifest {
    pub format_version: u16,
    pub generation: u64,
    pub signer_key_id: [u8; 32],
    pub manifest_digest: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestBinding {
    format_version: u16,
    cluster_id: String,
    cluster_incarnation: u64,
    generation: u64,
    signer_key_id: String,
    manifest_digest: String,
}

impl InitialNode {
    pub fn endpoint_socket_addr(&self) -> Result<SocketAddr, ConfigError> {
        parse_initial_endpoint(&self.endpoint).map(|(address, _)| address)
    }

    pub fn tls_leaf_fingerprint(&self) -> Result<[u8; 32], ConfigError> {
        let value = self.tls_leaf_sha256.as_deref().ok_or_else(|| {
            ConfigError::Invalid(format!(
                "initial node {} is missing tls_leaf_sha256",
                self.node_id
            ))
        })?;
        decode_sha256(value).map_err(|message| {
            ConfigError::Invalid(format!(
                "initial node {} tls_leaf_sha256 {message}",
                self.node_id
            ))
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportTlsMaterial {
    pub ca_pem: Vec<u8>,
    pub certificate_pem: Vec<u8>,
    pub private_key_pem: Vec<u8>,
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
                tls_dns_name: None,
                tls_leaf_sha256: None,
            }],
            bootstrap_manifest: None,
            verified_bootstrap_manifest: None,
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
        let config = parse_config_text(&text)?;
        ensure_ordinary_config_is_unbound(&config)?;
        Ok(config)
    }

    /// Load, verify, and immutably bind the authenticated OpenRaft bootstrap
    /// manifest before any durable database or listener is opened.
    pub fn load_openraft_signed(
        config_path: impl AsRef<Path>,
        trust_key_path: impl AsRef<Path>,
    ) -> Result<Self, ConfigError> {
        let bytes = read_bounded_nofollow(
            config_path.as_ref(),
            "signed configuration",
            MAX_MANIFEST_BYTES,
            true,
        )?;
        let text = std::str::from_utf8(&bytes).map_err(|error| {
            ConfigError::Parse(format!("signed configuration is not UTF-8: {error}"))
        })?;
        let mut config = parse_config_text(text)?;
        let verified = config.verify_openraft_manifest(trust_key_path)?;
        ensure_manifest_binding(&config, &verified)?;
        config.verified_bootstrap_manifest = Some(verified);
        Ok(config)
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
            let (endpoint, _) = parse_initial_endpoint(&node.endpoint)?;
            if !endpoints.insert(endpoint) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate initial node endpoint {}",
                    node.endpoint
                )));
            }
            if node.voter {
                voters += 1;
            }
            match (&node.tls_dns_name, &node.tls_leaf_sha256) {
                (None, None) => {}
                (Some(dns_name), Some(_)) => {
                    validate_dns_name(dns_name).map_err(|message| {
                        ConfigError::Invalid(format!(
                            "initial node {} tls_dns_name {message}",
                            node.node_id
                        ))
                    })?;
                    node.tls_leaf_fingerprint()?;
                }
                _ => {
                    return Err(ConfigError::Invalid(format!(
                        "initial node {} tls_dns_name and tls_leaf_sha256 must be configured together",
                        node.node_id
                    )));
                }
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
        if let Some(manifest) = &self.bootstrap_manifest {
            validate_manifest_signature_metadata(manifest)?;
        }
        Ok(())
    }
    pub fn cluster_id(&self) -> ClusterId {
        ClusterId::from_name(&self.cluster_id)
    }
    pub fn state_path(&self) -> PathBuf {
        self.data_dir.join("state").join("active.json")
    }
    pub fn identity_path(&self) -> PathBuf {
        self.data_dir.join(IDENTITY_FILE_NAME)
    }

    /// Validate the semantic peer-directory fields used by authenticated
    /// OpenRaft. Cryptographic verification is performed separately by
    /// [`Config::load_openraft_signed`].
    pub fn validate_openraft_mtls(&self) -> Result<(), ConfigError> {
        self.validate()?;
        if !self.tls.complete() {
            return Err(ConfigError::Invalid(
                "authenticated OpenRaft requires tls.ca, tls.certificate, and tls.private_key"
                    .into(),
            ));
        }
        let listen: SocketAddr = self
            .raft
            .listen
            .parse()
            .map_err(|_| ConfigError::Invalid("raft.listen is not a socket address".into()))?;
        let mut dns_names = std::collections::BTreeSet::new();
        let mut fingerprints = std::collections::BTreeSet::new();
        let mut local_endpoint = None;
        for node in &self.initial_nodes {
            let (endpoint, https) = parse_initial_endpoint(&node.endpoint)?;
            if !https {
                return Err(ConfigError::Invalid(format!(
                    "authenticated OpenRaft node {} endpoint must use https://",
                    node.node_id
                )));
            }
            let dns_name = node.tls_dns_name.as_deref().ok_or_else(|| {
                ConfigError::Invalid(format!(
                    "authenticated OpenRaft node {} is missing tls_dns_name",
                    node.node_id
                ))
            })?;
            validate_dns_name(dns_name).map_err(|message| {
                ConfigError::Invalid(format!(
                    "initial node {} tls_dns_name {message}",
                    node.node_id
                ))
            })?;
            let fingerprint = node.tls_leaf_fingerprint()?;
            if !dns_names.insert(dns_name.to_ascii_lowercase()) {
                return Err(ConfigError::Invalid(
                    "authenticated OpenRaft DNS names must be unique".into(),
                ));
            }
            if !fingerprints.insert(fingerprint) {
                return Err(ConfigError::Invalid(
                    "authenticated OpenRaft leaf fingerprints must be unique".into(),
                ));
            }
            if node.node_id == self.node_id {
                local_endpoint = Some(endpoint);
            }
        }
        let local_endpoint = local_endpoint.ok_or_else(|| {
            ConfigError::Invalid("local node is missing from the OpenRaft manifest".into())
        })?;
        if listen.port() != local_endpoint.port()
            || (!listen.ip().is_unspecified() && listen.ip() != local_endpoint.ip())
        {
            return Err(ConfigError::Invalid(
                "raft.listen does not match the local OpenRaft manifest endpoint".into(),
            ));
        }
        Ok(())
    }

    /// Return the exact domain-separated bytes covered by the bootstrap
    /// signature. The hexadecimal `signature` field itself is intentionally
    /// excluded; every other manifest-signature field is bound.
    pub fn openraft_manifest_signing_bytes(&self) -> Result<Vec<u8>, ConfigError> {
        self.validate_openraft_mtls()?;
        canonical_openraft_manifest(self)
    }

    pub fn verify_openraft_manifest(
        &self,
        trust_key_path: impl AsRef<Path>,
    ) -> Result<VerifiedOpenRaftManifest, ConfigError> {
        self.validate_openraft_mtls()?;
        let manifest = self.bootstrap_manifest.as_ref().ok_or_else(|| {
            ConfigError::Invalid(
                "authenticated OpenRaft requires bootstrap_manifest signature metadata".into(),
            )
        })?;
        let public_key = read_manifest_public_key(trust_key_path.as_ref())?;
        let key_id = sha256(&public_key);
        let configured_key_id = decode_lower_hex::<32>(&manifest.key_id, "manifest key_id")?;
        if key_id != configured_key_id {
            return Err(ConfigError::Invalid(
                "trusted manifest key does not match bootstrap_manifest.key_id".into(),
            ));
        }

        let ca_bytes = read_bounded_regular_file(
            self.tls.ca.as_deref().expect("validated CA path"),
            "tls.ca",
            false,
        )?;
        let actual_ca_digest = canonical_ca_trust_digest(&ca_bytes)?;
        let configured_ca_digest =
            decode_lower_hex::<32>(&manifest.ca_sha256, "manifest ca_sha256")?;
        if actual_ca_digest != configured_ca_digest {
            return Err(ConfigError::Invalid(
                "tls.ca trust set does not match the signed manifest digest".into(),
            ));
        }

        let signed = canonical_openraft_manifest(self)?;
        let signature = decode_lower_hex::<64>(&manifest.signature, "manifest signature")?;
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(&signed, &signature)
            .map_err(|_| ConfigError::Invalid("bootstrap manifest signature is invalid".into()))?;
        Ok(VerifiedOpenRaftManifest {
            format_version: manifest.format_version,
            generation: manifest.generation,
            signer_key_id: key_id,
            manifest_digest: sha256(&signed),
        })
    }

    pub fn openraft_bootstrap_node_id(&self) -> Result<u64, ConfigError> {
        self.initial_nodes
            .iter()
            .filter(|node| node.voter)
            .map(|node| node.node_id)
            .min()
            .ok_or_else(|| ConfigError::Invalid("OpenRaft voter set is empty".into()))
    }

    pub fn transport_tls_material(&self) -> Result<TransportTlsMaterial, ConfigError> {
        self.validate_openraft_mtls()?;
        Ok(TransportTlsMaterial {
            ca_pem: read_bounded_regular_file(
                self.tls.ca.as_deref().expect("validated CA path"),
                "tls.ca",
                false,
            )?,
            certificate_pem: read_bounded_regular_file(
                self.tls
                    .certificate
                    .as_deref()
                    .expect("validated certificate path"),
                "tls.certificate",
                false,
            )?,
            private_key_pem: read_bounded_regular_file(
                self.tls
                    .private_key
                    .as_deref()
                    .expect("validated private key path"),
                "tls.private_key",
                true,
            )?,
        })
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
    ensure_manifest_authorizes_state_access(config)?;
    ensure_private_dir(&config.data_dir)?;
    ensure_installation_identity(config)?;
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

/// Render the bounded health/replication view as Prometheus text exposition.
///
/// This intentionally exposes only values already present in `NodeStatus`.
/// Request latency histograms, query fingerprints and queue saturation need
/// instrumentation at their respective owners; emitting fabricated zeros here
/// would make the admin surface less trustworthy.
pub fn render_metrics(status: &NodeStatus) -> String {
    fn gauge(out: &mut String, name: &str, help: &str, value: impl std::fmt::Display) {
        use std::fmt::Write as _;
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} gauge");
        let _ = writeln!(out, "{name} {value}");
    }

    let mut out = String::new();
    gauge(
        &mut out,
        "chorus_storage_healthy",
        "Whether the local state store is healthy",
        u8::from(status.storage.healthy),
    );
    gauge(
        &mut out,
        "chorus_local_ready",
        "Whether local state is opened and identity-bound",
        u8::from(status.local_ready),
    );
    gauge(
        &mut out,
        "chorus_strict_ready",
        "Whether a quorum-confirmed strict read is available",
        u8::from(status.strict_ready),
    );
    gauge(
        &mut out,
        "chorus_storage_db_epoch",
        "Replicated logical database epoch",
        status.storage.db_epoch,
    );
    gauge(
        &mut out,
        "chorus_storage_catalog_epoch",
        "Replicated catalog epoch",
        status.storage.catalog_epoch,
    );
    gauge(
        &mut out,
        "chorus_replication_lag_entries",
        "Consensus commit index minus applied index",
        status.replication_lag,
    );
    gauge(
        &mut out,
        "chorus_disk_write_admission",
        "Whether local disk watermarks admit writes",
        u8::from(status.disk_write_admission),
    );
    gauge(
        &mut out,
        "chorus_data_dir_budget_bytes",
        "Configured data-directory budget in bytes",
        status.data_dir_budget_bytes,
    );
    if let Some(bytes) = status.state_file_bytes {
        gauge(
            &mut out,
            "chorus_state_file_bytes",
            "Observed state file size in bytes",
            bytes,
        );
    }

    use std::fmt::Write as _;
    let _ = writeln!(
        out,
        "# HELP chorus_node_info Static node identity and role\n# TYPE chorus_node_info gauge\nchorus_node_info{{node_id=\"{}\",role=\"{}\"}} 1",
        status.config_node_id, status.role
    );
    if let Some(consensus) = &status.consensus {
        gauge(
            &mut out,
            "chorus_consensus_quorum",
            "Whether a consensus quorum is currently available",
            u8::from(consensus.quorum),
        );
        gauge(
            &mut out,
            "chorus_consensus_term",
            "Current consensus term",
            consensus.term,
        );
        gauge(
            &mut out,
            "chorus_consensus_commit_index",
            "Current consensus commit index",
            consensus.commit_index,
        );
        gauge(
            &mut out,
            "chorus_consensus_applied_index",
            "Current state-machine applied index",
            consensus.applied_index,
        );
        gauge(
            &mut out,
            "chorus_consensus_voters",
            "Number of configured voters",
            consensus.voters.len(),
        );
        gauge(
            &mut out,
            "chorus_consensus_learners",
            "Number of configured learners",
            consensus.learners.len(),
        );
    }
    out
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
    // The logical snapshot entry stream is authoritative for KV bytes; do
    // not duplicate them in the metadata state envelope.
    data.kv.clear();
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

fn parse_config_text(text: &str) -> Result<Config, ConfigError> {
    // `Limits` predates the config loader and does not carry serde field
    // defaults. Merge only nested option tables so partial nested sections
    // remain compatible while required top-level identity fields stay
    // mandatory.
    let mut value: toml::Value =
        toml::from_str(text).map_err(|error| ConfigError::Parse(error.to_string()))?;
    let defaults = toml::Value::try_from(Config::defaults(".", 1))
        .map_err(|error| ConfigError::Parse(error.to_string()))?;
    for section in ["postgres", "raft", "storage", "limits", "tls"] {
        merge_toml_table(&mut value, &defaults, section);
    }
    let config: Config = value
        .try_into()
        .map_err(|error: toml::de::Error| ConfigError::Parse(error.to_string()))?;
    config.validate()?;
    Ok(config)
}

fn validate_manifest_signature_metadata(
    manifest: &BootstrapManifestSignature,
) -> Result<(), ConfigError> {
    if manifest.format_version != MANIFEST_FORMAT_VERSION {
        return Err(ConfigError::Invalid(format!(
            "bootstrap manifest format version {} is unsupported",
            manifest.format_version
        )));
    }
    if manifest.algorithm != "ed25519" {
        return Err(ConfigError::Invalid(
            "bootstrap manifest algorithm must be ed25519".into(),
        ));
    }
    if manifest.generation == 0 {
        return Err(ConfigError::Invalid(
            "bootstrap manifest generation must be nonzero".into(),
        ));
    }
    decode_lower_hex::<32>(&manifest.key_id, "manifest key_id")?;
    decode_lower_hex::<32>(&manifest.ca_sha256, "manifest ca_sha256")?;
    decode_lower_hex::<64>(&manifest.signature, "manifest signature")?;
    Ok(())
}

fn canonical_openraft_manifest(config: &Config) -> Result<Vec<u8>, ConfigError> {
    let manifest = config.bootstrap_manifest.as_ref().ok_or_else(|| {
        ConfigError::Invalid(
            "authenticated OpenRaft requires bootstrap_manifest signature metadata".into(),
        )
    })?;
    validate_manifest_signature_metadata(manifest)?;
    let key_id = decode_lower_hex::<32>(&manifest.key_id, "manifest key_id")?;
    let ca_digest = decode_lower_hex::<32>(&manifest.ca_sha256, "manifest ca_sha256")?;

    let mut encoded = Vec::with_capacity(2048);
    encoded.extend_from_slice(MANIFEST_DOMAIN);
    encoded.extend_from_slice(&manifest.format_version.to_be_bytes());
    put_manifest_bytes(&mut encoded, manifest.algorithm.as_bytes())?;
    encoded.extend_from_slice(&manifest.generation.to_be_bytes());
    encoded.extend_from_slice(&key_id);
    put_manifest_bytes(&mut encoded, config.cluster_id.as_bytes())?;
    encoded.extend_from_slice(&config.cluster_id().0);
    encoded.extend_from_slice(&config.cluster_incarnation.to_be_bytes());
    encoded.extend_from_slice(&ca_digest);

    let mut nodes: Vec<_> = config.initial_nodes.iter().collect();
    nodes.sort_by_key(|node| node.node_id);
    let count = u16::try_from(nodes.len())
        .map_err(|_| ConfigError::Invalid("bootstrap manifest has too many nodes".into()))?;
    encoded.extend_from_slice(&count.to_be_bytes());
    for node in nodes {
        encoded.extend_from_slice(&node.node_id.to_be_bytes());
        encoded.push(u8::from(node.voter));
        let (endpoint, https) = parse_initial_endpoint(&node.endpoint)?;
        if !https {
            return Err(ConfigError::Invalid(format!(
                "authenticated OpenRaft node {} endpoint must use https://",
                node.node_id
            )));
        }
        match endpoint {
            SocketAddr::V4(address) => {
                encoded.push(4);
                encoded.extend_from_slice(&address.ip().octets());
                encoded.extend_from_slice(&address.port().to_be_bytes());
            }
            SocketAddr::V6(address) => {
                encoded.push(6);
                encoded.extend_from_slice(&address.ip().octets());
                encoded.extend_from_slice(&address.port().to_be_bytes());
                encoded.extend_from_slice(&address.flowinfo().to_be_bytes());
                encoded.extend_from_slice(&address.scope_id().to_be_bytes());
            }
        }
        let dns_name = node.tls_dns_name.as_deref().ok_or_else(|| {
            ConfigError::Invalid(format!(
                "authenticated OpenRaft node {} is missing tls_dns_name",
                node.node_id
            ))
        })?;
        put_manifest_bytes(&mut encoded, dns_name.to_ascii_lowercase().as_bytes())?;
        encoded.extend_from_slice(&node.tls_leaf_fingerprint()?);
        if encoded.len() > MAX_MANIFEST_CANONICAL_BYTES {
            return Err(ConfigError::Invalid(
                "canonical bootstrap manifest exceeds 64 KiB".into(),
            ));
        }
    }
    Ok(encoded)
}

fn put_manifest_bytes(encoded: &mut Vec<u8>, value: &[u8]) -> Result<(), ConfigError> {
    let length = u16::try_from(value.len())
        .map_err(|_| ConfigError::Invalid("bootstrap manifest field is too long".into()))?;
    let next = encoded
        .len()
        .checked_add(2)
        .and_then(|length| length.checked_add(value.len()))
        .ok_or_else(|| ConfigError::Invalid("bootstrap manifest length overflow".into()))?;
    if next > MAX_MANIFEST_CANONICAL_BYTES {
        return Err(ConfigError::Invalid(
            "canonical bootstrap manifest exceeds 64 KiB".into(),
        ));
    }
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(value);
    Ok(())
}

fn canonical_ca_trust_digest(pem: &[u8]) -> Result<[u8; 32], ConfigError> {
    let mut reader = pem;
    let mut certificates = rustls_pemfile::certs(&mut reader)
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|error| ConfigError::Invalid(format!("could not parse tls.ca: {error}")))?;
    if certificates.is_empty() || certificates.len() > 64 {
        return Err(ConfigError::Invalid(
            "tls.ca must contain between 1 and 64 certificates".into(),
        ));
    }
    certificates.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
    if certificates
        .windows(2)
        .any(|pair| pair[0].as_ref() == pair[1].as_ref())
    {
        return Err(ConfigError::Invalid(
            "tls.ca contains a duplicate certificate".into(),
        ));
    }
    let mut canonical = Vec::new();
    canonical.extend_from_slice(b"chorus/ca-trust-set/v1\0");
    canonical.extend_from_slice(&(certificates.len() as u16).to_be_bytes());
    for certificate in certificates {
        let der = certificate.as_ref();
        let length = u32::try_from(der.len())
            .map_err(|_| ConfigError::Invalid("tls.ca certificate is too large".into()))?;
        canonical.extend_from_slice(&length.to_be_bytes());
        canonical.extend_from_slice(der);
    }
    Ok(sha256(&canonical))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    digest(&SHA256, bytes)
        .as_ref()
        .try_into()
        .expect("SHA-256 output is exactly 32 bytes")
}

fn decode_lower_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], ConfigError> {
    if value.len() != N.saturating_mul(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ConfigError::Invalid(format!(
            "{label} must be exactly {} lower-case hexadecimal characters",
            N.saturating_mul(2)
        )));
    }
    let mut decoded = [0; N];
    for (index, output) in decoded.iter_mut().enumerate() {
        *output = (hex_nibble(value.as_bytes()[index * 2]) << 4)
            | hex_nibble(value.as_bytes()[index * 2 + 1]);
    }
    Ok(decoded)
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn read_manifest_public_key(path: &Path) -> Result<[u8; 32], ConfigError> {
    let bytes = read_bounded_nofollow(path, "manifest trust key", MAX_MANIFEST_KEY_BYTES, true)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| ConfigError::Invalid("manifest trust key is not ASCII hex".into()))?;
    decode_lower_hex::<32>(text, "manifest trust key")
}

fn read_bounded_nofollow(
    path: &Path,
    label: &str,
    maximum: u64,
    reject_group_world_write: bool,
) -> Result<Vec<u8>, ConfigError> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| ConfigError::Invalid(format!("{label} cannot be read: {error}")))?;
    validate_bounded_file_metadata(&path_metadata, label, maximum, reject_group_world_write)?;
    let mut file = open_identity_read(path)
        .map_err(|error| ConfigError::Invalid(format!("{label} cannot be opened: {error}")))?;
    let opened_metadata = file
        .metadata()
        .map_err(|error| ConfigError::Invalid(format!("{label} cannot be inspected: {error}")))?;
    let current_metadata = fs::symlink_metadata(path)
        .map_err(|error| ConfigError::Invalid(format!("{label} cannot be rechecked: {error}")))?;
    if !same_file(&opened_metadata, &current_metadata) {
        return Err(ConfigError::Invalid(format!(
            "{label} changed while it was being opened"
        )));
    }
    validate_bounded_file_metadata(&opened_metadata, label, maximum, reject_group_world_write)?;
    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| ConfigError::Io(error.to_string()))?;
    if bytes.len() as u64 > maximum {
        return Err(ConfigError::Invalid(format!(
            "{label} exceeds {maximum} bytes"
        )));
    }
    Ok(bytes)
}

fn validate_bounded_file_metadata(
    metadata: &fs::Metadata,
    label: &str,
    maximum: u64,
    reject_group_world_write: bool,
) -> Result<(), ConfigError> {
    if !metadata.is_file() {
        return Err(ConfigError::Invalid(format!(
            "{label} is not a regular file"
        )));
    }
    if metadata.len() == 0 || metadata.len() > maximum {
        return Err(ConfigError::Invalid(format!(
            "{label} size must be between 1 and {maximum} bytes"
        )));
    }
    #[cfg(unix)]
    if reject_group_world_write {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(ConfigError::Invalid(format!(
                "{label} must not be group/world-writable"
            )));
        }
    }
    Ok(())
}

fn ensure_ordinary_config_is_unbound(config: &Config) -> Result<(), ConfigError> {
    if config.bootstrap_manifest.is_some() {
        return Err(ConfigError::Invalid(
            "signed OpenRaft configuration requires Config::load_openraft_signed and an external trust key"
                .into(),
        ));
    }
    let binding_path = config.data_dir.join(MANIFEST_BINDING_FILE_NAME);
    match fs::symlink_metadata(&binding_path) {
        Ok(_) => Err(ConfigError::Invalid(
            "unsigned configuration cannot open an installation with a bootstrap manifest binding"
                .into(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ConfigError::Io(format!(
            "could not inspect bootstrap manifest binding: {error}"
        ))),
    }
}

fn ensure_manifest_authorizes_state_access(config: &Config) -> Result<(), ConfigError> {
    match (
        config.bootstrap_manifest.as_ref(),
        config.verified_bootstrap_manifest.as_ref(),
    ) {
        (Some(_), Some(verified)) => ensure_manifest_binding(config, verified),
        (Some(_), None) => Err(ConfigError::Invalid(
            "signed OpenRaft configuration was not verified with an external trust key".into(),
        )),
        (None, Some(_)) => Err(ConfigError::Invalid(
            "verified bootstrap manifest capability does not match the configuration".into(),
        )),
        (None, None) => ensure_ordinary_config_is_unbound(config),
    }
}

fn ensure_manifest_binding(
    config: &Config,
    verified: &VerifiedOpenRaftManifest,
) -> Result<(), ConfigError> {
    ensure_private_dir(&config.data_dir)?;
    let path = config.data_dir.join(MANIFEST_BINDING_FILE_NAME);
    let expected = ManifestBinding {
        format_version: MANIFEST_BINDING_VERSION,
        cluster_id: config.cluster_id.clone(),
        cluster_incarnation: config.cluster_incarnation,
        generation: verified.generation,
        signer_key_id: encode_lower_hex(&verified.signer_key_id),
        manifest_digest: encode_lower_hex(&verified.manifest_digest),
    };
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let existing = read_manifest_binding(&path)?;
            if existing != expected {
                return Err(ConfigError::Invalid(
                    "persisted bootstrap manifest binding does not match the verified manifest"
                        .into(),
                ));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(artifact) = existing_manifest_bound_artifact(config)? {
                return Err(ConfigError::Invalid(format!(
                    "bootstrap manifest binding is missing while durable state exists at {}; refusing to bind an existing installation",
                    artifact.display()
                )));
            }
            create_manifest_binding(&path, &expected)
        }
        Err(error) => Err(ConfigError::Io(error.to_string())),
    }
}

fn existing_manifest_bound_artifact(config: &Config) -> Result<Option<PathBuf>, ConfigError> {
    match fs::symlink_metadata(config.identity_path()) {
        Ok(_) => return Ok(Some(config.identity_path())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(ConfigError::Io(error.to_string())),
    }
    existing_durable_artifact(config)
}

fn read_manifest_binding(path: &Path) -> Result<ManifestBinding, ConfigError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata =
            fs::symlink_metadata(path).map_err(|error| ConfigError::Io(error.to_string()))?;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ConfigError::Invalid(
                "bootstrap manifest binding must not be group/world-accessible".into(),
            ));
        }
    }
    let bytes = read_bounded_nofollow(
        path,
        "bootstrap manifest binding",
        MAX_MANIFEST_BINDING_BYTES,
        true,
    )?;
    let text = std::str::from_utf8(&bytes).map_err(|error| {
        ConfigError::Parse(format!("bootstrap manifest binding is not UTF-8: {error}"))
    })?;
    let binding: ManifestBinding =
        toml::from_str(text).map_err(|error| ConfigError::Parse(error.to_string()))?;
    if binding.format_version != MANIFEST_BINDING_VERSION
        || binding.cluster_id.trim().is_empty()
        || binding.cluster_incarnation == 0
        || binding.generation == 0
    {
        return Err(ConfigError::Invalid(
            "bootstrap manifest binding contains invalid metadata".into(),
        ));
    }
    decode_lower_hex::<32>(&binding.signer_key_id, "binding signer_key_id")?;
    decode_lower_hex::<32>(&binding.manifest_digest, "binding manifest_digest")?;
    Ok(binding)
}

fn create_manifest_binding(path: &Path, binding: &ManifestBinding) -> Result<(), ConfigError> {
    let text = toml::to_string(binding).map_err(|error| ConfigError::Parse(error.to_string()))?;
    if text.is_empty() || text.len() as u64 > MAX_MANIFEST_BINDING_BYTES {
        return Err(ConfigError::Invalid(
            "bootstrap manifest binding exceeds its size limit".into(),
        ));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| ConfigError::Invalid("manifest binding path has no parent".into()))?;
    let mut temporary = None;
    for _ in 0..64 {
        let sequence = NEXT_IDENTITY_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{MANIFEST_BINDING_FILE_NAME}.{}.{}.tmp",
            std::process::id(),
            sequence
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(ConfigError::Io(error.to_string())),
        }
    }
    let (temporary_path, mut file) = temporary.ok_or_else(|| {
        ConfigError::Io("could not allocate a manifest binding temporary file".into())
    })?;
    harden_open_file_permissions(&file)?;
    if let Err(error) = file
        .write_all(text.as_bytes())
        .and_then(|_| file.sync_all())
    {
        drop(file);
        let _ = fs::remove_file(&temporary_path);
        return Err(ConfigError::Io(error.to_string()));
    }
    drop(file);
    match fs::hard_link(&temporary_path, path) {
        Ok(()) => {
            sync_parent(path)?;
            fs::remove_file(&temporary_path).map_err(|error| ConfigError::Io(error.to_string()))?;
            sync_parent(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            fs::remove_file(&temporary_path).map_err(|error| ConfigError::Io(error.to_string()))?;
            if read_manifest_binding(path)? == *binding {
                Ok(())
            } else {
                Err(ConfigError::Invalid(
                    "a different bootstrap manifest binding won concurrent first-open creation"
                        .into(),
                ))
            }
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary_path);
            Err(ConfigError::Io(error.to_string()))
        }
    }
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct InstallationIdentity {
    format_version: u32,
    cluster_id: String,
    cluster_incarnation: u64,
    node_id: u64,
}

impl InstallationIdentity {
    fn from_config(config: &Config) -> Self {
        Self {
            format_version: IDENTITY_VERSION,
            cluster_id: config.cluster_id.clone(),
            cluster_incarnation: config.cluster_incarnation,
            node_id: config.node_id,
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.format_version != IDENTITY_VERSION {
            return Err(ConfigError::Invalid(format!(
                "identity version {} is unsupported",
                self.format_version
            )));
        }
        if self.cluster_id.trim().is_empty() {
            return Err(ConfigError::Invalid("identity cluster_id is empty".into()));
        }
        if self.cluster_id.len() > MAX_CLUSTER_ID_BYTES {
            return Err(ConfigError::Invalid(format!(
                "identity cluster_id exceeds {MAX_CLUSTER_ID_BYTES} bytes"
            )));
        }
        if self.cluster_incarnation == 0 {
            return Err(ConfigError::Invalid(
                "identity cluster_incarnation must be nonzero".into(),
            ));
        }
        if self.node_id == 0 {
            return Err(ConfigError::Invalid(
                "identity node_id must be nonzero".into(),
            ));
        }
        Ok(())
    }

    fn matches_config(&self, config: &Config) -> bool {
        self.cluster_id == config.cluster_id
            && self.cluster_incarnation == config.cluster_incarnation
            && self.node_id == config.node_id
    }
}

fn ensure_installation_identity(config: &Config) -> Result<(), ConfigError> {
    let path = config.identity_path();
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            let identity = read_installation_identity(&path, &metadata)?;
            identity.validate()?;
            if !identity.matches_config(config) {
                return Err(ConfigError::Invalid(
                    "persisted installation identity does not match configuration".into(),
                ));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(artifact) = existing_durable_artifact(config)? {
                return Err(ConfigError::Invalid(format!(
                    "identity is missing while durable state exists at {}; refusing to bind an existing installation",
                    artifact.display()
                )));
            }
            create_installation_identity(&path, &InstallationIdentity::from_config(config))
        }
        Err(error) => Err(ConfigError::Io(error.to_string())),
    }
}

fn existing_durable_artifact(config: &Config) -> Result<Option<PathBuf>, ConfigError> {
    let state_dir = config.data_dir.join("state");
    match fs::symlink_metadata(&state_dir) {
        Ok(metadata) if !metadata.is_dir() => return Ok(Some(state_dir)),
        Ok(_) => {
            let mut entries =
                fs::read_dir(&state_dir).map_err(|error| ConfigError::Io(error.to_string()))?;
            if let Some(entry) = entries.next() {
                return entry
                    .map(|entry| Some(entry.path()))
                    .map_err(|error| ConfigError::Io(error.to_string()));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(ConfigError::Io(error.to_string())),
    }

    let raft_redb = config.data_dir.join("raft.redb");
    match fs::symlink_metadata(&raft_redb) {
        Ok(_) => return Ok(Some(raft_redb)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(ConfigError::Io(error.to_string())),
    }
    for entry in
        fs::read_dir(&config.data_dir).map_err(|error| ConfigError::Io(error.to_string()))?
    {
        let entry = entry.map_err(|error| ConfigError::Io(error.to_string()))?;
        if entry.file_name().to_string_lossy().ends_with(".raft.log") {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

fn read_installation_identity(
    path: &Path,
    path_metadata: &fs::Metadata,
) -> Result<InstallationIdentity, ConfigError> {
    if path_metadata.file_type().is_symlink() {
        return Err(ConfigError::Invalid(
            "identity path must not be a symbolic link".into(),
        ));
    }
    if !path_metadata.is_file() {
        return Err(ConfigError::Invalid(
            "identity path is not a regular file".into(),
        ));
    }
    if path_metadata.len() > MAX_IDENTITY_BYTES {
        return Err(ConfigError::Invalid(format!(
            "identity file exceeds {MAX_IDENTITY_BYTES} bytes"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path_metadata.permissions().mode() & 0o077 != 0 {
            return Err(ConfigError::Invalid(
                "identity file must not be group/world-readable".into(),
            ));
        }
    }

    // Linux's O_NOFOLLOW closes the check/open symlink race.  The
    // create_new path below is likewise exclusive and never follows an
    // existing identity symlink.  Other platforms retain the metadata
    // recheck, which fails closed for ordinary path replacement.
    let mut file = open_identity_read(path).map_err(|error| ConfigError::Io(error.to_string()))?;
    let opened_metadata = file
        .metadata()
        .map_err(|error| ConfigError::Io(error.to_string()))?;
    let current_metadata =
        fs::symlink_metadata(path).map_err(|error| ConfigError::Io(error.to_string()))?;
    if current_metadata.file_type().is_symlink()
        || !current_metadata.is_file()
        || !same_file(&opened_metadata, &current_metadata)
    {
        return Err(ConfigError::Invalid(
            "identity path changed while it was being opened".into(),
        ));
    }
    if opened_metadata.len() > MAX_IDENTITY_BYTES {
        return Err(ConfigError::Invalid(format!(
            "identity file exceeds {MAX_IDENTITY_BYTES} bytes"
        )));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_IDENTITY_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| ConfigError::Io(error.to_string()))?;
    if bytes.len() as u64 > MAX_IDENTITY_BYTES {
        return Err(ConfigError::Invalid(format!(
            "identity file exceeds {MAX_IDENTITY_BYTES} bytes"
        )));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| ConfigError::Parse(format!("identity is not UTF-8: {error}")))?;
    toml::from_str(text).map_err(|error| ConfigError::Parse(error.to_string()))
}

fn create_installation_identity(
    path: &Path,
    identity: &InstallationIdentity,
) -> Result<(), ConfigError> {
    let text =
        toml::to_string_pretty(identity).map_err(|error| ConfigError::Parse(error.to_string()))?;
    if text.len() as u64 > MAX_IDENTITY_BYTES {
        return Err(ConfigError::Invalid(format!(
            "identity file exceeds {MAX_IDENTITY_BYTES} bytes"
        )));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| ConfigError::Invalid("identity path has no parent directory".into()))?;
    let mut temporary = None;
    for _ in 0..64 {
        let sequence = NEXT_IDENTITY_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{IDENTITY_FILE_NAME}.{}.{}.tmp",
            std::process::id(),
            sequence
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(ConfigError::Io(error.to_string())),
        }
    }
    let (temporary_path, mut file) = temporary.ok_or_else(|| {
        ConfigError::Io("could not allocate a unique identity temporary file".into())
    })?;
    harden_open_file_permissions(&file)?;
    if let Err(error) = file
        .write_all(text.as_bytes())
        .and_then(|_| file.sync_all())
    {
        drop(file);
        let _ = fs::remove_file(&temporary_path);
        return Err(ConfigError::Io(error.to_string()));
    }
    drop(file);

    match fs::hard_link(&temporary_path, path) {
        Ok(()) => {
            // The hard link publishes a complete, synced inode without ever
            // replacing an existing identity. Persist publication before
            // removing the private staging name.
            sync_parent(path)?;
            fs::remove_file(&temporary_path).map_err(|error| ConfigError::Io(error.to_string()))?;
            sync_parent(path)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            fs::remove_file(&temporary_path).map_err(|error| ConfigError::Io(error.to_string()))?;
            let metadata =
                fs::symlink_metadata(path).map_err(|error| ConfigError::Io(error.to_string()))?;
            let existing = read_installation_identity(path, &metadata)?;
            existing.validate()?;
            if &existing == identity {
                Ok(())
            } else {
                Err(ConfigError::Invalid(
                    "a different identity won concurrent first-open creation".into(),
                ))
            }
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary_path);
            Err(ConfigError::Io(error.to_string()))
        }
    }
}

fn open_identity_read(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Linux O_NOFOLLOW; keep this read-only path from resolving a
        // symlink between symlink_metadata and open.
        options.custom_flags(0x20000);
    }
    options.open(path)
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        left.len() == right.len()
    }
}

fn harden_open_file_permissions(file: &fs::File) -> Result<(), ConfigError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| ConfigError::Io(error.to_string()))?;
    }
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), ConfigError> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| ConfigError::Invalid("identity path has no parent directory".into()))?;
        let directory =
            fs::File::open(parent).map_err(|error| ConfigError::Io(error.to_string()))?;
        directory
            .sync_all()
            .map_err(|error| ConfigError::Io(error.to_string()))?;
    }
    Ok(())
}

fn parse_initial_endpoint(endpoint: &str) -> Result<(SocketAddr, bool), ConfigError> {
    let (authority, https) = match endpoint.strip_prefix("https://") {
        Some(authority) => (authority, true),
        None => (endpoint, false),
    };
    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
        || authority.contains('@')
    {
        return Err(ConfigError::Invalid(format!(
            "initial node endpoint {endpoint:?} is not a bare socket address or HTTPS socket seed"
        )));
    }
    let address: SocketAddr = authority.parse().map_err(|_| {
        ConfigError::Invalid(format!(
            "initial node endpoint {endpoint:?} is not a socket address"
        ))
    })?;
    if address.port() == 0 {
        return Err(ConfigError::Invalid(
            "initial node endpoint port must be nonzero".into(),
        ));
    }
    Ok((address, https))
}

fn validate_dns_name(value: &str) -> Result<(), &'static str> {
    if value.is_empty() || value.len() > 253 || !value.is_ascii() {
        return Err("must be a nonempty ASCII name no longer than 253 bytes");
    }
    for label in value.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || !label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
        {
            return Err("contains an invalid DNS label");
        }
    }
    Ok(())
}

fn decode_sha256(value: &str) -> Result<[u8; 32], &'static str> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("must be exactly 64 hexadecimal characters");
    }
    let mut decoded = [0; 32];
    for (index, output) in decoded.iter_mut().enumerate() {
        let high = value.as_bytes()[index * 2];
        let low = value.as_bytes()[index * 2 + 1];
        *output = (hex_nibble(high) << 4) | hex_nibble(low);
    }
    Ok(decoded)
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => unreachable!("decode_sha256 validated hexadecimal input"),
    }
}

fn read_bounded_regular_file(
    path: &Path,
    name: &str,
    private: bool,
) -> Result<Vec<u8>, ConfigError> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| ConfigError::Invalid(format!("{name} cannot be read: {error}")))?;
    validate_tls_metadata(&path_metadata, name, private)?;
    let mut file = open_identity_read(path)
        .map_err(|error| ConfigError::Invalid(format!("{name} cannot be opened: {error}")))?;
    let opened_metadata = file
        .metadata()
        .map_err(|error| ConfigError::Invalid(format!("{name} cannot be inspected: {error}")))?;
    let current_metadata = fs::symlink_metadata(path)
        .map_err(|error| ConfigError::Invalid(format!("{name} cannot be rechecked: {error}")))?;
    if !same_file(&opened_metadata, &current_metadata) {
        return Err(ConfigError::Invalid(format!(
            "{name} changed while it was being opened"
        )));
    }
    validate_tls_metadata(&opened_metadata, name, private)?;
    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_TLS_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| ConfigError::Io(error.to_string()))?;
    if bytes.len() as u64 > MAX_TLS_FILE_BYTES {
        return Err(ConfigError::Invalid(format!(
            "{name} exceeds {MAX_TLS_FILE_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

fn validate_tls_file(path: Option<&Path>, name: &str, private: bool) -> Result<(), ConfigError> {
    let path = path.ok_or_else(|| ConfigError::Invalid(format!("{name} is missing")))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| ConfigError::Invalid(format!("{name} cannot be read: {e}")))?;
    validate_tls_metadata(&metadata, name, private)
}

fn validate_tls_metadata(
    metadata: &fs::Metadata,
    name: &str,
    private: bool,
) -> Result<(), ConfigError> {
    if !metadata.is_file() {
        return Err(ConfigError::Invalid(format!(
            "{name} is not a regular file"
        )));
    }
    if metadata.len() == 0 {
        return Err(ConfigError::Invalid(format!("{name} is empty")));
    }
    if metadata.len() > MAX_TLS_FILE_BYTES {
        return Err(ConfigError::Invalid(format!(
            "{name} exceeds {MAX_TLS_FILE_BYTES} bytes"
        )));
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

#[cfg(test)]
mod tests {
    use super::*;
    use chorus_codec::{
        ActivateOriginV1, CommitTransactionV1, KvMutationV1, ReplicatedCommandV1,
        canonical_mutations, payload_hash,
    };
    use chorus_common::{LogId, OriginId, RequestId};
    use chorus_storage::{MemoryStateStore, StateStore};
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair as RcgenKeyPair};
    use ring::signature::{Ed25519KeyPair, KeyPair as RingKeyPair};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_TEST_DIRECTORY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "chorus-admin-{label}-{}-{sequence}",
                std::process::id()
            ));
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn optional_file_bytes(path: &Path) -> Option<Vec<u8>> {
        match fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("read {}: {error}", path.display()),
        }
    }

    fn make_private_file(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("set private test permissions");
        }
    }

    fn fingerprint(byte: u8) -> String {
        std::iter::repeat_n(format!("{byte:02x}"), 32).collect()
    }

    fn authenticated_config(directory: &TestDirectory) -> Config {
        fs::create_dir_all(directory.path()).expect("create test directory");
        let ca = directory.path().join("ca.pem");
        let certificate = directory.path().join("node.pem");
        let private_key = directory.path().join("node-key.pem");
        fs::write(&ca, b"test CA").expect("write CA");
        fs::write(&certificate, b"test certificate").expect("write certificate");
        fs::write(&private_key, b"test private key").expect("write private key");
        make_private_file(&private_key);
        let mut config = Config::defaults(directory.path().join("data"), 1);
        config.tls = TlsConfig {
            ca: Some(ca),
            certificate: Some(certificate),
            private_key: Some(private_key),
        };
        config.initial_nodes = (1..=3)
            .map(|node_id| InitialNode {
                node_id,
                endpoint: format!("https://127.0.0.1:{}", 7000 + node_id),
                voter: true,
                tls_dns_name: Some(format!("node-{node_id}.chorus.test")),
                tls_leaf_sha256: Some(fingerprint(node_id as u8)),
            })
            .collect();
        config
    }

    fn ed25519_key(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).expect("test Ed25519 seed")
    }

    fn valid_ca_pem() -> String {
        let mut params = CertificateParams::new(Vec::new()).expect("CA parameters");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = RcgenKeyPair::generate().expect("CA key");
        params.self_signed(&key).expect("CA certificate").pem()
    }

    fn sign_manifest(config: &mut Config, key: &Ed25519KeyPair, generation: u64) {
        let ca = fs::read(config.tls.ca.as_ref().expect("CA path")).expect("CA bytes");
        config.bootstrap_manifest = Some(BootstrapManifestSignature {
            format_version: MANIFEST_FORMAT_VERSION,
            algorithm: "ed25519".into(),
            generation,
            key_id: encode_lower_hex(&sha256(key.public_key().as_ref())),
            ca_sha256: encode_lower_hex(&canonical_ca_trust_digest(&ca).expect("CA digest")),
            signature: "00".repeat(64),
        });
        let signed = config
            .openraft_manifest_signing_bytes()
            .expect("canonical manifest");
        config
            .bootstrap_manifest
            .as_mut()
            .expect("manifest metadata")
            .signature = encode_lower_hex(key.sign(&signed).as_ref());
    }

    fn signed_config(
        directory: &TestDirectory,
        key_seed: u8,
    ) -> (Config, PathBuf, PathBuf, Ed25519KeyPair) {
        let mut config = authenticated_config(directory);
        fs::write(config.tls.ca.as_ref().unwrap(), valid_ca_pem()).expect("valid CA PEM");
        let key = ed25519_key(key_seed);
        let trust_key_path = directory.path().join("manifest-ed25519.pub");
        fs::write(&trust_key_path, encode_lower_hex(key.public_key().as_ref())).expect("trust key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&trust_key_path, fs::Permissions::from_mode(0o644))
                .expect("trust-key permissions");
        }
        sign_manifest(&mut config, &key, 1);
        let config_path = directory.path().join("chorus.toml");
        config.save(&config_path).expect("signed config");
        (config, config_path, trust_key_path, key)
    }

    #[test]
    fn authenticated_openraft_manifest_is_complete_unique_and_listen_bound() {
        let directory = TestDirectory::new("authenticated-manifest");
        let config = authenticated_config(&directory);
        config.validate_openraft_mtls().expect("valid manifest");
        assert_eq!(1, config.openraft_bootstrap_node_id().unwrap());
        assert_eq!(
            [1; 32],
            config.initial_nodes[0].tls_leaf_fingerprint().unwrap()
        );

        let mut bare_endpoint = config.clone();
        bare_endpoint.initial_nodes[0].endpoint = "127.0.0.1:7001".into();
        assert!(
            bare_endpoint
                .validate_openraft_mtls()
                .unwrap_err()
                .to_string()
                .contains("https://")
        );

        let mut duplicate_identity = config.clone();
        duplicate_identity.initial_nodes[1].tls_leaf_sha256 =
            duplicate_identity.initial_nodes[0].tls_leaf_sha256.clone();
        assert!(
            duplicate_identity
                .validate_openraft_mtls()
                .unwrap_err()
                .to_string()
                .contains("fingerprints must be unique")
        );

        let mut mismatched_listen = config.clone();
        mismatched_listen.raft.listen = "127.0.0.1:7999".into();
        assert!(
            mismatched_listen
                .validate_openraft_mtls()
                .unwrap_err()
                .to_string()
                .contains("raft.listen")
        );

        let mut partial_identity = config;
        partial_identity.initial_nodes[2].tls_dns_name = None;
        assert!(partial_identity.validate().is_err());
    }

    #[test]
    fn metrics_render_low_cardinality_health_and_replication_gauges() {
        let directory = TestDirectory::new("metrics");
        let config = Config::defaults(directory.path().join("data"), 7);
        let store = MemoryStateStore::new();
        let rendered = render_metrics(&status(&config, &store, None));
        assert!(rendered.contains("# TYPE chorus_storage_healthy gauge"));
        assert!(rendered.contains("chorus_local_ready "));
        assert!(rendered.contains("chorus_strict_ready "));
        assert!(rendered.contains("chorus_node_info{node_id=\"7\",role=\"unknown\"} 1"));
        assert!(!rendered.contains("cluster_id"));
        assert!(!rendered.contains("SELECT"));
    }

    #[test]
    fn signed_manifest_verifies_canonical_order_and_pins_first_open() {
        let directory = TestDirectory::new("signed-manifest-valid");
        let (mut config, config_path, trust_key_path, _) = signed_config(&directory, 7);
        let canonical = config.openraft_manifest_signing_bytes().unwrap();
        let loaded = Config::load_openraft_signed(&config_path, &trust_key_path).unwrap();
        assert_eq!(canonical, loaded.openraft_manifest_signing_bytes().unwrap());

        let binding_path = config.data_dir.join(MANIFEST_BINDING_FILE_NAME);
        let binding_before = fs::read(&binding_path).expect("manifest binding");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                0o600,
                fs::metadata(&binding_path).unwrap().permissions().mode() & 0o777
            );
        }

        config.initial_nodes.reverse();
        config.save(&config_path).unwrap();
        let reordered = Config::load_openraft_signed(&config_path, &trust_key_path).unwrap();
        assert_eq!(
            canonical,
            reordered.openraft_manifest_signing_bytes().unwrap()
        );
        assert_eq!(binding_before, fs::read(binding_path).unwrap());
        assert!(!config.identity_path().exists());
        assert!(!config.data_dir.join("raft.redb").exists());
        assert!(!config.state_path().exists());
    }

    #[test]
    fn signed_manifest_cannot_downgrade_to_ordinary_load_or_state_access() {
        let directory = TestDirectory::new("signed-manifest-downgrade");
        let (config, config_path, trust_key_path, _) = signed_config(&directory, 18);

        let error = Config::load(&config_path).unwrap_err();
        assert!(error.to_string().contains("load_openraft_signed"));
        let error = match open_store(&config) {
            Ok(_) => panic!("unverified signed configuration opened durable state"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("was not verified"));
        assert!(!config.data_dir.exists());

        let verified = Config::load_openraft_signed(&config_path, &trust_key_path).unwrap();
        let binding_path = verified.data_dir.join(MANIFEST_BINDING_FILE_NAME);
        let binding_before = fs::read(&binding_path).unwrap();
        drop(open_store(&verified).unwrap());
        let identity_before = fs::read(verified.identity_path()).unwrap();
        let state_before = fs::read(verified.state_path()).unwrap();

        let mut stripped = verified;
        stripped.bootstrap_manifest = None;
        stripped.verified_bootstrap_manifest = None;
        stripped.save(&config_path).unwrap();

        let error = Config::load(&config_path).unwrap_err();
        assert!(error.to_string().contains("manifest binding"));
        let error = match open_store(&stripped) {
            Ok(_) => panic!("unsigned configuration opened manifest-bound state"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("manifest binding"));
        assert_eq!(binding_before, fs::read(binding_path).unwrap());
        assert_eq!(identity_before, fs::read(stripped.identity_path()).unwrap());
        assert_eq!(state_before, fs::read(stripped.state_path()).unwrap());
    }

    #[test]
    fn ordinary_unbound_configuration_still_loads_and_opens_state() {
        let directory = TestDirectory::new("ordinary-config-unbound");
        let config_path = directory.path().join("chorus.toml");
        let config = Config::defaults(directory.path().join("data"), 1);
        config.save(&config_path).unwrap();

        let loaded = Config::load(&config_path).unwrap();
        drop(open_store(&loaded).unwrap());
        assert!(loaded.identity_path().exists());
        assert!(loaded.state_path().exists());
        assert!(!loaded.data_dir.join(MANIFEST_BINDING_FILE_NAME).exists());
    }

    #[test]
    fn signed_manifest_rejects_tamper_wrong_key_and_invalid_signature_before_binding() {
        let tampered_directory = TestDirectory::new("signed-manifest-payload-tamper");
        let (mut tampered, config_path, trust_key_path, _) = signed_config(&tampered_directory, 8);
        tampered.initial_nodes[1].endpoint = "https://127.0.0.1:7202".into();
        tampered.save(&config_path).unwrap();
        let error = Config::load_openraft_signed(&config_path, &trust_key_path).unwrap_err();
        assert!(error.to_string().contains("signature is invalid"));
        assert!(!tampered.data_dir.exists());

        let signature_directory = TestDirectory::new("signed-manifest-signature-tamper");
        let (mut bad_signature, config_path, trust_key_path, _) =
            signed_config(&signature_directory, 9);
        bad_signature
            .bootstrap_manifest
            .as_mut()
            .unwrap()
            .signature
            .replace_range(..2, "01");
        bad_signature.save(&config_path).unwrap();
        let error = Config::load_openraft_signed(&config_path, &trust_key_path).unwrap_err();
        assert!(error.to_string().contains("signature is invalid"));
        assert!(!bad_signature.data_dir.exists());

        let wrong_key_directory = TestDirectory::new("signed-manifest-wrong-key");
        let (wrong_key, config_path, trust_key_path, _) = signed_config(&wrong_key_directory, 10);
        fs::write(
            &trust_key_path,
            encode_lower_hex(ed25519_key(11).public_key().as_ref()),
        )
        .unwrap();
        let error = Config::load_openraft_signed(&config_path, &trust_key_path).unwrap_err();
        assert!(error.to_string().contains("does not match"));
        assert!(!wrong_key.data_dir.exists());
    }

    #[test]
    fn manifest_binding_rejects_content_signer_rotation_and_missing_pin_with_artifacts() {
        let directory = TestDirectory::new("manifest-binding-immutable");
        let (original, config_path, trust_key_path, key) = signed_config(&directory, 12);
        Config::load_openraft_signed(&config_path, &trust_key_path).unwrap();
        let binding_path = original.data_dir.join(MANIFEST_BINDING_FILE_NAME);
        let binding_before = fs::read(&binding_path).unwrap();

        let mut changed = original.clone();
        changed.initial_nodes[1].endpoint = "https://127.0.0.1:7302".into();
        sign_manifest(&mut changed, &key, 2);
        changed.save(&config_path).unwrap();
        let error = Config::load_openraft_signed(&config_path, &trust_key_path).unwrap_err();
        assert!(error.to_string().contains("binding does not match"));
        assert_eq!(binding_before, fs::read(&binding_path).unwrap());

        let replacement_key = ed25519_key(13);
        let mut rekeyed = original.clone();
        sign_manifest(&mut rekeyed, &replacement_key, 1);
        rekeyed.save(&config_path).unwrap();
        fs::write(
            &trust_key_path,
            encode_lower_hex(replacement_key.public_key().as_ref()),
        )
        .unwrap();
        let error = Config::load_openraft_signed(&config_path, &trust_key_path).unwrap_err();
        assert!(error.to_string().contains("binding does not match"));
        assert_eq!(binding_before, fs::read(&binding_path).unwrap());

        let artifact_directory = TestDirectory::new("manifest-binding-artifact-gate");
        let (artifact_config, config_path, trust_key_path, _) =
            signed_config(&artifact_directory, 14);
        fs::create_dir_all(&artifact_config.data_dir).unwrap();
        let raft_path = artifact_config.data_dir.join("raft.redb");
        fs::write(&raft_path, b"existing durable bytes").unwrap();
        let error = Config::load_openraft_signed(&config_path, &trust_key_path).unwrap_err();
        assert!(error.to_string().contains("binding is missing"));
        assert_eq!(
            b"existing durable bytes".as_slice(),
            fs::read(&raft_path).unwrap()
        );
        assert!(
            !artifact_config
                .data_dir
                .join(MANIFEST_BINDING_FILE_NAME)
                .exists()
        );
    }

    #[test]
    fn manifest_key_and_config_size_bounds_fail_before_binding() {
        let key_directory = TestDirectory::new("manifest-key-oversize");
        let (key_config, config_path, trust_key_path, _) = signed_config(&key_directory, 15);
        fs::write(
            &trust_key_path,
            vec![b'a'; MAX_MANIFEST_KEY_BYTES as usize + 1],
        )
        .unwrap();
        assert!(Config::load_openraft_signed(&config_path, &trust_key_path).is_err());
        assert!(!key_config.data_dir.exists());

        let config_directory = TestDirectory::new("manifest-config-oversize");
        fs::create_dir_all(config_directory.path()).unwrap();
        let config_path = config_directory.path().join("chorus.toml");
        let key_path = config_directory.path().join("manifest.pub");
        fs::write(&config_path, vec![b'x'; MAX_MANIFEST_BYTES as usize + 1]).unwrap();
        fs::write(&key_path, "00".repeat(32)).unwrap();
        assert!(Config::load_openraft_signed(&config_path, &key_path).is_err());
        assert!(!config_directory.path().join("data").exists());
    }

    #[cfg(unix)]
    #[test]
    fn signed_manifest_rejects_config_and_key_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new("manifest-symlinks");
        let (config, config_path, trust_key_path, _) = signed_config(&directory, 16);
        let config_link = directory.path().join("config-link.toml");
        symlink(&config_path, &config_link).unwrap();
        assert!(Config::load_openraft_signed(&config_link, &trust_key_path).is_err());

        let key_link = directory.path().join("key-link.pub");
        symlink(&trust_key_path, &key_link).unwrap();
        assert!(Config::load_openraft_signed(&config_path, &key_link).is_err());
        assert!(!config.data_dir.exists());
    }

    #[cfg(unix)]
    #[test]
    fn signed_manifest_rejects_group_or_world_writable_inputs_before_binding() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new("manifest-writable-inputs");
        let (config, config_path, trust_key_path, _) = signed_config(&directory, 17);

        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o620)).unwrap();
        let error = Config::load_openraft_signed(&config_path, &trust_key_path).unwrap_err();
        assert!(error.to_string().contains("group/world-writable"));
        assert!(!config.data_dir.exists());

        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&trust_key_path, fs::Permissions::from_mode(0o666)).unwrap();
        let error = Config::load_openraft_signed(&config_path, &trust_key_path).unwrap_err();
        assert!(error.to_string().contains("group/world-writable"));
        assert!(!config.data_dir.exists());
    }

    #[test]
    fn authenticated_tls_material_reads_exact_bounded_private_files() {
        let directory = TestDirectory::new("authenticated-tls-material");
        let config = authenticated_config(&directory);
        let material = config.transport_tls_material().expect("read TLS material");
        assert_eq!(b"test CA", material.ca_pem.as_slice());
        assert_eq!(b"test certificate", material.certificate_pem.as_slice());
        assert_eq!(b"test private key", material.private_key_pem.as_slice());

        fs::write(
            config.tls.ca.as_ref().unwrap(),
            vec![0; MAX_TLS_FILE_BYTES as usize + 1],
        )
        .expect("write oversized CA");
        assert!(
            config
                .transport_tls_material()
                .unwrap_err()
                .to_string()
                .contains("exceeds")
        );
    }

    #[test]
    fn first_open_creates_private_identity_and_same_config_reopens() {
        let directory = TestDirectory::new("identity-first-open");
        let config = Config::defaults(directory.path(), 1);
        let store = open_store(&config).expect("first open");
        let before_hash = store.state_hash().expect("initial state hash");
        drop(store);

        let identity_bytes = fs::read(config.identity_path()).expect("identity bytes");
        let identity: InstallationIdentity =
            toml::from_slice(&identity_bytes).expect("identity TOML");
        assert_eq!(identity, InstallationIdentity::from_config(&config));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(config.identity_path())
                    .expect("identity metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(directory.path())
                    .expect("data directory metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }

        let reopened = open_store(&config).expect("same identity reopen");
        assert_eq!(reopened.state_hash().expect("reopened hash"), before_hash);
        assert_eq!(
            fs::read(config.identity_path()).expect("identity after reopen"),
            identity_bytes
        );
        assert!(
            fs::read_dir(directory.path())
                .expect("list data directory")
                .all(|entry| !entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".identity.toml."))
        );
    }

    #[test]
    fn identity_mismatch_rejects_before_durable_state_access() {
        let directory = TestDirectory::new("identity-mismatch");
        let config = Config::defaults(directory.path(), 1);
        drop(open_store(&config).expect("first open"));
        let identity_before = fs::read(config.identity_path()).expect("identity before");
        let state_before = optional_file_bytes(&config.state_path());
        let log_path = config.state_path().with_extension("raft.log");
        let log_before = optional_file_bytes(&log_path);

        let mut wrong_node = config.clone();
        wrong_node.node_id = 2;
        wrong_node.initial_nodes[0].node_id = 2;
        assert!(open_store(&wrong_node).is_err());

        let mut wrong_cluster = config.clone();
        wrong_cluster.cluster_id = "other-cluster".into();
        assert!(open_store(&wrong_cluster).is_err());

        let mut wrong_incarnation = config.clone();
        wrong_incarnation.cluster_incarnation += 1;
        assert!(open_store(&wrong_incarnation).is_err());

        assert_eq!(
            fs::read(config.identity_path()).expect("identity after mismatches"),
            identity_before
        );
        assert_eq!(optional_file_bytes(&config.state_path()), state_before);
        assert_eq!(optional_file_bytes(&log_path), log_before);
    }

    #[test]
    fn missing_identity_never_rebinds_existing_state_or_raft_log() {
        let directory = TestDirectory::new("identity-deleted");
        let config = Config::defaults(directory.path(), 1);
        drop(open_store(&config).expect("first open"));
        let state_before = optional_file_bytes(&config.state_path());
        let log_path = config.state_path().with_extension("raft.log");
        let log_before = optional_file_bytes(&log_path);
        fs::remove_file(config.identity_path()).expect("delete identity for recovery test");

        let mut changed_node = config.clone();
        changed_node.node_id = 2;
        changed_node.initial_nodes[0].node_id = 2;
        let error = match open_store(&changed_node) {
            Err(error) => error,
            Ok(_) => panic!("existing state must not be rebound"),
        };
        assert!(error.to_string().contains("identity is missing"));
        assert!(!config.identity_path().exists());
        assert_eq!(optional_file_bytes(&config.state_path()), state_before);
        assert_eq!(optional_file_bytes(&log_path), log_before);

        let log_only_directory = TestDirectory::new("identity-log-only");
        fs::create_dir_all(log_only_directory.path()).expect("create log-only data directory");
        let orphan_log = log_only_directory.path().join("orphan.raft.log");
        fs::write(&orphan_log, b"durable raft bytes").expect("write orphan log");
        let log_only_config = Config::defaults(log_only_directory.path(), 1);
        assert!(open_store(&log_only_config).is_err());
        assert_eq!(
            fs::read(&orphan_log).expect("orphan log bytes"),
            b"durable raft bytes"
        );
        assert!(!log_only_config.identity_path().exists());
        assert!(!log_only_config.state_path().exists());
    }

    #[test]
    fn malformed_and_oversize_identity_files_fail_closed() {
        for (label, bytes) in [
            ("malformed", b"format_version =".to_vec()),
            ("oversize", vec![b'x'; MAX_IDENTITY_BYTES as usize + 1]),
        ] {
            let directory = TestDirectory::new(label);
            fs::create_dir_all(directory.path()).expect("create data directory");
            let config = Config::defaults(directory.path(), 1);
            fs::write(config.identity_path(), &bytes).expect("write invalid identity");
            make_private_file(&config.identity_path());
            assert!(open_store(&config).is_err());
            assert_eq!(
                fs::read(config.identity_path()).expect("invalid identity unchanged"),
                bytes
            );
            assert!(!config.state_path().exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn identity_symlink_is_rejected_without_opening_state() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new("identity-symlink");
        fs::create_dir_all(directory.path()).expect("create data directory");
        let config = Config::defaults(directory.path(), 1);
        let target = directory.path().join("identity-target.toml");
        fs::write(
            &target,
            toml::to_string(&InstallationIdentity::from_config(&config)).expect("identity TOML"),
        )
        .expect("write symlink target");
        make_private_file(&target);
        symlink(&target, config.identity_path()).expect("identity symlink");

        assert!(open_store(&config).is_err());
        assert!(!config.state_path().exists());
        assert!(
            fs::symlink_metadata(config.identity_path())
                .expect("identity symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn logical_backup_roundtrip_keeps_kv_in_single_entry_stream() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "chorus-admin-logical-backup-{}-{nonce}.state",
            std::process::id()
        ));
        let raft_path = path.with_extension("raft.log");
        let store = FileStateStore::open(&path).expect("open test store");
        let cluster = ClusterId::from_name("chorus-admin-test");
        store
            .initialize_cluster(cluster.0, 1)
            .expect("initialize cluster");
        let origin = OriginId::new(7);
        store
            .apply(
                LogId { term: 1, index: 1 },
                &ReplicatedCommandV1::ActivateOrigin(ActivateOriginV1 { origin }),
            )
            .expect("activate origin");

        let mutations = vec![KvMutationV1::Put {
            key: vec![0x00, 0xff, 0x01],
            value: vec![0xde, 0xad, 0xbe, 0xef],
        }];
        let request_id = RequestId::new(origin, 1);
        let payload = canonical_mutations(&mutations).expect("canonical mutations");
        let command = ReplicatedCommandV1::CommitTransaction(CommitTransactionV1 {
            request_id,
            payload_hash: payload_hash(1, &request_id, 0, &payload),
            base_epoch: 0,
            mutations,
        });
        store
            .apply(LogId { term: 1, index: 2 }, &command)
            .expect("commit mutation");

        let backup = logical_backup_from_store(&store).expect("build backup");
        assert_eq!(
            backup.entries,
            vec![(vec![0x00, 0xff, 0x01], vec![0xde, 0xad, 0xbe, 0xef])]
        );
        let state: chorus_storage::StateData =
            serde_json::from_slice(backup.meta.get("state").expect("state metadata"))
                .expect("decode state metadata");
        assert!(
            state.kv.is_empty(),
            "metadata must not duplicate KV entries"
        );

        let decoded = LogicalSnapshot::decode(&backup.encode().expect("encode backup"))
            .expect("decode backup");
        assert_eq!(decoded.entries, backup.entries);
        assert!(is_logical_backup(&decoded));

        drop(store);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(raft_path);
    }
}
