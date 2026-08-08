#![forbid(unsafe_code)]

//! Local logical state and deterministic state-machine apply.
//!
//! `StateStore` is intentionally narrow: the SQL and transaction crates only
//! see immutable snapshots and atomic command application.  The included
//! memory and file implementations make the repository useful before a redb
//! adapter is introduced, while preserving the same on-disk logical format.

use chorus_codec::{
    ApplyResult, CommitTransactionV1, EncodedRowV1, KvMutationV1, LogicalSnapshot, MAX_ROW_BYTES,
    NodeOriginState, PhysicalKey, ReplicatedCommandV1, SchemaOperationV1, canonical_mutations,
    encode_composite, hash32, payload_hash,
};
use chorus_common::{
    ChorusError, Datum, LogId, MAX_KEY_BYTES, OriginId, Result, SqlError, SqlType,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

pub const META_DB_EPOCH: &str = "db_epoch";
pub const META_CATALOG_EPOCH: &str = "catalog_epoch";
const STATE_FILE_MAGIC: &[u8] = b"CHORUS-STATE\0";
const STATE_FILE_VERSION: u8 = 1;
const MAX_STATE_FILE_BYTES: usize = 256 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ObjectState {
    Live,
    Dropped,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ColumnState {
    Live,
    Dropped,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ColumnDescriptor {
    pub id: u32,
    pub name: String,
    pub data_type: SqlType,
    pub nullable: bool,
    pub default: Option<Datum>,
    pub state: ColumnState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndexColumn {
    pub column_id: u32,
    pub descending: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndexDescriptor {
    pub oid: u32,
    pub table_oid: u32,
    pub name: String,
    pub columns: Vec<IndexColumn>,
    pub unique: bool,
    pub state: ObjectState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TableDescriptor {
    pub oid: u32,
    pub schema_oid: u32,
    pub name: String,
    pub schema_version: u32,
    pub columns: Vec<ColumnDescriptor>,
    pub primary_key: Option<u32>,
    pub secondary_indexes: Vec<u32>,
    pub row_count: u64,
    pub state: ObjectState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Catalog {
    pub next_object_id: u32,
    pub tables: BTreeMap<u32, TableDescriptor>,
    pub indexes: BTreeMap<u32, IndexDescriptor>,
}

impl Default for Catalog {
    fn default() -> Self {
        Self {
            next_object_id: 10000,
            tables: BTreeMap::new(),
            indexes: BTreeMap::new(),
        }
    }
}

impl Catalog {
    pub fn allocate_id(&mut self) -> Result<u32> {
        let id = self.next_object_id;
        self.next_object_id = self
            .next_object_id
            .checked_add(1)
            .ok_or_else(|| ChorusError::Limit("catalog object id exhausted".into()))?;
        Ok(id)
    }
    pub fn table_by_name(&self, name: &str) -> Option<&TableDescriptor> {
        self.tables
            .values()
            .find(|t| t.state == ObjectState::Live && t.name == name)
    }
    pub fn table_by_name_mut(&mut self, name: &str) -> Option<&mut TableDescriptor> {
        self.tables
            .values_mut()
            .find(|t| t.state == ObjectState::Live && t.name == name)
    }
    pub fn table(&self, id: u32) -> Option<&TableDescriptor> {
        self.tables
            .get(&id)
            .filter(|t| t.state == ObjectState::Live)
    }
    pub fn table_mut(&mut self, id: u32) -> Option<&mut TableDescriptor> {
        self.tables
            .get_mut(&id)
            .filter(|t| t.state == ObjectState::Live)
    }
    pub fn index_by_name(&self, name: &str) -> Option<&IndexDescriptor> {
        self.indexes
            .values()
            .find(|i| i.state == ObjectState::Live && i.name == name)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Membership {
    pub log_id: LogId,
    pub voters: Vec<u64>,
    pub learners: Vec<u64>,
}

impl Default for Membership {
    fn default() -> Self {
        Self {
            log_id: LogId::ZERO,
            voters: vec![1],
            learners: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateData {
    pub format_version: u8,
    pub cluster_id: [u8; 16],
    pub cluster_incarnation: u64,
    pub db_epoch: u64,
    pub catalog_epoch: u64,
    pub last_applied: LogId,
    pub catalog: Catalog,
    pub kv: BTreeMap<Vec<u8>, Vec<u8>>,
    pub origins: BTreeMap<u64, NodeOriginState>,
    pub membership: Membership,
}

impl PartialEq for StateData {
    fn eq(&self, other: &Self) -> bool {
        self.format_version == other.format_version
            && self.cluster_id == other.cluster_id
            && self.cluster_incarnation == other.cluster_incarnation
            && self.db_epoch == other.db_epoch
            && self.catalog_epoch == other.catalog_epoch
            && self.last_applied == other.last_applied
            && self.catalog == other.catalog
            && self.kv == other.kv
            && self.origins == other.origins
            && self.membership == other.membership
    }
}
impl Eq for StateData {}

impl Default for StateData {
    fn default() -> Self {
        Self {
            format_version: 1,
            cluster_id: [0; 16],
            cluster_incarnation: 1,
            db_epoch: 0,
            catalog_epoch: 0,
            last_applied: LogId::ZERO,
            catalog: Catalog::default(),
            kv: BTreeMap::new(),
            origins: BTreeMap::new(),
            membership: Membership::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct StateSnapshot {
    data: Arc<StateData>,
}

impl StateSnapshot {
    pub fn db_epoch(&self) -> u64 {
        self.data.db_epoch
    }
    pub fn catalog_epoch(&self) -> u64 {
        self.data.catalog_epoch
    }
    pub fn last_applied(&self) -> LogId {
        self.data.last_applied
    }
    pub fn cluster_id(&self) -> [u8; 16] {
        self.data.cluster_id
    }
    pub fn catalog(&self) -> &Catalog {
        &self.data.catalog
    }
    pub fn kv(&self) -> &BTreeMap<Vec<u8>, Vec<u8>> {
        &self.data.kv
    }
    pub fn origins(&self) -> &BTreeMap<u64, NodeOriginState> {
        &self.data.origins
    }
    pub fn membership(&self) -> &Membership {
        &self.data.membership
    }
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.data.kv.get(key).map(Vec::as_slice)
    }
    pub fn scan(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
    ) -> impl Iterator<Item = (&Vec<u8>, &Vec<u8>)> {
        self.data
            .kv
            .range(start.to_vec()..)
            .take_while(move |(k, _)| end.map(|e| k.as_slice() < e).unwrap_or(true))
    }
    pub fn state_hash(&self) -> [u8; 32] {
        canonical_state_hash(&self.data)
    }
    pub fn to_data(&self) -> StateData {
        (*self.data).clone()
    }
}

pub trait StateStore: Send + Sync + 'static {
    fn snapshot(&self) -> Result<StateSnapshot>;
    fn apply(&self, log_id: LogId, command: &ReplicatedCommandV1) -> Result<ApplyResult>;
    fn install(&self, snapshot: &LogicalSnapshot) -> Result<()>;
    /// Restore an exact pre-apply image during an atomic replication rollback.
    /// Ordinary snapshot installation remains monotonic; consensus adapters
    /// use this separate hook only after an entry was never acknowledged.
    fn rollback(&self, snapshot: &LogicalSnapshot) -> Result<()> {
        self.install(snapshot)
    }
    fn state_hash(&self) -> Result<[u8; 32]>;
    fn status(&self) -> StoreStatus;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoreStatus {
    pub db_epoch: u64,
    pub catalog_epoch: u64,
    pub last_applied: LogId,
    pub state_hash: [u8; 32],
    pub healthy: bool,
}

#[derive(Clone)]
pub struct MemoryStateStore {
    inner: Arc<RwLock<StateData>>,
}

impl MemoryStateStore {
    pub fn new() -> Self {
        Self::with_cluster([0; 16], 1)
    }
    pub fn with_cluster(cluster_id: [u8; 16], incarnation: u64) -> Self {
        let mut d = StateData::default();
        d.cluster_id = cluster_id;
        d.cluster_incarnation = incarnation;
        Self {
            inner: Arc::new(RwLock::new(d)),
        }
    }
    pub fn from_data(data: StateData) -> Self {
        Self {
            inner: Arc::new(RwLock::new(data)),
        }
    }
    pub fn data(&self) -> StateData {
        self.inner.read().expect("state lock poisoned").clone()
    }
    fn apply_inner(
        data: &mut StateData,
        log_id: LogId,
        command: &ReplicatedCommandV1,
    ) -> Result<ApplyResult> {
        apply_command(data, log_id, command)
    }
}

impl Default for MemoryStateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl StateStore for MemoryStateStore {
    fn snapshot(&self) -> Result<StateSnapshot> {
        Ok(StateSnapshot {
            data: Arc::new(self.data()),
        })
    }
    fn apply(&self, log_id: LogId, command: &ReplicatedCommandV1) -> Result<ApplyResult> {
        let mut d = self
            .inner
            .write()
            .map_err(|_| ChorusError::Storage("state lock poisoned".into()))?;
        let before = d.clone();
        let result = Self::apply_inner(&mut d, log_id, command);
        if result.is_err() {
            *d = before;
        }
        result
    }
    fn install(&self, snapshot: &LogicalSnapshot) -> Result<()> {
        self.install_snapshot(snapshot, true)
    }
    fn rollback(&self, snapshot: &LogicalSnapshot) -> Result<()> {
        self.install_snapshot(snapshot, false)
    }
    fn state_hash(&self) -> Result<[u8; 32]> {
        Ok(self.snapshot()?.state_hash())
    }
    fn status(&self) -> StoreStatus {
        let d = self.data();
        StoreStatus {
            db_epoch: d.db_epoch,
            catalog_epoch: d.catalog_epoch,
            last_applied: d.last_applied,
            state_hash: canonical_state_hash(&d),
            healthy: true,
        }
    }
}

impl MemoryStateStore {
    fn install_snapshot(&self, snapshot: &LogicalSnapshot, enforce_order: bool) -> Result<()> {
        snapshot
            .validate()
            .map_err(|e| ChorusError::Serialization(format!("snapshot validation: {e}")))?;
        let current = self.data();
        if enforce_order && snapshot.header.last_included.index < current.last_applied.index {
            return Err(ChorusError::Protocol(
                "snapshot is older than the applied state".into(),
            ));
        }
        if current.cluster_id != [0; 16] && current.cluster_id != snapshot.header.cluster_id {
            return Err(ChorusError::Protocol(
                "snapshot cluster id does not match the bound store".into(),
            ));
        }
        let mut d = snapshot
            .meta
            .get("state")
            .map(|bytes| {
                serde_json::from_slice::<StateData>(bytes)
                    .map_err(|e| ChorusError::Serialization(format!("snapshot state decode: {e}")))
            })
            .transpose()?
            .unwrap_or_default();
        validate_state_data(&d)?;
        if d.cluster_id != [0; 16] && d.cluster_id != snapshot.header.cluster_id {
            return Err(ChorusError::Protocol("snapshot cluster id mismatch".into()));
        }
        d.format_version = 1;
        d.cluster_id = snapshot.header.cluster_id;
        d.cluster_incarnation = snapshot.header.cluster_incarnation;
        d.db_epoch = snapshot.header.db_epoch;
        d.catalog_epoch = snapshot.header.catalog_epoch;
        d.last_applied = snapshot.header.last_included;
        d.membership = Membership {
            log_id: snapshot.header.membership_log_id,
            voters: snapshot.header.voters.clone(),
            learners: snapshot.header.learners.clone(),
        };
        // The metadata stream is authoritative for catalog, allocator, and
        // origin deduplication state.  Rebuild the logical KV map from the
        // independently checksummed entry stream below.
        d.kv.clear();
        for (k, v) in &snapshot.entries {
            d.kv.insert(k.clone(), v.clone());
        }
        validate_state_data(&d)?;
        *self
            .inner
            .write()
            .map_err(|_| ChorusError::Storage("state lock poisoned".into()))? = d;
        Ok(())
    }
}

/// A crash-safe generation file store.  Writes go to `state.json.tmp`, flush
/// and sync the file, then atomically rename it.  The format is logical and
/// deliberately independent of redb page layout.
#[derive(Clone)]
pub struct FileStateStore {
    path: Arc<PathBuf>,
    memory: MemoryStateStore,
    persist_lock: Arc<Mutex<()>>,
}

impl FileStateStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let memory = if path.exists() {
            let mut f = File::open(&path).map_err(|e| ChorusError::Storage(e.to_string()))?;
            let mut bytes = Vec::new();
            f.read_to_end(&mut bytes)
                .map_err(|e| ChorusError::Storage(e.to_string()))?;
            if bytes.len() > MAX_STATE_FILE_BYTES {
                return Err(ChorusError::Storage("state file exceeds 256 MiB".into()));
            }
            let data = decode_state_file(&bytes)?;
            validate_state_data(&data)?;
            MemoryStateStore::from_data(data)
        } else {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| ChorusError::Storage(e.to_string()))?;
            }
            MemoryStateStore::new()
        };
        Ok(Self {
            path: Arc::new(path),
            memory,
            persist_lock: Arc::new(Mutex::new(())),
        })
    }
    fn persist(&self) -> Result<()> {
        let data = self.memory.data();
        validate_state_data(&data)?;
        let bytes = encode_state_file(&data)?;
        let tmp = self.path.with_extension("tmp");
        let mut f = File::create(&tmp).map_err(|e| ChorusError::Storage(e.to_string()))?;
        f.write_all(&bytes)
            .map_err(|e| ChorusError::Storage(e.to_string()))?;
        f.sync_all()
            .map_err(|e| ChorusError::Storage(e.to_string()))?;
        fs::rename(&tmp, &*self.path).map_err(|e| ChorusError::Storage(e.to_string()))?;
        if let Some(parent) = self.path.parent() {
            File::open(parent)
                .and_then(|dir| dir.sync_all())
                .map_err(|e| ChorusError::Storage(e.to_string()))?;
        }
        Ok(())
    }
    pub fn data(&self) -> StateData {
        self.memory.data()
    }
    pub fn rebase_cluster(&self, cluster_id: [u8; 16], incarnation: u64) -> Result<()> {
        if incarnation == 0 {
            return Err(ChorusError::Protocol(
                "cluster incarnation must be nonzero".into(),
            ));
        }
        let _persist_guard = self
            .persist_lock
            .lock()
            .map_err(|_| ChorusError::Storage("persist lock poisoned".into()))?;
        let before = self.memory.data();
        {
            let mut data = self
                .memory
                .inner
                .write()
                .map_err(|_| ChorusError::Storage("state lock poisoned".into()))?;
            data.cluster_id = cluster_id;
            data.cluster_incarnation = incarnation;
            data.membership = Membership {
                log_id: data.last_applied,
                voters: vec![],
                learners: vec![],
            };
            data.origins.clear();
        }
        if let Err(error) = self.persist() {
            *self
                .memory
                .inner
                .write()
                .map_err(|_| ChorusError::Storage("state lock poisoned".into()))? = before;
            return Err(error);
        }
        Ok(())
    }
    pub fn initialize_cluster(&self, cluster_id: [u8; 16], incarnation: u64) -> Result<()> {
        if incarnation == 0 {
            return Err(ChorusError::Protocol(
                "cluster incarnation must be nonzero".into(),
            ));
        }
        let _persist_guard = self
            .persist_lock
            .lock()
            .map_err(|_| ChorusError::Storage("persist lock poisoned".into()))?;
        let mut data = self
            .memory
            .inner
            .write()
            .map_err(|_| ChorusError::Storage("state lock poisoned".into()))?;
        let needs_init =
            data.cluster_id == [0; 16] && data.last_applied == LogId::ZERO && data.db_epoch == 0;
        if !needs_init {
            if data.cluster_id != cluster_id || data.cluster_incarnation != incarnation {
                return Err(ChorusError::Protocol(
                    "store is already bound to a different cluster".into(),
                ));
            }
            return Ok(());
        }
        let before = data.clone();
        data.cluster_id = cluster_id;
        data.cluster_incarnation = incarnation;
        drop(data);
        if let Err(error) = self.persist() {
            *self
                .memory
                .inner
                .write()
                .map_err(|_| ChorusError::Storage("state lock poisoned".into()))? = before;
            return Err(error);
        }
        Ok(())
    }
}

fn encode_state_file(data: &StateData) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(data).map_err(|e| ChorusError::Storage(e.to_string()))?;
    let required = STATE_FILE_MAGIC
        .len()
        .checked_add(1 + 4 + json.len() + 32)
        .ok_or_else(|| ChorusError::Storage("state file size exhausted".into()))?;
    if required > MAX_STATE_FILE_BYTES {
        return Err(ChorusError::Storage("state file exceeds 256 MiB".into()));
    }
    let mut out = Vec::with_capacity(required);
    out.extend_from_slice(STATE_FILE_MAGIC);
    out.push(STATE_FILE_VERSION);
    out.extend_from_slice(
        &u32::try_from(json.len())
            .map_err(|_| ChorusError::Storage("state file length exceeds u32".into()))?
            .to_be_bytes(),
    );
    out.extend_from_slice(&json);
    out.extend_from_slice(&hash32(&json));
    Ok(out)
}

fn decode_state_file(bytes: &[u8]) -> Result<StateData> {
    if bytes.starts_with(STATE_FILE_MAGIC) {
        let header_len = STATE_FILE_MAGIC.len() + 1 + 4;
        if bytes.len() < header_len + 32 {
            return Err(ChorusError::Storage("truncated state file".into()));
        }
        let version = bytes[STATE_FILE_MAGIC.len()];
        if version != STATE_FILE_VERSION {
            return Err(ChorusError::Storage(format!(
                "unsupported state file version {version}"
            )));
        }
        let len_start = STATE_FILE_MAGIC.len() + 1;
        let len = u32::from_be_bytes(
            bytes[len_start..len_start + 4]
                .try_into()
                .map_err(|_| ChorusError::Storage("invalid state length".into()))?,
        ) as usize;
        let data_start = header_len;
        let data_end = data_start
            .checked_add(len)
            .ok_or_else(|| ChorusError::Storage("state file length exhausted".into()))?;
        if data_end + 32 != bytes.len() {
            return Err(ChorusError::Storage("invalid state file length".into()));
        }
        let json = &bytes[data_start..data_end];
        if hash32(json) != bytes[data_end..] {
            return Err(ChorusError::Storage("state file checksum mismatch".into()));
        }
        return serde_json::from_slice(json)
            .map_err(|e| ChorusError::Storage(format!("state decode: {e}")));
    }
    // Read legacy JSON files once so a rolling upgrade remains possible; all
    // subsequent writes use the checksummed envelope above.
    serde_json::from_slice(bytes).map_err(|e| ChorusError::Storage(format!("state decode: {e}")))
}

fn validate_membership(membership: &Membership) -> Result<()> {
    if membership.voters.len() > 10_000 || membership.learners.len() > 10_000 {
        return Err(ChorusError::Limit("membership size exceeds limit".into()));
    }
    let mut ids = BTreeSet::new();
    for id in membership.voters.iter().chain(&membership.learners) {
        if *id == 0 || !ids.insert(*id) {
            return Err(ChorusError::Protocol(
                "membership contains duplicate or invalid node id".into(),
            ));
        }
    }
    if membership.voters.windows(2).any(|w| w[0] >= w[1])
        || membership.learners.windows(2).any(|w| w[0] >= w[1])
    {
        return Err(ChorusError::Protocol("membership is not sorted".into()));
    }
    Ok(())
}

fn validate_state_data(data: &StateData) -> Result<()> {
    if data.format_version != 1 {
        return Err(ChorusError::Serialization(format!(
            "unsupported state format version {}",
            data.format_version
        )));
    }
    if data.cluster_incarnation == 0 {
        return Err(ChorusError::Protocol(
            "cluster incarnation must be nonzero".into(),
        ));
    }
    validate_membership(&data.membership)?;
    if data.catalog.tables.len() > 1_024 || data.catalog.indexes.len() > 32 * 1_024 {
        return Err(ChorusError::Limit(
            "catalog object count exceeds limit".into(),
        ));
    }
    let mut object_ids = BTreeSet::new();
    let mut max_object_id = 0u32;
    for (oid, table) in &data.catalog.tables {
        if *oid == 0 || *oid != table.oid || !object_ids.insert(*oid) {
            return Err(ChorusError::Serialization("invalid table object id".into()));
        }
        max_object_id = max_object_id.max(*oid);
        if table.schema_oid == 0 || table.name.is_empty() || table.name.len() > 63 {
            return Err(ChorusError::Serialization(
                "invalid table descriptor".into(),
            ));
        }
        if table.columns.is_empty() || table.columns.len() > 256 {
            return Err(ChorusError::Limit("invalid table column count".into()));
        }
        let mut column_ids = BTreeSet::new();
        let mut column_names = BTreeSet::new();
        for column in &table.columns {
            if column.id == 0
                || !column_ids.insert(column.id)
                || column.name.is_empty()
                || column.name.len() > 63
                || !column_names.insert(&column.name)
            {
                return Err(ChorusError::Serialization(
                    "invalid column descriptor".into(),
                ));
            }
            max_object_id = max_object_id.max(column.id);
        }
        if let Some(primary) = table.primary_key {
            if !column_ids.contains(&primary) {
                return Err(ChorusError::Serialization(
                    "primary key references missing column".into(),
                ));
            }
        }
        if table.secondary_indexes.len() > 32
            || table
                .secondary_indexes
                .iter()
                .any(|index| !data.catalog.indexes.contains_key(index))
        {
            return Err(ChorusError::Limit("invalid table index references".into()));
        }
    }
    for (oid, index) in &data.catalog.indexes {
        if *oid == 0 || *oid != index.oid || !object_ids.insert(*oid) {
            return Err(ChorusError::Serialization("invalid index object id".into()));
        }
        max_object_id = max_object_id.max(*oid);
        if index.table_oid == 0 || index.name.is_empty() || index.name.len() > 63 {
            return Err(ChorusError::Serialization(
                "invalid index descriptor".into(),
            ));
        }
        if index.columns.is_empty() || index.columns.len() > 16 {
            return Err(ChorusError::Limit("invalid index column count".into()));
        }
        let table =
            data.catalog.tables.get(&index.table_oid).ok_or_else(|| {
                ChorusError::Serialization("index references missing table".into())
            })?;
        if !table.secondary_indexes.contains(oid) {
            return Err(ChorusError::Serialization(
                "index is not referenced by table".into(),
            ));
        }
        for column in &index.columns {
            if !table.columns.iter().any(|c| c.id == column.column_id) {
                return Err(ChorusError::Serialization(
                    "index references missing column".into(),
                ));
            }
        }
    }
    if max_object_id < u32::MAX && data.catalog.next_object_id <= max_object_id {
        return Err(ChorusError::Serialization(
            "catalog allocator is not ahead of object ids".into(),
        ));
    }
    for (key, value) in &data.kv {
        if key.is_empty() || key.len() > MAX_KEY_BYTES {
            return Err(ChorusError::Limit("physical key exceeds 8 KiB".into()));
        }
        if key.first() == Some(&0x20) && value.len() > MAX_ROW_BYTES {
            return Err(ChorusError::Limit("row exceeds 256 KiB".into()));
        }
    }
    for (node_id, origin) in &data.origins {
        if *node_id == 0 || origin.active_origin.node_id != *node_id {
            return Err(ChorusError::Protocol("invalid origin state".into()));
        }
        if origin.recent_results.len() > 16 {
            return Err(ChorusError::Limit(
                "origin deduplication history exceeds limit".into(),
            ));
        }
    }
    Ok(())
}

impl StateStore for FileStateStore {
    fn snapshot(&self) -> Result<StateSnapshot> {
        self.memory.snapshot()
    }
    fn apply(&self, log_id: LogId, command: &ReplicatedCommandV1) -> Result<ApplyResult> {
        let _persist_guard = self
            .persist_lock
            .lock()
            .map_err(|_| ChorusError::Storage("persist lock poisoned".into()))?;
        let before = self.memory.data();
        let out = self.memory.apply(log_id, command)?;
        if let Err(error) = self.persist() {
            *self
                .memory
                .inner
                .write()
                .map_err(|_| ChorusError::Storage("state lock poisoned".into()))? = before;
            return Err(error);
        }
        Ok(out)
    }
    fn install(&self, snapshot: &LogicalSnapshot) -> Result<()> {
        let _persist_guard = self
            .persist_lock
            .lock()
            .map_err(|_| ChorusError::Storage("persist lock poisoned".into()))?;
        let before = self.memory.data();
        self.memory.install(snapshot)?;
        if let Err(error) = self.persist() {
            *self
                .memory
                .inner
                .write()
                .map_err(|_| ChorusError::Storage("state lock poisoned".into()))? = before;
            return Err(error);
        }
        Ok(())
    }
    fn rollback(&self, snapshot: &LogicalSnapshot) -> Result<()> {
        let _persist_guard = self
            .persist_lock
            .lock()
            .map_err(|_| ChorusError::Storage("persist lock poisoned".into()))?;
        let before = self.memory.data();
        self.memory.rollback(snapshot)?;
        if let Err(error) = self.persist() {
            *self
                .memory
                .inner
                .write()
                .map_err(|_| ChorusError::Storage("state lock poisoned".into()))? = before;
            return Err(error);
        }
        Ok(())
    }
    fn state_hash(&self) -> Result<[u8; 32]> {
        self.memory.state_hash()
    }
    fn status(&self) -> StoreStatus {
        self.memory.status()
    }
}

fn apply_command(
    data: &mut StateData,
    log_id: LogId,
    command: &ReplicatedCommandV1,
) -> Result<ApplyResult> {
    // A replayed entry is terminal at the state-machine boundary. In
    // particular, a stale Noop must not move last_applied backwards.
    // Raft log indexes are globally monotonic even when a new term starts;
    // comparing the derived `(term, index)` ordering alone would allow a
    // higher-term, lower-index adversarial entry to move the state machine
    // cursor backwards.
    if log_id.index <= data.last_applied.index {
        return Ok(ApplyResult::Noop);
    }
    let result = match command {
        ReplicatedCommandV1::Noop => ApplyResult::Noop,
        ReplicatedCommandV1::Membership { voters, learners } => {
            let voters_sorted = voters.windows(2).all(|w| w[0] < w[1]);
            let learners_sorted = learners.windows(2).all(|w| w[0] < w[1]);
            if !voters_sorted
                || !learners_sorted
                || voters.iter().any(|id| learners.binary_search(id).is_ok())
                || voters.contains(&0)
                || learners.contains(&0)
            {
                ApplyResult::Rejected("membership contains overlapping or invalid node ids".into())
            } else {
                data.membership = Membership {
                    log_id,
                    voters: voters.clone(),
                    learners: learners.clone(),
                };
                ApplyResult::Noop
            }
        }
        ReplicatedCommandV1::ActivateOrigin(a) => {
            if !data
                .origins
                .get(&a.origin.node_id)
                .is_some_and(|state| state.active_origin == a.origin)
            {
                data.origins.insert(
                    a.origin.node_id,
                    NodeOriginState {
                        active_origin: a.origin,
                        last_sequence: 0,
                        recent_results: Vec::new(),
                    },
                );
            }
            ApplyResult::Activated
        }
        ReplicatedCommandV1::CommitTransaction(c) => apply_commit(data, log_id, c)?,
        ReplicatedCommandV1::SchemaChange(c) => apply_schema(data, log_id, c)?,
    };
    data.last_applied = log_id;
    Ok(result)
}

fn apply_commit(
    data: &mut StateData,
    log_id: LogId,
    c: &CommitTransactionV1,
) -> Result<ApplyResult> {
    let origin = c.request_id.origin;
    let state = match data.origins.get(&origin.node_id) {
        Some(state) => state,
        None => return Ok(ApplyResult::StaleOrigin),
    };
    if state.active_origin != origin {
        return Ok(ApplyResult::StaleOrigin);
    }
    if let Some(previous) = state
        .recent_results
        .iter()
        .find(|r| r.sequence == c.request_id.sequence)
    {
        if previous.payload_hash == c.payload_hash {
            return Ok(ApplyResult::Duplicate(Box::new(previous.result.clone())));
        }
        return Ok(ApplyResult::ProtocolError(
            "duplicate request has a different payload hash".into(),
        ));
    }
    if c.request_id.sequence <= state.last_sequence {
        return Ok(ApplyResult::AlreadyProcessed);
    }
    let expected_sequence = state
        .last_sequence
        .checked_add(1)
        .ok_or_else(|| ChorusError::Limit("request sequence exhausted".into()))?;
    if c.request_id.sequence != expected_sequence {
        return Ok(ApplyResult::ProtocolError("request sequence gap".into()));
    }
    let canonical =
        canonical_mutations(&c.mutations).map_err(|e| ChorusError::Serialization(e.to_string()))?;
    let expected_hash = payload_hash(1, &c.request_id, c.base_epoch, &canonical);
    if expected_hash != c.payload_hash {
        let result = ApplyResult::ProtocolError("payload hash mismatch".into());
        record_data_result(data, origin, c, result.clone());
        return Ok(result);
    }
    let mut previous_key: Option<&[u8]> = None;
    let mut bytes = 0usize;
    for m in &c.mutations {
        if let Some(k) = previous_key {
            if k >= m.key() {
                let result = ApplyResult::ProtocolError(
                    "mutations are not strictly sorted and unique".into(),
                );
                record_data_result(data, origin, c, result.clone());
                return Ok(result);
            }
        }
        previous_key = Some(m.key());
        bytes = bytes
            .checked_add(m.encoded_len())
            .ok_or_else(|| ChorusError::Limit("transaction mutation size exhausted".into()))?;
        if m.key().len() > 8 * 1024 {
            let result = ApplyResult::Rejected("physical key exceeds limit".into());
            record_data_result(data, origin, c, result.clone());
            return Ok(result);
        }
    }
    if bytes > 4 * 1024 * 1024 || c.mutations.len() > 10_000 {
        let result = ApplyResult::Rejected("transaction mutation limit exceeded".into());
        record_data_result(data, origin, c, result.clone());
        return Ok(result);
    }
    if c.base_epoch != data.db_epoch {
        let result = ApplyResult::SerializationFailure {
            expected: c.base_epoch,
            actual: data.db_epoch,
        };
        record_data_result(data, origin, c, result.clone());
        return Ok(result);
    }
    // Apply is atomic from the caller's perspective: all validation above is
    // complete before mutating the KV map, and the caller rolls the whole
    // state back on an error.  Row-count metadata is maintained from the
    // canonical row key namespace as part of the same state-machine apply.
    for m in &c.mutations {
        match m {
            KvMutationV1::Put { key, value } => {
                validate_physical_mutation(data, key, Some(value))?;
                if is_row_key(key) && !data.kv.contains_key(key) {
                    adjust_row_count(data, key, 1)?;
                }
                data.kv.insert(key.clone(), value.clone());
            }
            KvMutationV1::Delete { key } => {
                validate_physical_mutation(data, key, None)?;
                if is_row_key(key) && data.kv.contains_key(key) {
                    adjust_row_count(data, key, -1)?;
                }
                data.kv.remove(key);
            }
        }
    }
    data.db_epoch = data
        .db_epoch
        .checked_add(1)
        .ok_or_else(|| ChorusError::Limit("database epoch exhausted".into()))?;
    let result = ApplyResult::Committed {
        epoch: data.db_epoch,
        log_id,
    };
    record_data_result(data, origin, c, result.clone());
    Ok(result)
}

fn record_data_result(
    data: &mut StateData,
    origin: OriginId,
    c: &CommitTransactionV1,
    result: ApplyResult,
) {
    if let Some(state) = data.origins.get_mut(&origin.node_id) {
        record_result(state, c, result);
    }
}

fn is_row_key(key: &[u8]) -> bool {
    key.len() >= 5 && key[0] == 0x20
}

fn table_id_from_row_key(key: &[u8]) -> u32 {
    u32::from_be_bytes([key[1], key[2], key[3], key[4]])
}

fn adjust_row_count(data: &mut StateData, key: &[u8], delta: i64) -> Result<()> {
    let table_id = table_id_from_row_key(key);
    let table = data
        .catalog
        .table_mut(table_id)
        .ok_or_else(|| ChorusError::Protocol("row mutation references unknown table".into()))?;
    table.row_count = if delta > 0 {
        table
            .row_count
            .checked_add(delta as u64)
            .ok_or_else(|| ChorusError::Limit("table row count exhausted".into()))?
    } else {
        table
            .row_count
            .checked_sub((-delta) as u64)
            .ok_or_else(|| ChorusError::Protocol("table row count underflow".into()))?
    };
    Ok(())
}

fn validate_physical_mutation(data: &StateData, key: &[u8], value: Option<&[u8]>) -> Result<()> {
    if key.len() < 5 {
        // Metadata adapters may use short, private keys.  User table/index
        // keys are always at least the five-byte prefix plus an object id and
        // are validated below.
        return Ok(());
    }
    match key[0] {
        0x20 => {
            if data.catalog.table(table_id_from_row_key(key)).is_none() {
                return Err(ChorusError::Protocol(
                    "row mutation references unknown table".into(),
                ));
            }
            if let Some(bytes) = value {
                EncodedRowV1::decode(bytes)
                    .map_err(|e| ChorusError::Serialization(e.to_string()))?;
            }
        }
        0x21 | 0x22 => {
            let index_id = u32::from_be_bytes([key[1], key[2], key[3], key[4]]);
            if !data
                .catalog
                .indexes
                .get(&index_id)
                .is_some_and(|i| i.state == ObjectState::Live)
            {
                return Err(ChorusError::Protocol(
                    "index mutation references unknown index".into(),
                ));
            }
        }
        _ => {
            return Err(ChorusError::Protocol(
                "mutation uses an unknown physical key prefix".into(),
            ));
        }
    }
    Ok(())
}

fn record_result(state: &mut NodeOriginState, c: &CommitTransactionV1, result: ApplyResult) {
    state.last_sequence = c.request_id.sequence;
    state.recent_results.push(chorus_codec::RequestResult {
        sequence: c.request_id.sequence,
        payload_hash: c.payload_hash,
        result,
    });
    if state.recent_results.len() > 16 {
        state.recent_results.remove(0);
    }
}

fn apply_schema(
    data: &mut StateData,
    log_id: LogId,
    c: &chorus_codec::SchemaCommandV1,
) -> Result<ApplyResult> {
    let origin = c.request_id.origin;
    {
        let state = match data.origins.get(&origin.node_id) {
            Some(state) => state,
            None => return Ok(ApplyResult::StaleOrigin),
        };
        if state.active_origin != origin {
            return Ok(ApplyResult::StaleOrigin);
        }
        if let Some(previous) = state
            .recent_results
            .iter()
            .find(|r| r.sequence == c.request_id.sequence)
        {
            if previous.payload_hash == c.payload_hash {
                return Ok(ApplyResult::Duplicate(Box::new(previous.result.clone())));
            }
            return Ok(ApplyResult::ProtocolError(
                "duplicate schema payload".into(),
            ));
        }
        let expected_sequence = state
            .last_sequence
            .checked_add(1)
            .ok_or_else(|| ChorusError::Limit("request sequence exhausted".into()))?;
        if c.request_id.sequence != expected_sequence {
            return Ok(if c.request_id.sequence <= state.last_sequence {
                ApplyResult::AlreadyProcessed
            } else {
                ApplyResult::ProtocolError("request sequence gap".into())
            });
        }
    }
    let payload =
        serde_json::to_vec(&c.operation).map_err(|e| ChorusError::Serialization(e.to_string()))?;
    let expected_hash = payload_hash(1, &c.request_id, c.base_epoch, &payload);
    let fake = CommitTransactionV1 {
        request_id: c.request_id,
        payload_hash: c.payload_hash,
        base_epoch: c.base_epoch,
        mutations: Vec::new(),
    };
    if expected_hash != c.payload_hash {
        let result = ApplyResult::ProtocolError("schema payload hash mismatch".into());
        record_result(
            data.origins
                .get_mut(&origin.node_id)
                .expect("origin checked"),
            &fake,
            result.clone(),
        );
        return Ok(result);
    }
    if c.base_epoch != data.db_epoch {
        let result = ApplyResult::SerializationFailure {
            expected: c.base_epoch,
            actual: data.db_epoch,
        };
        record_result(
            data.origins
                .get_mut(&origin.node_id)
                .expect("origin checked"),
            &fake,
            result.clone(),
        );
        return Ok(result);
    }
    let op = c.operation.clone();
    // Schema operations may build indexes by scanning and inserting many
    // entries. Keep a state-data checkpoint so a deterministic rejection
    // cannot leave a partially-built catalog or index behind.
    let before_schema = data.clone();
    let result = match apply_schema_op(data, &op) {
        Ok(result) => result,
        Err(error) => {
            *data = before_schema;
            ApplyResult::Rejected(error.to_string())
        }
    };
    if matches!(result, ApplyResult::Rejected(_)) {
        record_result(
            data.origins
                .get_mut(&origin.node_id)
                .expect("origin checked"),
            &fake,
            result.clone(),
        );
        return Ok(result);
    }
    data.catalog_epoch = data
        .catalog_epoch
        .checked_add(1)
        .ok_or_else(|| ChorusError::Limit("catalog epoch exhausted".into()))?;
    data.db_epoch = data
        .db_epoch
        .checked_add(1)
        .ok_or_else(|| ChorusError::Limit("database epoch exhausted".into()))?;
    let committed = ApplyResult::Committed {
        epoch: data.db_epoch,
        log_id,
    };
    record_result(
        data.origins
            .get_mut(&origin.node_id)
            .expect("origin checked"),
        &fake,
        committed.clone(),
    );
    Ok(committed)
}

fn apply_schema_op(
    data: &mut StateData,
    op: &SchemaOperationV1,
) -> std::result::Result<ApplyResult, SqlError> {
    match op {
        SchemaOperationV1::CreateTable {
            table_id,
            schema_id,
            name,
            schema_version,
            columns,
            primary_key,
        } => {
            if *table_id == 0 || name.is_empty() || name.len() > 63 {
                return Err(SqlError::new("54000", "invalid table identifier"));
            }
            if columns.is_empty() || columns.len() > 256 {
                return Err(SqlError::new("54000", "table must contain 1..256 columns"));
            }
            let mut column_ids = std::collections::BTreeSet::new();
            let mut column_names = std::collections::BTreeSet::new();
            for (id, column_name, _, _, _) in columns {
                if *id == 0
                    || !column_ids.insert(*id)
                    || column_name.is_empty()
                    || column_name.len() > 63
                    || !column_names.insert(column_name)
                {
                    return Err(SqlError::new("42710", "duplicate or invalid column"));
                }
            }
            if primary_key.len() > 16 || primary_key.iter().any(|id| !column_ids.contains(id)) {
                return Err(SqlError::new("42703", "primary key column does not exist"));
            }
            if data.catalog.table_by_name(name).is_some() {
                return Err(SqlError::new("42P07", "relation already exists"));
            }
            let cols = columns
                .iter()
                .map(|(id, n, ty, nullable, default)| ColumnDescriptor {
                    id: *id,
                    name: n.clone(),
                    data_type: *ty,
                    nullable: *nullable,
                    default: default.clone(),
                    state: ColumnState::Live,
                })
                .collect();
            let table_next = checked_next_u32(*table_id, "table object id")?;
            let column_next = columns
                .iter()
                .map(|(id, _, _, _, _)| checked_next_u32(*id, "column object id"))
                .collect::<std::result::Result<Vec<_>, _>>()?
                .into_iter()
                .max()
                .unwrap_or(0);
            data.catalog.next_object_id =
                data.catalog.next_object_id.max(table_next).max(column_next);
            data.catalog.tables.insert(
                *table_id,
                TableDescriptor {
                    oid: *table_id,
                    schema_oid: *schema_id,
                    name: name.clone(),
                    schema_version: *schema_version,
                    columns: cols,
                    primary_key: primary_key.first().copied(),
                    secondary_indexes: Vec::new(),
                    row_count: 0,
                    state: ObjectState::Live,
                },
            );
        }
        SchemaOperationV1::DropTable {
            table_id,
            expected_version,
        } => {
            let index_ids = data
                .catalog
                .table(*table_id)
                .ok_or_else(|| SqlError::new("42P01", "table does not exist"))
                .and_then(|table| {
                    if table.schema_version != *expected_version {
                        Err(SqlError::serialization("table descriptor changed"))
                    } else {
                        Ok(table.secondary_indexes.clone())
                    }
                })?;
            for index_id in &index_ids {
                if let Some(index) = data.catalog.indexes.get_mut(index_id) {
                    index.state = ObjectState::Dropped;
                }
            }
            let t = data
                .catalog
                .table_mut(*table_id)
                .ok_or_else(|| SqlError::new("42P01", "table does not exist"))?;
            t.state = ObjectState::Dropped;
            t.schema_version = checked_next_u32(t.schema_version, "schema version")?;
        }
        SchemaOperationV1::AddColumn {
            table_id,
            column_id,
            expected_version,
            name,
            data_type,
            nullable,
            default,
        } => {
            let t = data
                .catalog
                .table_mut(*table_id)
                .ok_or_else(|| SqlError::new("42P01", "table does not exist"))?;
            if t.schema_version != *expected_version
                || t.columns.iter().any(|c| {
                    (c.name == *name && c.state == ColumnState::Live) || c.id == *column_id
                })
                || *column_id == 0
                || name.is_empty()
                || name.len() > 63
            {
                return Err(SqlError::new(
                    "42701",
                    "column already exists or table changed",
                ));
            }
            t.columns.push(ColumnDescriptor {
                id: *column_id,
                name: name.clone(),
                data_type: *data_type,
                nullable: *nullable,
                default: default.clone(),
                state: ColumnState::Live,
            });
            t.schema_version = checked_next_u32(t.schema_version, "schema version")?;
            data.catalog.next_object_id = data
                .catalog
                .next_object_id
                .max(checked_next_u32(*column_id, "column object id")?);
        }
        SchemaOperationV1::DropColumn {
            table_id,
            column_id,
            expected_version,
        } => {
            let (primary_key, secondary_indexes, schema_version) = data
                .catalog
                .table(*table_id)
                .ok_or_else(|| SqlError::new("42P01", "table does not exist"))
                .map(|table| {
                    (
                        table.primary_key,
                        table.secondary_indexes.clone(),
                        table.schema_version,
                    )
                })?;
            if schema_version != *expected_version {
                return Err(SqlError::serialization("table descriptor changed"));
            }
            let used_by_index = secondary_indexes.iter().any(|index_id| {
                data.catalog.indexes.get(index_id).is_some_and(|index| {
                    index
                        .columns
                        .iter()
                        .any(|column| column.column_id == *column_id)
                })
            });
            if primary_key == Some(*column_id) || used_by_index {
                return Err(SqlError::new(
                    "2BP01",
                    "cannot drop a column used by an index or primary key",
                ));
            }
            let t = data
                .catalog
                .table_mut(*table_id)
                .ok_or_else(|| SqlError::new("42P01", "table does not exist"))?;
            let c = t
                .columns
                .iter_mut()
                .find(|c| c.id == *column_id)
                .ok_or_else(|| SqlError::new("42703", "column does not exist"))?;
            c.state = ColumnState::Dropped;
            t.schema_version = checked_next_u32(t.schema_version, "schema version")?;
        }
        SchemaOperationV1::RenameTable {
            table_id,
            new_name,
            expected_version,
        } => {
            if new_name.is_empty() || new_name.len() > 63 {
                return Err(SqlError::new("42602", "invalid relation name"));
            }
            if data
                .catalog
                .table_by_name(new_name)
                .is_some_and(|table| table.oid != *table_id)
            {
                return Err(SqlError::new("42P07", "relation already exists"));
            }
            let t = data
                .catalog
                .table_mut(*table_id)
                .ok_or_else(|| SqlError::new("42P01", "table does not exist"))?;
            if t.schema_version != *expected_version {
                return Err(SqlError::serialization("table descriptor changed"));
            }
            t.name = new_name.clone();
            t.schema_version = checked_next_u32(t.schema_version, "schema version")?;
        }
        SchemaOperationV1::RenameColumn {
            table_id,
            column_id,
            new_name,
            expected_version,
        } => {
            if new_name.is_empty() || new_name.len() > 63 {
                return Err(SqlError::new("42602", "invalid column name"));
            }
            let (schema_version, duplicate) = data
                .catalog
                .table(*table_id)
                .ok_or_else(|| SqlError::new("42P01", "table does not exist"))
                .map(|table| {
                    (
                        table.schema_version,
                        table.columns.iter().any(|column| {
                            column.state == ColumnState::Live
                                && column.id != *column_id
                                && column.name == *new_name
                        }),
                    )
                })?;
            if schema_version != *expected_version {
                return Err(SqlError::serialization("table descriptor changed"));
            }
            if duplicate {
                return Err(SqlError::new("42701", "column already exists"));
            }
            let t = data
                .catalog
                .table_mut(*table_id)
                .ok_or_else(|| SqlError::new("42P01", "table does not exist"))?;
            if t.schema_version != *expected_version {
                return Err(SqlError::serialization("table descriptor changed"));
            }
            let c = t
                .columns
                .iter_mut()
                .find(|c| c.id == *column_id)
                .ok_or_else(|| SqlError::new("42703", "column does not exist"))?;
            c.name = new_name.clone();
            t.schema_version = checked_next_u32(t.schema_version, "schema version")?;
        }
        SchemaOperationV1::CreateIndex {
            index_id,
            table_id,
            name,
            unique,
            columns,
        } => {
            if *index_id == 0 || name.is_empty() || name.len() > 63 {
                return Err(SqlError::new("54000", "invalid index identifier"));
            }
            if data.catalog.index_by_name(name).is_some() {
                return Err(SqlError::new("42P07", "index already exists"));
            }
            if data.catalog.table(*table_id).is_none() {
                return Err(SqlError::new("42P01", "table does not exist"));
            }
            if columns.is_empty() || columns.len() > 16 {
                return Err(SqlError::new("54000", "index must contain 1..16 columns"));
            }
            let table = data
                .catalog
                .table(*table_id)
                .expect("table checked")
                .clone();
            for (column_id, _) in columns {
                if !table
                    .columns
                    .iter()
                    .any(|c| c.id == *column_id && c.state == ColumnState::Live)
                {
                    return Err(SqlError::new("42703", "index column does not exist"));
                }
            }
            let desc = IndexDescriptor {
                oid: *index_id,
                table_oid: *table_id,
                name: name.clone(),
                columns: columns
                    .iter()
                    .map(|(c, d)| IndexColumn {
                        column_id: *c,
                        descending: *d,
                    })
                    .collect(),
                unique: *unique,
                state: ObjectState::Live,
            };
            // Build the index deterministically while the schema command is
            // still atomic.  A unique index uses a key without the row suffix
            // for non-NULL values, so a duplicate is detected on every
            // replica in the same byte order.
            let row_prefix = [0x20]
                .into_iter()
                .chain(table.oid.to_be_bytes())
                .collect::<Vec<_>>();
            let row_end = chorus_codec::successor(&row_prefix);
            let rows: Vec<_> = data
                .kv
                .range(row_prefix.clone()..)
                .take_while(|(k, _)| row_end.as_deref().map(|e| k.as_slice() < e).unwrap_or(true))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            for (row_key, bytes) in rows {
                let row = EncodedRowV1::decode(&bytes)
                    .map_err(|e| SqlError::new("XX000", e.to_string()))?;
                let key = index_entry_key(&desc, &row, &row_key)
                    .map_err(|e| SqlError::new("XX000", e.to_string()))?;
                if desc.unique && !index_contains_null(&desc, &row) && data.kv.contains_key(&key) {
                    return Err(SqlError::new(
                        "23505",
                        "duplicate key violates unique index",
                    ));
                }
                data.kv.insert(key, Vec::new());
            }
            data.catalog.indexes.insert(*index_id, desc);
            let t = data.catalog.table_mut(*table_id).expect("table checked");
            t.secondary_indexes.push(*index_id);
            t.schema_version = checked_next_u32(t.schema_version, "schema version")?;
            data.catalog.next_object_id = data
                .catalog
                .next_object_id
                .max(checked_next_u32(*index_id, "index object id")?);
        }
        SchemaOperationV1::DropIndex {
            index_id,
            expected_table_version,
        } => {
            let table_id = data
                .catalog
                .indexes
                .get(index_id)
                .ok_or_else(|| SqlError::new("42704", "index does not exist"))?
                .table_oid;
            if data.catalog.table(table_id).map(|t| t.schema_version)
                != Some(*expected_table_version)
            {
                return Err(SqlError::serialization("table descriptor changed"));
            }
            if let Some(i) = data.catalog.indexes.get_mut(index_id) {
                i.state = ObjectState::Dropped;
            }
            let t = data.catalog.table_mut(table_id).expect("table checked");
            t.schema_version = checked_next_u32(t.schema_version, "schema version")?;
        }
    }
    Ok(ApplyResult::Noop)
}

fn index_contains_null(index: &IndexDescriptor, row: &EncodedRowV1) -> bool {
    index
        .columns
        .iter()
        .any(|c| row.get(c.column_id).is_none_or(Datum::is_null))
}

fn checked_next_u32(value: u32, what: &str) -> std::result::Result<u32, SqlError> {
    value
        .checked_add(1)
        .ok_or_else(|| SqlError::new("54000", format!("{what} exhausted")))
}

fn index_entry_key(
    index: &IndexDescriptor,
    row: &EncodedRowV1,
    row_key: &[u8],
) -> std::result::Result<Vec<u8>, chorus_codec::CodecError> {
    let values = index
        .columns
        .iter()
        .map(|c| row.get(c.column_id).cloned().unwrap_or(Datum::Null))
        .collect::<Vec<_>>();
    let descending = index
        .columns
        .iter()
        .map(|c| c.descending)
        .collect::<Vec<_>>();
    let encoded = encode_composite(&values, &descending)?;
    let unique_nonnull = index.unique && !index_contains_null(index, row);
    Ok(
        PhysicalKey::index(index.oid, &encoded, row_key, unique_nonnull)
            .map_err(|e| chorus_codec::CodecError::Malformed(e.to_string()))?
            .0,
    )
}

fn canonical_state_hash(data: &StateData) -> [u8; 32] {
    let bytes = serde_json::to_vec(data).unwrap_or_default();
    hash32(&bytes)
}

pub fn snapshot_from_store(store: &dyn StateStore) -> Result<LogicalSnapshot> {
    let s = store.snapshot()?;
    let data = s.to_data();
    let mut meta = BTreeMap::new();
    meta.insert(
        "state".into(),
        serde_json::to_vec(&data).map_err(|e| ChorusError::Serialization(e.to_string()))?,
    );
    let entries = s.kv().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    LogicalSnapshot::try_new(
        s.cluster_id(),
        data.cluster_incarnation,
        s.last_applied(),
        s.membership().log_id,
        s.membership().voters.clone(),
        s.membership().learners.clone(),
        s.db_epoch(),
        s.catalog_epoch(),
        meta,
        entries,
    )
    .map_err(|e| ChorusError::Serialization(format!("snapshot build: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chorus_common::RequestId;
    fn command(
        origin: OriginId,
        seq: u64,
        epoch: u64,
        key: &[u8],
        val: &[u8],
    ) -> ReplicatedCommandV1 {
        let id = RequestId::new(origin, seq);
        let m = vec![KvMutationV1::Put {
            key: key.to_vec(),
            value: val.to_vec(),
        }];
        let canonical = canonical_mutations(&m).unwrap();
        let h = payload_hash(1, &id, epoch, &canonical);
        ReplicatedCommandV1::CommitTransaction(CommitTransactionV1 {
            request_id: id,
            payload_hash: h,
            base_epoch: epoch,
            mutations: m,
        })
    }
    #[test]
    fn epoch_and_duplicate_are_atomic() {
        let store = MemoryStateStore::new();
        let o = OriginId::new(1);
        store
            .apply(
                LogId { term: 1, index: 1 },
                &ReplicatedCommandV1::ActivateOrigin(chorus_codec::ActivateOriginV1 { origin: o }),
            )
            .unwrap();
        let c = command(o, 1, 0, b"k", b"v");
        let r = store.apply(LogId { term: 1, index: 2 }, &c).unwrap();
        assert!(matches!(r, ApplyResult::Committed { epoch: 1, .. }));
        let r2 = store.apply(LogId { term: 1, index: 3 }, &c).unwrap();
        assert!(matches!(r2, ApplyResult::Duplicate(_)));
        assert_eq!(store.snapshot().unwrap().db_epoch(), 1);
    }
    #[test]
    fn failed_epoch_does_not_mutate() {
        let store = MemoryStateStore::new();
        let o = OriginId::new(1);
        store
            .apply(
                LogId { term: 1, index: 1 },
                &ReplicatedCommandV1::ActivateOrigin(chorus_codec::ActivateOriginV1 { origin: o }),
            )
            .unwrap();
        let c = command(o, 1, 5, b"k", b"v");
        assert!(matches!(
            store.apply(LogId { term: 1, index: 2 }, &c).unwrap(),
            ApplyResult::SerializationFailure { .. }
        ));
        assert!(store.snapshot().unwrap().get(b"k").is_none());
    }

    #[test]
    fn higher_term_lower_index_cannot_regress_cursor() {
        let store = MemoryStateStore::new();
        store
            .apply(LogId { term: 1, index: 5 }, &ReplicatedCommandV1::Noop)
            .unwrap();
        store
            .apply(LogId { term: 2, index: 1 }, &ReplicatedCommandV1::Noop)
            .unwrap();
        assert_eq!(store.snapshot().unwrap().last_applied().index, 5);
    }

    #[test]
    fn logical_snapshot_roundtrip_preserves_catalog_and_origins() {
        let store = MemoryStateStore::new();
        let origin = OriginId::new(3);
        store
            .apply(
                LogId { term: 1, index: 1 },
                &ReplicatedCommandV1::ActivateOrigin(chorus_codec::ActivateOriginV1 { origin }),
            )
            .unwrap();
        let operation = SchemaOperationV1::CreateTable {
            table_id: 100,
            schema_id: 2200,
            name: "snap_test".into(),
            schema_version: 1,
            columns: vec![(101, "id".into(), SqlType::Integer, false, None)],
            primary_key: vec![101],
        };
        let id = RequestId::new(origin, 1);
        let payload = serde_json::to_vec(&operation).unwrap();
        let command = ReplicatedCommandV1::SchemaChange(chorus_codec::SchemaCommandV1 {
            request_id: id,
            payload_hash: payload_hash(1, &id, 0, &payload),
            base_epoch: 0,
            operation,
        });
        store.apply(LogId { term: 1, index: 2 }, &command).unwrap();
        let snapshot = snapshot_from_store(&store).unwrap();
        let restored = MemoryStateStore::new();
        restored.install(&snapshot).unwrap();
        assert_eq!(store.state_hash().unwrap(), restored.state_hash().unwrap());
        assert!(
            restored
                .snapshot()
                .unwrap()
                .catalog()
                .table_by_name("snap_test")
                .is_some()
        );
        assert_eq!(restored.snapshot().unwrap().origins().len(), 1);
    }
}
