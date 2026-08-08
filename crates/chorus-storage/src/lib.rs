#![forbid(unsafe_code)]

//! Local logical state and deterministic state-machine apply.
//!
//! `StateStore` is intentionally narrow: the SQL and transaction crates only
//! see immutable snapshots and atomic command application.  The included
//! memory and file implementations make the repository useful before a redb
//! adapter is introduced, while preserving the same on-disk logical format.

use chorus_codec::{
    ApplyResult, CommitTransactionV1, EncodedRowV1, KvMutationV1, LogicalSnapshot, NodeOriginState,
    PhysicalKey, ReplicatedCommandV1, SchemaOperationV1, encode_command, encode_composite, hash32,
    payload_hash,
};
use chorus_common::{ChorusError, Datum, LogId, OriginId, RequestId, Result, SqlError, SqlType};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

pub const META_DB_EPOCH: &str = "db_epoch";
pub const META_CATALOG_EPOCH: &str = "catalog_epoch";

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
        let mut d = StateData::default();
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
        for (k, v) in &snapshot.entries {
            d.kv.insert(k.clone(), v.clone());
        }
        *self
            .inner
            .write()
            .map_err(|_| ChorusError::Storage("state lock poisoned".into()))? = d;
        Ok(())
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

/// A crash-safe generation file store.  Writes go to `state.json.tmp`, flush
/// and sync the file, then atomically rename it.  The format is logical and
/// deliberately independent of redb page layout.
#[derive(Clone)]
pub struct FileStateStore {
    path: Arc<PathBuf>,
    memory: MemoryStateStore,
}

impl FileStateStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let memory = if path.exists() {
            let mut f = File::open(&path).map_err(|e| ChorusError::Storage(e.to_string()))?;
            let mut bytes = Vec::new();
            f.read_to_end(&mut bytes)
                .map_err(|e| ChorusError::Storage(e.to_string()))?;
            let data: StateData = serde_json::from_slice(&bytes)
                .map_err(|e| ChorusError::Storage(format!("state decode: {e}")))?;
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
        })
    }
    fn persist(&self) -> Result<()> {
        let bytes = serde_json::to_vec(&self.memory.data())
            .map_err(|e| ChorusError::Storage(e.to_string()))?;
        let tmp = self.path.with_extension("tmp");
        let mut f = File::create(&tmp).map_err(|e| ChorusError::Storage(e.to_string()))?;
        f.write_all(&bytes)
            .map_err(|e| ChorusError::Storage(e.to_string()))?;
        f.sync_all()
            .map_err(|e| ChorusError::Storage(e.to_string()))?;
        fs::rename(&tmp, &*self.path).map_err(|e| ChorusError::Storage(e.to_string()))?;
        Ok(())
    }
    pub fn data(&self) -> StateData {
        self.memory.data()
    }
}

impl StateStore for FileStateStore {
    fn snapshot(&self) -> Result<StateSnapshot> {
        self.memory.snapshot()
    }
    fn apply(&self, log_id: LogId, command: &ReplicatedCommandV1) -> Result<ApplyResult> {
        let out = self.memory.apply(log_id, command)?;
        self.persist()?;
        Ok(out)
    }
    fn install(&self, snapshot: &LogicalSnapshot) -> Result<()> {
        self.memory.install(snapshot)?;
        self.persist()
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
    if log_id <= data.last_applied && !matches!(command, ReplicatedCommandV1::Noop) {
        return Ok(ApplyResult::Noop);
    }
    let result = match command {
        ReplicatedCommandV1::Noop => ApplyResult::Noop,
        ReplicatedCommandV1::Membership { voters, learners } => {
            data.membership = Membership {
                log_id,
                voters: sorted_unique(voters),
                learners: sorted_unique(learners),
            };
            ApplyResult::Noop
        }
        ReplicatedCommandV1::ActivateOrigin(a) => {
            data.origins.insert(
                a.origin.node_id,
                NodeOriginState {
                    active_origin: a.origin,
                    last_sequence: 0,
                    recent_results: Vec::new(),
                },
            );
            ApplyResult::Activated
        }
        ReplicatedCommandV1::CommitTransaction(c) => apply_commit(data, log_id, c)?,
        ReplicatedCommandV1::SchemaChange(c) => apply_schema(data, log_id, c)?,
    };
    data.last_applied = log_id;
    Ok(result)
}

fn sorted_unique(values: &[u64]) -> Vec<u64> {
    let mut v = values.to_vec();
    v.sort_unstable();
    v.dedup();
    v
}

fn apply_commit(
    data: &mut StateData,
    log_id: LogId,
    c: &CommitTransactionV1,
) -> Result<ApplyResult> {
    let origin = c.request_id.origin;
    let state = data
        .origins
        .get(&origin.node_id)
        .ok_or_else(|| ChorusError::Protocol("origin is not activated".into()))?;
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
    if c.request_id.sequence != state.last_sequence + 1 {
        return Ok(ApplyResult::ProtocolError("request sequence gap".into()));
    }
    let mut canonical = Vec::new();
    for m in &c.mutations {
        canonical.extend_from_slice(m.key());
        canonical.push(match m {
            KvMutationV1::Put { .. } => 1,
            KvMutationV1::Delete { .. } => 2,
        });
        if let KvMutationV1::Put { value, .. } = m {
            canonical.extend_from_slice(value);
        }
    }
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
        bytes += m.encoded_len();
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
        let state = data
            .origins
            .get(&origin.node_id)
            .ok_or_else(|| ChorusError::Protocol("origin is not activated".into()))?;
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
        if c.request_id.sequence != state.last_sequence + 1 {
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
    let result =
        apply_schema_op(data, &op).unwrap_or_else(|e| ApplyResult::Rejected(e.to_string()));
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
            data.catalog.next_object_id = data.catalog.next_object_id.max(*table_id + 1).max(
                columns
                    .iter()
                    .map(|(id, _, _, _, _)| *id)
                    .max()
                    .unwrap_or(0)
                    + 1,
            );
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
            let t = data
                .catalog
                .table_mut(*table_id)
                .ok_or_else(|| SqlError::new("42P01", "table does not exist"))?;
            if t.schema_version != *expected_version {
                return Err(SqlError::serialization("table descriptor changed"));
            }
            t.state = ObjectState::Dropped;
            t.schema_version += 1;
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
                || t.columns
                    .iter()
                    .any(|c| c.name == *name && c.state == ColumnState::Live)
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
            t.schema_version += 1;
            data.catalog.next_object_id = data.catalog.next_object_id.max(*column_id + 1);
        }
        SchemaOperationV1::DropColumn {
            table_id,
            column_id,
            expected_version,
        } => {
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
            c.state = ColumnState::Dropped;
            t.schema_version += 1;
        }
        SchemaOperationV1::RenameTable {
            table_id,
            new_name,
            expected_version,
        } => {
            let t = data
                .catalog
                .table_mut(*table_id)
                .ok_or_else(|| SqlError::new("42P01", "table does not exist"))?;
            if t.schema_version != *expected_version {
                return Err(SqlError::serialization("table descriptor changed"));
            }
            t.name = new_name.clone();
            t.schema_version += 1;
        }
        SchemaOperationV1::RenameColumn {
            table_id,
            column_id,
            new_name,
            expected_version,
        } => {
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
            t.schema_version += 1;
        }
        SchemaOperationV1::CreateIndex {
            index_id,
            table_id,
            name,
            unique,
            columns,
        } => {
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
            t.schema_version += 1;
            data.catalog.next_object_id = data.catalog.next_object_id.max(*index_id + 1);
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
            t.schema_version += 1;
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
    let mut meta = BTreeMap::new();
    meta.insert(
        "state".into(),
        serde_json::to_vec(&s.to_data()).map_err(|e| ChorusError::Serialization(e.to_string()))?,
    );
    let entries = s.kv().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    Ok(LogicalSnapshot::new(
        s.cluster_id(),
        1,
        s.last_applied(),
        s.membership().log_id,
        s.membership().voters.clone(),
        s.membership().learners.clone(),
        s.db_epoch(),
        s.catalog_epoch(),
        meta,
        entries,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn command(
        store: &MemoryStateStore,
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
        let mut canonical = Vec::new();
        canonical.extend_from_slice(key);
        canonical.push(1);
        canonical.extend_from_slice(val);
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
        let c = command(&store, o, 1, 0, b"k", b"v");
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
        let c = command(&store, o, 1, 5, b"k", b"v");
        assert!(matches!(
            store.apply(LogId { term: 1, index: 2 }, &c).unwrap(),
            ApplyResult::SerializationFailure { .. }
        ));
        assert!(store.snapshot().unwrap().get(b"k").is_none());
    }
}
