#![forbid(unsafe_code)]

//! Versioned, deterministic encodings shared by storage, consensus and the
//! SQL layer.  The codecs are intentionally self-contained rather than using
//! a serializer whose map iteration or enum layout could change underneath a
//! persisted database.

use chorus_common::{
    ChorusError, Datum, LogId, MAX_INDEXED_VALUE_BYTES, MAX_KEY_BYTES, OriginId, RequestId, SqlType,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MEMCOMPARABLE_VERSION: u8 = 1;
pub const ROW_VERSION: u8 = 1;
pub const COMMAND_VERSION: u8 = 1;
pub const SNAPSHOT_VERSION: u16 = 1;
/// The row format is bounded before decoding so a malformed length prefix
/// cannot cause an unbounded allocation in the state machine.
pub const MAX_ROW_BYTES: usize = 256 * 1024;
/// Commands are carried in the Raft log and are bounded by the transaction
/// limits.  The limit also protects the JSON compatibility envelope below.
pub const MAX_COMMAND_BYTES: usize = 4 * 1024 * 1024;
/// A logical snapshot is streamed in production; this in-memory reference
/// codec still rejects bodies larger than the supported snapshot budget.
pub const MAX_SNAPSHOT_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_SNAPSHOT_ENTRIES: usize = 10_000_000;
const SNAPSHOT_BODY_VERSION: u8 = 1;
const SNAPSHOT_STREAM_VERSION: u8 = 2;
const SNAPSHOT_BLOCK_BYTES: usize = 1024 * 1024;
const SNAPSHOT_MAX_BLOCKS: usize = MAX_SNAPSHOT_BYTES / SNAPSHOT_BLOCK_BYTES + 1;
const SNAPSHOT_HEADER_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct PhysicalKey(pub Vec<u8>);

impl PhysicalKey {
    pub fn new(bytes: Vec<u8>) -> Result<Self, CodecError> {
        if bytes.len() > MAX_KEY_BYTES {
            return Err(CodecError::Limit("physical key exceeds 8 KiB".into()));
        }
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn row(table_id: u32, row_key: &[u8]) -> Result<Self, CodecError> {
        let mut out = vec![0x20];
        out.extend_from_slice(&table_id.to_be_bytes());
        out.extend_from_slice(row_key);
        Self::new(out)
    }
    pub fn index(
        index_id: u32,
        index_key: &[u8],
        row_key: &[u8],
        unique: bool,
    ) -> Result<Self, CodecError> {
        let mut out = vec![if unique { 0x22 } else { 0x21 }];
        out.extend_from_slice(&index_id.to_be_bytes());
        out.extend_from_slice(index_key);
        // A non-NULL unique key identifies the indexed value alone.  For a
        // non-unique (or NULL-containing unique) entry the row suffix keeps
        // duplicate values distinct and makes ordered scans possible.
        if !unique {
            out.extend_from_slice(row_key);
        }
        Self::new(out)
    }
    pub fn table_desc(table_id: u32) -> Self {
        Self([0x12].into_iter().chain(table_id.to_be_bytes()).collect())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodecError {
    Truncated,
    InvalidVersion(u64),
    InvalidTag(u8),
    InvalidUtf8,
    InvalidJson(String),
    Limit(String),
    Malformed(String),
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CodecError {}
impl From<CodecError> for ChorusError {
    fn from(e: CodecError) -> Self {
        ChorusError::Serialization(e.to_string())
    }
}

pub fn hash32(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

pub fn payload_hash(
    command_version: u8,
    request_id: &RequestId,
    base_epoch: u64,
    payload: &[u8],
) -> [u8; 32] {
    let mut b = Vec::new();
    b.push(command_version);
    put_u64(&mut b, request_id.origin.node_id);
    b.extend_from_slice(&request_id.origin.boot_nonce);
    put_u64(&mut b, request_id.sequence);
    put_u64(&mut b, base_epoch);
    // Length-frame the command body.  Without this boundary, two different
    // canonical payloads can hash as the same concatenated request prefix.
    put_u64(&mut b, payload.len() as u64);
    b.extend_from_slice(payload);
    hash32(&b)
}

/// Encode one nullable field so lexicographic byte order agrees with the
/// canonical ascending order. NULL is first; variable values use a doubled
/// zero escape and a double-zero terminator.
pub fn encode_memcomparable(d: &Datum) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
    encode_memcomparable_into(&mut out, d, false)?;
    Ok(out)
}

pub fn encode_memcomparable_desc(d: &Datum) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
    encode_memcomparable_into(&mut out, d, true)?;
    Ok(out)
}

fn encode_memcomparable_into(
    out: &mut Vec<u8>,
    d: &Datum,
    descending: bool,
) -> Result<(), CodecError> {
    let start = out.len();
    let (tag, bytes, variable): (u8, Vec<u8>, bool) = match d {
        Datum::Null => (0, Vec::new(), false),
        Datum::Boolean(v) => (1, vec![*v as u8], false),
        // Datum's canonical comparator treats all signed integer widths as
        // one numeric domain.  Normalize to i64 so byte order agrees across
        // Int16/Int32/Int64 as well as within each width.
        Datum::Int16(v) => (2, ((*v as i64) ^ i64::MIN).to_be_bytes().to_vec(), false),
        Datum::Int32(v) => (2, ((*v as i64) ^ i64::MIN).to_be_bytes().to_vec(), false),
        Datum::Int64(v) => (2, ((*v) ^ i64::MIN).to_be_bytes().to_vec(), false),
        Datum::Float64(v) => (5, float_key(*v).to_vec(), false),
        Datum::Date(v) => (
            6,
            ((i32::from_be_bytes(v.to_be_bytes()) ^ i32::MIN).to_be_bytes()).to_vec(),
            false,
        ),
        Datum::Timestamp(v) => (
            7,
            ((i64::from_be_bytes(v.to_be_bytes()) ^ i64::MIN).to_be_bytes()).to_vec(),
            false,
        ),
        Datum::TimestampTz(v) => (
            8,
            ((i64::from_be_bytes(v.to_be_bytes()) ^ i64::MIN).to_be_bytes()).to_vec(),
            false,
        ),
        Datum::Uuid(v) => (9, v.to_vec(), false),
        Datum::Text(v) => (10, v.as_bytes().to_vec(), true),
        Datum::Bytes(v) => (11, v.clone(), true),
        Datum::Jsonb(v) => {
            let canonical =
                Datum::canonical_json(v).map_err(|e| CodecError::InvalidJson(e.message))?;
            (12, canonical.into_bytes(), true)
        }
    };
    if variable && bytes.len() > MAX_INDEXED_VALUE_BYTES {
        return Err(CodecError::Limit(
            "encoded indexed value exceeds 4 KiB".into(),
        ));
    }
    out.push(if descending { !tag } else { tag });
    if variable {
        for b in bytes {
            if b == 0 {
                out.extend_from_slice(&[0, 0xff]);
            } else {
                out.push(b);
            }
        }
        out.extend_from_slice(&[0, 0]);
    } else {
        out.extend_from_slice(&bytes);
    }
    if descending {
        for b in &mut out[start + 1..] {
            *b = !*b;
        }
    }
    if out.len().saturating_sub(start) > MAX_INDEXED_VALUE_BYTES + 2 {
        return Err(CodecError::Limit(
            "encoded indexed value exceeds limit".into(),
        ));
    }
    Ok(())
}

fn float_key(value: f64) -> [u8; 8] {
    let bits = if value.is_nan() {
        f64::NAN.to_bits()
    } else if value == 0.0 {
        // SQL equality treats -0.0 and +0.0 as equal; canonicalize them so
        // the key codec does not split one logical value into two keys.
        0
    } else {
        value.to_bits()
    };
    let transformed = if bits & (1 << 63) != 0 {
        !bits
    } else {
        bits ^ (1 << 63)
    };
    transformed.to_be_bytes()
}

pub fn encode_composite(values: &[Datum], descending: &[bool]) -> Result<Vec<u8>, CodecError> {
    if values.len() != descending.len() {
        return Err(CodecError::Malformed(
            "composite direction count mismatch".into(),
        ));
    }
    let mut out = Vec::new();
    for (v, d) in values.iter().zip(descending) {
        encode_memcomparable_into(&mut out, v, *d)?;
    }
    if out.len() > MAX_KEY_BYTES {
        return Err(CodecError::Limit("composite key exceeds 8 KiB".into()));
    }
    Ok(out)
}

pub fn successor(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut v = prefix.to_vec();
    for i in (0..v.len()).rev() {
        if v[i] != 0xff {
            v[i] += 1;
            v.truncate(i + 1);
            return Some(v);
        }
    }
    None
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EncodedRowV1 {
    pub format_version: u8,
    pub schema_version: u32,
    pub fields: Vec<(u32, Datum)>,
}

impl EncodedRowV1 {
    pub fn new(schema_version: u32, mut fields: Vec<(u32, Datum)>) -> Result<Self, CodecError> {
        if fields.len() > 256 {
            return Err(CodecError::Limit("too many row fields".into()));
        }
        // JSONB is a logical value, so canonicalize it before it becomes
        // durable. This keeps equivalent JSON values from receiving
        // different state hashes or index keys.
        for (_, datum) in &mut fields {
            if let Datum::Jsonb(value) = datum {
                *value =
                    Datum::canonical_json(value).map_err(|e| CodecError::InvalidJson(e.message))?;
            }
        }
        fields.sort_by_key(|(id, _)| *id);
        for w in fields.windows(2) {
            if w[0].0 == w[1].0 {
                return Err(CodecError::Malformed("duplicate column id".into()));
            }
        }
        let mut encoded_bytes = 1usize + 4 + 4;
        for (_, datum) in &fields {
            let payload_len = datum_payload_len(datum)?;
            encoded_bytes = encoded_bytes
                .checked_add(4 + 1 + 4 + payload_len)
                .ok_or_else(|| CodecError::Limit("row size exhausted".into()))?;
        }
        if encoded_bytes > MAX_ROW_BYTES {
            return Err(CodecError::Limit("encoded row exceeds 256 KiB".into()));
        }
        Ok(Self {
            format_version: ROW_VERSION,
            schema_version,
            fields,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if self.format_version != ROW_VERSION {
            return Err(CodecError::InvalidVersion(self.format_version as u64));
        }
        if self.fields.len() > 256 {
            return Err(CodecError::Limit("too many row fields".into()));
        }
        let mut out = vec![self.format_version];
        put_u32(&mut out, self.schema_version);
        put_u32(
            &mut out,
            u32::try_from(self.fields.len())
                .map_err(|_| CodecError::Limit("too many row fields".into()))?,
        );
        for (id, d) in &self.fields {
            put_u32(&mut out, *id);
            encode_datum(&mut out, d)?;
        }
        if out.len() > MAX_ROW_BYTES {
            return Err(CodecError::Limit("encoded row exceeds 256 KiB".into()));
        }
        Ok(out)
    }
    pub fn decode(mut bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() > MAX_ROW_BYTES {
            return Err(CodecError::Limit("encoded row exceeds 256 KiB".into()));
        }
        let version = take_u8(&mut bytes)?;
        if version != ROW_VERSION {
            return Err(CodecError::InvalidVersion(version as u64));
        }
        let schema = take_u32(&mut bytes)?;
        let n = take_u32(&mut bytes)? as usize;
        if n > 256 {
            return Err(CodecError::Limit("too many row fields".into()));
        }
        let mut fields = Vec::with_capacity(n);
        for _ in 0..n {
            fields.push((take_u32(&mut bytes)?, decode_datum(&mut bytes)?));
        }
        if !bytes.is_empty() {
            return Err(CodecError::Malformed("trailing row bytes".into()));
        }
        Self::new(schema, fields)
    }
    pub fn get(&self, column_id: u32) -> Option<&Datum> {
        self.fields
            .binary_search_by_key(&column_id, |(id, _)| *id)
            .ok()
            .map(|i| &self.fields[i].1)
    }
}

fn encode_datum(out: &mut Vec<u8>, d: &Datum) -> Result<(), CodecError> {
    let (tag, payload) = match d {
        Datum::Null => (0, Vec::new()),
        Datum::Boolean(v) => (1, vec![*v as u8]),
        Datum::Int16(v) => (2, v.to_be_bytes().to_vec()),
        Datum::Int32(v) => (3, v.to_be_bytes().to_vec()),
        Datum::Int64(v) => (4, v.to_be_bytes().to_vec()),
        Datum::Float64(v) => (5, v.to_bits().to_be_bytes().to_vec()),
        Datum::Text(v) => (6, v.as_bytes().to_vec()),
        Datum::Bytes(v) => (7, v.clone()),
        Datum::Date(v) => (8, v.to_be_bytes().to_vec()),
        Datum::Timestamp(v) => (9, v.to_be_bytes().to_vec()),
        Datum::TimestampTz(v) => (10, v.to_be_bytes().to_vec()),
        Datum::Uuid(v) => (11, v.to_vec()),
        Datum::Jsonb(v) => {
            let canonical =
                Datum::canonical_json(v).map_err(|e| CodecError::InvalidJson(e.message))?;
            (12, canonical.into_bytes())
        }
    };
    if payload.len() > MAX_ROW_BYTES {
        return Err(CodecError::Limit("datum exceeds row limit".into()));
    }
    out.push(tag);
    put_u32(
        out,
        u32::try_from(payload.len())
            .map_err(|_| CodecError::Limit("datum length exceeds u32".into()))?,
    );
    out.extend_from_slice(&payload);
    Ok(())
}

fn datum_payload_len(d: &Datum) -> Result<usize, CodecError> {
    let len = match d {
        Datum::Null => 0,
        Datum::Boolean(_) => 1,
        Datum::Int16(_) => 2,
        Datum::Int32(_) | Datum::Date(_) => 4,
        Datum::Int64(_) | Datum::Float64(_) | Datum::Timestamp(_) | Datum::TimestampTz(_) => 8,
        Datum::Uuid(_) => 16,
        Datum::Text(v) => v.len(),
        Datum::Bytes(v) => v.len(),
        Datum::Jsonb(v) => Datum::canonical_json(v)
            .map_err(|e| CodecError::InvalidJson(e.message))?
            .len(),
    };
    if len > MAX_ROW_BYTES {
        return Err(CodecError::Limit("datum exceeds row limit".into()));
    }
    Ok(len)
}

/// Encode one logical datum using the stable row-datum representation. The
/// storage hash uses this helper instead of serializer output.
pub fn encode_datum_v1(d: &Datum) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
    encode_datum(&mut out, d)?;
    Ok(out)
}
fn decode_datum(input: &mut &[u8]) -> Result<Datum, CodecError> {
    let tag = take_u8(input)?;
    let len = take_u32(input)? as usize;
    if len > MAX_ROW_BYTES {
        return Err(CodecError::Limit("datum exceeds limit".into()));
    }
    let p = take(input, len)?;
    let wrong = || CodecError::Malformed("invalid datum length".into());
    Ok(match tag {
        0 if len == 0 => Datum::Null,
        1 if len == 1 && p[0] <= 1 => Datum::Boolean(p[0] != 0),
        2 if len == 2 => Datum::Int16(i16::from_be_bytes([p[0], p[1]])),
        3 if len == 4 => Datum::Int32(i32::from_be_bytes(p.try_into().map_err(|_| wrong())?)),
        4 if len == 8 => Datum::Int64(i64::from_be_bytes(p.try_into().map_err(|_| wrong())?)),
        5 if len == 8 => Datum::Float64(f64::from_bits(u64::from_be_bytes(
            p.try_into().map_err(|_| wrong())?,
        ))),
        6 => Datum::Text(String::from_utf8(p.to_vec()).map_err(|_| CodecError::InvalidUtf8)?),
        7 => Datum::Bytes(p.to_vec()),
        8 if len == 4 => Datum::Date(i32::from_be_bytes(p.try_into().map_err(|_| wrong())?)),
        9 if len == 8 => Datum::Timestamp(i64::from_be_bytes(p.try_into().map_err(|_| wrong())?)),
        10 if len == 8 => {
            Datum::TimestampTz(i64::from_be_bytes(p.try_into().map_err(|_| wrong())?))
        }
        11 if len == 16 => Datum::Uuid(p.try_into().map_err(|_| wrong())?),
        12 => {
            let s = String::from_utf8(p.to_vec()).map_err(|_| CodecError::InvalidUtf8)?;
            Datum::Jsonb(
                chorus_common::Datum::canonical_json(&s)
                    .map_err(|e| CodecError::InvalidJson(e.message))?,
            )
        }
        _ => return Err(CodecError::InvalidTag(tag)),
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum KvMutationV1 {
    Put { key: Vec<u8>, value: Vec<u8> },
    Delete { key: Vec<u8> },
}

impl KvMutationV1 {
    pub fn key(&self) -> &[u8] {
        match self {
            Self::Put { key, .. } | Self::Delete { key } => key,
        }
    }
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::Put { key, value } => 1 + 4 + key.len() + 4 + value.len(),
            Self::Delete { key } => 1 + 4 + key.len(),
        }
    }
}

/// Canonical, length-framed mutation bytes used by the replicated payload
/// hash.  Framing every key/value prevents ambiguous concatenations such as
/// `(key="ab", value="c")` and `(key="a", value="bc")` from sharing a
/// digest, while sorting makes the hash independent of producer iteration
/// order.
pub fn canonical_mutations(mutations: &[KvMutationV1]) -> Result<Vec<u8>, CodecError> {
    let mut ordered = mutations.to_vec();
    ordered.sort_by(|a, b| {
        a.key().cmp(b.key()).then_with(|| match (a, b) {
            (KvMutationV1::Put { value: av, .. }, KvMutationV1::Put { value: bv, .. }) => {
                av.cmp(bv)
            }
            (KvMutationV1::Delete { .. }, KvMutationV1::Delete { .. }) => std::cmp::Ordering::Equal,
            (KvMutationV1::Put { .. }, KvMutationV1::Delete { .. }) => std::cmp::Ordering::Less,
            (KvMutationV1::Delete { .. }, KvMutationV1::Put { .. }) => std::cmp::Ordering::Greater,
        })
    });
    let mut out = Vec::new();
    put_u32(
        &mut out,
        u32::try_from(ordered.len()).map_err(|_| CodecError::Limit("too many mutations".into()))?,
    );
    for mutation in ordered {
        out.push(match mutation {
            KvMutationV1::Put { .. } => 1,
            KvMutationV1::Delete { .. } => 2,
        });
        put_u32(
            &mut out,
            u32::try_from(mutation.key().len())
                .map_err(|_| CodecError::Limit("mutation key exceeds u32".into()))?,
        );
        out.extend_from_slice(mutation.key());
        if let KvMutationV1::Put { value, .. } = mutation {
            put_u32(
                &mut out,
                u32::try_from(value.len())
                    .map_err(|_| CodecError::Limit("mutation value exceeds u32".into()))?,
            );
            out.extend_from_slice(&value);
        }
        if out.len() > MAX_COMMAND_BYTES {
            return Err(CodecError::Limit(
                "canonical mutation payload exceeds 4 MiB".into(),
            ));
        }
    }
    Ok(out)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SchemaOperationV1 {
    CreateTable {
        table_id: u32,
        schema_id: u32,
        name: String,
        schema_version: u32,
        columns: Vec<(u32, String, SqlType, bool, Option<Datum>)>,
        primary_key: Vec<u32>,
    },
    DropTable {
        table_id: u32,
        expected_version: u32,
    },
    AddColumn {
        table_id: u32,
        column_id: u32,
        expected_version: u32,
        name: String,
        data_type: SqlType,
        nullable: bool,
        default: Option<Datum>,
    },
    DropColumn {
        table_id: u32,
        column_id: u32,
        expected_version: u32,
    },
    RenameTable {
        table_id: u32,
        new_name: String,
        expected_version: u32,
    },
    RenameColumn {
        table_id: u32,
        column_id: u32,
        new_name: String,
        expected_version: u32,
    },
    CreateIndex {
        index_id: u32,
        table_id: u32,
        name: String,
        unique: bool,
        columns: Vec<(u32, bool)>,
    },
    DropIndex {
        index_id: u32,
        expected_table_version: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActivateOriginV1 {
    pub origin: OriginId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommitTransactionV1 {
    pub request_id: RequestId,
    pub payload_hash: [u8; 32],
    pub base_epoch: u64,
    pub mutations: Vec<KvMutationV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SchemaCommandV1 {
    pub request_id: RequestId,
    pub payload_hash: [u8; 32],
    pub base_epoch: u64,
    pub operation: SchemaOperationV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ReplicatedCommandV1 {
    Noop,
    ActivateOrigin(ActivateOriginV1),
    CommitTransaction(CommitTransactionV1),
    SchemaChange(SchemaCommandV1),
    Membership {
        voters: Vec<u64>,
        learners: Vec<u64>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ApplyResult {
    Noop,
    Activated,
    Committed { epoch: u64, log_id: LogId },
    SerializationFailure { expected: u64, actual: u64 },
    Duplicate(Box<ApplyResult>),
    StaleOrigin,
    AlreadyProcessed,
    ProtocolError(String),
    Rejected(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NodeOriginState {
    pub active_origin: OriginId,
    pub last_sequence: u64,
    pub recent_results: Vec<RequestResult>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RequestResult {
    pub sequence: u64,
    pub payload_hash: [u8; 32],
    pub result: ApplyResult,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnapshotHeader {
    pub format_version: u16,
    pub cluster_id: [u8; 16],
    pub cluster_incarnation: u64,
    pub last_included: LogId,
    pub membership_log_id: LogId,
    pub voters: Vec<u64>,
    pub learners: Vec<u64>,
    pub db_epoch: u64,
    pub catalog_epoch: u64,
    pub entry_count: u64,
    pub uncompressed_bytes: u64,
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LogicalSnapshot {
    pub header: SnapshotHeader,
    pub meta: BTreeMap<String, Vec<u8>>,
    pub entries: Vec<(Vec<u8>, Vec<u8>)>,
}

impl LogicalSnapshot {
    pub fn new(
        cluster_id: [u8; 16],
        cluster_incarnation: u64,
        last_included: LogId,
        membership_log_id: LogId,
        voters: Vec<u64>,
        learners: Vec<u64>,
        db_epoch: u64,
        catalog_epoch: u64,
        meta: BTreeMap<String, Vec<u8>>,
        mut entries: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Self {
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let body = snapshot_body(&meta, &entries).unwrap_or_default();
        let digest = hash32(&body);
        let count = entries.len() as u64;
        Self {
            header: SnapshotHeader {
                format_version: SNAPSHOT_VERSION,
                cluster_id,
                cluster_incarnation,
                last_included,
                membership_log_id,
                voters,
                learners,
                db_epoch,
                catalog_epoch,
                entry_count: count,
                uncompressed_bytes: body.len() as u64,
                digest,
            },
            meta,
            entries,
        }
    }
    pub fn try_new(
        cluster_id: [u8; 16],
        cluster_incarnation: u64,
        last_included: LogId,
        membership_log_id: LogId,
        voters: Vec<u64>,
        learners: Vec<u64>,
        db_epoch: u64,
        catalog_epoch: u64,
        meta: BTreeMap<String, Vec<u8>>,
        entries: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<Self, CodecError> {
        let snapshot = Self::new(
            cluster_id,
            cluster_incarnation,
            last_included,
            membership_log_id,
            voters,
            learners,
            db_epoch,
            catalog_epoch,
            meta,
            entries,
        );
        snapshot.validate()?;
        Ok(snapshot)
    }
    pub fn validate(&self) -> Result<(), CodecError> {
        if self.header.format_version != SNAPSHOT_VERSION {
            return Err(CodecError::InvalidVersion(
                self.header.format_version as u64,
            ));
        }
        if self.header.cluster_incarnation == 0 {
            return Err(CodecError::Malformed(
                "snapshot cluster incarnation must be nonzero".into(),
            ));
        }
        if self.header.membership_log_id.index > self.header.last_included.index {
            return Err(CodecError::Malformed(
                "snapshot membership log is newer than the included log".into(),
            ));
        }
        validate_membership(&self.header.voters, &self.header.learners)?;
        if self.entries.len() > MAX_SNAPSHOT_ENTRIES {
            return Err(CodecError::Limit("too many snapshot entries".into()));
        }
        for (key, _) in &self.entries {
            if key.is_empty() || key.len() > MAX_KEY_BYTES {
                return Err(CodecError::Limit("snapshot key exceeds 8 KiB".into()));
            }
        }
        for pair in self.entries.windows(2) {
            if pair[0].0 >= pair[1].0 {
                return Err(CodecError::Malformed(
                    "snapshot entries are not strictly sorted".into(),
                ));
            }
        }
        for key in self.meta.keys() {
            if key.is_empty() || key.len() > 63 {
                return Err(CodecError::Malformed(
                    "invalid snapshot metadata key".into(),
                ));
            }
        }
        let body = snapshot_body(&self.meta, &self.entries)?;
        if self.header.entry_count != self.entries.len() as u64 {
            return Err(CodecError::Malformed(
                "snapshot entry count mismatch".into(),
            ));
        }
        if self.header.uncompressed_bytes != body.len() as u64 {
            return Err(CodecError::Malformed("snapshot byte count mismatch".into()));
        }
        if hash32(&body) != self.header.digest {
            return Err(CodecError::Malformed(
                "snapshot logical digest mismatch".into(),
            ));
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        encode_snapshot_stream(self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(CodecError::Limit("snapshot exceeds 256 MiB".into()));
        }
        if bytes.len() < 16 + 4 + 32 {
            return Err(CodecError::Malformed("invalid snapshot magic".into()));
        }
        if &bytes[..16] == SNAPSHOT_STREAM_MAGIC {
            return decode_snapshot_stream(bytes);
        }
        if &bytes[..16] != SNAPSHOT_MAGIC {
            return Err(CodecError::Malformed("invalid snapshot magic".into()));
        }
        let mut rest = &bytes[16..];
        let len = take_u32(&mut rest)? as usize;
        let data = take(&mut rest, len)?;
        let digest = take(&mut rest, 32)?;
        if hash32(data) != digest {
            return Err(CodecError::Malformed("snapshot checksum mismatch".into()));
        }
        if !rest.is_empty() {
            return Err(CodecError::Malformed("trailing snapshot bytes".into()));
        }
        let s: Self =
            serde_json::from_slice(data).map_err(|e| CodecError::Malformed(e.to_string()))?;
        s.validate()?;
        Ok(s)
    }
}

const SNAPSHOT_MAGIC: &[u8; 16] = b"CHORUS-SNAPSHOT\0";
const SNAPSHOT_STREAM_MAGIC: &[u8; 16] = b"CHORUS-SNAP2\0\0\0\0";

fn encode_snapshot_stream(snapshot: &LogicalSnapshot) -> Result<Vec<u8>, CodecError> {
    let body = snapshot_body(&snapshot.meta, &snapshot.entries)?;
    if body.len() > MAX_SNAPSHOT_BYTES {
        return Err(CodecError::Limit("snapshot body exceeds 256 MiB".into()));
    }
    let header = serde_json::to_vec(&snapshot.header)
        .map_err(|error| CodecError::Malformed(format!("snapshot header encode: {error}")))?;
    if header.len() > SNAPSHOT_HEADER_BYTES {
        return Err(CodecError::Limit(
            "snapshot header exceeds configured bound".into(),
        ));
    }
    let block_count = body.len().div_ceil(SNAPSHOT_BLOCK_BYTES);
    if block_count == 0 || block_count > SNAPSHOT_MAX_BLOCKS {
        return Err(CodecError::Limit(
            "snapshot block count exceeds configured bound".into(),
        ));
    }
    let mut out = Vec::new();
    out.extend_from_slice(SNAPSHOT_STREAM_MAGIC);
    out.push(SNAPSHOT_STREAM_VERSION);
    put_u32(
        &mut out,
        u32::try_from(header.len())
            .map_err(|_| CodecError::Limit("snapshot header length exceeds u32".into()))?,
    );
    out.extend_from_slice(&header);
    put_u32(
        &mut out,
        u32::try_from(block_count)
            .map_err(|_| CodecError::Limit("snapshot block count exceeds u32".into()))?,
    );
    for chunk in body.chunks(SNAPSHOT_BLOCK_BYTES) {
        let compressed = zstd::bulk::compress(chunk, 1)
            .map_err(|error| CodecError::Malformed(format!("snapshot compression: {error}")))?;
        put_u32(
            &mut out,
            u32::try_from(chunk.len())
                .map_err(|_| CodecError::Limit("snapshot block length exceeds u32".into()))?,
        );
        put_u32(
            &mut out,
            u32::try_from(compressed.len()).map_err(|_| {
                CodecError::Limit("compressed snapshot block length exceeds u32".into())
            })?,
        );
        out.extend_from_slice(&hash32(chunk));
        out.extend_from_slice(&compressed);
        if out.len() > MAX_SNAPSHOT_BYTES {
            return Err(CodecError::Limit("snapshot exceeds 256 MiB".into()));
        }
    }
    // The footer is independent of the per-block checksums and proves that
    // the decoded logical stream is exactly the stream named by the header.
    out.extend_from_slice(&hash32(&body));
    if out.len() > MAX_SNAPSHOT_BYTES {
        return Err(CodecError::Limit("snapshot exceeds 256 MiB".into()));
    }
    Ok(out)
}

fn decode_snapshot_stream(bytes: &[u8]) -> Result<LogicalSnapshot, CodecError> {
    let mut rest = &bytes[16..];
    let stream_version = take_u8(&mut rest)?;
    if stream_version != SNAPSHOT_STREAM_VERSION {
        return Err(CodecError::InvalidVersion(stream_version as u64));
    }
    let header_len = take_u32(&mut rest)? as usize;
    if header_len == 0 || header_len > SNAPSHOT_HEADER_BYTES {
        return Err(CodecError::Limit(
            "snapshot header exceeds configured bound".into(),
        ));
    }
    let header_bytes = take(&mut rest, header_len)?;
    let header: SnapshotHeader = serde_json::from_slice(header_bytes)
        .map_err(|error| CodecError::Malformed(format!("snapshot header decode: {error}")))?;
    let block_count = take_u32(&mut rest)? as usize;
    if block_count == 0 || block_count > SNAPSHOT_MAX_BLOCKS {
        return Err(CodecError::Limit(
            "snapshot block count exceeds configured bound".into(),
        ));
    }
    let mut body = Vec::new();
    for _ in 0..block_count {
        let uncompressed_len = take_u32(&mut rest)? as usize;
        let compressed_len = take_u32(&mut rest)? as usize;
        if uncompressed_len == 0 || uncompressed_len > SNAPSHOT_BLOCK_BYTES {
            return Err(CodecError::Limit(
                "snapshot block has an invalid uncompressed length".into(),
            ));
        }
        if compressed_len == 0 || compressed_len > MAX_SNAPSHOT_BYTES {
            return Err(CodecError::Limit(
                "snapshot block has an invalid compressed length".into(),
            ));
        }
        let expected_digest: [u8; 32] = take(&mut rest, 32)?
            .try_into()
            .map_err(|_| CodecError::Truncated)?;
        let compressed = take(&mut rest, compressed_len)?;
        let decoded = zstd::bulk::decompress(compressed, uncompressed_len)
            .map_err(|error| CodecError::Malformed(format!("snapshot decompression: {error}")))?;
        if decoded.len() != uncompressed_len || hash32(&decoded) != expected_digest {
            return Err(CodecError::Malformed(
                "snapshot block checksum or length mismatch".into(),
            ));
        }
        body.extend_from_slice(&decoded);
        if body.len() > MAX_SNAPSHOT_BYTES {
            return Err(CodecError::Limit("snapshot body exceeds 256 MiB".into()));
        }
    }
    let footer: [u8; 32] = take(&mut rest, 32)?
        .try_into()
        .map_err(|_| CodecError::Truncated)?;
    if !rest.is_empty() {
        return Err(CodecError::Malformed("trailing snapshot bytes".into()));
    }
    if footer != hash32(&body) || footer != header.digest {
        return Err(CodecError::Malformed(
            "snapshot logical digest mismatch".into(),
        ));
    }
    let (meta, entries) = decode_snapshot_body(&body)?;
    let snapshot = LogicalSnapshot {
        header,
        meta,
        entries,
    };
    snapshot.validate()?;
    Ok(snapshot)
}

fn validate_membership(voters: &[u64], learners: &[u64]) -> Result<(), CodecError> {
    if voters.len() > 10_000 || learners.len() > 10_000 {
        return Err(CodecError::Limit("invalid snapshot membership size".into()));
    }
    let mut all = BTreeSet::new();
    for id in voters.iter().chain(learners) {
        if *id == 0 || !all.insert(*id) {
            return Err(CodecError::Malformed(
                "snapshot membership contains duplicate or invalid node id".into(),
            ));
        }
    }
    if voters.windows(2).any(|w| w[0] >= w[1]) || learners.windows(2).any(|w| w[0] >= w[1]) {
        return Err(CodecError::Malformed(
            "snapshot membership is not sorted".into(),
        ));
    }
    Ok(())
}

fn snapshot_body(
    meta: &BTreeMap<String, Vec<u8>>,
    entries: &[(Vec<u8>, Vec<u8>)],
) -> Result<Vec<u8>, CodecError> {
    if entries.len() > MAX_SNAPSHOT_ENTRIES {
        return Err(CodecError::Limit("too many snapshot entries".into()));
    }
    let mut out = Vec::new();
    out.push(SNAPSHOT_BODY_VERSION);
    put_u32(
        &mut out,
        u32::try_from(meta.len())
            .map_err(|_| CodecError::Limit("too many snapshot metadata records".into()))?,
    );
    for (key, value) in meta {
        push_blob(&mut out, key.as_bytes())?;
        push_blob(&mut out, value)?;
    }
    put_u32(
        &mut out,
        u32::try_from(entries.len())
            .map_err(|_| CodecError::Limit("too many snapshot entries".into()))?,
    );
    for (key, value) in entries {
        push_blob(&mut out, key)?;
        push_blob(&mut out, value)?;
    }
    Ok(out)
}

fn decode_snapshot_body(
    mut input: &[u8],
) -> Result<(BTreeMap<String, Vec<u8>>, Vec<(Vec<u8>, Vec<u8>)>), CodecError> {
    let body_version = take_u8(&mut input)?;
    if body_version != SNAPSHOT_BODY_VERSION {
        return Err(CodecError::InvalidVersion(body_version as u64));
    }
    let meta_count = take_u32(&mut input)? as usize;
    if meta_count > 1_000_000 {
        return Err(CodecError::Limit(
            "snapshot metadata record count exceeds configured bound".into(),
        ));
    }
    let mut meta = BTreeMap::new();
    for _ in 0..meta_count {
        let key = take_blob(&mut input)?;
        let key = String::from_utf8(key).map_err(|_| CodecError::InvalidUtf8)?;
        if key.is_empty() || key.len() > 63 || meta.contains_key(&key) {
            return Err(CodecError::Malformed(
                "snapshot metadata key is invalid or duplicated".into(),
            ));
        }
        meta.insert(key, take_blob(&mut input)?);
    }
    let entry_count = take_u32(&mut input)? as usize;
    if entry_count > MAX_SNAPSHOT_ENTRIES {
        return Err(CodecError::Limit("too many snapshot entries".into()));
    }
    let mut entries = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        let key = take_blob(&mut input)?;
        if key.is_empty() || key.len() > MAX_KEY_BYTES {
            return Err(CodecError::Limit("snapshot key exceeds 8 KiB".into()));
        }
        let value = take_blob(&mut input)?;
        entries.push((key, value));
    }
    if !input.is_empty() {
        return Err(CodecError::Malformed("trailing snapshot body bytes".into()));
    }
    Ok((meta, entries))
}

fn take_blob(input: &mut &[u8]) -> Result<Vec<u8>, CodecError> {
    let len = take_u32(input)? as usize;
    if len > MAX_SNAPSHOT_BYTES {
        return Err(CodecError::Limit(
            "snapshot field exceeds configured bound".into(),
        ));
    }
    Ok(take(input, len)?.to_vec())
}

fn push_blob(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CodecError> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| CodecError::Limit("snapshot field length exceeds u32".into()))?;
    let required = 4usize
        .checked_add(bytes.len())
        .and_then(|n| out.len().checked_add(n))
        .ok_or_else(|| CodecError::Limit("snapshot size exhausted".into()))?;
    if required > MAX_SNAPSHOT_BYTES {
        return Err(CodecError::Limit("snapshot exceeds 256 MiB".into()));
    }
    put_u32(out, len);
    out.extend_from_slice(bytes);
    Ok(())
}

pub fn encode_command(command: &ReplicatedCommandV1) -> Result<Vec<u8>, CodecError> {
    let data = serde_json::to_vec(command).map_err(|e| CodecError::Malformed(e.to_string()))?;
    if data.len() > MAX_COMMAND_BYTES {
        return Err(CodecError::Limit("command exceeds 4 MiB".into()));
    }
    let mut out = vec![COMMAND_VERSION];
    put_u32(
        &mut out,
        u32::try_from(data.len())
            .map_err(|_| CodecError::Limit("command length exceeds u32".into()))?,
    );
    out.extend_from_slice(&data);
    Ok(out)
}
pub fn decode_command(bytes: &[u8]) -> Result<ReplicatedCommandV1, CodecError> {
    if bytes.len() > MAX_COMMAND_BYTES + 5 {
        return Err(CodecError::Limit("command exceeds 4 MiB".into()));
    }
    let mut b = bytes;
    let version = take_u8(&mut b)?;
    if version != COMMAND_VERSION {
        return Err(CodecError::InvalidVersion(version as u64));
    }
    let len = take_u32(&mut b)? as usize;
    if len > MAX_COMMAND_BYTES {
        return Err(CodecError::Limit("command exceeds 4 MiB".into()));
    }
    let data = take(&mut b, len)?;
    if !b.is_empty() {
        return Err(CodecError::Malformed("trailing command bytes".into()));
    }
    serde_json::from_slice(data).map_err(|e| CodecError::Malformed(e.to_string()))
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn take<'a>(input: &mut &'a [u8], n: usize) -> Result<&'a [u8], CodecError> {
    if input.len() < n {
        return Err(CodecError::Truncated);
    }
    let (a, b) = input.split_at(n);
    *input = b;
    Ok(a)
}
fn take_u8(input: &mut &[u8]) -> Result<u8, CodecError> {
    Ok(take(input, 1)?[0])
}
fn take_u32(input: &mut &[u8]) -> Result<u32, CodecError> {
    Ok(u32::from_be_bytes(
        take(input, 4)?
            .try_into()
            .map_err(|_| CodecError::Truncated)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn row_roundtrip_and_order() {
        let row =
            EncodedRowV1::new(3, vec![(2, Datum::Text("x".into())), (1, Datum::Int64(4))]).unwrap();
        let decoded = EncodedRowV1::decode(&row.encode().unwrap()).unwrap();
        assert_eq!(decoded, row);
        assert!(
            encode_memcomparable(&Datum::Int64(-1)).unwrap()
                < encode_memcomparable(&Datum::Int64(1)).unwrap()
        );
    }
    #[test]
    fn composite_prefix_successor() {
        let k = encode_composite(&[Datum::Int32(1)], &[false]).unwrap();
        assert!(successor(&k).is_some());
    }
    #[test]
    fn command_roundtrip() {
        let c = ReplicatedCommandV1::Noop;
        assert_eq!(decode_command(&encode_command(&c).unwrap()).unwrap(), c);
    }

    #[test]
    fn hash32_uses_the_pinned_blake3_vector() {
        assert_eq!(
            hash32(b""),
            [
                0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc,
                0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca,
                0xe4, 0x1f, 0x32, 0x62,
            ]
        );
    }

    #[test]
    fn snapshot_stream_roundtrip_checks_blocks_and_reads_legacy_format() {
        let large_meta = vec![0x5a; SNAPSHOT_BLOCK_BYTES + 123];
        let snapshot = LogicalSnapshot::try_new(
            [7; 16],
            3,
            LogId { term: 2, index: 9 },
            LogId { term: 2, index: 4 },
            vec![1, 2, 3],
            vec![4],
            11,
            5,
            BTreeMap::from([(String::from("state"), large_meta)]),
            vec![(vec![0x20, 0, 0, 0, 1], b"row".to_vec())],
        )
        .unwrap();
        assert!(
            snapshot_body(&snapshot.meta, &snapshot.entries)
                .unwrap()
                .len()
                > SNAPSHOT_BLOCK_BYTES
        );
        let encoded = snapshot.encode().unwrap();
        assert_eq!(&encoded[..16], SNAPSHOT_STREAM_MAGIC);
        assert_eq!(snapshot, LogicalSnapshot::decode(&encoded).unwrap());

        let mut tampered = encoded.clone();
        let middle = tampered.len() / 2;
        tampered[middle] ^= 1;
        assert!(LogicalSnapshot::decode(&tampered).is_err());

        let legacy_json = serde_json::to_vec(&snapshot).unwrap();
        let mut legacy = SNAPSHOT_MAGIC.to_vec();
        put_u32(&mut legacy, legacy_json.len() as u32);
        legacy.extend_from_slice(&legacy_json);
        legacy.extend_from_slice(&hash32(&legacy_json));
        assert_eq!(snapshot, LogicalSnapshot::decode(&legacy).unwrap());
    }
}
