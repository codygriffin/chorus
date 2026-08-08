#![forbid(unsafe_code)]

//! Versioned, deterministic encodings shared by storage, consensus and the
//! SQL layer.  The codecs are intentionally self-contained rather than using
//! a serializer whose map iteration or enum layout could change underneath a
//! persisted database.

use chorus_common::{
    ChorusError, Datum, FORMAT_VERSION, LogId, MAX_INDEXED_VALUE_BYTES, MAX_KEY_BYTES, OriginId,
    RequestId, Result as ChorusResult, SqlError, SqlType, checked_add_u64,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const MEMCOMPARABLE_VERSION: u8 = 1;
pub const ROW_VERSION: u8 = 1;
pub const COMMAND_VERSION: u8 = 1;
pub const SNAPSHOT_VERSION: u16 = 1;

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
    // SHA-256 is available in the minimal deployment toolchain and provides a
    // stable 256-bit command/state digest. The command API leaves this helper
    // behind a function so a pure BLAKE3 implementation can be swapped in
    // without changing persisted structures.
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

pub fn payload_hash(
    command_version: u8,
    request_id: &RequestId,
    base_epoch: u64,
    payload: &[u8],
) -> [u8; 32] {
    let mut b = Vec::with_capacity(1 + 8 + 16 + 8 + 8 + payload.len());
    b.push(command_version);
    put_u64(&mut b, request_id.origin.node_id);
    b.extend_from_slice(&request_id.origin.boot_nonce);
    put_u64(&mut b, request_id.sequence);
    put_u64(&mut b, base_epoch);
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
        Datum::Int16(v) => (
            2,
            ((i16::from_be_bytes(v.to_be_bytes()) ^ i16::MIN).to_be_bytes()).to_vec(),
            false,
        ),
        Datum::Int32(v) => (
            3,
            ((i32::from_be_bytes(v.to_be_bytes()) ^ i32::MIN).to_be_bytes()).to_vec(),
            false,
        ),
        Datum::Int64(v) => (
            4,
            ((i64::from_be_bytes(v.to_be_bytes()) ^ i64::MIN).to_be_bytes()).to_vec(),
            false,
        ),
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
        Datum::Jsonb(v) => (12, v.as_bytes().to_vec(), true),
    };
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
    if out.len() > MAX_INDEXED_VALUE_BYTES + 32 {
        return Err(CodecError::Limit(
            "encoded indexed value exceeds limit".into(),
        ));
    }
    Ok(())
}

fn float_key(value: f64) -> [u8; 8] {
    let bits = if value.is_nan() {
        f64::NAN.to_bits()
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
        fields.sort_by_key(|(id, _)| *id);
        for w in fields.windows(2) {
            if w[0].0 == w[1].0 {
                return Err(CodecError::Malformed("duplicate column id".into()));
            }
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
        let mut out = vec![self.format_version];
        put_u32(&mut out, self.schema_version);
        put_u32(&mut out, self.fields.len() as u32);
        for (id, d) in &self.fields {
            put_u32(&mut out, *id);
            encode_datum(&mut out, d)?;
        }
        Ok(out)
    }
    pub fn decode(mut bytes: &[u8]) -> Result<Self, CodecError> {
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
        Datum::Jsonb(v) => (12, v.as_bytes().to_vec()),
    };
    out.push(tag);
    put_u32(out, payload.len() as u32);
    out.extend_from_slice(&payload);
    Ok(())
}
fn decode_datum(input: &mut &[u8]) -> Result<Datum, CodecError> {
    let tag = take_u8(input)?;
    let len = take_u32(input)? as usize;
    if len > 1024 * 1024 {
        return Err(CodecError::Limit("datum exceeds limit".into()));
    }
    let p = take(input, len)?;
    let wrong = || CodecError::Malformed("invalid datum length".into());
    Ok(match tag {
        0 if len == 0 => Datum::Null,
        1 if len == 1 => Datum::Boolean(p[0] != 0),
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
        let body = snapshot_body(&meta, &entries);
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
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let body = snapshot_body(&self.meta, &self.entries);
        if hash32(&body) != self.header.digest {
            return Err(CodecError::Malformed("snapshot digest mismatch".into()));
        }
        let encoded = serde_json::to_vec(self).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let mut out = b"CHORUS-SNAPSHOT\0".to_vec();
        put_u32(&mut out, encoded.len() as u32);
        out.extend_from_slice(&encoded);
        out.extend_from_slice(&hash32(&encoded));
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() < 16 + 4 + 32 || &bytes[..16] != b"CHORUS-SNAPSHOT\0" {
            return Err(CodecError::Malformed("invalid snapshot magic".into()));
        }
        let mut rest = &bytes[16..];
        let len = take_u32(&mut rest)? as usize;
        let data = take(&mut rest, len)?;
        let digest = take(&mut rest, 32)?;
        if hash32(data) != digest {
            return Err(CodecError::Malformed("snapshot checksum mismatch".into()));
        }
        let s: Self =
            serde_json::from_slice(data).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let body = snapshot_body(&s.meta, &s.entries);
        if hash32(&body) != s.header.digest {
            return Err(CodecError::Malformed(
                "snapshot logical digest mismatch".into(),
            ));
        }
        Ok(s)
    }
}

fn snapshot_body(meta: &BTreeMap<String, Vec<u8>>, entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    serde_json::to_vec(&(meta, entries)).unwrap_or_default()
}

pub fn encode_command(command: &ReplicatedCommandV1) -> Result<Vec<u8>, CodecError> {
    let data = serde_json::to_vec(command).map_err(|e| CodecError::Malformed(e.to_string()))?;
    let mut out = vec![COMMAND_VERSION];
    put_u32(&mut out, data.len() as u32);
    out.extend_from_slice(&data);
    Ok(out)
}
pub fn decode_command(bytes: &[u8]) -> Result<ReplicatedCommandV1, CodecError> {
    let mut b = bytes;
    let version = take_u8(&mut b)?;
    if version != COMMAND_VERSION {
        return Err(CodecError::InvalidVersion(version as u64));
    }
    let len = take_u32(&mut b)? as usize;
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
}
