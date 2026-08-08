#![forbid(unsafe_code)]

//! Shared contracts used by every Chorus layer.
//!
//! The MVP deliberately keeps these contracts independent of a consensus or
//! storage implementation.  In particular, request identities and logical
//! values are versioned and have deterministic encodings in `chorus-codec`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

pub const FORMAT_VERSION: u8 = 1;
pub const MAX_KEY_BYTES: usize = 8 * 1024;
pub const MAX_INDEXED_VALUE_BYTES: usize = 4 * 1024;
/// PostgreSQL's timestamp wire epoch (2000-01-01), retained for protocol
/// adapters.  SQL values inside Chorus use Unix microseconds so diagnostics
/// and the host clock helper share one representation.
pub const POSTGRES_EPOCH_UNIX_SECS: i64 = 946_684_800;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct OriginId {
    pub node_id: u64,
    pub boot_nonce: [u8; 16],
}

impl OriginId {
    pub fn new(node_id: u64) -> Self {
        // UUID v4 uses the OS CSPRNG.  Avoid relying on a clock for identity.
        Self {
            node_id,
            boot_nonce: *Uuid::new_v4().as_bytes(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct RequestId {
    pub origin: OriginId,
    pub sequence: u64,
}

impl RequestId {
    pub fn new(origin: OriginId, sequence: u64) -> Self {
        Self { origin, sequence }
    }
}

#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
pub struct LogId {
    pub term: u64,
    pub index: u64,
}

impl LogId {
    pub const ZERO: Self = Self { term: 0, index: 0 };
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ClusterId(pub [u8; 16]);

impl ClusterId {
    pub fn from_name(name: &str) -> Self {
        let mut h = Sha256::new();
        h.update(b"chorus-cluster-v1\0");
        h.update(name.as_bytes());
        let d = h.finalize();
        let mut out = [0; 16];
        out.copy_from_slice(&d[..16]);
        Self(out)
    }
}

impl fmt::Display for ClusterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum SqlType {
    Boolean,
    Bytea,
    SmallInt,
    Integer,
    BigInt,
    Text,
    Varchar(Option<u32>),
    Double,
    Date,
    Timestamp,
    TimestampTz,
    Uuid,
    Jsonb,
}

impl SqlType {
    pub fn oid(self) -> u32 {
        match self {
            Self::Boolean => 16,
            Self::Bytea => 17,
            Self::BigInt => 20,
            Self::SmallInt => 21,
            Self::Integer => 23,
            Self::Text => 25,
            Self::Double => 701,
            Self::Varchar(_) => 1043,
            Self::Date => 1082,
            Self::Timestamp => 1114,
            Self::TimestampTz => 1184,
            Self::Uuid => 2950,
            Self::Jsonb => 3802,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Boolean => "boolean",
            Self::Bytea => "bytea",
            Self::SmallInt => "smallint",
            Self::Integer => "integer",
            Self::BigInt => "bigint",
            Self::Text => "text",
            Self::Varchar(_) => "character varying",
            Self::Double => "double precision",
            Self::Date => "date",
            Self::Timestamp => "timestamp without time zone",
            Self::TimestampTz => "timestamp with time zone",
            Self::Uuid => "uuid",
            Self::Jsonb => "jsonb",
        }
    }
}

/// Logical values. `Null` is represented explicitly instead of using an
/// Option around every datum, which makes row and wire codecs less error prone.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Datum {
    Null,
    Boolean(bool),
    Int16(i16),
    Int32(i32),
    Int64(i64),
    Float64(f64),
    Text(String),
    Bytes(Vec<u8>),
    Date(i32),
    Timestamp(i64),
    TimestampTz(i64),
    Uuid([u8; 16]),
    Jsonb(String),
}

impl PartialEq for Datum {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Float64(a), Self::Float64(b)) => (a.is_nan() && b.is_nan()) || a == b,
            _ => self.cmp(other) == Ordering::Equal,
        }
    }
}
impl Eq for Datum {}

impl Datum {
    pub fn sql_type(&self) -> Option<SqlType> {
        Some(match self {
            Self::Null => return None,
            Self::Boolean(_) => SqlType::Boolean,
            Self::Bytes(_) => SqlType::Bytea,
            Self::Int16(_) => SqlType::SmallInt,
            Self::Int32(_) => SqlType::Integer,
            Self::Int64(_) => SqlType::BigInt,
            Self::Float64(_) => SqlType::Double,
            Self::Text(_) => SqlType::Text,
            Self::Date(_) => SqlType::Date,
            Self::Timestamp(_) => SqlType::Timestamp,
            Self::TimestampTz(_) => SqlType::TimestampTz,
            Self::Uuid(_) => SqlType::Uuid,
            Self::Jsonb(_) => SqlType::Jsonb,
        })
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    pub fn as_bool(&self) -> Option<bool> {
        if let Self::Boolean(v) = self {
            Some(*v)
        } else {
            None
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int16(v) => Some(*v as i64),
            Self::Int32(v) => Some(*v as i64),
            Self::Int64(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Int16(v) => Some(*v as f64),
            Self::Int32(v) => Some(*v as f64),
            Self::Int64(v) => Some(*v as f64),
            Self::Float64(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_text(&self) -> Option<&str> {
        if let Self::Text(v) = self {
            Some(v)
        } else {
            None
        }
    }

    /// PostgreSQL-compatible three-valued boolean coercion helper.
    pub fn truthy(&self) -> Option<bool> {
        self.as_bool()
    }

    /// A deterministic textual representation used by diagnostics and the
    /// simple-query protocol. It intentionally never uses locale settings.
    pub fn display_text(&self) -> String {
        match self {
            Self::Null => String::new(),
            Self::Boolean(v) => v.to_string(),
            Self::Int16(v) => v.to_string(),
            Self::Int32(v) => v.to_string(),
            Self::Int64(v) => v.to_string(),
            Self::Float64(v) if v.is_nan() => "NaN".into(),
            Self::Float64(v) if *v == f64::INFINITY => "Infinity".into(),
            Self::Float64(v) if *v == f64::NEG_INFINITY => "-Infinity".into(),
            Self::Float64(v) => v.to_string(),
            Self::Text(v) => v.clone(),
            Self::Bytes(v) => format!("\\x{}", hex(v)),
            Self::Date(v) => format_date(*v),
            Self::Timestamp(v) | Self::TimestampTz(v) => format_timestamp(*v),
            Self::Uuid(v) => uuid_text(v),
            Self::Jsonb(v) => v.clone(),
        }
    }

    pub fn canonical_json(input: &str) -> std::result::Result<String, SqlError> {
        let value: serde_json::Value =
            serde_json::from_str(input).map_err(|e| SqlError::new("22P02", e.to_string()))?;
        Ok(canonical_json_value(&value))
    }
}

impl PartialOrd for Datum {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Datum {
    fn cmp(&self, other: &Self) -> Ordering {
        use Datum::*;
        // NULL sorts before non-NULL in the canonical ascending key order.
        if self.is_null() {
            return if other.is_null() {
                Ordering::Equal
            } else {
                Ordering::Less
            };
        }
        if other.is_null() {
            return Ordering::Greater;
        }
        let rank = |d: &Datum| match d {
            Boolean(_) => 1,
            Int16(_) => 2,
            Int32(_) => 2,
            Int64(_) => 2,
            Float64(_) => 3,
            Text(_) => 4,
            Bytes(_) => 5,
            Date(_) => 6,
            Timestamp(_) => 7,
            TimestampTz(_) => 8,
            Uuid(_) => 9,
            Jsonb(_) => 10,
            Null => 0,
        };
        let (a, b) = (rank(self), rank(other));
        if a != b {
            return a.cmp(&b);
        }
        match (self, other) {
            (Boolean(a), Boolean(b)) => a.cmp(b),
            (Int16(a), Int16(b)) => a.cmp(b),
            (Int32(a), Int32(b)) => a.cmp(b),
            (Int64(a), Int64(b)) => a.cmp(b),
            (Int16(a), Int32(b)) => (*a as i32).cmp(b),
            (Int16(a), Int64(b)) => (*a as i64).cmp(b),
            (Int32(a), Int16(b)) => a.cmp(&(*b as i32)),
            (Int32(a), Int64(b)) => (*a as i64).cmp(b),
            (Int64(a), Int16(b)) => a.cmp(&(*b as i64)),
            (Int64(a), Int32(b)) => a.cmp(&(*b as i64)),
            (Float64(a), Float64(b)) => float_cmp(*a, *b),
            (Text(a), Text(b)) => a.as_bytes().cmp(b.as_bytes()),
            (Bytes(a), Bytes(b)) => a.cmp(b),
            (Date(a), Date(b)) => a.cmp(b),
            (Timestamp(a), Timestamp(b)) | (TimestampTz(a), TimestampTz(b)) => a.cmp(b),
            (Uuid(a), Uuid(b)) => a.cmp(b),
            (Jsonb(a), Jsonb(b)) => a.as_bytes().cmp(b.as_bytes()),
            _ => self.display_text().cmp(&other.display_text()),
        }
    }
}

fn float_cmp(a: f64, b: f64) -> Ordering {
    match (a.is_nan(), b.is_nan()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => a.partial_cmp(&b).unwrap_or(Ordering::Equal),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn uuid_text(v: &[u8; 16]) -> String {
    let h = hex(v);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}
fn canonical_json_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "null".into(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into()),
        serde_json::Value::Array(a) => format!(
            "[{}]",
            a.iter()
                .map(canonical_json_value)
                .collect::<Vec<_>>()
                .join(",")
        ),
        serde_json::Value::Object(o) => {
            let mut keys: Vec<_> = o.keys().collect();
            keys.sort();
            format!(
                "{{{}}}",
                keys.iter()
                    .map(|k| format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_default(),
                        canonical_json_value(&o[*k])
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{message}")]
pub struct SqlError {
    pub code: &'static str,
    pub message: String,
    pub detail: Option<String>,
    pub hint: Option<String>,
    pub position: Option<usize>,
}

impl SqlError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            detail: None,
            hint: None,
            position: None,
        }
    }
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
    pub fn at(mut self, position: usize) -> Self {
        self.position = Some(position);
        self
    }
    pub fn serialization(message: impl Into<String>) -> Self {
        Self::new("40001", message)
    }
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new("0A000", message)
    }
    pub fn cluster_unavailable(message: impl Into<String>) -> Self {
        Self::new("57P03", message)
    }
    pub fn failed_transaction() -> Self {
        Self::new(
            "25P02",
            "current transaction is aborted, commands ignored until end of transaction block",
        )
    }
}

#[derive(Clone, Debug, Error)]
pub enum ChorusError {
    #[error("sql error: {0}")]
    Sql(#[from] SqlError),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("consensus unavailable: {0}")]
    Consensus(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("resource limit: {0}")]
    Limit(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("internal invariant failure: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, ChorusError>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Limits {
    pub max_transaction_age_ms: u64,
    pub idle_in_transaction_timeout_ms: u64,
    pub max_transaction_bytes: usize,
    pub max_mutations: usize,
    pub max_row_bytes: usize,
    pub max_sql_message_bytes: usize,
    pub max_returning_bytes: usize,
    pub max_key_bytes: usize,
    pub max_indexed_value_bytes: usize,
    pub max_connections: usize,
    pub max_active_queries: usize,
    pub query_workers: usize,
    pub query_work_mem_bytes: usize,
    pub global_work_mem_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_transaction_age_ms: 30_000,
            idle_in_transaction_timeout_ms: 15_000,
            max_transaction_bytes: 4 * 1024 * 1024,
            max_mutations: 10_000,
            max_row_bytes: 256 * 1024,
            max_sql_message_bytes: 1024 * 1024,
            max_returning_bytes: 8 * 1024 * 1024,
            max_key_bytes: MAX_KEY_BYTES,
            max_indexed_value_bytes: MAX_INDEXED_VALUE_BYTES,
            max_connections: 32,
            max_active_queries: 8,
            query_workers: 2,
            query_work_mem_bytes: 4 * 1024 * 1024,
            global_work_mem_bytes: 32 * 1024 * 1024,
        }
    }
}

pub fn unix_now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

/// Format a PostgreSQL-style date value (days since 1970-01-01) without a
/// locale or time-zone dependency.
pub fn format_date(days_since_unix_epoch: i32) -> String {
    let (year, month, day) = civil_from_days(days_since_unix_epoch as i64);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Format a UTC timestamp represented as Unix microseconds.  PostgreSQL's
/// text representation is intentionally kept at microsecond precision only
/// when needed.
pub fn format_timestamp(micros: i64) -> String {
    let seconds = micros.div_euclid(1_000_000);
    let fraction = micros.rem_euclid(1_000_000);
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    if fraction == 0 {
        format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
    } else {
        let mut frac = format!("{fraction:06}");
        while frac.ends_with('0') {
            frac.pop();
        }
        format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{frac}")
    }
}

// Howard Hinnant's proleptic-Gregorian civil calendar conversion, expressed
// without floating point so dates before the Unix epoch remain correct.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m, d)
}

pub fn checked_add_u64(a: u64, b: u64, what: &str) -> Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| ChorusError::Limit(format!("{what} exhausted")))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn null_and_nan_order_is_deterministic() {
        assert!(Datum::Null < Datum::Int64(1));
        assert!(Datum::Float64(f64::NAN) > Datum::Float64(100.0));
        assert_eq!(Datum::Float64(f64::NAN), Datum::Float64(f64::NAN));
    }
    #[test]
    fn json_is_canonicalized() {
        assert_eq!(
            Datum::canonical_json(r#"{"b":1,"a":2}"#).unwrap(),
            r#"{"a":2,"b":1}"#
        );
    }
    #[test]
    fn temporal_text_is_stable() {
        assert_eq!(format_date(0), "1970-01-01");
        assert_eq!(format_date(19_723), "2024-01-01");
        assert_eq!(
            format_timestamp(1_704_067_200_123_000),
            "2024-01-01 00:00:00.123"
        );
        assert_eq!(Datum::Date(0).display_text(), "1970-01-01");
    }
}
