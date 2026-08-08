#![forbid(unsafe_code)]

//! Minimal PostgreSQL v3 frontend. It implements startup, trust
//! authentication, simple query, the extended Parse/Bind/Describe/Execute /
//! Sync flow, cancellation keys, and structured errors without depending on a
//! native PostgreSQL client library.

use chorus_common::{Datum, SqlError, SqlType};
use chorus_sql::{QueryResult, ResultColumn, SqlEngine, SqlSession};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::thread;

#[derive(Clone, Debug)]
pub struct PgConfig {
    pub tcp_listen: Option<String>,
    pub unix_socket: Option<String>,
    pub max_connections: usize,
}
impl Default for PgConfig {
    fn default() -> Self {
        Self {
            tcp_listen: Some("127.0.0.1:5432".into()),
            unix_socket: None,
            max_connections: 32,
        }
    }
}

pub struct PgServer {
    engine: Arc<SqlEngine>,
    config: PgConfig,
}
impl PgServer {
    pub fn new(engine: Arc<SqlEngine>, config: PgConfig) -> Self {
        Self { engine, config }
    }
    pub fn serve(&self) -> std::io::Result<()> {
        if let Some(addr) = &self.config.tcp_listen {
            let listener = TcpListener::bind(addr)?;
            let engine = self.engine.clone();
            thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let e = engine.clone();
                    thread::spawn(move || {
                        let _ = Connection::new(e, Box::new(stream)).run();
                    });
                }
            });
        }
        if let Some(path) = &self.config.unix_socket {
            let _ = std::fs::remove_file(path);
            let listener = UnixListener::bind(path)?;
            let engine = self.engine.clone();
            thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let e = engine.clone();
                    thread::spawn(move || {
                        let _ = Connection::new(e, Box::new(stream)).run();
                    });
                }
            });
        }
        loop {
            thread::park();
        }
    }
    pub fn serve_tcp_once(&self, addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr)?;
        if let Ok((stream, _)) = listener.accept() {
            Connection::new(self.engine.clone(), Box::new(stream)).run()?;
        }
        Ok(())
    }
}

trait Io: Read + Write + Send {}
impl<T: Read + Write + Send> Io for T {}
struct Connection {
    engine: Arc<SqlEngine>,
    io: Box<dyn Io>,
    session: SqlSession,
    portals: HashMap<String, Portal>,
    prepared_types: HashMap<String, Vec<u32>>,
    backend_pid: u32,
    secret: u32,
}
#[derive(Clone)]
struct Portal {
    sql: String,
    params: Vec<Datum>,
    max_rows: usize,
}

impl Connection {
    fn new(engine: Arc<SqlEngine>, io: Box<dyn Io>) -> Self {
        let session = engine.session();
        let pid = std::process::id();
        Self {
            engine,
            io,
            session,
            portals: HashMap::new(),
            prepared_types: HashMap::new(),
            backend_pid: pid,
            secret: pid.rotate_left(13),
        }
    }
    fn run(mut self) -> std::io::Result<()> {
        self.startup()?;
        loop {
            let Some((typ, body)) = self.message()? else {
                return Ok(());
            };
            match typ {
                b'Q' => self.simple_query(&body)?,
                b'P' => self.parse(&body)?,
                b'B' => self.bind(&body)?,
                b'D' => self.describe(&body)?,
                b'E' => self.execute(&body)?,
                b'C' => self.close(&body)?,
                b'S' => self.ready()?,
                b'H' => self.io.flush()?,
                b'X' => return Ok(()),
                b'F' => self.cancel(&body)?,
                _ => {
                    self.error(&SqlError::unsupported("frontend message is not supported"))?;
                    self.ready()?;
                }
            }
        }
    }
    fn startup(&mut self) -> std::io::Result<()> {
        let (mut len, mut code) = self.read_startup_header()?;
        if code == 80877103 {
            self.io.write_all(b"N")?;
            (len, code) = self.read_startup_header()?;
        } else if code == 80877102 {
            return Ok(());
        }
        if len < 8 {
            return Ok(());
        }
        let mut body = vec![0; (len - 8) as usize];
        self.io.read_exact(&mut body)?;
        let mut p = 0;
        let mut app = String::new();
        while p < body.len() {
            let (k, n) = cstr(&body[p..]);
            p += n;
            if k.is_empty() {
                break;
            }
            let (v, n2) = cstr(&body[p..]);
            p += n2;
            if k == "application_name" {
                app = v;
            }
        }
        let _ = self.session.set_param("application_name", &app);
        self.send_authentication_ok()?;
        self.parameter("server_version", "16.0")?;
        self.parameter("server_version_num", "160000")?;
        self.parameter("client_encoding", "UTF8")?;
        self.parameter("DateStyle", "ISO, MDY")?;
        self.parameter("TimeZone", "UTC")?;
        self.parameter("standard_conforming_strings", "on")?;
        self.parameter("integer_datetimes", "on")?;
        self.parameter("application_name", &app)?;
        self.backend_key()?;
        self.ready()
    }
    fn read_startup_header(&mut self) -> std::io::Result<(u32, u32)> {
        let mut b = [0; 8];
        self.io.read_exact(&mut b)?;
        Ok((
            u32::from_be_bytes(b[..4].try_into().unwrap()),
            u32::from_be_bytes(b[4..].try_into().unwrap()),
        ))
    }
    fn simple_query(&mut self, body: &[u8]) -> std::io::Result<()> {
        let sql = cstr(body).0;
        if sql.is_empty() {
            self.write_message(b'I', &[])?;
            return self.ready();
        }
        match self.session.execute(&sql, &[]) {
            Ok(r) => {
                self.result(&r)?;
                self.ready()
            }
            Err(e) => {
                self.error(&e)?;
                self.ready()
            }
        }
    }
    fn parse(&mut self, body: &[u8]) -> std::io::Result<()> {
        let (name, n) = cstr(body);
        let (sql, sql_n) = cstr(&body[n..]);
        let mut p = n + sql_n;
        let mut types = Vec::new();
        if p + 2 <= body.len() {
            let count = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
            p += 2;
            if p + count.saturating_mul(4) <= body.len() {
                for _ in 0..count {
                    types.push(u32::from_be_bytes(body[p..p + 4].try_into().unwrap()));
                    p += 4;
                }
            }
        }
        match self.session.prepare(&name, &sql) {
            Ok(()) => {
                self.prepared_types.insert(name, types);
                self.write_message(b'1', &[])
            }
            Err(e) => self.error(&e),
        }
    }
    fn bind(&mut self, body: &[u8]) -> std::io::Result<()> {
        let (portal, n1) = cstr(body);
        let (statement, n2) = cstr(&body[n1..]);
        let mut p = n1 + n2;
        if p + 2 > body.len() {
            return self.error(&SqlError::new("08P01", "malformed Bind"));
        }
        let formats = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
        p += 2;
        let mut f = Vec::new();
        for _ in 0..formats {
            f.push(u16::from_be_bytes([body[p], body[p + 1]]));
            p += 2;
        }
        let count = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
        p += 2;
        let mut params = Vec::new();
        for i in 0..count {
            let len = i32::from_be_bytes(body[p..p + 4].try_into().unwrap());
            p += 4;
            if len < 0 {
                params.push(Datum::Null);
            } else {
                let data = &body[p..p + len as usize];
                p += len as usize;
                let format = f
                    .get(i)
                    .copied()
                    .unwrap_or_else(|| f.first().copied().unwrap_or(0));
                let oid = self
                    .prepared_types
                    .get(&statement)
                    .and_then(|types| types.get(i))
                    .copied()
                    .unwrap_or(0);
                params.push(if format == 1 {
                    decode_binary_param(data, oid).unwrap_or_else(|| Datum::Bytes(data.to_vec()))
                } else {
                    Datum::Text(String::from_utf8_lossy(data).into())
                });
            }
        }
        if p + 2 > body.len() {
            return self.error(&SqlError::new("08P01", "malformed Bind"));
        }
        let result_formats_count = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
        p += 2 + result_formats_count * 2;
        let sql = self.session_sql(&statement).unwrap_or_default();
        let declared = self
            .prepared_types
            .get(&statement)
            .cloned()
            .unwrap_or_default();
        for (i, value) in params.iter_mut().enumerate() {
            if let Datum::Text(text) = value {
                let oid = declared.get(i).copied().unwrap_or(0);
                if let Some(v) = decode_text_param(text, oid) {
                    *value = v;
                }
            }
        }
        self.portals.insert(
            portal,
            Portal {
                sql,
                params,
                max_rows: usize::MAX,
            },
        );
        self.write_message(b'2', &[])
    }
    fn session_sql(&self, name: &str) -> Option<String> {
        self.session.prepared_sql(name).map(str::to_string)
    }
    fn describe(&mut self, body: &[u8]) -> std::io::Result<()> {
        let kind = body.first().copied().unwrap_or(b'S');
        if kind == b'P' {
            self.write_message(b'n', &[])
        } else {
            self.write_message(b'Z', &[b'I'])
        }
    }
    fn execute(&mut self, body: &[u8]) -> std::io::Result<()> {
        let (portal, n) = cstr(body);
        let max = u32::from_be_bytes(body[n..n + 4].try_into().unwrap()) as usize;
        let Some(p) = self.portals.get(&portal).cloned() else {
            return self.error(&SqlError::new("34000", "portal does not exist"));
        };
        let _ = max;
        match self.session.execute(&p.sql, &p.params) {
            Ok(r) => self.result(&r),
            Err(e) => self.error(&e),
        }
    }
    fn close(&mut self, body: &[u8]) -> std::io::Result<()> {
        let (name, _) = cstr(&body[1..]);
        if body.first() == Some(&b'P') {
            self.portals.remove(&name);
        }
        self.write_message(b'3', &[])
    }
    fn cancel(&mut self, body: &[u8]) -> std::io::Result<()> {
        let _ = body;
        Ok(())
    }
    fn result(&mut self, r: &QueryResult) -> std::io::Result<()> {
        if !r.columns.is_empty() {
            let mut b = Vec::new();
            put_u16(&mut b, r.columns.len() as u16);
            for c in &r.columns {
                cstr_put(&mut b, &c.name);
                b.extend_from_slice(&c.table_oid.to_be_bytes());
                b.extend_from_slice(&c.column_oid.to_be_bytes());
                b.extend_from_slice(&(-1i16).to_be_bytes());
                b.extend_from_slice(&(c.data_type.oid() as u32).to_be_bytes());
                b.extend_from_slice(&(-1i16).to_be_bytes());
                b.push(0);
            }
            self.write_message(b'T', &b)?;
            for row in &r.rows {
                let mut d = Vec::new();
                put_u16(&mut d, row.len() as u16);
                for v in row {
                    let text = v.display_text();
                    d.extend_from_slice(&(text.len() as i32).to_be_bytes());
                    d.extend_from_slice(text.as_bytes());
                }
                self.write_message(b'D', &d)?;
            }
        }
        let mut tag = r.command_tag.clone();
        if tag.is_empty() {
            tag = "SELECT 0".into();
        }
        let mut b = tag.into_bytes();
        b.push(0);
        self.write_message(b'C', &b)
    }
    fn ready(&mut self) -> std::io::Result<()> {
        self.write_message(
            b'Z',
            &[match self.session.transaction_status() {
                chorus_txn::TransactionStatus::Failed => b'E',
                chorus_txn::TransactionStatus::Active => b'T',
                _ => b'I',
            }],
        )
    }
    fn send_authentication_ok(&mut self) -> std::io::Result<()> {
        self.write_message(b'R', &0u32.to_be_bytes())
    }
    fn parameter(&mut self, k: &str, v: &str) -> std::io::Result<()> {
        let mut b = Vec::new();
        cstr_put(&mut b, k);
        cstr_put(&mut b, v);
        self.write_message(b'S', &b)
    }
    fn backend_key(&mut self) -> std::io::Result<()> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.backend_pid.to_be_bytes());
        b.extend_from_slice(&self.secret.to_be_bytes());
        self.write_message(b'K', &b)
    }
    fn error(&mut self, e: &SqlError) -> std::io::Result<()> {
        let mut b = Vec::new();
        field(&mut b, b'S', "ERROR");
        field(&mut b, b'C', e.code);
        field(&mut b, b'M', &e.message);
        if let Some(d) = &e.detail {
            field(&mut b, b'D', d);
        }
        if let Some(h) = &e.hint {
            field(&mut b, b'H', h);
        }
        b.push(0);
        self.write_message(b'E', &b)
    }
    fn message(&mut self) -> std::io::Result<Option<(u8, Vec<u8>)>> {
        let mut h = [0; 5];
        match self.io.read_exact(&mut h) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        };
        let len = u32::from_be_bytes(h[1..].try_into().unwrap()) as usize;
        if len < 4 || len > 16 * 1024 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid frontend message length",
            ));
        }
        let mut b = vec![0; len - 4];
        self.io.read_exact(&mut b)?;
        Ok(Some((h[0], b)))
    }
    fn write_message(&mut self, typ: u8, body: &[u8]) -> std::io::Result<()> {
        let len = (body.len() + 4) as u32;
        self.io.write_all(&[typ])?;
        self.io.write_all(&len.to_be_bytes())?;
        self.io.write_all(body)?;
        self.io.flush()
    }
}

fn cstr(bytes: &[u8]) -> (String, usize) {
    let n = bytes.iter().position(|x| *x == 0).unwrap_or(bytes.len());
    (
        String::from_utf8_lossy(&bytes[..n]).into(),
        (n + 1).min(bytes.len()),
    )
}

fn decode_text_param(text: &str, oid: u32) -> Option<Datum> {
    match oid {
        16 => text.parse::<bool>().ok().map(Datum::Boolean),
        21 => text.parse::<i16>().ok().map(Datum::Int16),
        23 => text.parse::<i32>().ok().map(Datum::Int32),
        20 => text.parse::<i64>().ok().map(Datum::Int64),
        701 => text.parse::<f64>().ok().map(Datum::Float64),
        3802 => chorus_common::Datum::canonical_json(text)
            .ok()
            .map(Datum::Jsonb),
        2950 => parse_uuid(text).map(Datum::Uuid),
        0 => {
            if let Ok(v) = text.parse::<i64>() {
                Some(Datum::Int64(v))
            } else if let Ok(v) = text.parse::<f64>() {
                Some(Datum::Float64(v))
            } else if let Ok(v) = text.parse::<bool>() {
                Some(Datum::Boolean(v))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn decode_binary_param(bytes: &[u8], oid: u32) -> Option<Datum> {
    match oid {
        16 if bytes.len() == 1 => Some(Datum::Boolean(bytes[0] != 0)),
        21 if bytes.len() == 2 => Some(Datum::Int16(i16::from_be_bytes(bytes.try_into().ok()?))),
        23 if bytes.len() == 4 => Some(Datum::Int32(i32::from_be_bytes(bytes.try_into().ok()?))),
        20 if bytes.len() == 8 => Some(Datum::Int64(i64::from_be_bytes(bytes.try_into().ok()?))),
        701 if bytes.len() == 8 => Some(Datum::Float64(f64::from_bits(u64::from_be_bytes(
            bytes.try_into().ok()?,
        )))),
        17 => Some(Datum::Bytes(bytes.to_vec())),
        25 | 1043 => Some(Datum::Text(String::from_utf8(bytes.to_vec()).ok()?)),
        2950 if bytes.len() == 16 => Some(Datum::Uuid(bytes.try_into().ok()?)),
        3802 => chorus_common::Datum::canonical_json(&String::from_utf8(bytes.to_vec()).ok()?)
            .ok()
            .map(Datum::Jsonb),
        _ => None,
    }
}

fn parse_uuid(text: &str) -> Option<[u8; 16]> {
    let clean = text.trim().replace('-', "");
    if clean.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}
fn cstr_put(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(s.as_bytes());
    out.push(0);
}
fn put_u16(out: &mut Vec<u8>, n: u16) {
    out.extend_from_slice(&n.to_be_bytes());
}
fn field(out: &mut Vec<u8>, code: u8, value: &str) {
    out.push(code);
    cstr_put(out, value);
}
