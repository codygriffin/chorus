#![forbid(unsafe_code)]

//! Minimal PostgreSQL v3 frontend. It implements startup, trust
//! authentication, simple query, the extended Parse/Bind/Describe/Execute /
//! Sync flow, cancellation keys, and structured errors without depending on a
//! native PostgreSQL client library.

use chorus_common::{Datum, POSTGRES_EPOCH_UNIX_SECS, SqlError, SqlType};
use chorus_sql::{QueryResult, ResultColumn, SqlEngine, SqlSession};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

// Keep wire limits deliberately conservative.  PostgreSQL's protocol uses a
// signed 32-bit length, but accepting multi-gigabyte frames is an easy denial
// of service and would defeat the SQL/row limits enforced by the engine.
const MAX_FRONTEND_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_STARTUP_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_WIRE_RESULT_BYTES: usize = 16 * 1024 * 1024;
const MAX_PARAMETER_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROTOCOL_ITEMS: usize = u16::MAX as usize;
const PROTOCOL_VERSION_3_0: u32 = 196_608;
const PROTOCOL_VERSION_3_2: u32 = 196_610;
const SSL_REQUEST_CODE: u32 = 80_877_103;
const CANCEL_REQUEST_CODE: u32 = 80_877_102;
const GSSENC_REQUEST_CODE: u32 = 80_877_104;

type CancelKey = (u32, u32);

fn cancel_registry() -> &'static Mutex<HashMap<CancelKey, Arc<AtomicBool>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<CancelKey, Arc<AtomicBool>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

static NEXT_BACKEND_PID: AtomicU32 = AtomicU32::new(1);

fn next_backend_pid() -> u32 {
    // BackendKeyData is an identifier, not an OS process id.  Incorporating
    // the process id keeps diagnostics familiar while the monotonic suffix
    // prevents every connection in one process sharing a cancellation key.
    let process = std::process::id();
    let serial = NEXT_BACKEND_PID.fetch_add(1, Ordering::Relaxed);
    process.wrapping_add(serial.rotate_left(7)).max(1)
}

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
        let active = Arc::new(AtomicUsize::new(0));
        if let Some(addr) = &self.config.tcp_listen {
            let listener = TcpListener::bind(addr)?;
            let engine = self.engine.clone();
            let active_connections = Arc::clone(&active);
            let max_connections = self.config.max_connections;
            thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let Ok(permit) = ConnectionPermit::try_acquire(
                        Arc::clone(&active_connections),
                        max_connections,
                    ) else {
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    };
                    let e = engine.clone();
                    thread::spawn(move || {
                        let _permit = permit;
                        let _ = Connection::new(e, Box::new(stream)).run();
                    });
                }
            });
        }
        if let Some(path) = &self.config.unix_socket {
            let _ = std::fs::remove_file(path);
            let listener = UnixListener::bind(path)?;
            let engine = self.engine.clone();
            let active_connections = Arc::clone(&active);
            let max_connections = self.config.max_connections;
            thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let Ok(permit) = ConnectionPermit::try_acquire(
                        Arc::clone(&active_connections),
                        max_connections,
                    ) else {
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    };
                    let e = engine.clone();
                    thread::spawn(move || {
                        let _permit = permit;
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
            let permit = ConnectionPermit::try_acquire(
                Arc::new(AtomicUsize::new(0)),
                self.config.max_connections,
            )
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::WouldBlock, "connection limit reached")
            })?;
            let _permit = permit;
            Connection::new(self.engine.clone(), Box::new(stream)).run()?;
        }
        Ok(())
    }
}

struct ConnectionPermit {
    active: Arc<AtomicUsize>,
}

impl ConnectionPermit {
    fn try_acquire(active: Arc<AtomicUsize>, max: usize) -> std::result::Result<Self, ()> {
        if max == 0 {
            return Err(());
        }
        let mut current = active.load(Ordering::Acquire);
        loop {
            if current >= max {
                return Err(());
            }
            match active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(Self { active }),
                Err(observed) => current = observed,
            }
        }
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

trait Io: Read + Write + Send {}
impl<T: Read + Write + Send> Io for T {}
struct Connection {
    io: Box<dyn Io>,
    session: SqlSession,
    portals: HashMap<String, Portal>,
    prepared_types: HashMap<String, Vec<u32>>,
    backend_pid: u32,
    secret: u32,
    cancel_token: Arc<AtomicBool>,
    extended_error: bool,
}
#[derive(Clone)]
struct Portal {
    sql: String,
    params: Vec<Datum>,
    /// The result format list from Bind.  An empty list means text for all
    /// columns; a one-element list applies to every column.
    result_formats: Vec<u16>,
    pending: Option<QueryResult>,
}

struct StartupParams {
    values: HashMap<String, String>,
}

impl StartupParams {
    fn parse(body: &[u8]) -> Result<Self, SqlError> {
        let mut p = 0usize;
        let mut values = HashMap::new();
        loop {
            let key = startup_cstr(body, &mut p)?;
            if key.is_empty() {
                if p != body.len() {
                    return Err(SqlError::new("08P01", "trailing bytes in startup packet"));
                }
                break;
            }
            let value = startup_cstr(body, &mut p)?;
            if key.len() > 256 || value.len() > 4096 {
                return Err(SqlError::new("54000", "startup parameter is too long"));
            }
            values.insert(key, value);
        }
        Ok(Self { values })
    }

    fn get(&self, key: &str) -> Option<String> {
        self.values
            .get(key)
            .or_else(|| {
                self.values
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case(key))
                    .map(|(_, value)| value)
            })
            .cloned()
    }
}

fn startup_cstr(body: &[u8], pos: &mut usize) -> Result<String, SqlError> {
    if *pos >= body.len() {
        return Err(SqlError::new("08P01", "unterminated startup parameter"));
    }
    let start = *pos;
    let Some(rel) = body[start..].iter().position(|b| *b == 0) else {
        return Err(SqlError::new("08P01", "unterminated startup parameter"));
    };
    let end = start + rel;
    *pos = end + 1;
    String::from_utf8(body[start..end].to_vec())
        .map_err(|_| SqlError::new("22021", "invalid UTF-8 in startup packet"))
}

type WireResult<T> = std::result::Result<T, SqlError>;

struct Decoder<'a> {
    body: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn new(body: &'a [u8]) -> Self {
        Self { body, pos: 0 }
    }

    fn cstr(&mut self, what: &'static str) -> WireResult<String> {
        let start = self.pos;
        let Some(rel) = self.body[start..].iter().position(|b| *b == 0) else {
            return Err(SqlError::new("08P01", format!("unterminated {what}")));
        };
        let end = start + rel;
        self.pos = end + 1;
        String::from_utf8(self.body[start..end].to_vec())
            .map_err(|_| SqlError::new("22021", format!("invalid UTF-8 in {what}")))
    }

    fn u16(&mut self, what: &'static str) -> WireResult<u16> {
        let bytes = self.take(2, what)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self, what: &'static str) -> WireResult<u32> {
        let bytes = self.take(4, what)?;
        Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
    }

    fn i32(&mut self, what: &'static str) -> WireResult<i32> {
        let bytes = self.take(4, what)?;
        Ok(i32::from_be_bytes(bytes.try_into().unwrap()))
    }

    fn bytes(&mut self, len: usize, what: &'static str) -> WireResult<&'a [u8]> {
        self.take(len, what)
    }

    fn take(&mut self, len: usize, what: &'static str) -> WireResult<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| SqlError::new("08P01", format!("{what} length overflow")))?;
        if end > self.body.len() {
            return Err(SqlError::new("08P01", format!("truncated {what}")));
        }
        let out = &self.body[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn finish(&self, what: &'static str) -> WireResult<()> {
        if self.pos == self.body.len() {
            Ok(())
        } else {
            Err(SqlError::new("08P01", format!("trailing bytes in {what}")))
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Ok(mut registry) = cancel_registry().lock() {
            registry.remove(&(self.backend_pid, self.secret));
        }
    }
}

impl Connection {
    fn new(engine: Arc<SqlEngine>, io: Box<dyn Io>) -> Self {
        let session = engine.session();
        let pid = next_backend_pid();
        let secret = pid
            .rotate_left(13)
            .wrapping_add(NEXT_BACKEND_PID.load(Ordering::Relaxed));
        let cancel_token = Arc::new(AtomicBool::new(false));
        if let Ok(mut registry) = cancel_registry().lock() {
            registry.insert((pid, secret), Arc::clone(&cancel_token));
        }
        Self {
            io,
            session,
            portals: HashMap::new(),
            prepared_types: HashMap::new(),
            backend_pid: pid,
            secret,
            cancel_token,
            extended_error: false,
        }
    }
    fn run(mut self) -> std::io::Result<()> {
        if !self.startup()? {
            return Ok(());
        }
        loop {
            let Some((typ, body)) = self.message()? else {
                return Ok(());
            };

            // Extended-protocol errors are synchronized by Sync, not by an
            // immediate ReadyForQuery.  Ignore all work messages until that
            // Sync arrives; Flush and Terminate are still handled so clients
            // can drain/close a failed pipeline cleanly.
            if self.extended_error {
                match typ {
                    b'S' => {
                        self.extended_error = false;
                        self.ready()?;
                    }
                    b'H' => self.io.flush()?,
                    b'X' => return Ok(()),
                    _ => {}
                }
                continue;
            }
            match typ {
                b'Q' => self.simple_query(&body)?,
                b'P' => self.parse(&body)?,
                b'B' => self.bind(&body)?,
                b'D' => self.describe(&body)?,
                b'E' => self.execute(&body)?,
                b'C' => self.close(&body)?,
                b'S' => self.sync()?,
                b'H' => self.io.flush()?,
                b'X' => return Ok(()),
                _ => {
                    self.error(&SqlError::unsupported("frontend message is not supported"))?;
                    self.ready()?;
                }
            }
        }
    }
    /// Read startup packets.  `false` means this connection was a standalone
    /// SSL/GSS/cancellation request and must be closed without a ReadyForQuery.
    fn startup(&mut self) -> std::io::Result<bool> {
        let (mut len, mut code) = self.read_startup_header()?;
        loop {
            if len < 8 || (len as usize) > MAX_STARTUP_MESSAGE_BYTES {
                self.startup_error("invalid startup packet length")?;
                return Ok(false);
            }
            let body_len = len as usize - 8;
            let mut body = vec![0; body_len];
            self.io.read_exact(&mut body)?;

            if code == SSL_REQUEST_CODE || code == GSSENC_REQUEST_CODE {
                if len != 8 {
                    self.startup_error("malformed SSL/GSS encryption request")?;
                    return Ok(false);
                }
                // This MVP is trust-authenticated and does not terminate TLS
                // itself.  Explicitly decline both negotiation requests, as
                // libpq requires, and continue with an ordinary StartupMessage.
                self.io.write_all(b"N")?;
                self.io.flush()?;
                (len, code) = self.read_startup_header()?;
                continue;
            }
            if code == CANCEL_REQUEST_CODE {
                if len != 16 || body.len() != 8 {
                    return Ok(false);
                }
                let pid = u32::from_be_bytes(body[..4].try_into().unwrap());
                let secret = u32::from_be_bytes(body[4..].try_into().unwrap());
                if let Ok(registry) = cancel_registry().lock() {
                    if let Some(token) = registry.get(&(pid, secret)) {
                        token.store(true, Ordering::Release);
                    }
                }
                return Ok(false);
            }
            if code != PROTOCOL_VERSION_3_0 && code != PROTOCOL_VERSION_3_2 {
                self.startup_error("unsupported frontend protocol version")?;
                return Ok(false);
            }

            let params = match StartupParams::parse(&body) {
                Ok(params) => params,
                Err(e) => {
                    self.startup_error(&e.message)?;
                    return Ok(false);
                }
            };
            let app = params.get("application_name").unwrap_or_default();
            let user = params.get("user").unwrap_or_default();
            if user.is_empty() {
                self.startup_error("startup packet did not include user")?;
                return Ok(false);
            }
            if let Some(encoding) = params.get("client_encoding") {
                if !encoding.eq_ignore_ascii_case("utf8") && !encoding.eq_ignore_ascii_case("utf-8")
                {
                    self.startup_error("unsupported client_encoding")?;
                    return Ok(false);
                }
            }
            if let Some(timezone) = params.get("TimeZone") {
                if !timezone.eq_ignore_ascii_case("UTC") {
                    self.startup_error("unsupported TimeZone")?;
                    return Ok(false);
                }
            }
            if let Some(datestyle) = params.get("DateStyle") {
                if !datestyle.to_ascii_uppercase().starts_with("ISO") {
                    self.startup_error("unsupported DateStyle")?;
                    return Ok(false);
                }
            }
            if self.session.set_param("application_name", &app).is_err() {
                self.startup_error("invalid application_name")?;
                return Ok(false);
            }
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
            self.ready()?;
            return Ok(true);
        }
    }
    fn startup_error(&mut self, message: &str) -> std::io::Result<()> {
        self.error(&SqlError::new("08P01", message))
    }
    fn read_startup_header(&mut self) -> std::io::Result<(u32, u32)> {
        let mut b = [0; 8];
        self.io.read_exact(&mut b)?;
        Ok((
            u32::from_be_bytes(b[..4].try_into().unwrap()),
            u32::from_be_bytes(b[4..].try_into().unwrap()),
        ))
    }
    fn extended_failure(&mut self, e: &SqlError) -> std::io::Result<()> {
        self.error(e)?;
        self.extended_error = true;
        Ok(())
    }
    fn query_cancelled(&self) -> bool {
        self.cancel_token.swap(false, Ordering::AcqRel)
    }
    fn sync(&mut self) -> std::io::Result<()> {
        self.extended_error = false;
        self.ready()
    }
    fn simple_query(&mut self, body: &[u8]) -> std::io::Result<()> {
        let mut decoder = Decoder::new(body);
        let sql = match decoder
            .cstr("simple query")
            .and_then(|sql| decoder.finish("simple query").map(|()| sql))
        {
            Ok(sql) => sql,
            Err(e) => {
                self.error(&e)?;
                return self.ready();
            }
        };
        if sql.is_empty() {
            self.write_message(b'I', &[])?;
            return self.ready();
        }
        if self.query_cancelled() {
            self.error(&SqlError::new(
                "57014",
                "canceling statement due to user request",
            ))?;
            return self.ready();
        }
        match self.session.execute(&sql, &[]) {
            Ok(r) => {
                if self.query_cancelled() {
                    self.error(&SqlError::new(
                        "57014",
                        "canceling statement due to user request",
                    ))?;
                    return self.ready();
                }
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
        let mut decoder = Decoder::new(body);
        let parsed = (|| {
            let name = decoder.cstr("statement name")?;
            let sql = decoder.cstr("Parse query")?;
            let count = decoder.u16("Parse parameter count")? as usize;
            let mut supplied = Vec::with_capacity(count);
            for _ in 0..count {
                supplied.push(decoder.u32("Parse parameter type")?);
            }
            decoder.finish("Parse message")?;
            Ok::<_, SqlError>((name, sql, supplied))
        })();
        let (name, sql, supplied) = match parsed {
            Ok(value) => value,
            Err(e) => return self.extended_failure(&e),
        };
        let types = infer_parameter_types(&sql, &supplied);
        match self.session.prepare(&name, &sql) {
            Ok(()) => {
                if name.is_empty() {
                    // A successful Parse of the unnamed statement destroys
                    // the unnamed portal, matching PostgreSQL's lifecycle.
                    self.portals.remove("");
                }
                self.prepared_types.insert(name, types);
                self.write_message(b'1', &[])
            }
            Err(e) => self.extended_failure(&e),
        }
    }
    fn bind(&mut self, body: &[u8]) -> std::io::Result<()> {
        let mut decoder = Decoder::new(body);
        let parsed = (|| {
            let portal = decoder.cstr("portal name")?;
            let statement = decoder.cstr("statement name")?;
            let format_count = decoder.u16("Bind parameter format count")? as usize;
            let mut formats = Vec::with_capacity(format_count);
            for _ in 0..format_count {
                let format = decoder.u16("Bind parameter format")?;
                if format > 1 {
                    return Err(SqlError::new("08P01", "invalid parameter format code"));
                }
                formats.push(format);
            }
            let count = decoder.u16("Bind parameter count")? as usize;
            if format_count != 0 && format_count != 1 && format_count != count {
                return Err(SqlError::new(
                    "08P01",
                    "incorrect number of Bind parameter formats",
                ));
            }
            let declared = self
                .prepared_types
                .get(&statement)
                .cloned()
                .ok_or_else(|| SqlError::new("26000", "prepared statement does not exist"))?;
            if count != declared.len() {
                return Err(SqlError::new(
                    "08P01",
                    "bind message supplies an incorrect number of parameters",
                ));
            }
            let mut params = Vec::with_capacity(count);
            for i in 0..count {
                let len = decoder.i32("Bind parameter length")?;
                if len < -1 {
                    return Err(SqlError::new("08P01", "invalid Bind parameter length"));
                }
                if len < 0 {
                    params.push(Datum::Null);
                    continue;
                }
                let len = len as usize;
                if len > MAX_PARAMETER_BYTES {
                    return Err(SqlError::new(
                        "54000",
                        "Bind parameter exceeds configured limit",
                    ));
                }
                let data = decoder.bytes(len, "Bind parameter")?;
                let format = format_at(&formats, i).ok_or_else(|| {
                    SqlError::new("08P01", "incorrect number of Bind parameter formats")
                })?;
                let oid = declared[i];
                params.push(decode_param(data, oid, format)?);
            }
            let result_count = decoder.u16("Bind result format count")? as usize;
            let mut result_formats = Vec::with_capacity(result_count);
            for _ in 0..result_count {
                let format = decoder.u16("Bind result format")?;
                if format > 1 {
                    return Err(SqlError::new("08P01", "invalid result format code"));
                }
                result_formats.push(format);
            }
            decoder.finish("Bind message")?;
            let sql = self
                .session_sql(&statement)
                .ok_or_else(|| SqlError::new("26000", "prepared statement does not exist"))?;
            Ok::<_, SqlError>((portal, sql, params, result_formats))
        })();
        let (portal, sql, params, result_formats) = match parsed {
            Ok(value) => value,
            Err(e) => return self.extended_failure(&e),
        };
        // A successful Bind replaces an existing unnamed portal.
        self.portals.insert(
            portal,
            Portal {
                sql,
                params,
                result_formats,
                pending: None,
            },
        );
        self.write_message(b'2', &[])
    }
    fn session_sql(&self, name: &str) -> Option<String> {
        self.session.prepared_sql(name).map(str::to_string)
    }
    fn describe(&mut self, body: &[u8]) -> std::io::Result<()> {
        let Some(kind) = body.first().copied() else {
            return self.extended_failure(&SqlError::new("08P01", "malformed Describe"));
        };
        if kind != b'P' && kind != b'S' {
            return self.extended_failure(&SqlError::new("08P01", "invalid Describe target"));
        }
        let mut decoder = Decoder::new(&body[1..]);
        let name = match decoder
            .cstr("Describe name")
            .and_then(|name| decoder.finish("Describe message").map(|()| name))
        {
            Ok(name) => name,
            Err(e) => return self.extended_failure(&e),
        };
        if kind == b'P' {
            let Some(portal) = self.portals.get(&name).cloned() else {
                return self.extended_failure(&SqlError::new("34000", "portal does not exist"));
            };
            if let Some(result) = portal.pending {
                return self.row_description_with_formats(&result, &portal.result_formats);
            }
            if let Some(result) = infer_result_description(&portal.sql, &self.prepared_types) {
                return self.row_description_with_formats(&result, &portal.result_formats);
            }
            self.write_message(b'n', &[])
        } else {
            let Some(types) = self.prepared_types.get(&name).cloned() else {
                return self.extended_failure(&SqlError::new(
                    "26000",
                    "prepared statement does not exist",
                ));
            };
            let mut p = Vec::new();
            put_u16_checked(&mut p, types.len())?;
            for oid in types {
                p.extend_from_slice(&oid.to_be_bytes());
            }
            self.write_message(b't', &p)?;
            if let Some(sql) = self.session_sql(&name) {
                if let Some(result) = infer_result_description(&sql, &self.prepared_types) {
                    return self.row_description_with_formats(&result, &[]);
                }
            }
            self.write_message(b'n', &[])
        }
    }
    fn execute(&mut self, body: &[u8]) -> std::io::Result<()> {
        let mut decoder = Decoder::new(body);
        let parsed = (|| {
            let portal = decoder.cstr("portal name")?;
            let max = decoder.u32("Execute max rows")? as usize;
            decoder.finish("Execute message")?;
            Ok::<_, SqlError>((portal, max))
        })();
        let (portal, max) = match parsed {
            Ok(value) => value,
            Err(e) => return self.extended_failure(&e),
        };
        if self.query_cancelled() {
            return self.extended_failure(&SqlError::new(
                "57014",
                "canceling statement due to user request",
            ));
        }
        let Some(mut p) = self.portals.get(&portal).cloned() else {
            return self.extended_failure(&SqlError::new("34000", "portal does not exist"));
        };
        let mut result = if let Some(pending) = p.pending.take() {
            pending
        } else {
            match self.session.execute(&p.sql, &p.params) {
                Ok(r) => r,
                Err(e) => return self.extended_failure(&e),
            }
        };
        if self.query_cancelled() {
            return self.extended_failure(&SqlError::new(
                "57014",
                "canceling statement due to user request",
            ));
        }
        if max > 0 && result.rows.len() > max {
            let remaining = result.rows.split_off(max);
            let formats = p.result_formats.clone();
            p.pending = Some(QueryResult {
                columns: result.columns.clone(),
                rows: remaining,
                command_tag: result.command_tag.clone(),
                affected_rows: result.affected_rows,
                notices: result.notices.clone(),
            });
            self.portals.insert(portal, p);
            self.result_rows_with_formats(&result, &formats)?;
            return self.write_message(b's', &[]);
        }
        let formats = p.result_formats.clone();
        self.portals.insert(portal, p);
        self.result_with_formats(&result, &formats)
    }
    fn close(&mut self, body: &[u8]) -> std::io::Result<()> {
        let Some(kind) = body.first().copied() else {
            return self.extended_failure(&SqlError::new("08P01", "malformed Close"));
        };
        let mut decoder = Decoder::new(&body[1..]);
        let name = match decoder
            .cstr("Close name")
            .and_then(|name| decoder.finish("Close message").map(|()| name))
        {
            Ok(name) => name,
            Err(e) => return self.extended_failure(&e),
        };
        match kind {
            b'P' => {
                self.portals.remove(&name);
            }
            b'S' => {
                self.session.close_prepared(&name);
                self.prepared_types.remove(&name);
            }
            _ => return self.extended_failure(&SqlError::new("08P01", "invalid Close target")),
        }
        self.write_message(b'3', &[])
    }
    fn result(&mut self, r: &QueryResult) -> std::io::Result<()> {
        self.result_with_formats(r, &[])
    }
    fn result_with_formats(
        &mut self,
        r: &QueryResult,
        result_formats: &[u16],
    ) -> std::io::Result<()> {
        self.result_rows_with_formats(r, result_formats)?;
        let mut tag = r.command_tag.clone();
        if tag.eq_ignore_ascii_case("SELECT") {
            tag = format!("SELECT {}", r.affected_rows);
        } else if tag.is_empty() {
            tag = "SELECT 0".into();
        }
        let mut b = tag.into_bytes();
        b.push(0);
        self.write_message(b'C', &b)
    }
    fn result_rows(&mut self, r: &QueryResult) -> std::io::Result<()> {
        self.result_rows_with_formats(r, &[])
    }
    fn result_rows_with_formats(
        &mut self,
        r: &QueryResult,
        result_formats: &[u16],
    ) -> std::io::Result<()> {
        validate_result_formats(result_formats, r.columns.len())?;
        if !r.columns.is_empty() {
            self.row_description_with_formats(r, result_formats)?;
            let mut total_bytes = 0usize;
            for row in &r.rows {
                if row.len() != r.columns.len() || row.len() > MAX_PROTOCOL_ITEMS {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "result row has an invalid column count",
                    ));
                }
                let mut d = Vec::new();
                put_u16(&mut d, row.len() as u16);
                for (i, v) in row.iter().enumerate() {
                    if v.is_null() {
                        d.extend_from_slice(&(-1i32).to_be_bytes());
                        continue;
                    }
                    let format = format_at(result_formats, i).unwrap_or(0);
                    let value = if format == 1 {
                        encode_binary_result(v, r.columns[i].data_type)
                    } else {
                        encode_text_result(v).into_bytes()
                    };
                    if value.len() > i32::MAX as usize
                        || d.len().saturating_add(value.len()).saturating_add(4)
                            > MAX_WIRE_RESULT_BYTES
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "result row exceeds configured wire limit",
                        ));
                    }
                    d.extend_from_slice(&(value.len() as i32).to_be_bytes());
                    d.extend_from_slice(&value);
                }
                total_bytes = total_bytes.saturating_add(d.len());
                if total_bytes > MAX_WIRE_RESULT_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "result exceeds configured wire limit",
                    ));
                }
                self.write_message(b'D', &d)?;
            }
        }
        Ok(())
    }
    fn row_description(&mut self, r: &QueryResult) -> std::io::Result<()> {
        self.row_description_with_formats(r, &[])
    }
    fn row_description_with_formats(
        &mut self,
        r: &QueryResult,
        result_formats: &[u16],
    ) -> std::io::Result<()> {
        let b = row_description_body(r, result_formats)?;
        self.write_message(b'T', &b)
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
        field(&mut b, b'C', sqlstate(e));
        field(&mut b, b'M', &e.message);
        if let Some(d) = &e.detail {
            field(&mut b, b'D', d);
        }
        if let Some(h) = &e.hint {
            field(&mut b, b'H', h);
        }
        if let Some(position) = e.position {
            field(&mut b, b'P', &position.to_string());
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
        if len < 4 || len > MAX_FRONTEND_MESSAGE_BYTES {
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
        let total = body.len().checked_add(4).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "wire message length overflow",
            )
        })?;
        if total > MAX_FRONTEND_MESSAGE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "wire message exceeds configured limit",
            ));
        }
        let len = total as u32;
        self.io.write_all(&[typ])?;
        self.io.write_all(&len.to_be_bytes())?;
        self.io.write_all(body)?;
        self.io.flush()
    }
}

fn format_at(formats: &[u16], index: usize) -> Option<u16> {
    match formats {
        [] => Some(0),
        [format] => Some(*format),
        formats => formats.get(index).copied(),
    }
}

fn validate_result_formats(formats: &[u16], columns: usize) -> std::io::Result<()> {
    if formats.len() > 1 && formats.len() != columns {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "incorrect number of result formats",
        ));
    }
    if formats.iter().any(|format| *format > 1) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid result format code",
        ));
    }
    Ok(())
}

fn decode_param(bytes: &[u8], oid: u32, format: u16) -> WireResult<Datum> {
    match format {
        0 => {
            let text = std::str::from_utf8(bytes)
                .map_err(|_| SqlError::new("22021", "invalid UTF-8 parameter"))?;
            if let Some(value) = decode_text_param(text, oid) {
                Ok(value)
            } else if oid == 0 {
                Ok(Datum::Text(text.into()))
            } else {
                Err(SqlError::new(
                    "22P02",
                    "invalid input syntax for parameter type",
                ))
            }
        }
        1 => decode_binary_param(bytes, oid)
            .ok_or_else(|| SqlError::new("22P03", "invalid binary representation")),
        _ => Err(SqlError::new("08P01", "invalid parameter format code")),
    }
}

fn decode_text_param(text: &str, oid: u32) -> Option<Datum> {
    match oid {
        16 => parse_bool(text).map(Datum::Boolean),
        21 => text.parse::<i16>().ok().map(Datum::Int16),
        23 => text.parse::<i32>().ok().map(Datum::Int32),
        20 => text.parse::<i64>().ok().map(Datum::Int64),
        701 => text.parse::<f64>().ok().map(Datum::Float64),
        17 => parse_bytea_text(text).map(Datum::Bytes),
        25 | 1043 => Some(Datum::Text(text.into())),
        1082 => parse_date_text(text).map(Datum::Date),
        1114 => parse_timestamp_text(text).map(Datum::Timestamp),
        1184 => parse_timestamp_text(text).map(Datum::TimestampTz),
        3802 => chorus_common::Datum::canonical_json(text)
            .ok()
            .map(Datum::Jsonb),
        2950 => parse_uuid(text).map(Datum::Uuid),
        0 => {
            if let Ok(v) = text.parse::<i64>() {
                Some(Datum::Int64(v))
            } else if let Ok(v) = text.parse::<f64>() {
                Some(Datum::Float64(v))
            } else if let Some(v) = parse_bool(text) {
                Some(Datum::Boolean(v))
            } else {
                Some(Datum::Text(text.into()))
            }
        }
        _ => None,
    }
}

fn decode_binary_param(bytes: &[u8], oid: u32) -> Option<Datum> {
    match oid {
        16 if bytes.len() == 1 && (bytes[0] == 0 || bytes[0] == 1) => {
            Some(Datum::Boolean(bytes[0] != 0))
        }
        21 if bytes.len() == 2 => Some(Datum::Int16(i16::from_be_bytes(bytes.try_into().ok()?))),
        23 if bytes.len() == 4 => Some(Datum::Int32(i32::from_be_bytes(bytes.try_into().ok()?))),
        20 if bytes.len() == 8 => Some(Datum::Int64(i64::from_be_bytes(bytes.try_into().ok()?))),
        701 if bytes.len() == 8 => Some(Datum::Float64(f64::from_bits(u64::from_be_bytes(
            bytes.try_into().ok()?,
        )))),
        17 => Some(Datum::Bytes(bytes.to_vec())),
        25 | 1043 => Some(Datum::Text(String::from_utf8(bytes.to_vec()).ok()?)),
        1082 if bytes.len() == 4 => Some(Datum::Date(
            i32::from_be_bytes(bytes.try_into().ok()?) + unix_days_to_pg_epoch_days(),
        )),
        1114 if bytes.len() == 8 => Some(Datum::Timestamp(
            i64::from_be_bytes(bytes.try_into().ok()?)
                .checked_add(POSTGRES_EPOCH_UNIX_SECS.checked_mul(1_000_000)?)?,
        )),
        1184 if bytes.len() == 8 => Some(Datum::TimestampTz(
            i64::from_be_bytes(bytes.try_into().ok()?)
                .checked_add(POSTGRES_EPOCH_UNIX_SECS.checked_mul(1_000_000)?)?,
        )),
        2950 if bytes.len() == 16 => Some(Datum::Uuid(bytes.try_into().ok()?)),
        3802 if bytes.first() == Some(&1) => {
            chorus_common::Datum::canonical_json(&String::from_utf8(bytes[1..].to_vec()).ok()?)
                .ok()
                .map(Datum::Jsonb)
        }
        _ => None,
    }
}

fn encode_text_result(value: &Datum) -> String {
    value.display_text()
}

fn encode_binary_result(value: &Datum, ty: SqlType) -> Vec<u8> {
    match (ty, value) {
        (SqlType::Boolean, Datum::Boolean(v)) => vec![u8::from(*v)],
        (SqlType::Bytea, Datum::Bytes(v)) => v.clone(),
        (SqlType::SmallInt, Datum::Int16(v)) => v.to_be_bytes().to_vec(),
        (SqlType::Integer, Datum::Int32(v)) => v.to_be_bytes().to_vec(),
        (SqlType::BigInt, Datum::Int64(v)) => v.to_be_bytes().to_vec(),
        (SqlType::Double, Datum::Float64(v)) => v.to_bits().to_be_bytes().to_vec(),
        (SqlType::Text, Datum::Text(v)) | (SqlType::Varchar(_), Datum::Text(v)) => {
            v.as_bytes().to_vec()
        }
        (SqlType::Date, Datum::Date(v)) => {
            (v - unix_days_to_pg_epoch_days()).to_be_bytes().to_vec()
        }
        (SqlType::Timestamp, Datum::Timestamp(v))
        | (SqlType::TimestampTz, Datum::TimestampTz(v)) => v
            .checked_sub(POSTGRES_EPOCH_UNIX_SECS.saturating_mul(1_000_000))
            .unwrap_or_default()
            .to_be_bytes()
            .to_vec(),
        (SqlType::Uuid, Datum::Uuid(v)) => v.to_vec(),
        (SqlType::Jsonb, Datum::Jsonb(v)) => {
            let mut out = Vec::with_capacity(v.len() + 1);
            out.push(1);
            out.extend_from_slice(v.as_bytes());
            out
        }
        (_, other) => encode_text_result(other).into_bytes(),
    }
}

fn parse_bool(text: &str) -> Option<bool> {
    match text.trim().to_ascii_lowercase().as_str() {
        "t" | "true" | "1" | "on" | "yes" => Some(true),
        "f" | "false" | "0" | "off" | "no" => Some(false),
        _ => None,
    }
}

fn parse_bytea_text(text: &str) -> Option<Vec<u8>> {
    let text = text.strip_prefix("\\x")?;
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

fn parse_date_text(text: &str) -> Option<i32> {
    let mut parts = text.trim().split('-');
    let year = parts.next()?.parse::<i64>().ok()?;
    let month = parts.next()?.parse::<i64>().ok()?;
    let day = parts.next()?.parse::<i64>().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    i32::try_from(days).ok()
}

fn parse_timestamp_text(text: &str) -> Option<i64> {
    let text = text
        .trim()
        .trim_end_matches("+00")
        .trim_end_matches("+00:00");
    let (date, time) = text.split_once([' ', 'T'])?;
    let days = parse_date_text(date)? as i64;
    let mut time_parts = time.split(':');
    let hour = time_parts.next()?.parse::<i64>().ok()?;
    let minute = time_parts.next()?.parse::<i64>().ok()?;
    let second_text = time_parts.next()?;
    if time_parts.next().is_some() || hour > 23 || minute > 59 {
        return None;
    }
    let (second, micros) = if let Some((whole, fraction)) = second_text.split_once('.') {
        let second = whole.parse::<i64>().ok()?;
        let mut fraction = fraction.to_string();
        if fraction.len() > 6 {
            fraction.truncate(6);
        }
        while fraction.len() < 6 {
            fraction.push('0');
        }
        (second, fraction.parse::<i64>().ok()?)
    } else {
        (second_text.parse::<i64>().ok()?, 0)
    };
    if second > 59 {
        return None;
    }
    days.checked_mul(86_400_000_000)?.checked_add(
        hour.checked_mul(3_600_000_000)?
            .checked_add(minute.checked_mul(60_000_000)?)?
            .checked_add(second.checked_mul(1_000_000)?)?
            .checked_add(micros)?,
    )
}

fn unix_days_to_pg_epoch_days() -> i32 {
    10_957
}

fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    let y = year.checked_sub(i64::from(month <= 2))?;
    let era = (if y >= 0 { y } else { y - 399 }).div_euclid(400);
    let yoe = y - era * 400;
    let mp = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

fn put_u16_checked(out: &mut Vec<u8>, value: usize) -> std::io::Result<()> {
    if value > MAX_PROTOCOL_ITEMS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "wire item count exceeds u16",
        ));
    }
    put_u16(out, value as u16);
    Ok(())
}

fn sqlstate(error: &SqlError) -> &'static str {
    let code = error.code.as_bytes();
    if code.len() == 5 && code.iter().all(|b| b.is_ascii_alphanumeric()) {
        error.code
    } else {
        "XX000"
    }
}

fn infer_parameter_types(sql: &str, supplied: &[u32]) -> Vec<u32> {
    let mut max_param = supplied.len();
    let bytes = sql.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\'' || bytes[i] == b'"' {
            let quote = bytes[i];
            i += 1;
            while i < bytes.len() {
                if bytes[i] == quote {
                    if i + 1 < bytes.len() && bytes[i + 1] == quote {
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if bytes[i] == b'$' {
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end > start {
                if let Ok(n) = sql[start..end].parse::<usize>() {
                    max_param = max_param.max(n);
                }
                i = end;
                continue;
            }
        }
        i += 1;
    }
    let mut types = supplied.to_vec();
    types.resize(max_param, 0);
    types
}

// The SQL engine owns planning and catalog lookup.  Keeping Describe's
// fallback as NoData is preferable to executing a statement merely to obtain
// metadata (which could commit a write); an actual result always carries its
// authoritative RowDescription.
fn infer_result_description(
    _sql: &str,
    _prepared_types: &HashMap<String, Vec<u32>>,
) -> Option<QueryResult> {
    None
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

fn row_description_body(r: &QueryResult, result_formats: &[u16]) -> std::io::Result<Vec<u8>> {
    if r.columns.len() > MAX_PROTOCOL_ITEMS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "too many result columns",
        ));
    }
    validate_result_formats(result_formats, r.columns.len())?;
    let mut b = Vec::new();
    put_u16(&mut b, r.columns.len() as u16);
    for (i, c) in r.columns.iter().enumerate() {
        cstr_put(&mut b, &c.name);
        b.extend_from_slice(&c.table_oid.to_be_bytes());
        // Attribute number is int16; a synthetic expression has no table
        // attribute and therefore uses zero.
        b.extend_from_slice(&(c.column_oid as i16).to_be_bytes());
        b.extend_from_slice(&c.data_type.oid().to_be_bytes());
        // PostgreSQL RowDescription: type length int16, type modifier int32,
        // and result format int16.  Variable-width types use -1 length.
        b.extend_from_slice(&(-1i16).to_be_bytes());
        b.extend_from_slice(&(-1i32).to_be_bytes());
        b.extend_from_slice(&format_at(result_formats, i).unwrap_or(0).to_be_bytes());
    }
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_description_has_exact_postgres_field_layout() {
        let result = QueryResult {
            columns: vec![ResultColumn {
                name: "value".into(),
                data_type: SqlType::Integer,
                table_oid: 42,
                column_oid: 7,
            }],
            rows: Vec::new(),
            command_tag: "SELECT".into(),
            affected_rows: 0,
            notices: Vec::new(),
        };
        let body = row_description_body(&result, &[1]).expect("row description");
        assert_eq!(u16::from_be_bytes([body[0], body[1]]), 1);
        let mut p = 2;
        assert_eq!(&body[p..p + 6], b"value\0");
        p += 6;
        assert_eq!(u32::from_be_bytes(body[p..p + 4].try_into().unwrap()), 42);
        p += 4;
        assert_eq!(i16::from_be_bytes(body[p..p + 2].try_into().unwrap()), 7);
        p += 2;
        assert_eq!(u32::from_be_bytes(body[p..p + 4].try_into().unwrap()), 23);
        p += 4;
        assert_eq!(i16::from_be_bytes(body[p..p + 2].try_into().unwrap()), -1);
        p += 2;
        assert_eq!(i32::from_be_bytes(body[p..p + 4].try_into().unwrap()), -1);
        p += 4;
        assert_eq!(i16::from_be_bytes(body[p..p + 2].try_into().unwrap()), 1);
        p += 2;
        assert_eq!(p, body.len());
    }
}
