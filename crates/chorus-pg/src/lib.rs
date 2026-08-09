#![forbid(unsafe_code)]

//! Minimal PostgreSQL v3 frontend. It implements startup, trust
//! authentication, simple query, the extended Parse/Bind/Describe/Execute /
//! Sync flow, cancellation keys, and structured errors without depending on a
//! native PostgreSQL client library.

use chorus_common::{Datum, POSTGRES_EPOCH_UNIX_SECS, SqlError, SqlType};
use chorus_sql::{QueryResult, ResultColumn, SqlEngine, SqlSession};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

// Keep wire limits deliberately conservative.  PostgreSQL's protocol uses a
// signed 32-bit length, but accepting multi-gigabyte frames is an easy denial
// of service and would defeat the SQL/row limits enforced by the engine.
const MAX_FRONTEND_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_STARTUP_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_WIRE_RESULT_BYTES: usize = 16 * 1024 * 1024;
const MAX_PARAMETER_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROTOCOL_ITEMS: usize = u16::MAX as usize;
const MAX_STATEMENT_BYTES: usize = 1024 * 1024;
const MAX_NAMED_PREPARED: usize = 256;
const MAX_NAMED_PORTALS: usize = 256;
const MAX_RETAINED_EXTENDED_QUERY_BYTES: usize = 16 * 1024 * 1024;
const PROTOCOL_VERSION_3_0: u32 = 196_608;
const PROTOCOL_VERSION_3_2: u32 = 196_610;
const SSL_REQUEST_CODE: u32 = 80_877_103;
const CANCEL_REQUEST_CODE: u32 = 80_877_102;
const GSSENC_REQUEST_CODE: u32 = 80_877_104;

type CancelKey = (u32, u32);

struct CancelRegistration {
    active: AtomicBool,
    requested: Arc<AtomicBool>,
}

fn cancel_registry() -> &'static Mutex<HashMap<CancelKey, Arc<CancelRegistration>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<CancelKey, Arc<CancelRegistration>>>> = OnceLock::new();
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

const DEFAULT_SHUTDOWN_DRAIN: Duration = Duration::from_secs(5);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// A server-owned handle for PostgreSQL listeners and their connection
/// workers. It lets an embedding process bind/report readiness first, then
/// request a bounded drain and deterministic listener cleanup.
pub struct PgServerHandle {
    shutdown: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    manager: Mutex<Option<JoinHandle<std::io::Result<()>>>>,
    tcp_addr: Option<SocketAddr>,
    unix_socket: Option<std::path::PathBuf>,
}

impl PgServerHandle {
    /// Request listener shutdown. Existing sessions are allowed to drain until
    /// the configured deadline; the manager then closes their sockets.
    pub fn signal_shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    /// Number of sessions which currently hold a connection permit.
    pub fn active_connections(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    /// Return the actual bound TCP address (useful when the configured port is
    /// zero in tests or an embedding application).
    pub fn tcp_addr(&self) -> Option<SocketAddr> {
        self.tcp_addr
    }

    pub fn unix_socket(&self) -> Option<&std::path::Path> {
        self.unix_socket.as_deref()
    }

    /// Signal shutdown and wait for listener/session workers to finish.
    pub fn shutdown(self) -> std::io::Result<()> {
        self.signal_shutdown();
        self.wait()
    }

    /// Wait for the server manager. This blocks until `signal_shutdown` is
    /// called (or the server was created with an already-set token).
    pub fn wait(self) -> std::io::Result<()> {
        let manager = self
            .manager
            .lock()
            .map_err(|_| std::io::Error::other("PostgreSQL server manager lock poisoned"))?
            .take();
        let Some(manager) = manager else {
            return Ok(());
        };
        manager
            .join()
            .map_err(|_| std::io::Error::other("PostgreSQL server manager panicked"))?
    }
}

impl Drop for PgServerHandle {
    fn drop(&mut self) {
        self.signal_shutdown();
        let manager = self
            .manager
            .lock()
            .ok()
            .and_then(|mut manager| manager.take());
        if let Some(manager) = manager {
            let _ = manager.join();
        }
    }
}

impl PgServer {
    pub fn new(engine: Arc<SqlEngine>, config: PgConfig) -> Self {
        Self { engine, config }
    }

    /// Start listeners and return after both sockets are bound. The returned
    /// handle owns listener and connection-worker shutdown. This is the
    /// lifecycle API used by graceful shutdown callers.
    pub fn start(&self) -> std::io::Result<PgServerHandle> {
        self.start_with_token(Arc::new(AtomicBool::new(false)), DEFAULT_SHUTDOWN_DRAIN)
    }

    /// Start listeners with the default shutdown token and a caller-selected
    /// drain deadline. Primarily useful to embedders and deterministic tests.
    pub fn start_with_drain_timeout(
        &self,
        drain_timeout: Duration,
    ) -> std::io::Result<PgServerHandle> {
        self.start_with_token(Arc::new(AtomicBool::new(false)), drain_timeout)
    }

    /// Start listeners with a caller-owned shutdown token and drain deadline.
    /// The token is sampled by the accept loops and may be shared with a
    /// signal handler or a higher-level node lifecycle.
    pub fn start_with_shutdown(
        &self,
        shutdown: Arc<AtomicBool>,
        drain_timeout: Duration,
    ) -> std::io::Result<PgServerHandle> {
        self.start_with_token(shutdown, drain_timeout)
    }

    /// Bind, serve, and wait for a caller-owned shutdown token. Existing
    /// `serve` users retain the indefinitely-running behavior below.
    pub fn serve_with_shutdown(
        &self,
        shutdown: Arc<AtomicBool>,
        drain_timeout: Duration,
    ) -> std::io::Result<()> {
        self.start_with_shutdown(shutdown, drain_timeout)?.wait()
    }

    pub fn serve(&self) -> std::io::Result<()> {
        self.start()?.wait()
    }

    fn start_with_token(
        &self,
        shutdown: Arc<AtomicBool>,
        drain_timeout: Duration,
    ) -> std::io::Result<PgServerHandle> {
        let active = Arc::new(AtomicUsize::new(0));
        let registry = Arc::new(ConnectionRegistry::default());
        let mut tcp_addr = None;
        let tcp_listener = if let Some(addr) = &self.config.tcp_listen {
            let listener = TcpListener::bind(addr)?;
            listener.set_nonblocking(true)?;
            tcp_addr = Some(listener.local_addr()?);
            Some(listener)
        } else {
            None
        };

        let mut unix_socket = None;
        let mut unix_identity = None;
        let unix_listener = if let Some(path) = &self.config.unix_socket {
            prepare_unix_socket_path(path)?;
            let listener = UnixListener::bind(path)?;
            listener.set_nonblocking(true)?;
            unix_identity = Some(unix_socket_identity(path)?);
            unix_socket = Some(std::path::PathBuf::from(path));
            Some(listener)
        } else {
            None
        };

        // All binds complete before any accept thread is spawned. A later
        // Unix bind failure therefore cannot leak an already-live TCP server.
        let mut listener_threads = Vec::new();
        if let Some(listener) = tcp_listener {
            listener_threads.push(spawn_tcp_accept_loop(
                listener,
                Arc::clone(&shutdown),
                Arc::clone(&self.engine),
                Arc::clone(&active),
                self.config.max_connections,
                Arc::clone(&registry),
            ));
        }
        if let Some(listener) = unix_listener {
            listener_threads.push(spawn_unix_accept_loop(
                listener,
                Arc::clone(&shutdown),
                Arc::clone(&self.engine),
                Arc::clone(&active),
                self.config.max_connections,
                Arc::clone(&registry),
            ));
        }

        let manager_shutdown = Arc::clone(&shutdown);
        let manager_active = Arc::clone(&active);
        let manager_registry = Arc::clone(&registry);
        let manager_unix_socket = unix_socket.clone();
        let manager_unix_identity = unix_identity;
        let manager = thread::spawn(move || {
            while !manager_shutdown.load(Ordering::Acquire) {
                thread::park_timeout(ACCEPT_POLL_INTERVAL);
            }
            for listener in listener_threads {
                let _ = listener.join();
            }

            let deadline = Instant::now() + drain_timeout;
            while manager_active.load(Ordering::Acquire) != 0 && Instant::now() < deadline {
                thread::park_timeout(Duration::from_millis(5));
            }
            if manager_active.load(Ordering::Acquire) != 0 {
                manager_registry.close_all();
            }
            for worker in manager_registry.take_workers() {
                let _ = worker.join();
            }
            // A worker may have been between its final read and permit drop
            // when the first close pass ran. Close once more before reporting
            // completion and make the permit invariant observable.
            if manager_active.load(Ordering::Acquire) != 0 {
                manager_registry.close_all();
                for worker in manager_registry.take_workers() {
                    let _ = worker.join();
                }
            }
            if let Some(path) = manager_unix_socket {
                remove_owned_unix_socket(&path, manager_unix_identity)?;
            }
            Ok(())
        });

        Ok(PgServerHandle {
            shutdown,
            active,
            manager: Mutex::new(Some(manager)),
            tcp_addr,
            unix_socket,
        })
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

trait ShutdownSocket: Send + Sync {
    fn close(&self);
}

impl ShutdownSocket for TcpStream {
    fn close(&self) {
        let _ = self.shutdown(Shutdown::Both);
    }
}

impl ShutdownSocket for UnixStream {
    fn close(&self) {
        let _ = self.shutdown(Shutdown::Both);
    }
}

#[derive(Default)]
struct ConnectionRegistry {
    next_id: AtomicUsize,
    sockets: Mutex<HashMap<usize, Arc<dyn ShutdownSocket>>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
}

impl ConnectionRegistry {
    fn register(&self, socket: Arc<dyn ShutdownSocket>) -> usize {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut sockets) = self.sockets.lock() {
            sockets.insert(id, socket);
        }
        id
    }

    fn unregister(&self, id: usize) {
        if let Ok(mut sockets) = self.sockets.lock() {
            sockets.remove(&id);
        }
    }

    fn close_all(&self) {
        if let Ok(sockets) = self.sockets.lock() {
            for socket in sockets.values() {
                socket.close();
            }
        }
    }

    fn add_worker(&self, worker: JoinHandle<()>) {
        if let Ok(mut workers) = self.workers.lock() {
            workers.push(worker);
        }
    }

    fn take_workers(&self) -> Vec<JoinHandle<()>> {
        self.workers
            .lock()
            .map(|mut workers| std::mem::take(&mut *workers))
            .unwrap_or_default()
    }
}

fn spawn_tcp_accept_loop(
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
    engine: Arc<SqlEngine>,
    active: Arc<AtomicUsize>,
    max_connections: usize,
    registry: Arc<ConnectionRegistry>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        loop {
            if shutdown.load(Ordering::Acquire) {
                return;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    if shutdown.load(Ordering::Acquire) {
                        let _ = stream.shutdown(Shutdown::Both);
                        return;
                    }
                    let Ok(control) = stream.try_clone() else {
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    };
                    let Ok(permit) =
                        ConnectionPermit::try_acquire(Arc::clone(&active), max_connections)
                    else {
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    };
                    spawn_connection_worker(
                        stream,
                        Arc::new(control),
                        engine.clone(),
                        permit,
                        Arc::clone(&registry),
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::park_timeout(ACCEPT_POLL_INTERVAL);
                }
                Err(_) => return,
            }
        }
    })
}

fn spawn_unix_accept_loop(
    listener: UnixListener,
    shutdown: Arc<AtomicBool>,
    engine: Arc<SqlEngine>,
    active: Arc<AtomicUsize>,
    max_connections: usize,
    registry: Arc<ConnectionRegistry>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        loop {
            if shutdown.load(Ordering::Acquire) {
                return;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    if shutdown.load(Ordering::Acquire) {
                        let _ = stream.shutdown(Shutdown::Both);
                        return;
                    }
                    let Ok(control) = stream.try_clone() else {
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    };
                    let Ok(permit) =
                        ConnectionPermit::try_acquire(Arc::clone(&active), max_connections)
                    else {
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    };
                    spawn_connection_worker(
                        stream,
                        Arc::new(control),
                        engine.clone(),
                        permit,
                        Arc::clone(&registry),
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::park_timeout(ACCEPT_POLL_INTERVAL);
                }
                Err(_) => return,
            }
        }
    })
}

fn spawn_connection_worker<S>(
    stream: S,
    control: Arc<dyn ShutdownSocket>,
    engine: Arc<SqlEngine>,
    permit: ConnectionPermit,
    registry: Arc<ConnectionRegistry>,
) where
    S: Io + 'static,
{
    let socket_id = registry.register(control);
    let worker_registry = Arc::clone(&registry);
    let worker = thread::spawn(move || {
        let _permit = permit;
        let _ = Connection::new(engine, Box::new(stream)).run();
        worker_registry.unregister(socket_id);
    });
    registry.add_worker(worker);
}

#[derive(Clone, Copy)]
struct UnixSocketIdentity {
    dev: u64,
    ino: u64,
}

fn unix_socket_identity(path: &str) -> std::io::Result<UnixSocketIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path)?;
    Ok(UnixSocketIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    })
}

fn prepare_unix_socket_path(path: &str) -> std::io::Result<()> {
    let path = std::path::Path::new(path);
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;
                if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "refusing to replace a non-socket Unix path",
                    ));
                }
                // Do not unlink a live listener owned by another process. A
                // failed connect identifies a stale socket pathname that can
                // safely be replaced during restart.
                if UnixStream::connect(path).is_ok() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AddrInUse,
                        "Unix socket is already serving",
                    ));
                }
            }
            std::fs::remove_file(path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

fn remove_owned_unix_socket(
    path: &std::path::Path,
    identity: Option<UnixSocketIdentity>,
) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;
                if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
                    return Ok(());
                }
                use std::os::unix::fs::MetadataExt;
                let Some(identity) = identity else {
                    return Ok(());
                };
                if metadata.dev() != identity.dev || metadata.ino() != identity.ino {
                    return Ok(());
                }
                // A replacement socket can legally reuse the same inode on
                // some filesystems. A successful connect proves that the
                // pathname is serving again, so never unlink it during old
                // server cleanup even in that reuse case.
                if UnixStream::connect(path).is_ok() {
                    return Ok(());
                }
            }
            std::fs::remove_file(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
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

trait Io: Read + Write + Send {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()>;
}

impl Io for TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }
}

impl Io for UnixStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        UnixStream::set_read_timeout(self, timeout)
    }
}

#[cfg(test)]
impl Io for std::io::Cursor<Vec<u8>> {
    fn set_read_timeout(&self, _timeout: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }
}
struct Connection {
    io: Box<dyn Io>,
    session: SqlSession,
    portals: HashMap<String, Portal>,
    prepared_types: HashMap<String, Vec<u32>>,
    retained_extended_query_bytes: usize,
    extended_query_state_limit: usize,
    backend_pid: u32,
    secret: u32,
    cancel_token: Arc<AtomicBool>,
    cancel_registration: Arc<CancelRegistration>,
    extended_error: bool,
    idle_transaction_deadline: Option<Instant>,
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
        let pid = next_backend_pid();
        let secret = pid
            .rotate_left(13)
            .wrapping_add(NEXT_BACKEND_PID.load(Ordering::Relaxed));
        let cancel_token = Arc::new(AtomicBool::new(false));
        let cancel_registration = Arc::new(CancelRegistration {
            active: AtomicBool::new(false),
            requested: Arc::clone(&cancel_token),
        });
        if let Ok(mut registry) = cancel_registry().lock() {
            registry.insert((pid, secret), Arc::clone(&cancel_registration));
        }
        let mut session = engine.session();
        session.set_cancellation_checker(Some(cancel_token.clone()));
        Self {
            io,
            session,
            portals: HashMap::new(),
            prepared_types: HashMap::new(),
            retained_extended_query_bytes: 0,
            extended_query_state_limit: MAX_RETAINED_EXTENDED_QUERY_BYTES,
            backend_pid: pid,
            secret,
            cancel_token,
            cancel_registration,
            extended_error: false,
            idle_transaction_deadline: None,
        }
    }
    fn run(mut self) -> std::io::Result<()> {
        if !self.startup()? {
            return Ok(());
        }
        loop {
            let next = match self.message() {
                Ok(next) => next,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) && self.idle_transaction_deadline.is_some() =>
                {
                    self.fatal_idle_transaction_timeout()?;
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            let Some((typ, body)) = next else {
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
                    if let Some(registration) = registry.get(&(pid, secret)) {
                        if registration.active.load(Ordering::Acquire) {
                            registration.requested.store(true, Ordering::Release);
                        }
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
    fn begin_query(&self) {
        // A request received while the backend was idle belongs to no query.
        // Clear it before opening the active window observed by CancelRequest.
        self.cancel_token.store(false, Ordering::Release);
        self.cancel_registration
            .active
            .store(true, Ordering::Release);
    }
    fn end_query(&self) {
        self.cancel_registration
            .active
            .store(false, Ordering::Release);
        self.cancel_token.store(false, Ordering::Release);
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
        self.begin_query();
        let result = self.session.execute(&sql, &[]);
        self.end_query();
        match result {
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

    fn prepared_entry_bytes(&self, name: &str) -> WireResult<usize> {
        match (
            self.session.prepared_sql(name),
            self.prepared_types.get(name),
        ) {
            (Some(sql), Some(types)) => prepared_retained_bytes(name, sql, types),
            (None, None) => Ok(0),
            _ => Err(SqlError::new(
                "XX000",
                "prepared statement accounting is inconsistent",
            )),
        }
    }

    fn portal_entry_bytes(&self, name: &str) -> WireResult<usize> {
        self.portals
            .get(name)
            .map_or(Ok(0), |portal| portal_retained_bytes(name, portal))
    }

    fn projected_extended_query_bytes(&self, removed: usize, added: usize) -> WireResult<usize> {
        projected_retained_bytes(
            self.retained_extended_query_bytes,
            removed,
            added,
            self.extended_query_state_limit,
        )
    }

    fn replace_portal_accounted(
        &mut self,
        name: &str,
        portal: Portal,
        old_bytes: usize,
    ) -> WireResult<()> {
        let added = portal_retained_bytes(name, &portal)?;
        let projected = self.projected_extended_query_bytes(old_bytes, added)?;
        self.portals.insert(name.to_string(), portal);
        self.retained_extended_query_bytes = projected;
        Ok(())
    }

    fn discard_portal_accounted(&mut self, name: &str, old_bytes: usize) -> WireResult<()> {
        let projected = self.projected_extended_query_bytes(old_bytes, 0)?;
        self.portals.remove(name);
        self.retained_extended_query_bytes = projected;
        Ok(())
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
        if statement_exceeds_limit(&sql) {
            return self.extended_failure(&SqlError::new(
                "54000",
                "prepared statement exceeds configured size limit",
            ));
        }
        if !name.is_empty() && self.prepared_types.contains_key(&name) {
            return self
                .extended_failure(&SqlError::new("42P05", "prepared statement already exists"));
        }
        if named_resource_limit_reached(&self.prepared_types, &name, MAX_NAMED_PREPARED) {
            return self.extended_failure(&SqlError::new(
                "54000",
                "too many named prepared statements",
            ));
        }
        let types = match infer_parameter_types(&sql, &supplied) {
            Ok(types) => types,
            Err(e) => return self.extended_failure(&e),
        };
        let old_statement_bytes = match self.prepared_entry_bytes(&name) {
            Ok(bytes) => bytes,
            Err(e) => return self.extended_failure(&e),
        };
        let old_unnamed_portal_bytes = if name.is_empty() {
            match self.portal_entry_bytes("") {
                Ok(bytes) => bytes,
                Err(e) => return self.extended_failure(&e),
            }
        } else {
            0
        };
        let removed = match old_statement_bytes.checked_add(old_unnamed_portal_bytes) {
            Some(bytes) => bytes,
            None => {
                return self.extended_failure(&SqlError::new(
                    "XX000",
                    "extended-query accounting overflow",
                ));
            }
        };
        let added = match prepared_retained_bytes(&name, &sql, &types) {
            Ok(bytes) => bytes,
            Err(e) => return self.extended_failure(&e),
        };
        let projected = match self.projected_extended_query_bytes(removed, added) {
            Ok(bytes) => bytes,
            Err(e) => return self.extended_failure(&e),
        };
        match self.session.prepare(&name, &sql) {
            Ok(()) => {
                if name.is_empty() {
                    // A successful Parse of the unnamed statement destroys
                    // the unnamed portal, matching PostgreSQL's lifecycle.
                    self.portals.remove("");
                }
                self.prepared_types.insert(name, types);
                self.retained_extended_query_bytes = projected;
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
        if !portal.is_empty() && self.portals.contains_key(&portal) {
            return self.extended_failure(&SqlError::new("42P03", "portal already exists"));
        }
        if named_resource_limit_reached(&self.portals, &portal, MAX_NAMED_PORTALS) {
            return self.extended_failure(&SqlError::new("54000", "too many named portals"));
        }
        let candidate = Portal {
            sql,
            params,
            result_formats,
            pending: None,
        };
        let old_bytes = match self.portal_entry_bytes(&portal) {
            Ok(bytes) => bytes,
            Err(e) => return self.extended_failure(&e),
        };
        let added = match portal_retained_bytes(&portal, &candidate) {
            Ok(bytes) => bytes,
            Err(e) => return self.extended_failure(&e),
        };
        let projected = match self.projected_extended_query_bytes(old_bytes, added) {
            Ok(bytes) => bytes,
            Err(e) => return self.extended_failure(&e),
        };
        // The unnamed portal is the only portal implicitly replaced by Bind.
        self.portals.insert(portal, candidate);
        self.retained_extended_query_bytes = projected;
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
        let (mut p, old_portal_bytes) = match self.portals.get(&portal) {
            Some(existing) => match portal_retained_bytes(&portal, existing) {
                Ok(bytes) => (existing.clone(), bytes),
                Err(e) => return self.extended_failure(&e),
            },
            None => {
                return self.extended_failure(&SqlError::new("34000", "portal does not exist"));
            }
        };
        self.begin_query();
        let result = if let Some(pending) = p.pending.take() {
            Ok(pending)
        } else {
            self.session.execute(&p.sql, &p.params)
        };
        self.end_query();
        let mut result = match result {
            Ok(result) => result,
            Err(e) => return self.extended_failure(&e),
        };
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
            if let Err(e) = self.replace_portal_accounted(&portal, p, old_portal_bytes) {
                // The query has already executed.  Discard the portal rather
                // than leave its old executable state available for an
                // accidental retry after Sync.
                if let Err(accounting_error) =
                    self.discard_portal_accounted(&portal, old_portal_bytes)
                {
                    return self.extended_failure(&accounting_error);
                }
                return self.extended_failure(&e);
            }
            self.result_rows_with_formats(&result, &formats)?;
            return self.write_message(b's', &[]);
        }
        let formats = p.result_formats.clone();
        if let Err(e) = self.replace_portal_accounted(&portal, p, old_portal_bytes) {
            if let Err(accounting_error) = self.discard_portal_accounted(&portal, old_portal_bytes)
            {
                return self.extended_failure(&accounting_error);
            }
            return self.extended_failure(&e);
        }
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
                let old_bytes = match self.portal_entry_bytes(&name) {
                    Ok(bytes) => bytes,
                    Err(e) => return self.extended_failure(&e),
                };
                if let Err(e) = self.discard_portal_accounted(&name, old_bytes) {
                    return self.extended_failure(&e);
                }
            }
            b'S' => {
                let old_bytes = match self.prepared_entry_bytes(&name) {
                    Ok(bytes) => bytes,
                    Err(e) => return self.extended_failure(&e),
                };
                let projected = match self.projected_extended_query_bytes(old_bytes, 0) {
                    Ok(bytes) => bytes,
                    Err(e) => return self.extended_failure(&e),
                };
                self.session.close_prepared(&name);
                self.prepared_types.remove(&name);
                self.retained_extended_query_bytes = projected;
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
        self.error_with_severity("ERROR", e)
    }
    fn fatal_idle_transaction_timeout(&mut self) -> std::io::Result<()> {
        self.error_with_severity(
            "FATAL",
            &SqlError::new(
                "25P03",
                "terminating connection due to idle-in-transaction timeout",
            ),
        )
    }
    fn error_with_severity(&mut self, severity: &str, e: &SqlError) -> std::io::Result<()> {
        let mut b = Vec::new();
        field(&mut b, b'S', severity);
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

    fn arm_idle_transaction_timeout(&mut self) -> std::io::Result<()> {
        let in_transaction = matches!(
            self.session.transaction_status(),
            chorus_txn::TransactionStatus::Active | chorus_txn::TransactionStatus::Failed
        );
        let timeout_ms = self
            .session
            .settings()
            .idle_in_transaction_session_timeout_ms;
        if !in_transaction || timeout_ms == 0 {
            return self.clear_idle_transaction_timeout();
        }

        let now = Instant::now();
        let deadline = match self.idle_transaction_deadline {
            Some(deadline) => deadline,
            None => now
                .checked_add(Duration::from_millis(timeout_ms))
                .unwrap_or(now),
        };
        self.idle_transaction_deadline = Some(deadline);
        if deadline <= now {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "idle-in-transaction timeout expired",
            ));
        }
        self.io
            .set_read_timeout(Some(deadline.saturating_duration_since(now)))
    }

    fn clear_idle_transaction_timeout(&mut self) -> std::io::Result<()> {
        let had_deadline = self.idle_transaction_deadline.take().is_some();
        if had_deadline {
            self.io.set_read_timeout(None)?;
        }
        Ok(())
    }

    /// Read one complete frontend frame while honoring an absolute idle
    /// deadline.  `Read::read_exact` may reset a socket timeout for each
    /// partial read; this loop recomputes the remaining duration so a client
    /// dribbling a partial frame cannot extend the transaction-idle budget.
    fn read_exact_at_deadline(&mut self, buffer: &mut [u8]) -> std::io::Result<()> {
        let mut offset = 0;
        while offset < buffer.len() {
            if let Some(deadline) = self.idle_transaction_deadline {
                let now = Instant::now();
                if deadline <= now {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "idle-in-transaction timeout expired",
                    ));
                }
                self.io
                    .set_read_timeout(Some(deadline.saturating_duration_since(now)))?;
            }
            match self.io.read(&mut buffer[offset..]) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "unexpected EOF while reading frontend message",
                    ));
                }
                Ok(read) => offset += read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn message(&mut self) -> std::io::Result<Option<(u8, Vec<u8>)>> {
        self.arm_idle_transaction_timeout()?;
        let mut h = [0; 5];
        match self.read_exact_at_deadline(&mut h) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                self.clear_idle_transaction_timeout()?;
                return Ok(None);
            }
            Err(e) => return Err(e),
        }
        let len = u32::from_be_bytes(h[1..].try_into().unwrap()) as usize;
        if len < 4 || len > MAX_FRONTEND_MESSAGE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid frontend message length",
            ));
        }
        let mut b = vec![0; len - 4];
        self.read_exact_at_deadline(&mut b)?;
        self.clear_idle_transaction_timeout()?;
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

fn retained_size_overflow() -> SqlError {
    SqlError::new("54000", "extended-query retained state size overflow")
}

fn charge_retained(total: &mut usize, bytes: usize) -> WireResult<()> {
    *total = total
        .checked_add(bytes)
        .ok_or_else(retained_size_overflow)?;
    Ok(())
}

fn charge_retained_items<T>(total: &mut usize, count: usize) -> WireResult<()> {
    let bytes = count
        .checked_mul(std::mem::size_of::<T>())
        .ok_or_else(retained_size_overflow)?;
    charge_retained(total, bytes)
}

/// Charge the logical payload retained in both prepared-statement maps.  The
/// separate object-count limit bounds allocator and HashMap bucket overhead.
fn prepared_retained_bytes(name: &str, sql: &str, types: &[u32]) -> WireResult<usize> {
    let mut total = 2usize
        .checked_mul(std::mem::size_of::<String>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<u32>>()))
        .ok_or_else(retained_size_overflow)?;
    charge_retained(
        &mut total,
        name.len()
            .checked_mul(2)
            .ok_or_else(retained_size_overflow)?,
    )?;
    charge_retained(&mut total, sql.len())?;
    charge_retained_items::<u32>(&mut total, types.len())?;
    Ok(total)
}

fn datum_heap_bytes(value: &Datum) -> usize {
    match value {
        Datum::Text(value) | Datum::Jsonb(value) => value.capacity(),
        Datum::Bytes(value) => value.capacity(),
        _ => 0,
    }
}

/// Heap storage owned by a suspended result.  The inline QueryResult itself
/// is already part of `Portal`; this charges its nested vectors and strings.
fn pending_result_heap_bytes(result: &QueryResult) -> WireResult<usize> {
    let mut total = 0usize;
    charge_retained_items::<ResultColumn>(&mut total, result.columns.capacity())?;
    for column in &result.columns {
        charge_retained(&mut total, column.name.capacity())?;
    }
    charge_retained_items::<Vec<Datum>>(&mut total, result.rows.capacity())?;
    for row in &result.rows {
        charge_retained_items::<Datum>(&mut total, row.capacity())?;
        for value in row {
            charge_retained(&mut total, datum_heap_bytes(value))?;
        }
    }
    charge_retained(&mut total, result.command_tag.capacity())?;
    charge_retained_items::<String>(&mut total, result.notices.capacity())?;
    for notice in &result.notices {
        charge_retained(&mut total, notice.capacity())?;
    }
    Ok(total)
}

/// Charge all variable state retained by a portal, including decoded Bind
/// values and any result remainder held for portal suspension.
fn portal_retained_bytes(name: &str, portal: &Portal) -> WireResult<usize> {
    let mut total = std::mem::size_of::<Portal>();
    charge_retained(&mut total, name.len())?;
    charge_retained(&mut total, portal.sql.capacity())?;
    charge_retained_items::<Datum>(&mut total, portal.params.capacity())?;
    for value in &portal.params {
        charge_retained(&mut total, datum_heap_bytes(value))?;
    }
    charge_retained_items::<u16>(&mut total, portal.result_formats.capacity())?;
    if let Some(result) = &portal.pending {
        charge_retained(&mut total, pending_result_heap_bytes(result)?)?;
    }
    Ok(total)
}

fn projected_retained_bytes(
    current: usize,
    removed: usize,
    added: usize,
    limit: usize,
) -> WireResult<usize> {
    let projected = current
        .checked_sub(removed)
        .ok_or_else(|| SqlError::new("XX000", "extended-query accounting underflow"))?
        .checked_add(added)
        .ok_or_else(retained_size_overflow)?;
    if projected > limit {
        return Err(SqlError::new(
            "54000",
            "extended-query retained state exceeds configured limit",
        ));
    }
    Ok(projected)
}

fn named_resource_limit_reached<T>(
    resources: &HashMap<String, T>,
    name: &str,
    limit: usize,
) -> bool {
    if name.is_empty() || resources.contains_key(name) {
        return false;
    }
    resources.keys().filter(|key| !key.is_empty()).count() >= limit
}

fn statement_exceeds_limit(sql: &str) -> bool {
    sql.len() > MAX_STATEMENT_BYTES
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

fn infer_parameter_types(sql: &str, supplied: &[u32]) -> WireResult<Vec<u32>> {
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
                let n = sql[start..end].parse::<usize>().map_err(|_| {
                    SqlError::new("54000", "parameter number exceeds protocol limit")
                })?;
                if n > MAX_PROTOCOL_ITEMS {
                    return Err(SqlError::new(
                        "54000",
                        "parameter number exceeds protocol limit",
                    ));
                }
                max_param = max_param.max(n);
                i = end;
                continue;
            }
        }
        i += 1;
    }
    let mut types = supplied.to_vec();
    types.resize(max_param, 0);
    Ok(types)
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
    use chorus_common::{Limits, OriginId};
    use chorus_storage::{MemoryStateStore, StateStore};
    use chorus_txn::{Committer, LocalCommitter};
    use std::io::{Cursor, Read, Write};
    use std::sync::Mutex;

    struct IdleTimeoutIo {
        input: Vec<u8>,
        position: usize,
        read_timeout: Mutex<Option<Duration>>,
        output: Arc<Mutex<Vec<u8>>>,
        timed_reads: Arc<AtomicUsize>,
    }

    impl IdleTimeoutIo {
        fn new(input: Vec<u8>) -> (Self, Arc<Mutex<Vec<u8>>>, Arc<AtomicUsize>) {
            let output = Arc::new(Mutex::new(Vec::new()));
            let timed_reads = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    input,
                    position: 0,
                    read_timeout: Mutex::new(None),
                    output: Arc::clone(&output),
                    timed_reads: Arc::clone(&timed_reads),
                },
                output,
                timed_reads,
            )
        }
    }

    impl Read for IdleTimeoutIo {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.position < self.input.len() {
                let count = (self.input.len() - self.position).min(buffer.len());
                buffer[..count].copy_from_slice(&self.input[self.position..self.position + count]);
                self.position += count;
                return Ok(count);
            }
            let timeout = *self.read_timeout.lock().expect("timeout lock");
            if let Some(timeout) = timeout {
                self.timed_reads.fetch_add(1, Ordering::AcqRel);
                std::thread::sleep(timeout + Duration::from_millis(2));
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "simulated idle timeout",
                ));
            }
            Ok(0)
        }
    }

    impl Write for IdleTimeoutIo {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.output
                .lock()
                .expect("output lock")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Io for IdleTimeoutIo {
        fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
            *self.read_timeout.lock().expect("timeout lock") = timeout;
            Ok(())
        }
    }

    fn startup_wire() -> Vec<u8> {
        let mut wire = Vec::new();
        let params = [b'u', b's', b'e', b'r', 0, b't', b'e', b's', b't', 0, 0];
        wire.extend_from_slice(&((params.len() as u32 + 8).to_be_bytes()));
        wire.extend_from_slice(&PROTOCOL_VERSION_3_0.to_be_bytes());
        wire.extend_from_slice(&params);
        wire
    }

    fn test_connection() -> Connection {
        let store = Arc::new(MemoryStateStore::new()) as Arc<dyn StateStore>;
        let committer = Arc::new(
            LocalCommitter::new(Arc::clone(&store), OriginId::new(1)).expect("test committer"),
        ) as Arc<dyn Committer>;
        let engine = SqlEngine::new(store, committer, Limits::default());
        Connection::new(engine, Box::new(Cursor::new(Vec::new())))
    }

    #[test]
    fn idle_transaction_timeout_is_fatal_even_for_a_partial_frontend_frame() {
        let store = Arc::new(MemoryStateStore::new()) as Arc<dyn StateStore>;
        let committer = Arc::new(
            LocalCommitter::new(Arc::clone(&store), OriginId::new(1)).expect("test committer"),
        ) as Arc<dyn Committer>;
        let engine = SqlEngine::new(store, committer, Limits::default());
        let mut input = startup_wire();
        input.push(b'Q');
        let (io, output, timed_reads) = IdleTimeoutIo::new(input);
        let mut connection = Connection::new(engine, Box::new(io));
        connection
            .session
            .set_param("idle_in_transaction_session_timeout", "20")
            .unwrap();
        connection.session.execute("BEGIN", &[]).unwrap();

        connection
            .run()
            .expect("idle timeout is a protocol outcome");
        assert!(timed_reads.load(Ordering::Acquire) >= 1);
        let output = output.lock().expect("output lock");
        let text = String::from_utf8_lossy(&output);
        assert!(text.contains("FATAL"), "missing FATAL response: {text:?}");
        assert!(text.contains("25P03"), "missing SQLSTATE: {text:?}");
        assert!(
            text.contains("idle-in-transaction timeout"),
            "missing timeout detail: {text:?}"
        );
    }

    #[test]
    fn ordinary_idle_session_does_not_arm_transaction_timeout_and_reset_clears_it() {
        let mut connection = test_connection();
        connection
            .session
            .set_param("idle_in_transaction_session_timeout", "20")
            .unwrap();

        let (io, _output, timed_reads) = IdleTimeoutIo::new(Vec::new());
        connection.io = Box::new(io);
        connection.arm_idle_transaction_timeout().unwrap();
        assert!(connection.idle_transaction_deadline.is_none());
        assert_eq!(timed_reads.load(Ordering::Acquire), 0);

        connection.session.execute("BEGIN", &[]).unwrap();
        connection.arm_idle_transaction_timeout().unwrap();
        assert!(connection.idle_transaction_deadline.is_some());
        connection
            .session
            .set_param("idle_in_transaction_session_timeout", "0")
            .unwrap();
        connection.arm_idle_transaction_timeout().unwrap();
        assert!(connection.idle_transaction_deadline.is_none());
    }

    fn test_server(tcp_listen: Option<String>, unix_socket: Option<String>) -> PgServer {
        let store = Arc::new(MemoryStateStore::new()) as Arc<dyn StateStore>;
        let committer = Arc::new(
            LocalCommitter::new(Arc::clone(&store), OriginId::new(1)).expect("test committer"),
        ) as Arc<dyn Committer>;
        let engine = SqlEngine::new(store, committer, Limits::default());
        PgServer::new(
            engine,
            PgConfig {
                tcp_listen,
                unix_socket,
                max_connections: 2,
            },
        )
    }

    fn unique_socket_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "chorus-pg-{label}-{}-{}",
            std::process::id(),
            NEXT_BACKEND_PID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn wait_for_active(handle: &PgServerHandle, expected: usize) {
        for _ in 0..100 {
            if handle.active_connections() >= expected {
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        panic!(
            "expected at least {expected} active PostgreSQL sessions, observed {}",
            handle.active_connections()
        );
    }

    #[test]
    fn server_shutdown_drains_sessions_rejects_new_connections_and_removes_owned_unix_socket() {
        let unix_path = unique_socket_path("drain");
        let server = test_server(
            Some("127.0.0.1:0".into()),
            Some(unix_path.display().to_string()),
        );
        let handle = server
            .start_with_drain_timeout(Duration::from_secs(1))
            .expect("bind listeners");
        let address = handle.tcp_addr().expect("TCP listener address");
        let active = Arc::clone(&handle.active);
        assert!(unix_path.exists());
        let client = TcpStream::connect(address).expect("connect before shutdown");
        wait_for_active(&handle, 1);

        handle.signal_shutdown();
        drop(client);
        handle.wait().expect("graceful shutdown");

        assert_eq!(active.load(Ordering::Acquire), 0);
        assert!(!unix_path.exists(), "only the owned socket is removed");
        assert!(
            TcpStream::connect(address).is_err(),
            "listener still accepts after shutdown"
        );
    }

    #[test]
    fn server_shutdown_force_closes_stuck_sessions_at_deadline() {
        let server = test_server(Some("127.0.0.1:0".into()), None);
        let handle = server
            .start_with_drain_timeout(Duration::from_millis(35))
            .expect("bind listener");
        let address = handle.tcp_addr().expect("TCP listener address");
        let active = Arc::clone(&handle.active);
        let mut client = TcpStream::connect(address).expect("connect before shutdown");
        client
            .set_read_timeout(Some(Duration::from_millis(250)))
            .expect("set read timeout");
        wait_for_active(&handle, 1);

        let started = Instant::now();
        handle.shutdown().expect("bounded forced shutdown");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "shutdown exceeded its bounded drain deadline"
        );
        assert_eq!(active.load(Ordering::Acquire), 0);
        let mut byte = [0u8; 1];
        assert!(
            matches!(client.read(&mut byte), Ok(0) | Err(_)),
            "stuck session remained readable after forced close"
        );
        assert!(
            TcpStream::connect(address).is_err(),
            "listener still accepts after shutdown"
        );
    }

    #[test]
    fn server_shutdown_does_not_remove_a_replacement_unix_socket() {
        let unix_path = unique_socket_path("replacement");
        let server = test_server(
            Some("127.0.0.1:0".into()),
            Some(unix_path.display().to_string()),
        );
        let handle = server
            .start_with_drain_timeout(Duration::from_millis(250))
            .expect("bind listeners");
        let client = TcpStream::connect(handle.tcp_addr().unwrap()).expect("connect session");
        wait_for_active(&handle, 1);
        handle.signal_shutdown();

        // The old accept loop has stopped, but its manager is still draining
        // the active TCP session. Replace the pathname with another socket in
        // that window; shutdown must compare inode identity before unlinking.
        std::thread::sleep(Duration::from_millis(20));
        std::fs::remove_file(&unix_path).expect("remove old socket pathname");
        let replacement = UnixListener::bind(&unix_path).expect("bind replacement socket");
        handle.wait().expect("shutdown old server");
        assert!(unix_path.exists(), "replacement socket was removed");
        drop(replacement);
        let _ = std::fs::remove_file(&unix_path);
        drop(client);
    }

    #[test]
    fn failed_unix_bind_releases_a_previously_bound_tcp_listener() {
        let probe = TcpListener::bind("127.0.0.1:0").expect("reserve test port");
        let address = probe.local_addr().expect("reserved address");
        drop(probe);

        let unix_path = unique_socket_path("invalid");
        std::fs::write(&unix_path, b"not a socket").expect("create invalid Unix path");
        let server = test_server(
            Some(address.to_string()),
            Some(unix_path.display().to_string()),
        );
        assert!(
            server
                .start_with_drain_timeout(Duration::from_millis(20))
                .is_err(),
            "regular Unix path was unexpectedly replaced"
        );
        let rebound = TcpListener::bind(address).expect("TCP listener leaked after failed bind");
        drop(rebound);
        std::fs::remove_file(unix_path).expect("remove invalid Unix path");
    }

    fn parse_body(name: &str, sql: &str, types: &[u32]) -> Vec<u8> {
        let mut body = Vec::new();
        cstr_put(&mut body, name);
        cstr_put(&mut body, sql);
        put_u16(&mut body, types.len() as u16);
        for oid in types {
            body.extend_from_slice(&oid.to_be_bytes());
        }
        body
    }

    fn bind_body(portal: &str, statement: &str, value: Option<&[u8]>) -> Vec<u8> {
        let mut body = Vec::new();
        cstr_put(&mut body, portal);
        cstr_put(&mut body, statement);
        put_u16(&mut body, 0);
        put_u16(&mut body, usize::from(value.is_some()) as u16);
        if let Some(value) = value {
            body.extend_from_slice(&(value.len() as i32).to_be_bytes());
            body.extend_from_slice(value);
        }
        put_u16(&mut body, 0);
        body
    }

    fn close_body(kind: u8, name: &str) -> Vec<u8> {
        let mut body = vec![kind];
        cstr_put(&mut body, name);
        body
    }

    fn recomputed_retained_bytes(connection: &Connection) -> usize {
        let prepared = connection
            .prepared_types
            .iter()
            .map(|(name, types)| {
                prepared_retained_bytes(
                    name,
                    connection
                        .session
                        .prepared_sql(name)
                        .expect("matching prepared SQL"),
                    types,
                )
                .expect("prepared accounting")
            })
            .sum::<usize>();
        let portals = connection
            .portals
            .iter()
            .map(|(name, portal)| portal_retained_bytes(name, portal).expect("portal accounting"))
            .sum::<usize>();
        prepared + portals
    }

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

    #[test]
    fn named_resource_count_excludes_existing_and_unnamed_keys() {
        let mut resources = HashMap::new();
        resources.insert("one".to_string(), 1usize);
        resources.insert("two".to_string(), 2usize);
        assert!(named_resource_limit_reached(&resources, "new", 2));
        assert!(!named_resource_limit_reached(&resources, "one", 2));
        assert!(!named_resource_limit_reached(&resources, "", 0));

        // Duplicate protocol objects are rejected separately.  This helper
        // only decides whether a new name would consume another count slot.
        resources.insert("one".to_string(), 3);
        resources.insert(String::new(), 4);
        assert_eq!(resources.len(), 3);
        assert_eq!(resources["one"], 3);
        assert_eq!(resources[""], 4);
    }

    #[test]
    fn named_resource_rejection_does_not_mutate_and_close_releases_slot() {
        let mut resources = HashMap::new();
        resources.insert("one".to_string(), 1usize);
        resources.insert("two".to_string(), 2usize);
        let before = resources.clone();
        if !named_resource_limit_reached(&resources, "three", 2) {
            resources.insert("three".to_string(), 3);
        }
        assert_eq!(resources, before);
        resources.remove("one");
        assert!(!named_resource_limit_reached(&resources, "three", 2));
    }

    #[test]
    fn statement_size_limit_is_exact_and_uses_bytes() {
        assert!(!statement_exceeds_limit(&"x".repeat(MAX_STATEMENT_BYTES)));
        assert!(statement_exceeds_limit(
            &"x".repeat(MAX_STATEMENT_BYTES + 1)
        ));
        assert!(statement_exceeds_limit(
            &"é".repeat(MAX_STATEMENT_BYTES / 2 + 1)
        ));
    }

    #[test]
    fn parse_budget_and_named_duplicate_reject_before_mutation() {
        let mut connection = test_connection();
        connection.extended_query_state_limit = 0;
        connection
            .parse(&parse_body("limited", "SELECT 1", &[]))
            .expect("wire error response");
        assert!(connection.extended_error);
        assert!(!connection.prepared_types.contains_key("limited"));
        assert!(connection.session.prepared_sql("limited").is_none());
        assert_eq!(connection.retained_extended_query_bytes, 0);

        connection.extended_error = false;
        connection.extended_query_state_limit = MAX_RETAINED_EXTENDED_QUERY_BYTES;
        connection
            .parse(&parse_body("named", "SELECT 1", &[]))
            .expect("ParseComplete");
        let before = connection.retained_extended_query_bytes;
        connection
            .parse(&parse_body("named", "SELECT 2", &[]))
            .expect("duplicate error response");
        assert!(connection.extended_error);
        assert_eq!(connection.session.prepared_sql("named"), Some("SELECT 1"));
        assert_eq!(connection.retained_extended_query_bytes, before);
        assert_eq!(before, recomputed_retained_bytes(&connection));
    }

    #[test]
    fn bind_budget_duplicate_and_close_preserve_exact_accounting() {
        let mut connection = test_connection();
        connection
            .parse(&parse_body("statement", "SELECT $1", &[25]))
            .expect("ParseComplete");
        let prepared_bytes = connection.retained_extended_query_bytes;

        connection.extended_query_state_limit = prepared_bytes;
        connection
            .bind(&bind_body("limited", "statement", Some(b"first")))
            .expect("wire error response");
        assert!(connection.extended_error);
        assert!(!connection.portals.contains_key("limited"));
        assert_eq!(connection.retained_extended_query_bytes, prepared_bytes);

        connection.extended_error = false;
        connection.extended_query_state_limit = MAX_RETAINED_EXTENDED_QUERY_BYTES;
        connection
            .bind(&bind_body("portal", "statement", Some(b"first")))
            .expect("BindComplete");
        let with_portal = connection.retained_extended_query_bytes;
        connection
            .bind(&bind_body("portal", "statement", Some(b"replacement")))
            .expect("duplicate portal error response");
        assert!(connection.extended_error);
        assert_eq!(
            connection.portals["portal"].params[0],
            Datum::Text("first".into())
        );
        assert_eq!(connection.retained_extended_query_bytes, with_portal);

        connection.extended_error = false;
        connection
            .close(&close_body(b'P', "portal"))
            .expect("CloseComplete");
        assert_eq!(connection.retained_extended_query_bytes, prepared_bytes);
        connection
            .close(&close_body(b'S', "statement"))
            .expect("CloseComplete");
        assert_eq!(connection.retained_extended_query_bytes, 0);
        assert_eq!(0, recomputed_retained_bytes(&connection));
    }

    #[test]
    fn unnamed_parse_replacement_releases_statement_and_portal_payload() {
        let mut connection = test_connection();
        connection
            .parse(&parse_body("", "SELECT $1", &[25]))
            .expect("ParseComplete");
        connection
            .bind(&bind_body("", "", Some(b"retained payload")))
            .expect("BindComplete");
        let before = connection.retained_extended_query_bytes;
        assert!(connection.portals.contains_key(""));

        connection
            .parse(&parse_body("", "SELECT 2", &[]))
            .expect("ParseComplete");
        assert!(!connection.portals.contains_key(""));
        assert_eq!(connection.session.prepared_sql(""), Some("SELECT 2"));
        assert!(connection.retained_extended_query_bytes < before);
        assert_eq!(
            connection.retained_extended_query_bytes,
            recomputed_retained_bytes(&connection)
        );
    }

    #[test]
    fn parameter_number_is_bounded_before_type_vector_resize() {
        let error = infer_parameter_types("SELECT $65536", &[]).unwrap_err();
        assert_eq!(error.code, "54000");
        let types = infer_parameter_types("SELECT $65535", &[]).expect("protocol maximum");
        assert_eq!(types.len(), MAX_PROTOCOL_ITEMS);
    }
}
