use chorus_common::{Limits, OriginId};
use chorus_pg::{PgConfig, PgServer};
use chorus_sql::SqlEngine;
use chorus_storage::{MemoryStateStore, StateStore};
use chorus_txn::{Committer, LocalCommitter};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

fn send_message(stream: &mut TcpStream, typ: u8, body: &[u8]) {
    let length = u32::try_from(body.len() + 4).expect("message length");
    stream.write_all(&[typ]).expect("message type");
    stream
        .write_all(&length.to_be_bytes())
        .expect("message length");
    stream.write_all(body).expect("message body");
}

fn read_message(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut header = [0; 5];
    stream
        .read_exact(&mut header)
        .expect("backend message header");
    let length = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
    assert!(
        length >= 4,
        "backend message length must include its prefix"
    );
    let mut body = vec![0; length - 4];
    stream.read_exact(&mut body).expect("backend message body");
    (header[0], body)
}

fn startup(stream: &mut TcpStream) {
    let mut params = Vec::new();
    params.extend_from_slice(b"user\0test\0database\0chorus\0\0");
    let length = u32::try_from(params.len() + 8).expect("startup length");
    stream
        .write_all(&length.to_be_bytes())
        .expect("startup length");
    stream
        .write_all(&196_608u32.to_be_bytes())
        .expect("protocol version");
    stream.write_all(&params).expect("startup parameters");

    loop {
        let (typ, body) = read_message(stream);
        if typ == b'Z' {
            assert_eq!(body, vec![b'I']);
            break;
        }
    }
}

fn simple_query(stream: &mut TcpStream, sql: &str) -> Vec<(u8, Vec<u8>)> {
    let mut body = sql.as_bytes().to_vec();
    body.push(0);
    send_message(stream, b'Q', &body);
    let mut messages = Vec::new();
    loop {
        let message = read_message(stream);
        let done = message.0 == b'Z';
        messages.push(message);
        if done {
            return messages;
        }
    }
}

fn open_test_connection() -> (chorus_pg::PgServerHandle, TcpStream) {
    let store: Arc<dyn StateStore> = Arc::new(MemoryStateStore::new());
    let origin = OriginId::new(1);
    let committer: Arc<dyn Committer> =
        Arc::new(LocalCommitter::new(store.clone(), origin).expect("test committer"));
    let engine = SqlEngine::new(store, committer, Limits::default());
    let server = PgServer::new(
        engine,
        PgConfig {
            tcp_listen: Some("127.0.0.1:0".into()),
            unix_socket: None,
            max_connections: 4,
            remote: None,
        },
    );
    let handle = server
        .start_with_drain_timeout(Duration::from_secs(1))
        .expect("bind test listener");
    let address = handle.tcp_addr().expect("TCP listener address");
    let mut stream = TcpStream::connect(address).expect("connect test listener");
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("read timeout");
    startup(&mut stream);
    (handle, stream)
}

#[test]
fn simple_query_batch_emits_each_result_before_one_ready_for_query() {
    let (handle, mut stream) = open_test_connection();
    let messages = simple_query(&mut stream, "SELECT 1; SELECT 2;");
    let types = messages.iter().map(|message| message.0).collect::<Vec<_>>();

    assert_eq!(types, vec![b'T', b'D', b'C', b'T', b'D', b'C', b'Z']);
    assert_eq!(messages.last().unwrap().1, vec![b'I']);
    handle.shutdown().expect("shutdown test listener");
}

#[test]
fn simple_query_transaction_boundaries_report_status_and_committed_prefix() {
    let (handle, mut stream) = open_test_connection();

    let opened = simple_query(&mut stream, "SELECT 1; BEGIN; SELECT 2;");
    assert_eq!(
        opened.iter().map(|message| message.0).collect::<Vec<_>>(),
        vec![b'T', b'D', b'C', b'C', b'T', b'D', b'C', b'Z']
    );
    assert_eq!(opened.last().unwrap().1, vec![b'T']);

    let closed = simple_query(&mut stream, "COMMIT; SELECT 3;");
    assert_eq!(
        closed.iter().map(|message| message.0).collect::<Vec<_>>(),
        vec![b'C', b'T', b'D', b'C', b'Z']
    );
    assert_eq!(closed.last().unwrap().1, vec![b'I']);

    let created = simple_query(
        &mut stream,
        "CREATE TABLE wire_segments (id integer primary key);",
    );
    assert_eq!(
        created.iter().map(|message| message.0).collect::<Vec<_>>(),
        vec![b'C', b'Z']
    );

    let failed = simple_query(
        &mut stream,
        "INSERT INTO wire_segments VALUES (1); COMMIT; INSERT INTO missing_wire_segment VALUES (2);",
    );
    assert_eq!(
        failed.iter().map(|message| message.0).collect::<Vec<_>>(),
        vec![b'C', b'C', b'E', b'Z']
    );
    assert_eq!(failed.last().unwrap().1, vec![b'I']);

    // The prefix crossed an explicit commit boundary before the later error.
    let count = simple_query(&mut stream, "SELECT count(*) FROM wire_segments;");
    assert_eq!(
        count.iter().map(|message| message.0).collect::<Vec<_>>(),
        vec![b'T', b'D', b'C', b'Z']
    );
    assert_eq!(count.last().unwrap().1, vec![b'I']);

    handle.shutdown().expect("shutdown test listener");
}
