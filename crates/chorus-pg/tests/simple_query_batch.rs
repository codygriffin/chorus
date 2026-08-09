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

#[test]
fn simple_query_batch_emits_each_result_before_one_ready_for_query() {
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

    send_message(&mut stream, b'Q', b"SELECT 1; SELECT 2;\0");
    let mut types = Vec::new();
    loop {
        let (typ, _body) = read_message(&mut stream);
        types.push(typ);
        if typ == b'Z' {
            break;
        }
    }

    assert_eq!(types, vec![b'T', b'D', b'C', b'T', b'D', b'C', b'Z']);
    handle.shutdown().expect("shutdown test listener");
}
