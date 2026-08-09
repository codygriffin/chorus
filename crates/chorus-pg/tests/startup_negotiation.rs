use chorus_common::{Limits, OriginId};
use chorus_pg::{PgConfig, PgServer, PgServerHandle};
use chorus_sql::SqlEngine;
use chorus_storage::{MemoryStateStore, StateStore};
use chorus_txn::{Committer, LocalCommitter};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

const PROTOCOL_3_0: u32 = 196_608;
const PROTOCOL_3_2: u32 = 196_610;

fn open_server() -> PgServerHandle {
    let store: Arc<dyn StateStore> = Arc::new(MemoryStateStore::new());
    let committer: Arc<dyn Committer> = Arc::new(
        LocalCommitter::new(Arc::clone(&store), OriginId::new(1)).expect("test committer"),
    );
    let engine = SqlEngine::new(store, committer, Limits::default());
    PgServer::new(
        engine,
        PgConfig {
            tcp_listen: Some("127.0.0.1:0".into()),
            unix_socket: None,
            max_connections: 8,
            remote: None,
        },
    )
    .start_with_drain_timeout(Duration::from_secs(1))
    .expect("bind test listener")
}

fn connect(handle: &PgServerHandle) -> TcpStream {
    let stream = TcpStream::connect(handle.tcp_addr().expect("TCP listener address"))
        .expect("connect test listener");
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .expect("write timeout");
    stream
}

fn send_startup(stream: &mut TcpStream, protocol: u32, parameters: &[(&str, &str)]) {
    let mut body = Vec::new();
    for (name, value) in parameters {
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);
    let length = u32::try_from(body.len() + 8).expect("startup length");
    stream.write_all(&length.to_be_bytes()).expect("length");
    stream.write_all(&protocol.to_be_bytes()).expect("protocol");
    stream.write_all(&body).expect("startup body");
}

fn read_message(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut header = [0; 5];
    stream.read_exact(&mut header).expect("backend header");
    let length = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
    assert!(length >= 4, "backend length includes its own prefix");
    let mut body = vec![0; length - 4];
    stream.read_exact(&mut body).expect("backend body");
    (header[0], body)
}

fn read_until_ready(stream: &mut TcpStream) -> Vec<(u8, Vec<u8>)> {
    let mut messages = Vec::new();
    loop {
        let message = read_message(stream);
        let ready = message.0 == b'Z';
        messages.push(message);
        if ready {
            return messages;
        }
    }
}

fn parse_negotiation(body: &[u8]) -> (u32, Vec<String>) {
    assert!(body.len() >= 8, "negotiation header");
    let protocol = u32::from_be_bytes(body[0..4].try_into().unwrap());
    let count = u32::from_be_bytes(body[4..8].try_into().unwrap()) as usize;
    let mut position = 8;
    let mut options = Vec::with_capacity(count);
    for _ in 0..count {
        let end = body[position..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| position + offset)
            .expect("protocol option terminator");
        options.push(String::from_utf8(body[position..end].to_vec()).expect("option UTF-8"));
        position = end + 1;
    }
    assert_eq!(position, body.len(), "trailing negotiation bytes");
    (protocol, options)
}

#[test]
fn startup_negotiates_honest_protocol_and_reports_reserved_options() {
    let handle = open_server();

    let mut protocol_3_0 = connect(&handle);
    send_startup(&mut protocol_3_0, PROTOCOL_3_0, &[("user", "test")]);
    let messages = read_until_ready(&mut protocol_3_0);
    assert_eq!(messages.first().map(|message| message.0), Some(b'R'));
    assert!(!messages.iter().any(|message| message.0 == b'v'));

    let mut protocol_3_2 = connect(&handle);
    send_startup(&mut protocol_3_2, PROTOCOL_3_2, &[("user", "test")]);
    let messages = read_until_ready(&mut protocol_3_2);
    assert_eq!(messages.first().map(|message| message.0), Some(b'v'));
    assert_eq!(parse_negotiation(&messages[0].1), (PROTOCOL_3_0, vec![]));
    assert_eq!(messages.get(1).map(|message| message.0), Some(b'R'));

    let mut invalid_protocol_3_2 = connect(&handle);
    send_startup(&mut invalid_protocol_3_2, PROTOCOL_3_2, &[]);
    let negotiation = read_message(&mut invalid_protocol_3_2);
    assert_eq!(negotiation.0, b'v');
    assert_eq!(parse_negotiation(&negotiation.1), (PROTOCOL_3_0, vec![]));
    assert_eq!(
        read_message(&mut invalid_protocol_3_2).0,
        b'E',
        "protocol negotiation must precede startup validation"
    );

    let mut reserved_options = connect(&handle);
    send_startup(
        &mut reserved_options,
        PROTOCOL_3_0,
        &[
            ("user", "test"),
            ("_pq_.first", "one"),
            ("_pq_.second", "two"),
        ],
    );
    let messages = read_until_ready(&mut reserved_options);
    assert_eq!(messages.first().map(|message| message.0), Some(b'v'));
    assert_eq!(
        parse_negotiation(&messages[0].1),
        (
            PROTOCOL_3_0,
            vec!["_pq_.first".to_string(), "_pq_.second".to_string()]
        )
    );
    assert_eq!(messages.get(1).map(|message| message.0), Some(b'R'));

    let mut unsupported_major = connect(&handle);
    send_startup(&mut unsupported_major, 4 << 16, &[("user", "test")]);
    let message = read_message(&mut unsupported_major);
    assert_eq!(message.0, b'E', "wrong major must fail before auth");

    drop((
        protocol_3_0,
        protocol_3_2,
        invalid_protocol_3_2,
        reserved_options,
        unsupported_major,
    ));
    handle.shutdown().expect("shutdown test listener");
}
