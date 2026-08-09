use chorus_common::{Limits, OriginId};
use chorus_pg::{PgConfig, PgServer};
use chorus_sql::SqlEngine;
use chorus_storage::{MemoryStateStore, StateStore};
use chorus_txn::{Committer, LocalCommitter};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

fn send_message(stream: &mut TcpStream, message_type: u8, body: &[u8]) {
    let length = u32::try_from(body.len() + 4).expect("message length");
    stream.write_all(&[message_type]).expect("message type");
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
    assert!(length >= 4, "backend length includes its own prefix");
    let mut body = vec![0; length - 4];
    stream.read_exact(&mut body).expect("backend message body");
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

fn put_cstr(body: &mut Vec<u8>, value: &str) {
    body.extend_from_slice(value.as_bytes());
    body.push(0);
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
    let messages = read_until_ready(stream);
    assert_eq!(messages.last().unwrap().1, vec![b'I']);
}

fn parse(stream: &mut TcpStream, name: &str, sql: &str, parameter_oids: &[u32]) {
    let mut body = Vec::new();
    put_cstr(&mut body, name);
    put_cstr(&mut body, sql);
    body.extend_from_slice(&(parameter_oids.len() as u16).to_be_bytes());
    for oid in parameter_oids {
        body.extend_from_slice(&oid.to_be_bytes());
    }
    send_message(stream, b'P', &body);
}

fn bind(
    stream: &mut TcpStream,
    portal: &str,
    statement: &str,
    parameters: &[&[u8]],
    result_formats: &[u16],
) {
    let mut body = Vec::new();
    put_cstr(&mut body, portal);
    put_cstr(&mut body, statement);
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&(parameters.len() as u16).to_be_bytes());
    for parameter in parameters {
        body.extend_from_slice(&(parameter.len() as i32).to_be_bytes());
        body.extend_from_slice(parameter);
    }
    body.extend_from_slice(&(result_formats.len() as u16).to_be_bytes());
    for format in result_formats {
        body.extend_from_slice(&format.to_be_bytes());
    }
    send_message(stream, b'B', &body);
}

fn describe(stream: &mut TcpStream, kind: u8, name: &str) {
    let mut body = vec![kind];
    put_cstr(&mut body, name);
    send_message(stream, b'D', &body);
}

fn execute(stream: &mut TcpStream, portal: &str) {
    let mut body = Vec::new();
    put_cstr(&mut body, portal);
    body.extend_from_slice(&0u32.to_be_bytes());
    send_message(stream, b'E', &body);
}

fn sync(stream: &mut TcpStream) {
    send_message(stream, b'S', &[]);
}

fn simple_query(stream: &mut TcpStream, sql: &str) -> Vec<(u8, Vec<u8>)> {
    let mut body = sql.as_bytes().to_vec();
    body.push(0);
    send_message(stream, b'Q', &body);
    read_until_ready(stream)
}

#[derive(Debug, Eq, PartialEq)]
struct FieldDescription {
    name: String,
    table_oid: u32,
    attribute: i16,
    type_oid: u32,
    format: i16,
}

fn row_description(body: &[u8]) -> Vec<FieldDescription> {
    let count = u16::from_be_bytes(body[0..2].try_into().unwrap()) as usize;
    let mut position = 2;
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        let end = body[position..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| position + offset)
            .expect("field name terminator");
        let name = String::from_utf8(body[position..end].to_vec()).expect("field name");
        position = end + 1;
        let table_oid = u32::from_be_bytes(body[position..position + 4].try_into().unwrap());
        position += 4;
        let attribute = i16::from_be_bytes(body[position..position + 2].try_into().unwrap());
        position += 2;
        let type_oid = u32::from_be_bytes(body[position..position + 4].try_into().unwrap());
        position += 4;
        position += 2; // type length
        position += 4; // type modifier
        let format = i16::from_be_bytes(body[position..position + 2].try_into().unwrap());
        position += 2;
        fields.push(FieldDescription {
            name,
            table_oid,
            attribute,
            type_oid,
            format,
        });
    }
    assert_eq!(position, body.len());
    fields
}

fn open_connection() -> (chorus_pg::PgServerHandle, TcpStream) {
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
    let mut stream = TcpStream::connect(handle.tcp_addr().unwrap()).expect("connect test listener");
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("read timeout");
    startup(&mut stream);
    (handle, stream)
}

#[test]
fn describe_statement_binds_zero_row_shape_and_commands_report_no_data() {
    let (handle, mut stream) = open_connection();
    let created = simple_query(
        &mut stream,
        "CREATE TABLE describe_wire (id integer primary key, value text);",
    );
    assert_eq!(
        created.iter().map(|message| message.0).collect::<Vec<_>>(),
        vec![b'C', b'Z']
    );

    parse(
        &mut stream,
        "select_empty",
        "SELECT id, value FROM describe_wire WHERE false",
        &[],
    );
    describe(&mut stream, b'S', "select_empty");
    sync(&mut stream);
    let described = read_until_ready(&mut stream);
    assert_eq!(
        described
            .iter()
            .map(|message| message.0)
            .collect::<Vec<_>>(),
        vec![b'1', b't', b'T', b'Z']
    );
    assert_eq!(described[1].1, vec![0, 0]);
    let fields = row_description(&described[2].1);
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0].name, "id");
    assert_eq!(fields[0].type_oid, 23);
    assert_ne!(fields[0].table_oid, 0);
    assert_ne!(fields[0].attribute, 0);
    assert_eq!(fields[1].name, "value");
    assert_eq!(fields[1].type_oid, 25);
    assert_eq!(described.last().unwrap().1, vec![b'I']);

    parse(
        &mut stream,
        "update_no_rows",
        "UPDATE describe_wire SET value = 'updated' WHERE id = 1",
        &[],
    );
    describe(&mut stream, b'S', "update_no_rows");
    sync(&mut stream);
    let no_data = read_until_ready(&mut stream);
    assert_eq!(
        no_data.iter().map(|message| message.0).collect::<Vec<_>>(),
        vec![b'1', b't', b'n', b'Z']
    );

    parse(
        &mut stream,
        "missing",
        "SELECT * FROM missing_describe_wire",
        &[],
    );
    describe(&mut stream, b'S', "missing");
    sync(&mut stream);
    let missing = read_until_ready(&mut stream);
    assert_eq!(
        missing.iter().map(|message| message.0).collect::<Vec<_>>(),
        vec![b'1', b'E', b'Z']
    );
    assert!(missing[1].1.windows(6).any(|window| window == b"42P01\0"));
    assert_eq!(missing.last().unwrap().1, vec![b'I']);

    drop(stream);
    handle.shutdown().expect("shutdown test listener");
}

#[test]
fn portal_describe_is_non_mutating_and_execute_uses_the_described_formats_once() {
    let (handle, mut stream) = open_connection();

    parse(&mut stream, "cast_value", "SELECT $1::integer", &[23]);
    bind(&mut stream, "cast_portal", "cast_value", &[b"9"], &[1]);
    describe(&mut stream, b'P', "cast_portal");
    execute(&mut stream, "cast_portal");
    sync(&mut stream);
    let cast = read_until_ready(&mut stream);
    assert_eq!(
        cast.iter().map(|message| message.0).collect::<Vec<_>>(),
        vec![b'1', b'2', b'T', b'D', b'C', b'Z']
    );
    let cast_fields = row_description(&cast[2].1);
    assert_eq!(cast_fields[0].type_oid, 23);
    assert_eq!(cast_fields[0].format, 1);
    assert_eq!(i32::from_be_bytes(cast[3].1[6..10].try_into().unwrap()), 9);

    simple_query(
        &mut stream,
        "CREATE TABLE describe_portal (id integer primary key, value text);",
    );

    parse(
        &mut stream,
        "insert_returning",
        "INSERT INTO describe_portal VALUES ($1, 'bound') RETURNING id, value",
        &[23],
    );
    bind(
        &mut stream,
        "insert_portal",
        "insert_returning",
        &[b"7"],
        &[1, 0],
    );
    describe(&mut stream, b'P', "insert_portal");
    sync(&mut stream);
    let described = read_until_ready(&mut stream);
    assert_eq!(
        described
            .iter()
            .map(|message| message.0)
            .collect::<Vec<_>>(),
        vec![b'1', b'2', b'T', b'Z']
    );
    let fields = row_description(&described[2].1);
    assert_eq!(
        fields
            .iter()
            .map(|field| (field.type_oid, field.format))
            .collect::<Vec<_>>(),
        vec![(23, 1), (25, 0)]
    );

    // Describe binds metadata only; the portal has not executed yet.
    let before = simple_query(&mut stream, "SELECT count(*) FROM describe_portal");
    assert_eq!(
        before.iter().map(|message| message.0).collect::<Vec<_>>(),
        vec![b'T', b'D', b'C', b'Z']
    );
    assert!(before[1].1.ends_with(b"0"));

    execute(&mut stream, "insert_portal");
    sync(&mut stream);
    let executed = read_until_ready(&mut stream);
    assert_eq!(
        executed.iter().map(|message| message.0).collect::<Vec<_>>(),
        vec![b'D', b'C', b'Z'],
        "Execute must not repeat the RowDescription already emitted by Describe"
    );
    let row = &executed[0].1;
    assert_eq!(u16::from_be_bytes(row[0..2].try_into().unwrap()), 2);
    assert_eq!(i32::from_be_bytes(row[2..6].try_into().unwrap()), 4);
    assert_eq!(i32::from_be_bytes(row[6..10].try_into().unwrap()), 7);

    drop(stream);
    handle.shutdown().expect("shutdown test listener");
}

#[test]
fn empty_simple_and_extended_queries_emit_empty_query_response() {
    let (handle, mut stream) = open_connection();

    for sql in ["", "  ; ;  "] {
        let messages = simple_query(&mut stream, sql);
        assert_eq!(
            messages.iter().map(|message| message.0).collect::<Vec<_>>(),
            vec![b'I', b'Z']
        );
        assert!(messages[0].1.is_empty());
        assert_eq!(messages[1].1, vec![b'I']);
    }

    let begun = simple_query(&mut stream, "BEGIN");
    assert_eq!(begun.last().unwrap().1, vec![b'T']);
    let active_empty = simple_query(&mut stream, ";");
    assert_eq!(
        active_empty
            .iter()
            .map(|message| message.0)
            .collect::<Vec<_>>(),
        vec![b'I', b'Z']
    );
    assert_eq!(active_empty.last().unwrap().1, vec![b'T']);
    assert_eq!(
        simple_query(&mut stream, "ROLLBACK").last().unwrap().1,
        vec![b'I']
    );

    parse(&mut stream, "empty_statement", " ; ", &[]);
    bind(&mut stream, "empty_portal", "empty_statement", &[], &[]);
    describe(&mut stream, b'S', "empty_statement");
    describe(&mut stream, b'P', "empty_portal");
    execute(&mut stream, "empty_portal");
    sync(&mut stream);
    let extended = read_until_ready(&mut stream);
    assert_eq!(
        extended.iter().map(|message| message.0).collect::<Vec<_>>(),
        vec![b'1', b'2', b't', b'n', b'n', b'I', b'Z']
    );
    assert_eq!(extended[2].1, vec![0, 0]);
    for index in [3usize, 4, 5] {
        assert!(extended[index].1.is_empty());
    }
    assert_eq!(extended.last().unwrap().1, vec![b'I']);

    let ordinary = simple_query(&mut stream, "SELECT 1");
    assert_eq!(
        ordinary.iter().map(|message| message.0).collect::<Vec<_>>(),
        vec![b'T', b'D', b'C', b'Z']
    );

    parse(&mut stream, "multi", "SELECT 1; SELECT 2", &[]);
    sync(&mut stream);
    let multi = read_until_ready(&mut stream);
    assert_eq!(
        multi.iter().map(|message| message.0).collect::<Vec<_>>(),
        vec![b'E', b'Z']
    );

    drop(stream);
    handle.shutdown().expect("shutdown test listener");
}
