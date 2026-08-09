use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chorus_common::{Limits, OriginId};
use chorus_pg::{PgConfig, PgRemoteConfig, PgServer, PgServerHandle, scram_verifier_for_password};
use chorus_sql::SqlEngine;
use chorus_storage::{MemoryStateStore, StateStore};
use chorus_txn::{Committer, LocalCommitter};
use rcgen::{CertificateParams, KeyPair};
use ring::digest::{SHA256, digest};
use ring::hmac::{HMAC_SHA256, Key as HmacKey, sign as hmac_sign};
use ring::pbkdf2::{PBKDF2_HMAC_SHA256, derive as pbkdf2_derive};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

fn write_message<S: Write>(stream: &mut S, typ: u8, body: &[u8]) {
    stream.write_all(&[typ]).expect("message type");
    stream
        .write_all(&(u32::try_from(body.len() + 4).unwrap()).to_be_bytes())
        .expect("message length");
    stream.write_all(body).expect("message body");
    stream.flush().expect("message flush");
}

fn read_message<S: Read>(stream: &mut S) -> (u8, Vec<u8>) {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).expect("backend header");
    let length = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
    assert!(
        length >= 4 && length <= 1024 * 1024,
        "bounded backend frame"
    );
    let mut body = vec![0; length - 4];
    stream.read_exact(&mut body).expect("backend body");
    (header[0], body)
}

fn cstr(body: &mut Vec<u8>, value: &str) {
    body.extend_from_slice(value.as_bytes());
    body.push(0);
}

fn startup<S: Write>(stream: &mut S, user: &str) {
    let mut body = Vec::new();
    cstr(&mut body, "user");
    cstr(&mut body, user);
    cstr(&mut body, "database");
    cstr(&mut body, "chorus");
    body.push(0);
    stream
        .write_all(&(u32::try_from(body.len() + 8).unwrap()).to_be_bytes())
        .unwrap();
    stream.write_all(&196_608u32.to_be_bytes()).unwrap();
    stream.write_all(&body).unwrap();
    stream.flush().unwrap();
}

fn scram_attrs(value: &str) -> std::collections::HashMap<String, String> {
    value
        .split(',')
        .map(|part| {
            let (key, value) = part.split_once('=').unwrap();
            (key.to_owned(), value.to_owned())
        })
        .collect()
}

fn client_proof(password: &str, salt: &[u8], iterations: u32, auth_message: &str) -> Vec<u8> {
    let mut salted = [0u8; 32];
    pbkdf2_derive(
        PBKDF2_HMAC_SHA256,
        NonZeroU32::new(iterations).unwrap(),
        salt,
        password.as_bytes(),
        &mut salted,
    );
    let client_key = hmac_sign(&HmacKey::new(HMAC_SHA256, &salted), b"Client Key");
    let stored_key = digest(&SHA256, client_key.as_ref());
    let signature = hmac_sign(
        &HmacKey::new(HMAC_SHA256, stored_key.as_ref()),
        auth_message.as_bytes(),
    );
    client_key
        .as_ref()
        .iter()
        .zip(signature.as_ref())
        .map(|(key, signature)| key ^ signature)
        .collect()
}

fn connect_tls(
    handle: &PgServerHandle,
    certificate: CertificateDer<'static>,
) -> StreamOwned<ClientConnection, TcpStream> {
    let mut roots = RootCertStore::empty();
    roots.add(certificate).expect("test root certificate");
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let address = handle.remote_addr().expect("remote listener address");
    let stream = TcpStream::connect(address).expect("remote connection");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let name = ServerName::try_from("localhost".to_owned()).unwrap();
    let client = ClientConnection::new(Arc::new(config), name).expect("TLS client");
    StreamOwned::new(client, stream)
}

fn open_server() -> (PgServerHandle, CertificateDer<'static>) {
    let params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    let key = KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap();
    let certificate_der = CertificateDer::from(certificate.der().to_vec());
    let verifier = scram_verifier_for_password("secret", b"0123456789abcdef", 4096).unwrap();
    let store: Arc<dyn StateStore> = Arc::new(MemoryStateStore::new());
    let committer: Arc<dyn Committer> =
        Arc::new(LocalCommitter::new(Arc::clone(&store), OriginId::new(1)).unwrap());
    let engine = SqlEngine::new(store, committer, Limits::default());
    let server = PgServer::new(
        engine,
        PgConfig {
            tcp_listen: None,
            unix_socket: None,
            max_connections: 8,
            remote: Some(PgRemoteConfig {
                listen: "127.0.0.1:0".into(),
                certificate_pem: certificate.pem().into_bytes(),
                private_key_pem: key.serialize_pem().into_bytes(),
                auth_file: format!("app:{verifier}\n").into_bytes(),
            }),
        },
    );
    let handle = server
        .start_with_drain_timeout(Duration::from_secs(2))
        .expect("start remote listener");
    (handle, certificate_der)
}

#[test]
fn remote_postgres_requires_tls_and_scram_and_serves_queries() {
    let (handle, certificate) = open_server();
    let mut stream = connect_tls(&handle, certificate);
    startup(&mut stream, "app");

    let (kind, body) = read_message(&mut stream);
    assert_eq!(kind, b'R');
    assert_eq!(u32::from_be_bytes(body[..4].try_into().unwrap()), 10);
    let mut position = 4;
    let mechanism_end = body[position..].iter().position(|byte| *byte == 0).unwrap();
    assert_eq!(&body[position..position + mechanism_end], b"SCRAM-SHA-256");
    position += mechanism_end + 1;
    assert_eq!(body[position], 0, "mechanism list terminator");

    let first = b"n,,n=app,r=clientnonce";
    let mut initial = Vec::new();
    cstr(&mut initial, "SCRAM-SHA-256");
    initial.extend_from_slice(&(first.len() as i32).to_be_bytes());
    initial.extend_from_slice(first);
    write_message(&mut stream, b'p', &initial);

    let (kind, body) = read_message(&mut stream);
    assert_eq!(kind, b'R');
    assert_eq!(u32::from_be_bytes(body[..4].try_into().unwrap()), 11);
    let server_first = std::str::from_utf8(&body[4..]).unwrap();
    let attrs = scram_attrs(server_first);
    let server_nonce = attrs["r"].clone();
    assert!(server_nonce.starts_with("clientnonce"));
    let salt = BASE64.decode(&attrs["s"]).unwrap();
    let iterations = attrs["i"].parse::<u32>().unwrap();
    let final_without_proof = format!("c=biws,r={server_nonce}");
    let auth_message = format!("n=app,r=clientnonce,{server_first},{final_without_proof}");
    let proof = client_proof("secret", &salt, iterations, &auth_message);
    let final_message = format!("{final_without_proof},p={}", BASE64.encode(proof));
    write_message(&mut stream, b'p', final_message.as_bytes());

    let (kind, body) = read_message(&mut stream);
    assert_eq!(kind, b'R');
    assert_eq!(u32::from_be_bytes(body[..4].try_into().unwrap()), 12);
    let (kind, body) = read_message(&mut stream);
    assert_eq!(kind, b'R');
    assert_eq!(body, 0u32.to_be_bytes());
    loop {
        let (kind, _) = read_message(&mut stream);
        if kind == b'Z' {
            break;
        }
    }

    write_message(&mut stream, b'Q', b"SELECT 1\0");
    let mut saw_row = false;
    loop {
        let (kind, _) = read_message(&mut stream);
        saw_row |= kind == b'D';
        if kind == b'Z' {
            break;
        }
    }
    assert!(saw_row, "authenticated remote query returned a row");
    drop(stream);
    handle.shutdown().expect("shutdown remote listener");
}

#[test]
fn remote_postgres_rejects_invalid_scram_proof_before_ready() {
    let (handle, certificate) = open_server();
    let mut stream = connect_tls(&handle, certificate);
    startup(&mut stream, "app");
    let (kind, body) = read_message(&mut stream);
    assert_eq!(kind, b'R');
    assert_eq!(u32::from_be_bytes(body[..4].try_into().unwrap()), 10);

    let first = b"n,,n=app,r=badnonce";
    let mut initial = Vec::new();
    cstr(&mut initial, "SCRAM-SHA-256");
    initial.extend_from_slice(&(first.len() as i32).to_be_bytes());
    initial.extend_from_slice(first);
    write_message(&mut stream, b'p', &initial);
    let (kind, body) = read_message(&mut stream);
    assert_eq!(kind, b'R');
    assert_eq!(u32::from_be_bytes(body[..4].try_into().unwrap()), 11);
    let server_first = std::str::from_utf8(&body[4..]).unwrap();
    let attrs = scram_attrs(server_first);
    let server_nonce = attrs["r"].clone();
    let salt = BASE64.decode(&attrs["s"]).unwrap();
    let iterations = attrs["i"].parse::<u32>().unwrap();
    let final_without_proof = format!("c=biws,r={server_nonce}");
    let auth_message = format!("n=app,r=badnonce,{server_first},{final_without_proof}");
    let proof = client_proof("wrong-password", &salt, iterations, &auth_message);
    write_message(
        &mut stream,
        b'p',
        format!("{final_without_proof},p={}", BASE64.encode(proof)).as_bytes(),
    );
    let (kind, body) = read_message(&mut stream);
    assert_eq!(kind, b'E');
    assert!(body.windows(5).any(|window| window == b"28P01"));
    handle.shutdown().expect("shutdown remote listener");
}
