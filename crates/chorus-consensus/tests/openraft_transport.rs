use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use chorus_consensus::openraft_transport::wire::Envelope;
use chorus_consensus::openraft_transport::wire::open_raft_transport_client::OpenRaftTransportClient;
use chorus_consensus::openraft_transport::wire::open_raft_transport_server::OpenRaftTransport;
use chorus_consensus::openraft_transport::{
    MAX_RPC_PAYLOAD_BYTES, MAX_SNAPSHOT_CHUNK_BYTES, PeerAuthenticator, PeerTlsConfig, RpcMethod,
    TransportTlsIdentity, authenticated_server_builder, bounded_transport_server,
    connect_authenticated, envelope, leaf_fingerprint, validate_response_envelope,
    validate_snapshot_chunk_size,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Channel;
use tonic::{Request, Response, Status};

const CLUSTER_ID: [u8; 16] = [0x71; 16];
const INCARNATION: u64 = 9;

struct TestCa {
    certificate: Certificate,
    key: KeyPair,
}

struct TestLeaf {
    certificate_pem: Vec<u8>,
    private_key_pem: Vec<u8>,
    fingerprint: [u8; 32],
}

fn test_ca() -> TestCa {
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let key = KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap();
    TestCa { certificate, key }
}

fn test_leaf(ca: &TestCa, dns_name: &str) -> TestLeaf {
    let mut params = CertificateParams::new(vec![dns_name.to_owned()]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let key = KeyPair::generate().unwrap();
    let certificate = params.signed_by(&key, &ca.certificate, &ca.key).unwrap();
    TestLeaf {
        certificate_pem: certificate.pem().into_bytes(),
        private_key_pem: key.serialize_pem().into_bytes(),
        fingerprint: leaf_fingerprint(certificate.der().as_ref()),
    }
}

fn peer(node_id: u64, endpoint: String, dns_name: &str, leaf: &TestLeaf) -> PeerTlsConfig {
    PeerTlsConfig {
        node_id,
        endpoint,
        dns_name: dns_name.into(),
        leaf_sha256: leaf.fingerprint,
    }
}

fn identity(
    ca: &TestCa,
    node_id: u64,
    leaf: &TestLeaf,
    peers: Vec<PeerTlsConfig>,
) -> Arc<TransportTlsIdentity> {
    Arc::new(TransportTlsIdentity {
        cluster_id: CLUSTER_ID,
        cluster_incarnation: INCARNATION,
        node_id,
        ca_pem: ca.certificate.pem().into_bytes(),
        certificate_pem: leaf.certificate_pem.clone(),
        private_key_pem: leaf.private_key_pem.clone(),
        peers: peers
            .into_iter()
            .map(|peer| (peer.node_id, peer))
            .collect::<BTreeMap<_, _>>(),
    })
}

#[derive(Clone)]
struct GateService {
    identity: Arc<TransportTlsIdentity>,
    authenticator: PeerAuthenticator,
    calls: Arc<AtomicUsize>,
}

impl GateService {
    fn handle(
        &self,
        request: Request<Envelope>,
        method: RpcMethod,
    ) -> Result<Response<Envelope>, Status> {
        self.authenticator
            .authenticate(&request, request.get_ref(), method)?;
        let request = request.into_inner();
        self.calls.fetch_add(1, Ordering::SeqCst);
        let response = envelope(&self.identity, request.source_node_id, request.payload)
            .map_err(|error| Status::internal(error.to_string()))?;
        Ok(Response::new(response))
    }
}

#[tonic::async_trait]
impl OpenRaftTransport for GateService {
    async fn vote(&self, request: Request<Envelope>) -> Result<Response<Envelope>, Status> {
        self.handle(request, RpcMethod::Vote)
    }

    async fn append_entries(
        &self,
        request: Request<Envelope>,
    ) -> Result<Response<Envelope>, Status> {
        self.handle(request, RpcMethod::AppendEntries)
    }

    async fn install_snapshot(
        &self,
        request: Request<Envelope>,
    ) -> Result<Response<Envelope>, Status> {
        self.handle(request, RpcMethod::InstallSnapshot)
    }
}

async fn start_server(
    identity: Arc<TransportTlsIdentity>,
    calls: Arc<AtomicUsize>,
) -> (
    std::net::SocketAddr,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);
    let authenticator = PeerAuthenticator::new(Arc::clone(&identity)).unwrap();
    let service = GateService {
        identity: Arc::clone(&identity),
        authenticator,
        calls,
    };
    let tls = identity.server_tls_config().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        authenticated_server_builder()
            .tls_config(tls)
            .unwrap()
            .add_service(bounded_transport_server(service))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    (address, shutdown_tx, task)
}

async fn vote(
    client: &mut OpenRaftTransportClient<Channel>,
    envelope: Envelope,
) -> Result<Envelope, Status> {
    client
        .vote(Request::new(envelope))
        .await
        .map(Response::into_inner)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_binds_peer_leaf_and_envelope_before_handler() {
    let ca = test_ca();
    let server_leaf = test_leaf(&ca, "node-1.chorus.test");
    let client_leaf = test_leaf(&ca, "node-2.chorus.test");
    let forged_leaf = test_leaf(&ca, "node-3.chorus.test");
    let calls = Arc::new(AtomicUsize::new(0));

    let placeholder_endpoint = "https://127.0.0.1:1".to_owned();
    let server_identity = identity(
        &ca,
        1,
        &server_leaf,
        vec![peer(
            2,
            placeholder_endpoint.clone(),
            "node-2.chorus.test",
            &client_leaf,
        )],
    );
    let (address, shutdown, task) = start_server(server_identity, Arc::clone(&calls)).await;
    let endpoint = format!("https://{address}");
    let server_peer = peer(1, endpoint, "node-1.chorus.test", &server_leaf);
    let client_identity = identity(&ca, 2, &client_leaf, vec![server_peer.clone()]);
    let mut client = connect_authenticated(&client_identity, &server_peer)
        .await
        .unwrap();

    let request = envelope(&client_identity, 1, b"vote".to_vec()).unwrap();
    let response = vote(&mut client, request).await.unwrap();
    validate_response_envelope(&client_identity, &server_peer, &response).unwrap();
    assert_eq!(b"vote", response.payload.as_slice());
    assert_eq!(1, calls.load(Ordering::SeqCst));

    let mut wrong_cluster = envelope(&client_identity, 1, Vec::new()).unwrap();
    wrong_cluster.cluster_id = [0x72; 16].to_vec();
    assert_eq!(
        tonic::Code::PermissionDenied,
        vote(&mut client, wrong_cluster).await.unwrap_err().code()
    );
    let mut wrong_incarnation = envelope(&client_identity, 1, Vec::new()).unwrap();
    wrong_incarnation.cluster_incarnation += 1;
    assert_eq!(
        tonic::Code::PermissionDenied,
        vote(&mut client, wrong_incarnation)
            .await
            .unwrap_err()
            .code()
    );
    assert_eq!(1, calls.load(Ordering::SeqCst));

    // The certificate is signed by the trusted CA, but its leaf fingerprint
    // is not the one assigned to source node 2 in the manifest.
    let forged_identity = identity(&ca, 2, &forged_leaf, vec![server_peer.clone()]);
    let mut forged_client = connect_authenticated(&forged_identity, &server_peer)
        .await
        .unwrap();
    let forged_request = envelope(&forged_identity, 1, Vec::new()).unwrap();
    assert_eq!(
        tonic::Code::PermissionDenied,
        vote(&mut forged_client, forged_request)
            .await
            .unwrap_err()
            .code()
    );
    assert_eq!(1, calls.load(Ordering::SeqCst));

    let _ = shutdown.send(());
    task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn untrusted_client_and_oversized_payloads_fail_closed() {
    let ca = test_ca();
    let other_ca = test_ca();
    let server_leaf = test_leaf(&ca, "node-1.chorus.test");
    let expected_client_leaf = test_leaf(&ca, "node-2.chorus.test");
    let untrusted_client_leaf = test_leaf(&other_ca, "node-2.chorus.test");
    let calls = Arc::new(AtomicUsize::new(0));
    let server_identity = identity(
        &ca,
        1,
        &server_leaf,
        vec![peer(
            2,
            "https://127.0.0.1:1".into(),
            "node-2.chorus.test",
            &expected_client_leaf,
        )],
    );
    let (address, shutdown, task) = start_server(server_identity, Arc::clone(&calls)).await;
    let server_peer = peer(
        1,
        format!("https://{address}"),
        "node-1.chorus.test",
        &server_leaf,
    );

    // Trust the real server CA locally, but present a client leaf issued by a
    // different CA. The server rejects the TLS handshake before the service.
    let untrusted_identity = Arc::new(TransportTlsIdentity {
        cluster_id: CLUSTER_ID,
        cluster_incarnation: INCARNATION,
        node_id: 2,
        ca_pem: ca.certificate.pem().into_bytes(),
        certificate_pem: untrusted_client_leaf.certificate_pem,
        private_key_pem: untrusted_client_leaf.private_key_pem,
        peers: BTreeMap::from([(1, server_peer.clone())]),
    });
    // Tonic may construct the Channel before the HTTP/2 request forces the
    // TLS handshake, so require the first RPC itself to fail.
    let mut untrusted_client = connect_authenticated(&untrusted_identity, &server_peer)
        .await
        .unwrap();
    let untrusted_request = envelope(&untrusted_identity, 1, Vec::new()).unwrap();
    assert!(
        vote(&mut untrusted_client, untrusted_request)
            .await
            .is_err()
    );
    assert_eq!(0, calls.load(Ordering::SeqCst));

    assert!(envelope(&untrusted_identity, 1, vec![0; MAX_RPC_PAYLOAD_BYTES + 1]).is_err());
    assert!(validate_snapshot_chunk_size(MAX_SNAPSHOT_CHUNK_BYTES).is_ok());
    assert!(validate_snapshot_chunk_size(MAX_SNAPSHOT_CHUNK_BYTES + 1).is_err());

    let _ = shutdown.send(());
    task.await.unwrap();
}
