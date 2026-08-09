use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use chorus_codec::{
    ApplyResult, CommitTransactionV1, KvMutationV1, canonical_mutations, payload_hash,
};
use chorus_common::{OriginId, RequestId};
use chorus_consensus::openraft_transport::{PeerTlsConfig, TransportTlsIdentity, leaf_fingerprint};
use chorus_consensus::{Consensus, OpenRaftConsensus, OpenRaftRuntimeOptions};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};

const CLUSTER_ID: [u8; 16] = [0x58; 16];
const INCARNATION: u64 = 17;

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

fn free_addresses(count: usize) -> Vec<SocketAddr> {
    let listeners: Vec<_> = (0..count)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let addresses = listeners
        .iter()
        .map(|listener| listener.local_addr().unwrap())
        .collect();
    drop(listeners);
    addresses
}

fn identity(
    ca: &TestCa,
    node_id: u64,
    leaves: &[TestLeaf],
    endpoints: &BTreeMap<u64, String>,
) -> Arc<TransportTlsIdentity> {
    let peers = (1..=3)
        .filter(|peer| *peer != node_id)
        .map(|peer| {
            let leaf = &leaves[peer as usize - 1];
            (
                peer,
                PeerTlsConfig {
                    node_id: peer,
                    endpoint: endpoints[&peer].clone(),
                    dns_name: format!("node-{peer}.chorus.test"),
                    leaf_sha256: leaf.fingerprint,
                },
            )
        })
        .collect();
    let local = &leaves[node_id as usize - 1];
    Arc::new(TransportTlsIdentity {
        cluster_id: CLUSTER_ID,
        cluster_incarnation: INCARNATION,
        node_id,
        ca_pem: ca.certificate.pem().into_bytes(),
        certificate_pem: local.certificate_pem.clone(),
        private_key_pem: local.private_key_pem.clone(),
        peers,
    })
}

fn open_node(
    root: &std::path::Path,
    node_id: u64,
    initialize: bool,
    identity: Arc<TransportTlsIdentity>,
    voters: &BTreeMap<u64, String>,
    addresses: &[SocketAddr],
) -> Arc<OpenRaftConsensus> {
    let directory = root.join(format!("node-{node_id}"));
    std::fs::create_dir_all(directory.join("state")).unwrap();
    OpenRaftConsensus::open_authenticated(
        node_id,
        directory.join("raft.redb"),
        directory.join("state/active.redb"),
        CLUSTER_ID,
        INCARNATION,
        initialize,
        identity,
        voters.clone(),
        OpenRaftRuntimeOptions {
            listen: addresses[node_id as usize - 1],
            heartbeat_ms: 80,
            election_timeout_min_ms: 240,
            election_timeout_max_ms: 480,
            snapshot_entries: 100,
        },
    )
    .unwrap()
}

fn wait_for(timeout: Duration, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("condition did not become true within {timeout:?}");
}

#[test]
fn authenticated_three_node_runtime_bootstraps_replicates_and_restarts() {
    let root = tempfile::tempdir().unwrap();
    let ca = test_ca();
    let leaves: Vec<_> = (1..=3)
        .map(|node_id| test_leaf(&ca, &format!("node-{node_id}.chorus.test")))
        .collect();
    let addresses = free_addresses(3);
    let voters: BTreeMap<_, _> = addresses
        .iter()
        .enumerate()
        .map(|(index, address)| (index as u64 + 1, format!("https://{address}")))
        .collect();
    let identities: Vec<_> = (1..=3)
        .map(|node_id| identity(&ca, node_id, &leaves, &voters))
        .collect();

    // Ordinary startup of even the deterministic bootstrap node is inert on
    // an empty directory. Dropping and explicitly reopening it with
    // `initialize=true` below is the only operation that creates membership.
    let inert_bootstrap = open_node(
        root.path(),
        1,
        false,
        Arc::clone(&identities[0]),
        &voters,
        &addresses,
    );
    assert_eq!(None, inert_bootstrap.status().leader_id);
    drop(inert_bootstrap);

    // Empty non-bootstrap followers expose only their authenticated Raft
    // service. They never initialize merely because the cluster is empty.
    let node2 = open_node(
        root.path(),
        2,
        false,
        Arc::clone(&identities[1]),
        &voters,
        &addresses,
    );
    let node3 = open_node(
        root.path(),
        3,
        false,
        Arc::clone(&identities[2]),
        &voters,
        &addresses,
    );
    assert_eq!(None, node2.status().leader_id);
    assert_eq!(None, node3.status().leader_id);

    let node1 = open_node(
        root.path(),
        1,
        true,
        Arc::clone(&identities[0]),
        &voters,
        &addresses,
    );
    assert_eq!(Some(1), node1.status().leader_id);

    let origin = OriginId::new(1);
    node1.activate_origin(origin).unwrap();
    let request_id = RequestId::new(origin, 1);
    let mutation = KvMutationV1::Put {
        key: b"key".to_vec(),
        value: b"authenticated-value".to_vec(),
    };
    let canonical = canonical_mutations(std::slice::from_ref(&mutation)).unwrap();
    let result = node1
        .submit(CommitTransactionV1 {
            request_id,
            payload_hash: payload_hash(1, &request_id, 0, &canonical),
            base_epoch: 0,
            mutations: vec![mutation],
        })
        .unwrap();
    assert!(matches!(result, ApplyResult::Committed { .. }));

    wait_for(Duration::from_secs(5), || {
        [node2.store(), node3.store()].iter().all(|store| {
            store
                .snapshot()
                .ok()
                .is_some_and(|snapshot| snapshot.get(b"key") == Some(&b"authenticated-value"[..]))
        })
    });

    // A follower authenticates and forwards its own origin-bound write to the
    // current leader. A different follower then establishes the leader read
    // barrier and waits for its local durable state machine to reach the
    // returned cursor before exposing the snapshot.
    let follower_origin = OriginId::new(2);
    node2.activate_origin(follower_origin).unwrap();
    let follower_request_id = RequestId::new(follower_origin, 1);
    let follower_mutation = KvMutationV1::Put {
        key: b"fwd".to_vec(),
        value: b"forwarded-value".to_vec(),
    };
    let follower_canonical = canonical_mutations(std::slice::from_ref(&follower_mutation)).unwrap();
    let follower_result = node2
        .submit(CommitTransactionV1 {
            request_id: follower_request_id,
            payload_hash: payload_hash(1, &follower_request_id, 1, &follower_canonical),
            base_epoch: 1,
            mutations: vec![follower_mutation],
        })
        .unwrap();
    assert!(matches!(follower_result, ApplyResult::Committed { .. }));
    assert_eq!(
        Some(&b"forwarded-value"[..]),
        node2.store().snapshot().unwrap().get(b"fwd")
    );
    let follower_read = node3.read_barrier().unwrap();
    assert_eq!(Some(&b"forwarded-value"[..]), follower_read.get(b"fwd"));

    drop(node3);
    let restarted = open_node(
        root.path(),
        3,
        false,
        Arc::clone(&identities[2]),
        &voters,
        &addresses,
    );
    wait_for(Duration::from_secs(5), || {
        restarted.store().snapshot().ok().is_some_and(|snapshot| {
            snapshot.get(b"key") == Some(&b"authenticated-value"[..])
                && snapshot.get(b"fwd") == Some(&b"forwarded-value"[..])
        })
    });

    drop(restarted);
    drop(node1);
    drop(node2);
}
