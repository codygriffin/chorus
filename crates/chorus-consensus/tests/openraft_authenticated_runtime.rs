use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use chorus_codec::{
    ActivateOriginV1, ApplyResult, CommitTransactionV1, KvMutationV1, ReplicatedCommandV1,
    canonical_mutations, payload_hash,
};
use chorus_common::{OriginId, RequestId};
use chorus_consensus::openraft_transport::{
    AuthenticatedNetworkFactory, ChangeMembershipGatewayRequest, ChangeMembershipGatewayResponse,
    ChangeMembershipIntent, MembershipStatusGatewayRequest, MembershipStatusGatewayResponse,
    PeerTlsConfig, TransportTlsIdentity, leaf_fingerprint,
};
use chorus_consensus::{Consensus, OpenRaftConsensus, OpenRaftRuntimeOptions};
use chorus_redb::RedbStateMachine;
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
    let peers = (1..=leaves.len() as u64)
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
    open_node_with_snapshot_bytes(
        root,
        node_id,
        initialize,
        identity,
        voters,
        addresses,
        128 * 1024 * 1024,
    )
}

fn open_node_with_snapshot_bytes(
    root: &std::path::Path,
    node_id: u64,
    initialize: bool,
    identity: Arc<TransportTlsIdentity>,
    voters: &BTreeMap<u64, String>,
    addresses: &[SocketAddr],
    snapshot_log_bytes: u64,
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
            snapshot_log_bytes,
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
    assert!(!inert_bootstrap.status().quorum);
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
    assert!(!node2.status().quorum);
    assert!(!node3.status().quorum);

    let node1 = open_node(
        root.path(),
        1,
        true,
        Arc::clone(&identities[0]),
        &voters,
        &addresses,
    );
    assert_eq!(Some(1), node1.status().leader_id);

    // A follower is strict-read ready only after it can authenticate a
    // current leader barrier and catch its local state machine up to that
    // cursor.  Leadership alone is not used as a quorum signal.
    wait_for(Duration::from_secs(5), || {
        node2.status().quorum && node3.status().quorum
    });
    let node2_status = node2.status();
    let node3_status = node3.status();
    assert!(node2_status.quorum);
    assert!(node3_status.quorum);
    assert!(node2_status.commit_index >= node2_status.applied_index);
    assert!(node3_status.commit_index >= node3_status.applied_index);

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

#[test]
fn authenticated_runtime_triggers_snapshot_at_retained_log_byte_limit() {
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
    let node1 = open_node_with_snapshot_bytes(
        root.path(),
        1,
        true,
        Arc::clone(&identities[0]),
        &voters,
        &addresses,
        1,
    );
    node1.activate_origin(OriginId::new(1)).unwrap();

    wait_for(Duration::from_secs(6), || {
        node1.snapshot_cursor().ok().flatten().is_some()
    });

    drop(node1);
    drop(node2);
    drop(node3);
}

#[test]
fn authenticated_leader_adds_promotes_and_removes_one_preprovisioned_learner() {
    let root = tempfile::tempdir().unwrap();
    let ca = test_ca();
    let leaves: Vec<_> = (1..=4)
        .map(|node_id| test_leaf(&ca, &format!("node-{node_id}.chorus.test")))
        .collect();
    let addresses = free_addresses(4);
    let endpoints: BTreeMap<_, _> = addresses
        .iter()
        .enumerate()
        .map(|(index, address)| (index as u64 + 1, format!("https://{address}")))
        .collect();
    let voters: BTreeMap<_, _> = endpoints
        .iter()
        .filter(|(node_id, _)| **node_id <= 3)
        .map(|(node_id, endpoint)| (*node_id, endpoint.clone()))
        .collect();
    let identities: Vec<_> = (1..=4)
        .map(|node_id| identity(&ca, node_id, &leaves, &endpoints))
        .collect();

    // The prospective learner is authenticated and listening before the
    // voter set is initialized, but it cannot initialize itself.
    let node4 = open_node(
        root.path(),
        4,
        false,
        Arc::clone(&identities[3]),
        &voters,
        &addresses,
    );
    assert_eq!(None, node4.status().leader_id);
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
    let node1 = open_node(
        root.path(),
        1,
        true,
        Arc::clone(&identities[0]),
        &voters,
        &addresses,
    );
    wait_for(Duration::from_secs(5), || {
        let status = node1.status();
        status.quorum && status.voters == [1, 2, 3]
    });

    let prospective_origin = OriginId::new(4);
    let prospective_factory = AuthenticatedNetworkFactory::new(Arc::clone(&identities[3])).unwrap();
    let client_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let pre_membership_error = client_runtime
        .block_on(prospective_factory.forward_client_write(
            1,
            ReplicatedCommandV1::ActivateOrigin(ActivateOriginV1 {
                origin: prospective_origin,
            }),
            Duration::from_secs(2),
        ))
        .unwrap_err();
    assert!(
        pre_membership_error
            .to_string()
            .contains("not a current Raft member")
    );
    let prospective_status_error = client_runtime
        .block_on(prospective_factory.membership_status(
            2,
            MembershipStatusGatewayRequest {
                requester_node_id: 4,
                hops_remaining: 1,
            },
            Duration::from_secs(2),
        ))
        .unwrap_err();
    assert!(
        prospective_status_error
            .to_string()
            .contains("not a current Raft voter")
    );
    let prospective_change_error = client_runtime
        .block_on(prospective_factory.change_membership(
            2,
            ChangeMembershipGatewayRequest {
                requester_node_id: 4,
                voters: vec![1, 2, 3],
                learners: vec![4],
                intent: Some(ChangeMembershipIntent::AddLearner { node_id: 4 }),
                hops_remaining: 1,
            },
            Duration::from_secs(2),
        ))
        .unwrap_err();
    assert!(
        prospective_change_error
            .to_string()
            .contains("not a current Raft voter")
    );
    let follower_error = node2.change_membership(vec![1, 2, 3], vec![4]).unwrap_err();
    assert!(
        follower_error
            .to_string()
            .contains("submitted to the current leader")
    );
    let unknown = node1
        .change_membership(vec![1, 2, 3], vec![99])
        .unwrap_err();
    assert!(unknown.to_string().contains("signed peer manifest"));
    // Control-plane status and mutation may start at a follower. The
    // authenticated service forwards each request once to the leader while
    // retaining the original voter identity for authorization.
    let control_factory = AuthenticatedNetworkFactory::new(Arc::clone(&identities[0])).unwrap();
    let status = client_runtime
        .block_on(control_factory.membership_status(
            2,
            MembershipStatusGatewayRequest {
                requester_node_id: 1,
                hops_remaining: 1,
            },
            Duration::from_secs(2),
        ))
        .unwrap();
    match status {
        MembershipStatusGatewayResponse::Current(view) => {
            assert_eq!(view.voters, vec![1, 2, 3]);
            assert!(view.learners.is_empty());
        }
        other => panic!("expected leader-authoritative membership status, got {other:?}"),
    }
    let add_request = ChangeMembershipGatewayRequest {
        requester_node_id: 1,
        voters: vec![1, 2, 3],
        learners: vec![4],
        intent: Some(ChangeMembershipIntent::AddLearner { node_id: 4 }),
        hops_remaining: 1,
    };
    let added = client_runtime
        .block_on(control_factory.change_membership(2, add_request.clone(), Duration::from_secs(2)))
        .unwrap();
    assert!(matches!(
        added,
        ChangeMembershipGatewayResponse::Applied {
            voters,
            learners
        } if voters == vec![1, 2, 3] && learners == vec![4]
    ));
    // An ambiguous caller retry re-establishes the blocking catch-up gate.
    let retried = client_runtime
        .block_on(control_factory.change_membership(2, add_request, Duration::from_secs(2)))
        .unwrap();
    assert!(matches!(
        retried,
        ChangeMembershipGatewayResponse::Applied { .. }
    ));
    wait_for(Duration::from_secs(5), || {
        let leader = node1.status();
        let learner = node4.status();
        leader.learners == [4] && learner.learners == [4]
    });
    node4.activate_origin(prospective_origin).unwrap();

    let origin = OriginId::new(1);
    node1.activate_origin(origin).unwrap();
    let request_id = RequestId::new(origin, 1);
    let mutation = KvMutationV1::Put {
        key: b"lrn".to_vec(),
        value: b"learner-value".to_vec(),
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
        node4
            .store()
            .snapshot()
            .ok()
            .is_some_and(|snapshot| snapshot.get(b"lrn") == Some(&b"learner-value"[..]))
    });

    let multi_swap = node1.change_membership(vec![1, 4], vec![2, 3]).unwrap_err();
    assert!(
        multi_swap
            .to_string()
            .contains("preserve an existing 3- or 5-voter set")
    );
    let leader_demotion = node1.change_membership(vec![2, 3, 4], vec![1]).unwrap_err();
    assert!(leader_demotion.to_string().contains("current leader"));

    // Replace nonleader voter 3 with the caught-up learner. OpenRaft first
    // commits a joint config and then a uniform [1,2,4] voter set, retaining
    // node 3 as a learner. An exact retry is safe after an ambiguous reply.
    let replacement_request = ChangeMembershipGatewayRequest {
        requester_node_id: 1,
        voters: vec![1, 2, 4],
        learners: vec![3],
        intent: Some(ChangeMembershipIntent::ReplaceVoter {
            promoted: 4,
            demoted: 3,
        }),
        hops_remaining: 1,
    };
    assert!(matches!(
        client_runtime
            .block_on(control_factory.change_membership(
                2,
                replacement_request.clone(),
                Duration::from_secs(2),
            ))
            .unwrap(),
        ChangeMembershipGatewayResponse::Applied { .. }
    ));
    assert!(matches!(
        client_runtime
            .block_on(control_factory.change_membership(
                2,
                replacement_request,
                Duration::from_secs(2),
            ))
            .unwrap(),
        ChangeMembershipGatewayResponse::Applied { .. }
    ));
    wait_for(Duration::from_secs(5), || {
        [&node1, &node2, &node3, &node4].into_iter().all(|node| {
            let status = node.status();
            status.voters == [1, 2, 4] && status.learners == [3]
        })
    });

    // The former voter is no longer needed for quorum. Stop it, commit with
    // the new voter set, then exercise the follower read barrier on promoted
    // node 4.
    drop(node3);
    let demoted_state_path = root.path().join("node-3/state/active.redb");
    let demoted_state =
        RedbStateMachine::open(&demoted_state_path, CLUSTER_ID, INCARNATION).unwrap();
    let exact = demoted_state.exact_membership().unwrap();
    assert_eq!(1, exact.membership().get_joint_config().len());
    assert_eq!(vec![1, 2, 4], exact.voter_ids().collect::<Vec<_>>());
    assert_eq!(
        vec![3],
        exact.membership().learner_ids().collect::<Vec<_>>()
    );
    drop(demoted_state);
    let request_id = RequestId::new(origin, 2);
    let mutation = KvMutationV1::Put {
        key: b"rpl".to_vec(),
        value: b"replacement-value".to_vec(),
    };
    let canonical = canonical_mutations(std::slice::from_ref(&mutation)).unwrap();
    let result = node1
        .submit(CommitTransactionV1 {
            request_id,
            payload_hash: payload_hash(1, &request_id, 1, &canonical),
            base_epoch: 1,
            mutations: vec![mutation],
        })
        .unwrap();
    assert!(matches!(result, ApplyResult::Committed { epoch: 2, .. }));
    let promoted_read = node4.read_barrier().unwrap();
    assert_eq!(promoted_read.get(b"rpl"), Some(&b"replacement-value"[..]));

    drop(node4);
    let promoted_state_path = root.path().join("node-4/state/active.redb");
    let promoted_state =
        RedbStateMachine::open(&promoted_state_path, CLUSTER_ID, INCARNATION).unwrap();
    let exact = promoted_state.exact_membership().unwrap();
    assert_eq!(1, exact.membership().get_joint_config().len());
    assert_eq!(vec![1, 2, 4], exact.voter_ids().collect::<Vec<_>>());
    assert_eq!(
        vec![3],
        exact.membership().learner_ids().collect::<Vec<_>>()
    );
    assert_eq!(endpoints[&4], exact.membership().get_node(&4).unwrap().addr);
    drop(promoted_state);

    let restarted = open_node(
        root.path(),
        4,
        false,
        Arc::clone(&identities[3]),
        &voters,
        &addresses,
    );
    wait_for(Duration::from_secs(5), || {
        let status = restarted.status();
        status.voters == [1, 2, 4]
            && status.learners == [3]
            && restarted.store().snapshot().ok().is_some_and(|snapshot| {
                snapshot.get(b"lrn") == Some(&b"learner-value"[..])
                    && snapshot.get(b"rpl") == Some(&b"replacement-value"[..])
            })
    });

    let restarted_demoted = open_node(
        root.path(),
        3,
        false,
        Arc::clone(&identities[2]),
        &voters,
        &addresses,
    );
    wait_for(Duration::from_secs(5), || {
        let status = restarted_demoted.status();
        status.voters == [1, 2, 4] && status.learners == [3]
    });

    // A demoted node remains a full member until an explicit second phase.
    // Activate it, remove exactly that learner, then require both its origin
    // and authenticated gateway authority to disappear with the membership.
    let removed_origin = OriginId::new(3);
    restarted_demoted.activate_origin(removed_origin).unwrap();
    let removal_request = ChangeMembershipGatewayRequest {
        requester_node_id: 1,
        voters: vec![1, 2, 4],
        learners: Vec::new(),
        intent: Some(ChangeMembershipIntent::RemoveLearner { node_id: 3 }),
        hops_remaining: 1,
    };
    assert!(matches!(
        client_runtime
            .block_on(control_factory.change_membership(
                2,
                removal_request.clone(),
                Duration::from_secs(2),
            ))
            .unwrap(),
        ChangeMembershipGatewayResponse::Applied { .. }
    ));
    assert!(matches!(
        client_runtime
            .block_on(
                control_factory.change_membership(2, removal_request, Duration::from_secs(2),)
            )
            .unwrap(),
        ChangeMembershipGatewayResponse::Applied { .. }
    ));
    wait_for(Duration::from_secs(5), || {
        [&node1, &node2, &restarted].into_iter().all(|node| {
            let status = node.status();
            status.voters == [1, 2, 4]
                && status.learners.is_empty()
                && !node.store().snapshot().unwrap().origins().contains_key(&3)
        })
    });
    assert!(!restarted_demoted.status().quorum);
    assert!(restarted_demoted.activate_origin(removed_origin).is_err());
    assert!(restarted_demoted.read_barrier().is_err());

    let removed_factory = AuthenticatedNetworkFactory::new(Arc::clone(&identities[2])).unwrap();
    let removed_write = client_runtime
        .block_on(removed_factory.forward_client_write(
            1,
            ReplicatedCommandV1::ActivateOrigin(ActivateOriginV1 {
                origin: removed_origin,
            }),
            Duration::from_secs(2),
        ))
        .unwrap_err();
    assert!(
        removed_write
            .to_string()
            .contains("not a current Raft member")
    );
    let removed_read = client_runtime
        .block_on(removed_factory.forward_read_barrier(1, Duration::from_secs(2)))
        .unwrap_err();
    assert!(
        removed_read
            .to_string()
            .contains("not a current Raft member")
    );
    let removed_status = client_runtime
        .block_on(removed_factory.membership_status(
            1,
            MembershipStatusGatewayRequest {
                requester_node_id: 3,
                hops_remaining: 1,
            },
            Duration::from_secs(2),
        ))
        .unwrap_err();
    assert!(
        removed_status
            .to_string()
            .contains("not a current Raft voter")
    );
    let removed_change = client_runtime
        .block_on(removed_factory.change_membership(
            1,
            ChangeMembershipGatewayRequest {
                requester_node_id: 3,
                voters: vec![1, 2, 4],
                learners: Vec::new(),
                intent: Some(ChangeMembershipIntent::RemoveLearner { node_id: 3 }),
                hops_remaining: 1,
            },
            Duration::from_secs(2),
        ))
        .unwrap_err();
    assert!(
        removed_change
            .to_string()
            .contains("not a current Raft voter")
    );

    drop(restarted_demoted);
    let removed_state =
        RedbStateMachine::open(&demoted_state_path, CLUSTER_ID, INCARNATION).unwrap();
    let exact = removed_state.exact_membership().unwrap();
    // OpenRaft stops replication to a removed learner before that learner can
    // apply its own removal entry. Its local image is intentionally stale;
    // the current voters' membership and gateway authorization are the
    // authority that keep it quarantined.
    assert_eq!(1, exact.membership().get_joint_config().len());
    assert_eq!(vec![1, 2, 4], exact.voter_ids().collect::<Vec<_>>());
    assert_eq!(
        vec![3],
        exact.membership().learner_ids().collect::<Vec<_>>()
    );
    assert!(removed_state.state_data().unwrap().origins.contains_key(&3));
    drop(removed_state);

    let quarantined = open_node(
        root.path(),
        3,
        false,
        Arc::clone(&identities[2]),
        &voters,
        &addresses,
    );
    assert!(!quarantined.status().quorum);
    assert!(quarantined.activate_origin(removed_origin).is_err());
    assert!(quarantined.read_barrier().is_err());
    drop(quarantined);

    let request_id = RequestId::new(origin, 3);
    let mutation = KvMutationV1::Put {
        key: b"rmv".to_vec(),
        value: b"post-removal".to_vec(),
    };
    let canonical = canonical_mutations(std::slice::from_ref(&mutation)).unwrap();
    let result = node1
        .submit(CommitTransactionV1 {
            request_id,
            payload_hash: payload_hash(1, &request_id, 2, &canonical),
            base_epoch: 2,
            mutations: vec![mutation],
        })
        .unwrap();
    assert!(matches!(result, ApplyResult::Committed { epoch: 3, .. }));
    assert_eq!(
        restarted.read_barrier().unwrap().get(b"rmv"),
        Some(&b"post-removal"[..])
    );

    drop(node1);
    let voter_state_path = root.path().join("node-1/state/active.redb");
    let voter_state = RedbStateMachine::open(&voter_state_path, CLUSTER_ID, INCARNATION).unwrap();
    let exact = voter_state.exact_membership().unwrap();
    assert_eq!(1, exact.membership().get_joint_config().len());
    assert_eq!(vec![1, 2, 4], exact.voter_ids().collect::<Vec<_>>());
    assert!(exact.membership().learner_ids().next().is_none());
    assert!(exact.membership().get_node(&3).is_none());
    drop(voter_state);
    let restarted_voter = open_node(
        root.path(),
        1,
        false,
        Arc::clone(&identities[0]),
        &voters,
        &addresses,
    );
    wait_for(Duration::from_secs(5), || {
        let status = restarted_voter.status();
        status.voters == [1, 2, 4] && status.learners.is_empty()
    });

    drop(restarted_voter);
    drop(restarted);
    drop(node2);
}
