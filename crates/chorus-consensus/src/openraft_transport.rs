//! Authenticated Tonic transport for the Chorus OpenRaft type configuration.
//!
//! The wire payload currently uses bounded, versioned JSON around OpenRaft's
//! serde types. Replacing it with the canonical binary transport codec remains
//! a release gate; identity, TLS, message-size, and deadline checks do not
//! depend on that future codec change.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tonic::Request;
use tonic::Status;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tonic::transport::{
    Certificate, Channel, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig,
};

pub mod wire {
    tonic::include_proto!("chorus.consensus.openraft");
}

pub const TRANSPORT_WIRE_VERSION: u32 = 1;
pub const MAX_RPC_MESSAGE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_RPC_PAYLOAD_BYTES: usize = MAX_RPC_MESSAGE_BYTES - 1024;
pub const MAX_SNAPSHOT_CHUNK_BYTES: usize = 1024 * 1024;
pub const RPC_QUEUE_CAPACITY: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpcMethod {
    Vote,
    AppendEntries,
    InstallSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerTlsConfig {
    pub node_id: u64,
    /// HTTPS URI, for example `https://127.0.0.1:7001`.
    pub endpoint: String,
    /// DNS SAN expected in this peer's leaf certificate.
    pub dns_name: String,
    /// SHA-256 of the peer's leaf DER certificate, supplied by the signed
    /// bootstrap manifest.
    pub leaf_sha256: [u8; 32],
}

#[derive(Clone)]
pub struct TransportTlsIdentity {
    pub cluster_id: [u8; 16],
    pub cluster_incarnation: u64,
    pub node_id: u64,
    pub ca_pem: Vec<u8>,
    pub certificate_pem: Vec<u8>,
    pub private_key_pem: Vec<u8>,
    pub peers: BTreeMap<u64, PeerTlsConfig>,
}

impl TransportTlsIdentity {
    pub fn validate(&self) -> Result<(), TransportConfigError> {
        if self.cluster_id == [0; 16] {
            return Err(TransportConfigError::Invalid(
                "cluster id must be nonzero".into(),
            ));
        }
        if self.cluster_incarnation == 0 || self.node_id == 0 {
            return Err(TransportConfigError::Invalid(
                "cluster incarnation and node id must be nonzero".into(),
            ));
        }
        if self.ca_pem.is_empty()
            || self.certificate_pem.is_empty()
            || self.private_key_pem.is_empty()
        {
            return Err(TransportConfigError::Invalid(
                "CA, certificate, and private key PEM are required".into(),
            ));
        }
        let mut fingerprints = BTreeSet::new();
        let mut dns_names = BTreeSet::new();
        for (node_id, peer) in &self.peers {
            if *node_id == 0 || *node_id != peer.node_id || *node_id == self.node_id {
                return Err(TransportConfigError::Invalid(
                    "peer map keys must match nonlocal, nonzero node ids".into(),
                ));
            }
            if !peer.endpoint.starts_with("https://")
                || peer.dns_name.is_empty()
                || peer.dns_name.chars().any(char::is_whitespace)
                || peer.leaf_sha256 == [0; 32]
            {
                return Err(TransportConfigError::Invalid(
                    "peer HTTPS endpoint, DNS name, and leaf fingerprint are required".into(),
                ));
            }
            if !fingerprints.insert(peer.leaf_sha256) || !dns_names.insert(&peer.dns_name) {
                return Err(TransportConfigError::Invalid(
                    "peer certificate fingerprints and DNS names must be unique".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn server_tls_config(&self) -> Result<ServerTlsConfig, TransportConfigError> {
        self.validate()?;
        Ok(ServerTlsConfig::new()
            .identity(Identity::from_pem(
                self.certificate_pem.clone(),
                self.private_key_pem.clone(),
            ))
            .client_ca_root(Certificate::from_pem(self.ca_pem.clone()))
            .client_auth_optional(false))
    }

    pub fn client_tls_config(
        &self,
        peer: &PeerTlsConfig,
    ) -> Result<ClientTlsConfig, TransportConfigError> {
        self.validate()?;
        if self.peers.get(&peer.node_id) != Some(peer) {
            return Err(TransportConfigError::Invalid(
                "peer is not present in the authenticated manifest".into(),
            ));
        }
        Ok(ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(self.ca_pem.clone()))
            .identity(Identity::from_pem(
                self.certificate_pem.clone(),
                self.private_key_pem.clone(),
            ))
            .domain_name(peer.dns_name.clone()))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransportConfigError {
    #[error("invalid authenticated transport configuration: {0}")]
    Invalid(String),
    #[error("transport endpoint error: {0}")]
    Endpoint(String),
    #[error("transport TLS error: {0}")]
    Tls(String),
}

#[derive(Clone)]
pub struct PeerAuthenticator {
    identity: Arc<TransportTlsIdentity>,
}

impl PeerAuthenticator {
    pub fn new(identity: Arc<TransportTlsIdentity>) -> Result<Self, TransportConfigError> {
        identity.validate()?;
        Ok(Self { identity })
    }

    /// Authenticate a decoded request before any OpenRaft handler is called.
    ///
    /// Rustls has already checked the CA chain and certificate validity. This
    /// step binds the verified leaf bytes to the stable node id from the
    /// signed manifest and cross-checks cluster identity in the envelope.
    pub fn authenticate<T>(
        &self,
        request: &Request<T>,
        envelope: &wire::Envelope,
        method: RpcMethod,
    ) -> Result<u64, Status> {
        validate_request_envelope(&self.identity, envelope, method)?;
        let tls = request
            .extensions()
            .get::<TlsConnectInfo<TcpConnectInfo>>()
            .ok_or_else(|| Status::unauthenticated("authenticated TLS connection is required"))?;
        let certificates = tls.peer_certs().ok_or_else(|| {
            Status::unauthenticated("authenticated TLS peer certificate is required")
        })?;
        let leaf = certificates
            .first()
            .ok_or_else(|| Status::unauthenticated("TLS peer certificate chain is empty"))?;
        let fingerprint = leaf_fingerprint(leaf.as_ref());
        let peer = self
            .identity
            .peers
            .get(&envelope.source_node_id)
            .ok_or_else(|| Status::permission_denied("source node is not in the peer manifest"))?;
        if fingerprint != peer.leaf_sha256 {
            return Err(Status::permission_denied(
                "TLS leaf certificate does not match source node",
            ));
        }
        Ok(peer.node_id)
    }
}

pub fn validate_request_envelope(
    identity: &TransportTlsIdentity,
    envelope: &wire::Envelope,
    _method: RpcMethod,
) -> Result<(), Status> {
    if envelope.version != TRANSPORT_WIRE_VERSION {
        return Err(Status::failed_precondition(
            "unsupported OpenRaft transport wire version",
        ));
    }
    if envelope.cluster_id.as_slice() != identity.cluster_id {
        return Err(Status::permission_denied("cluster id mismatch"));
    }
    if envelope.cluster_incarnation != identity.cluster_incarnation {
        return Err(Status::permission_denied("cluster incarnation mismatch"));
    }
    if envelope.source_node_id == 0 || envelope.target_node_id != identity.node_id {
        return Err(Status::permission_denied("source or target node mismatch"));
    }
    if envelope.payload.len() > MAX_RPC_PAYLOAD_BYTES {
        return Err(Status::resource_exhausted(
            "RPC payload exceeds 8 MiB limit",
        ));
    }
    Ok(())
}

pub fn validate_snapshot_chunk_size(data_len: usize) -> Result<(), Status> {
    if data_len > MAX_SNAPSHOT_CHUNK_BYTES {
        return Err(Status::resource_exhausted(
            "snapshot chunk exceeds 1 MiB limit",
        ));
    }
    Ok(())
}

pub fn validate_response_envelope(
    identity: &TransportTlsIdentity,
    peer: &PeerTlsConfig,
    envelope: &wire::Envelope,
) -> Result<(), TransportConfigError> {
    if envelope.version != TRANSPORT_WIRE_VERSION
        || envelope.cluster_id.as_slice() != identity.cluster_id
        || envelope.cluster_incarnation != identity.cluster_incarnation
        || envelope.source_node_id != peer.node_id
        || envelope.target_node_id != identity.node_id
        || envelope.payload.len() > MAX_RPC_PAYLOAD_BYTES
    {
        return Err(TransportConfigError::Invalid(
            "response envelope identity or size mismatch".into(),
        ));
    }
    Ok(())
}

pub fn envelope(
    identity: &TransportTlsIdentity,
    target_node_id: u64,
    payload: Vec<u8>,
) -> Result<wire::Envelope, TransportConfigError> {
    identity.validate()?;
    if target_node_id == 0 || payload.len() > MAX_RPC_PAYLOAD_BYTES {
        return Err(TransportConfigError::Invalid(
            "target node is zero or payload exceeds the transport limit".into(),
        ));
    }
    Ok(wire::Envelope {
        version: TRANSPORT_WIRE_VERSION,
        cluster_id: identity.cluster_id.to_vec(),
        cluster_incarnation: identity.cluster_incarnation,
        source_node_id: identity.node_id,
        target_node_id,
        payload,
    })
}

pub fn bounded_transport_server<S>(
    service: S,
) -> wire::open_raft_transport_server::OpenRaftTransportServer<S>
where
    S: wire::open_raft_transport_server::OpenRaftTransport,
{
    wire::open_raft_transport_server::OpenRaftTransportServer::new(service)
        .max_decoding_message_size(MAX_RPC_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_RPC_MESSAGE_BYTES)
}

pub fn authenticated_server_builder() -> Server {
    Server::builder()
        .concurrency_limit_per_connection(RPC_QUEUE_CAPACITY)
        .max_concurrent_streams(RPC_QUEUE_CAPACITY as u32)
        .timeout(Duration::from_secs(30))
}

pub async fn connect_authenticated(
    identity: &TransportTlsIdentity,
    peer: &PeerTlsConfig,
) -> Result<wire::open_raft_transport_client::OpenRaftTransportClient<Channel>, TransportConfigError>
{
    let tls = identity.client_tls_config(peer)?;
    let endpoint = Endpoint::from_shared(peer.endpoint.clone())
        .map_err(|error| TransportConfigError::Endpoint(error.to_string()))?
        .connect_timeout(Duration::from_secs(5))
        .concurrency_limit(RPC_QUEUE_CAPACITY)
        .buffer_size(RPC_QUEUE_CAPACITY)
        .tls_config(tls)
        .map_err(|error| TransportConfigError::Tls(error.to_string()))?;
    let channel = endpoint
        .connect()
        .await
        .map_err(|error| TransportConfigError::Endpoint(error.to_string()))?;
    Ok(
        wire::open_raft_transport_client::OpenRaftTransportClient::new(channel)
            .max_decoding_message_size(MAX_RPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_RPC_MESSAGE_BYTES),
    )
}

pub fn leaf_fingerprint(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}
