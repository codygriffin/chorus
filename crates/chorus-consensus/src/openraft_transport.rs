//! Authenticated Tonic transport for the Chorus OpenRaft type configuration.
//!
//! The wire payload currently uses bounded, versioned JSON around OpenRaft's
//! serde types. Replacing it with the canonical binary transport codec remains
//! a release gate; identity, TLS, message-size, and deadline checks do not
//! depend on that future codec change.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

use chorus_codec::{MAX_COMMAND_BYTES, encode_command};
use chorus_redb::ChorusRaftConfig;
use openraft::error::{
    Fatal, InstallSnapshotError, NetworkError, PayloadTooLarge, RPCError, RaftError, RemoteError,
    Timeout, Unreachable,
};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::{BasicNode, EntryPayload, RPCTypes, Raft};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;
use tonic::Status;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tonic::transport::{
    Certificate, Channel, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig,
};
use tonic::{Request, Response};

pub mod wire {
    tonic::include_proto!("chorus.consensus.openraft");
}

pub const TRANSPORT_WIRE_VERSION: u32 = 1;
pub const MAX_RPC_MESSAGE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_RPC_PAYLOAD_BYTES: usize = MAX_RPC_MESSAGE_BYTES - 1024;
pub const MAX_SNAPSHOT_CHUNK_BYTES: usize = 1024 * 1024;
pub const MAX_APPEND_ENTRIES: usize = 4096;
pub const RPC_QUEUE_CAPACITY: usize = 128;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const RPC_PAYLOAD_MAGIC: &[u8; 8] = b"CHRFRPC\0";
const RPC_PAYLOAD_VERSION: u8 = 1;
const RPC_PAYLOAD_HEADER_BYTES: usize = RPC_PAYLOAD_MAGIC.len() + 1 + 1 + 4;
const RPC_PAYLOAD_DIGEST_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RpcPayloadDomain {
    VoteRequest = 1,
    VoteResponse = 2,
    AppendEntriesRequest = 3,
    AppendEntriesResponse = 4,
    InstallSnapshotRequest = 5,
    InstallSnapshotResponse = 6,
}

impl RpcPayloadDomain {
    fn decode(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::VoteRequest),
            2 => Some(Self::VoteResponse),
            3 => Some(Self::AppendEntriesRequest),
            4 => Some(Self::AppendEntriesResponse),
            5 => Some(Self::InstallSnapshotRequest),
            6 => Some(Self::InstallSnapshotResponse),
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RpcCodecError {
    #[error("RPC payload exceeds the configured limit")]
    Limit,
    #[error("invalid RPC payload: {0}")]
    Invalid(String),
    #[error("RPC payload serialization failed: {0}")]
    Serialization(String),
}

struct CappedWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl CappedWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(4096)),
            limit,
            exceeded: false,
        }
    }
}

impl Write for CappedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let end = self
            .bytes
            .len()
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::other("RPC payload length overflow"))?;
        if end > self.limit {
            self.exceeded = true;
            return Err(io::Error::other("RPC payload exceeds configured limit"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Encode one strongly domain-separated OpenRaft payload without allowing
/// serde to grow an intermediate allocation beyond the transport limit.
pub fn encode_rpc_payload<T: Serialize>(
    domain: RpcPayloadDomain,
    value: &T,
) -> Result<Vec<u8>, RpcCodecError> {
    let body_limit = MAX_RPC_PAYLOAD_BYTES
        .checked_sub(RPC_PAYLOAD_HEADER_BYTES + RPC_PAYLOAD_DIGEST_BYTES)
        .ok_or(RpcCodecError::Limit)?;
    let mut writer = CappedWriter::new(body_limit);
    if let Err(error) = serde_json::to_writer(&mut writer, value) {
        return Err(if writer.exceeded {
            RpcCodecError::Limit
        } else {
            RpcCodecError::Serialization(error.to_string())
        });
    }
    let body_len = u32::try_from(writer.bytes.len()).map_err(|_| RpcCodecError::Limit)?;
    let mut encoded = Vec::with_capacity(
        RPC_PAYLOAD_HEADER_BYTES + writer.bytes.len() + RPC_PAYLOAD_DIGEST_BYTES,
    );
    encoded.extend_from_slice(RPC_PAYLOAD_MAGIC);
    encoded.push(RPC_PAYLOAD_VERSION);
    encoded.push(domain as u8);
    encoded.extend_from_slice(&body_len.to_be_bytes());
    encoded.extend_from_slice(&writer.bytes);
    encoded.extend_from_slice(&Sha256::digest(&writer.bytes));
    debug_assert!(encoded.len() <= MAX_RPC_PAYLOAD_BYTES);
    Ok(encoded)
}

/// Decode one bounded frame, rejecting wrong domains, unknown versions,
/// corrupt lengths/checksums, and trailing JSON tokens.
pub fn decode_rpc_payload<T: DeserializeOwned>(
    expected_domain: RpcPayloadDomain,
    encoded: &[u8],
) -> Result<T, RpcCodecError> {
    if encoded.len() > MAX_RPC_PAYLOAD_BYTES {
        return Err(RpcCodecError::Limit);
    }
    let minimum = RPC_PAYLOAD_HEADER_BYTES + RPC_PAYLOAD_DIGEST_BYTES;
    if encoded.len() < minimum || &encoded[..RPC_PAYLOAD_MAGIC.len()] != RPC_PAYLOAD_MAGIC {
        return Err(RpcCodecError::Invalid("bad payload magic or length".into()));
    }
    let version_offset = RPC_PAYLOAD_MAGIC.len();
    if encoded[version_offset] != RPC_PAYLOAD_VERSION {
        return Err(RpcCodecError::Invalid("unsupported payload version".into()));
    }
    let domain = RpcPayloadDomain::decode(encoded[version_offset + 1])
        .ok_or_else(|| RpcCodecError::Invalid("unknown payload domain".into()))?;
    if domain != expected_domain {
        return Err(RpcCodecError::Invalid("payload domain mismatch".into()));
    }
    let length_offset = version_offset + 2;
    let body_len = u32::from_be_bytes(
        encoded[length_offset..length_offset + 4]
            .try_into()
            .map_err(|_| RpcCodecError::Invalid("missing payload length".into()))?,
    ) as usize;
    let body_start = RPC_PAYLOAD_HEADER_BYTES;
    let body_end = body_start
        .checked_add(body_len)
        .ok_or_else(|| RpcCodecError::Invalid("payload length overflow".into()))?;
    let expected_len = body_end
        .checked_add(RPC_PAYLOAD_DIGEST_BYTES)
        .ok_or_else(|| RpcCodecError::Invalid("payload length overflow".into()))?;
    if expected_len != encoded.len() {
        return Err(RpcCodecError::Invalid(
            "payload length or trailing bytes mismatch".into(),
        ));
    }
    let body = &encoded[body_start..body_end];
    if Sha256::digest(body).as_slice() != &encoded[body_end..] {
        return Err(RpcCodecError::Invalid("payload checksum mismatch".into()));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let value = T::deserialize(&mut deserializer)
        .map_err(|error| RpcCodecError::Invalid(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| RpcCodecError::Invalid(format!("trailing JSON: {error}")))?;
    Ok(value)
}

type VoteWireResult = Result<VoteResponse<u64>, Fatal<u64>>;
type AppendWireResult = Result<AppendEntriesResponse<u64>, Fatal<u64>>;
type SnapshotWireResult =
    Result<InstallSnapshotResponse<u64>, RaftError<u64, InstallSnapshotError>>;

fn validate_append_request(
    request: &AppendEntriesRequest<ChorusRaftConfig>,
) -> Result<(), RpcCodecError> {
    if request.entries.len() > MAX_APPEND_ENTRIES {
        return Err(RpcCodecError::Limit);
    }
    for entry in &request.entries {
        if let EntryPayload::Normal(command) = &entry.payload {
            let encoded = encode_command(command).map_err(|error| match error {
                chorus_codec::CodecError::Limit(_) => RpcCodecError::Limit,
                other => RpcCodecError::Invalid(other.to_string()),
            })?;
            if encoded.len() > MAX_COMMAND_BYTES + 5 {
                return Err(RpcCodecError::Limit);
            }
        }
    }
    Ok(())
}

fn codec_status(error: RpcCodecError) -> Status {
    match error {
        RpcCodecError::Limit => Status::resource_exhausted(error.to_string()),
        RpcCodecError::Invalid(_) | RpcCodecError::Serialization(_) => {
            Status::invalid_argument(error.to_string())
        }
    }
}

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

/// Authenticated server-side bridge from the bounded Tonic envelope to one
/// concrete Chorus OpenRaft instance.
///
/// Peer certificate and envelope identity are checked before decoding or
/// invoking OpenRaft. This type is intentionally not wired into `chorus-node`
/// until the matching network factory has passed its transport gates.
#[derive(Clone)]
pub struct AuthenticatedRaftService {
    raft: Raft<ChorusRaftConfig>,
    identity: Arc<TransportTlsIdentity>,
    authenticator: PeerAuthenticator,
}

impl AuthenticatedRaftService {
    pub fn new(
        raft: Raft<ChorusRaftConfig>,
        identity: Arc<TransportTlsIdentity>,
    ) -> Result<Self, TransportConfigError> {
        let authenticator = PeerAuthenticator::new(Arc::clone(&identity))?;
        Ok(Self {
            raft,
            identity,
            authenticator,
        })
    }

    fn response(
        &self,
        target_node_id: u64,
        payload: Vec<u8>,
    ) -> Result<Response<wire::Envelope>, Status> {
        envelope(&self.identity, target_node_id, payload)
            .map(Response::new)
            .map_err(|error| Status::internal(error.to_string()))
    }
}

fn fatal_only<T>(result: Result<T, RaftError<u64>>) -> Result<T, Fatal<u64>> {
    match result {
        Ok(value) => Ok(value),
        Err(RaftError::Fatal(error)) => Err(error),
        Err(RaftError::APIError(never)) => match never {},
    }
}

#[tonic::async_trait]
impl wire::open_raft_transport_server::OpenRaftTransport for AuthenticatedRaftService {
    async fn vote(
        &self,
        request: Request<wire::Envelope>,
    ) -> Result<Response<wire::Envelope>, Status> {
        let source =
            self.authenticator
                .authenticate(&request, request.get_ref(), RpcMethod::Vote)?;
        let rpc: VoteRequest<u64> =
            decode_rpc_payload(RpcPayloadDomain::VoteRequest, &request.into_inner().payload)
                .map_err(codec_status)?;
        let result: VoteWireResult = fatal_only(self.raft.vote(rpc).await);
        let payload =
            encode_rpc_payload(RpcPayloadDomain::VoteResponse, &result).map_err(codec_status)?;
        self.response(source, payload)
    }

    async fn append_entries(
        &self,
        request: Request<wire::Envelope>,
    ) -> Result<Response<wire::Envelope>, Status> {
        let source = self.authenticator.authenticate(
            &request,
            request.get_ref(),
            RpcMethod::AppendEntries,
        )?;
        let rpc: AppendEntriesRequest<ChorusRaftConfig> = decode_rpc_payload(
            RpcPayloadDomain::AppendEntriesRequest,
            &request.into_inner().payload,
        )
        .map_err(codec_status)?;
        validate_append_request(&rpc).map_err(codec_status)?;
        let result: AppendWireResult = fatal_only(self.raft.append_entries(rpc).await);
        let payload = encode_rpc_payload(RpcPayloadDomain::AppendEntriesResponse, &result)
            .map_err(codec_status)?;
        self.response(source, payload)
    }

    async fn install_snapshot(
        &self,
        request: Request<wire::Envelope>,
    ) -> Result<Response<wire::Envelope>, Status> {
        let source = self.authenticator.authenticate(
            &request,
            request.get_ref(),
            RpcMethod::InstallSnapshot,
        )?;
        let rpc: InstallSnapshotRequest<ChorusRaftConfig> = decode_rpc_payload(
            RpcPayloadDomain::InstallSnapshotRequest,
            &request.into_inner().payload,
        )
        .map_err(codec_status)?;
        validate_snapshot_chunk_size(rpc.data.len())?;
        let result: SnapshotWireResult = self.raft.install_snapshot(rpc).await;
        let payload = encode_rpc_payload(RpcPayloadDomain::InstallSnapshotResponse, &result)
            .map_err(codec_status)?;
        self.response(source, payload)
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

fn authenticated_endpoint(
    identity: &TransportTlsIdentity,
    peer: &PeerTlsConfig,
) -> Result<Endpoint, TransportConfigError> {
    let tls = identity.client_tls_config(peer)?;
    Endpoint::from_shared(peer.endpoint.clone())
        .map_err(|error| TransportConfigError::Endpoint(error.to_string()))?
        .connect_timeout(CONNECT_TIMEOUT)
        .concurrency_limit(RPC_QUEUE_CAPACITY)
        .buffer_size(RPC_QUEUE_CAPACITY)
        .tls_config(tls)
        .map_err(|error| TransportConfigError::Tls(error.to_string()))
}

pub async fn connect_authenticated(
    identity: &TransportTlsIdentity,
    peer: &PeerTlsConfig,
) -> Result<wire::open_raft_transport_client::OpenRaftTransportClient<Channel>, TransportConfigError>
{
    let endpoint = authenticated_endpoint(identity, peer)?;
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

/// OpenRaft network factory backed by authenticated, lazily connected Tonic
/// channels. One reconnecting `Channel` is retained per immutable peer
/// manifest entry; creating an OpenRaft client does not perform network I/O.
#[derive(Clone)]
pub struct AuthenticatedNetworkFactory {
    identity: Arc<TransportTlsIdentity>,
    channels: Arc<AsyncMutex<BTreeMap<u64, Channel>>>,
}

impl AuthenticatedNetworkFactory {
    pub fn new(identity: Arc<TransportTlsIdentity>) -> Result<Self, TransportConfigError> {
        identity.validate()?;
        Ok(Self {
            identity,
            channels: Arc::new(AsyncMutex::new(BTreeMap::new())),
        })
    }

    /// Number of peer channels allocated so far. Exposed for health metrics
    /// and deterministic cache tests; channels are established lazily by
    /// Tonic when an RPC is first sent.
    pub async fn cached_peer_count(&self) -> usize {
        self.channels.lock().await.len()
    }

    async fn channel_for(&self, target: u64) -> Result<Channel, TransportConfigError> {
        let mut channels = self.channels.lock().await;
        if let Some(channel) = channels.get(&target) {
            return Ok(channel.clone());
        }
        let peer = self.identity.peers.get(&target).ok_or_else(|| {
            TransportConfigError::Invalid(format!(
                "target node {target} is not present in the authenticated manifest"
            ))
        })?;
        let channel = authenticated_endpoint(&self.identity, peer)?.connect_lazy();
        channels.insert(target, channel.clone());
        Ok(channel)
    }

    async fn client_for(
        &self,
        target: u64,
    ) -> Result<
        wire::open_raft_transport_client::OpenRaftTransportClient<Channel>,
        TransportConfigError,
    > {
        Ok(
            wire::open_raft_transport_client::OpenRaftTransportClient::new(
                self.channel_for(target).await?,
            )
            .max_decoding_message_size(MAX_RPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_RPC_MESSAGE_BYTES),
        )
    }
}

pub struct AuthenticatedNetwork {
    factory: AuthenticatedNetworkFactory,
    target: u64,
    target_node: BasicNode,
    configuration_error: Option<String>,
}

impl RaftNetworkFactory<ChorusRaftConfig> for AuthenticatedNetworkFactory {
    type Network = AuthenticatedNetwork;

    async fn new_client(&mut self, target: u64, node: &BasicNode) -> Self::Network {
        let configuration_error = match self.identity.peers.get(&target) {
            None => Some(format!(
                "target node {target} is not present in the authenticated manifest"
            )),
            Some(peer) if node.addr != peer.endpoint => Some(format!(
                "OpenRaft address for node {target} does not match the authenticated manifest"
            )),
            Some(_) => None,
        };
        AuthenticatedNetwork {
            factory: self.clone(),
            target,
            target_node: node.clone(),
            configuration_error,
        }
    }
}

fn io_error(kind: io::ErrorKind, message: impl Into<String>) -> io::Error {
    io::Error::new(kind, message.into())
}

fn unreachable_rpc<E>(message: impl Into<String>) -> RPCError<u64, BasicNode, E>
where
    E: std::error::Error,
{
    let error = io_error(io::ErrorKind::NotConnected, message);
    RPCError::Unreachable(Unreachable::new(&error))
}

fn network_rpc<E>(message: impl Into<String>) -> RPCError<u64, BasicNode, E>
where
    E: std::error::Error,
{
    let error = io_error(io::ErrorKind::InvalidData, message);
    RPCError::Network(NetworkError::new(&error))
}

fn timeout_rpc<E>(
    action: RPCTypes,
    source: u64,
    target: u64,
    timeout: Duration,
) -> RPCError<u64, BasicNode, E>
where
    E: std::error::Error,
{
    RPCError::Timeout(Timeout {
        action,
        id: source,
        target,
        timeout,
    })
}

impl AuthenticatedNetwork {
    fn configuration_error<E>(&self) -> Result<(), RPCError<u64, BasicNode, E>>
    where
        E: std::error::Error,
    {
        match &self.configuration_error {
            Some(message) => Err(unreachable_rpc(message.clone())),
            None => Ok(()),
        }
    }

    fn status_error<E>(
        &self,
        action: RPCTypes,
        timeout: Duration,
        status: Status,
    ) -> RPCError<u64, BasicNode, E>
    where
        E: std::error::Error,
    {
        if status.code() == tonic::Code::DeadlineExceeded {
            return timeout_rpc(action, self.factory.identity.node_id, self.target, timeout);
        }
        match status.code() {
            tonic::Code::Unavailable
            | tonic::Code::Unauthenticated
            | tonic::Code::PermissionDenied
            | tonic::Code::InvalidArgument
            | tonic::Code::FailedPrecondition
            | tonic::Code::ResourceExhausted => unreachable_rpc(status.to_string()),
            _ => network_rpc(status.to_string()),
        }
    }

    async fn client<E>(
        &self,
    ) -> Result<
        wire::open_raft_transport_client::OpenRaftTransportClient<Channel>,
        RPCError<u64, BasicNode, E>,
    >
    where
        E: std::error::Error,
    {
        self.configuration_error()?;
        self.factory
            .client_for(self.target)
            .await
            .map_err(|error| unreachable_rpc(error.to_string()))
    }

    fn request(&self, payload: Vec<u8>) -> Result<Request<wire::Envelope>, TransportConfigError> {
        envelope(&self.factory.identity, self.target, payload).map(Request::new)
    }

    fn validate_response<E>(
        &self,
        response: wire::Envelope,
    ) -> Result<Vec<u8>, RPCError<u64, BasicNode, E>>
    where
        E: std::error::Error,
    {
        let peer = self
            .factory
            .identity
            .peers
            .get(&self.target)
            .ok_or_else(|| {
                unreachable_rpc(format!(
                    "target node {} disappeared from the authenticated manifest",
                    self.target
                ))
            })?;
        validate_response_envelope(&self.factory.identity, peer, &response)
            .map_err(|error| unreachable_rpc(error.to_string()))?;
        Ok(response.payload)
    }
}

impl RaftNetwork<ChorusRaftConfig> for AuthenticatedNetwork {
    async fn vote(
        &mut self,
        rpc: VoteRequest<u64>,
        option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        self.configuration_error()?;
        let timeout = option.hard_ttl();
        let payload = encode_rpc_payload(RpcPayloadDomain::VoteRequest, &rpc)
            .map_err(|error| network_rpc(error.to_string()))?;
        let mut request = self
            .request(payload)
            .map_err(|error| unreachable_rpc(error.to_string()))?;
        request.set_timeout(timeout);
        let mut client = self.client().await?;
        let result = tokio::time::timeout(timeout, client.vote(request)).await;
        let response = match result {
            Err(_) => {
                return Err(timeout_rpc(
                    RPCTypes::Vote,
                    self.factory.identity.node_id,
                    self.target,
                    timeout,
                ));
            }
            Ok(Err(status)) => return Err(self.status_error(RPCTypes::Vote, timeout, status)),
            Ok(Ok(response)) => response.into_inner(),
        };
        let payload = self.validate_response(response)?;
        let result: VoteWireResult = decode_rpc_payload(RpcPayloadDomain::VoteResponse, &payload)
            .map_err(|error| network_rpc(error.to_string()))?;
        result.map_err(|error| {
            RPCError::RemoteError(RemoteError::new_with_node(
                self.target,
                self.target_node.clone(),
                RaftError::Fatal(error),
            ))
        })
    }

    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<ChorusRaftConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        self.configuration_error()?;
        if let Err(error) = validate_append_request(&rpc) {
            return Err(match error {
                RpcCodecError::Limit => RPCError::PayloadTooLarge(
                    PayloadTooLarge::new_entries_hint((rpc.entries.len() / 2).max(1) as u64),
                ),
                other => network_rpc(other.to_string()),
            });
        }
        let payload =
            encode_rpc_payload(RpcPayloadDomain::AppendEntriesRequest, &rpc).map_err(|error| {
                match error {
                    RpcCodecError::Limit => RPCError::PayloadTooLarge(
                        PayloadTooLarge::new_entries_hint((rpc.entries.len() / 2).max(1) as u64),
                    ),
                    other => network_rpc(other.to_string()),
                }
            })?;
        let timeout = option.hard_ttl();
        let mut request = self
            .request(payload)
            .map_err(|error| unreachable_rpc(error.to_string()))?;
        request.set_timeout(timeout);
        let mut client = self.client().await?;
        let result = tokio::time::timeout(timeout, client.append_entries(request)).await;
        let response = match result {
            Err(_) => {
                return Err(timeout_rpc(
                    RPCTypes::AppendEntries,
                    self.factory.identity.node_id,
                    self.target,
                    timeout,
                ));
            }
            Ok(Err(status)) if status.code() == tonic::Code::ResourceExhausted => {
                return Err(RPCError::PayloadTooLarge(
                    PayloadTooLarge::new_entries_hint((rpc.entries.len() / 2).max(1) as u64),
                ));
            }
            Ok(Err(status)) => {
                return Err(self.status_error(RPCTypes::AppendEntries, timeout, status));
            }
            Ok(Ok(response)) => response.into_inner(),
        };
        let payload = self.validate_response(response)?;
        let result: AppendWireResult =
            decode_rpc_payload(RpcPayloadDomain::AppendEntriesResponse, &payload)
                .map_err(|error| network_rpc(error.to_string()))?;
        result.map_err(|error| {
            RPCError::RemoteError(RemoteError::new_with_node(
                self.target,
                self.target_node.clone(),
                RaftError::Fatal(error),
            ))
        })
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<ChorusRaftConfig>,
        option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<u64>,
        RPCError<u64, BasicNode, RaftError<u64, InstallSnapshotError>>,
    > {
        self.configuration_error()?;
        if let Err(status) = validate_snapshot_chunk_size(rpc.data.len()) {
            return Err(unreachable_rpc(status.message().to_owned()));
        }
        let payload = encode_rpc_payload(RpcPayloadDomain::InstallSnapshotRequest, &rpc)
            .map_err(|error| unreachable_rpc(error.to_string()))?;
        let timeout = option.hard_ttl();
        let mut request = self
            .request(payload)
            .map_err(|error| unreachable_rpc(error.to_string()))?;
        request.set_timeout(timeout);
        let mut client = self.client().await?;
        let result = tokio::time::timeout(timeout, client.install_snapshot(request)).await;
        let response = match result {
            Err(_) => {
                return Err(timeout_rpc(
                    RPCTypes::InstallSnapshot,
                    self.factory.identity.node_id,
                    self.target,
                    timeout,
                ));
            }
            Ok(Err(status)) => {
                return Err(self.status_error(RPCTypes::InstallSnapshot, timeout, status));
            }
            Ok(Ok(response)) => response.into_inner(),
        };
        let payload = self.validate_response(response)?;
        let result: SnapshotWireResult =
            decode_rpc_payload(RpcPayloadDomain::InstallSnapshotResponse, &payload)
                .map_err(|error| network_rpc(error.to_string()))?;
        result.map_err(|error| {
            RPCError::RemoteError(RemoteError::new_with_node(
                self.target,
                self.target_node.clone(),
                error,
            ))
        })
    }
}

pub fn leaf_fingerprint(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}
