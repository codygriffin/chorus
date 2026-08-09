//! Durable state/snapshot publication fence shared with the Raft log store.
//!
//! A [`PurgeFenceHandle`] is intentionally obtained from an already-open
//! [`RedbRaftLogStore`].  The handle carries the log store's identity and uses
//! the same serialized, `Durability::Immediate` write path as log purging.
//! State-machine snapshot publication is the only intended caller: it must
//! persist its snapshot before advancing this fence.

use openraft::{LogId, NodeId, RaftTypeConfig, StorageError};
use serde::{Deserialize, Serialize};

use crate::RedbRaftLogStore;

pub(crate) const SNAPSHOT_MARKER_FORMAT_VERSION: u16 = 1;

/// Cross-database proof that a validated logical snapshot durably represents
/// one exact applied cursor and membership. The state database persists this
/// proof before the log database may advance commit/purge metadata.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(bound = "")]
pub(crate) struct DurableSnapshotMarker<NID: NodeId> {
    pub(crate) format_version: u16,
    pub(crate) cluster_id: [u8; 16],
    pub(crate) cluster_incarnation: u64,
    pub(crate) last_applied: LogId<NID>,
    pub(crate) membership_log_id: Option<LogId<NID>>,
    pub(crate) membership_digest: [u8; 32],
    pub(crate) logical_digest: [u8; 32],
}

impl<NID: NodeId> DurableSnapshotMarker<NID> {
    pub(crate) fn validate_identity(
        &self,
        cluster_id: [u8; 16],
        cluster_incarnation: u64,
    ) -> Result<(), String> {
        if self.format_version != SNAPSHOT_MARKER_FORMAT_VERSION
            || self.cluster_id != cluster_id
            || self.cluster_incarnation != cluster_incarnation
        {
            return Err("snapshot marker identity or format mismatch".into());
        }
        if self
            .membership_log_id
            .as_ref()
            .is_some_and(|membership| membership > &self.last_applied)
        {
            return Err("snapshot marker membership is ahead of applied state".into());
        }
        Ok(())
    }
}

/// An explicit capability to advance a matching Raft store's durable purge
/// fence.
///
/// This is opt-in.  A state machine opened without this handle keeps the
/// historical API and still persists snapshots, but it cannot authorize log
/// purging through the snapshot publication path.
pub struct PurgeFenceHandle<C: RaftTypeConfig> {
    store: RedbRaftLogStore<C>,
}

impl<C: RaftTypeConfig> Clone for PurgeFenceHandle<C> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
        }
    }
}

impl<C: RaftTypeConfig> PurgeFenceHandle<C> {
    pub(crate) fn from_store(store: &RedbRaftLogStore<C>) -> Self {
        Self {
            store: store.clone(),
        }
    }

    /// Identity of the Raft store this capability authorizes.
    pub fn cluster_id(&self) -> [u8; 16] {
        self.store.cluster_id()
    }

    /// Incarnation of the Raft store this capability authorizes.
    pub fn cluster_incarnation(&self) -> u64 {
        self.store.cluster_incarnation()
    }

    /// Advance the durable monotonic fence through `log_id`.
    pub fn advance(&self, log_id: LogId<C::NodeId>) -> Result<(), StorageError<C::NodeId>> {
        self.store.advance_purge_fence(log_id)
    }

    /// Read the currently published durable fence, if any.
    pub fn current(&self) -> Result<Option<LogId<C::NodeId>>, StorageError<C::NodeId>> {
        self.store.read_purge_fence()
    }

    pub(crate) fn imported_marker(
        &self,
    ) -> Result<Option<DurableSnapshotMarker<C::NodeId>>, StorageError<C::NodeId>> {
        self.store.read_imported_snapshot_marker()
    }

    /// Publish a state-durable imported snapshot. If its exact log id is not
    /// retained locally, the log store records the identity-bound proof and
    /// advances commit/fence/purge metadata in one immediate transaction.
    pub(crate) fn publish_imported(
        &self,
        marker: DurableSnapshotMarker<C::NodeId>,
    ) -> Result<(), StorageError<C::NodeId>> {
        self.store.publish_imported_snapshot(marker)
    }
}
