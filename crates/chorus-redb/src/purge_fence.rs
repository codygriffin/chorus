//! Durable state/snapshot publication fence shared with the Raft log store.
//!
//! A [`PurgeFenceHandle`] is intentionally obtained from an already-open
//! [`RedbRaftLogStore`].  The handle carries the log store's identity and uses
//! the same serialized, `Durability::Immediate` write path as log purging.
//! State-machine snapshot publication is the only intended caller: it must
//! persist its snapshot before advancing this fence.

use openraft::{LogId, RaftTypeConfig, StorageError};

use crate::RedbRaftLogStore;

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
}
