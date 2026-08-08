#![forbid(unsafe_code)]

//! An intentionally internal, no-dependency boundary for a future Raft
//! adapter.
//!
//! This crate is shaped around the durable pieces an OpenRaft integration
//! would need (hard state, vote persistence, committed replay, and suffix
//! replacement), but it is not OpenRaft and does not implement a Raft
//! runtime, elections, quorum accounting, networking, or authentication.
//! Keeping that distinction explicit prevents a storage-only proof from being
//! mistaken for a release-ready consensus implementation.

use chorus_codec::ReplicatedCommandV1;
use chorus_common::{ChorusError, LogId, Result};
use chorus_storage::consensus_log::{ConsensusLogEntry, DurableConsensusLog, HardState};
use std::path::Path;

pub mod state_machine;

/// The state of one capability in the internal readiness report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability {
    Ready,
    Blocked(&'static str),
}

impl Capability {
    pub fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// A capability report for the storage boundary.
///
/// The durable fields are checked against a live log where possible.  The
/// OpenRaft-shaped runtime fields remain explicitly blocked until the actual
/// dependency, transport, election, and quorum integration exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadinessReport {
    pub identity_bound_hard_state: Capability,
    pub term_vote_persistence: Capability,
    pub committed_range_replay: Capability,
    pub uncommitted_suffix_replacement: Capability,
    pub committed_truncation_rejection: Capability,
    pub membership_persistence: Capability,
    pub snapshot_payload_io: Capability,
    pub state_machine_atomic_apply: Capability,
    pub openraft_runtime: Capability,
    pub network_transport: Capability,
    pub elections_and_quorum: Capability,
}

impl ReadinessReport {
    /// Inspect durable primitives without claiming that an OpenRaft runtime
    /// is present.  `term_vote_persistence` and suffix capabilities are
    /// represented by this crate's facade and are proven across reopen and
    /// mutation in the deterministic contract tests.
    pub fn for_log(log: &DurableConsensusLog) -> Result<Self> {
        let state = log.hard_state()?;
        let identity_bound_hard_state =
            if state.cluster_id != [0; 16] && state.cluster_incarnation != 0 {
                Capability::Ready
            } else {
                Capability::Blocked("durable hard state has no nonzero identity")
            };

        let committed_range_replay = match (log.committed_entries(), log.replay_committed()) {
            (Ok(_), Ok(_)) => Capability::Ready,
            _ => Capability::Blocked("committed range or replay is not readable"),
        };

        Ok(Self {
            identity_bound_hard_state,
            term_vote_persistence: if state.current_term > 0 || state.voted_for.is_none() {
                Capability::Ready
            } else {
                Capability::Blocked("hard-state vote is inconsistent with its term")
            },
            committed_range_replay,
            uncommitted_suffix_replacement: Capability::Ready,
            committed_truncation_rejection: Capability::Ready,
            membership_persistence: Capability::Blocked(
                "membership is not persisted as OpenRaft-compatible hard state",
            ),
            snapshot_payload_io: Capability::Blocked(
                "only a snapshot marker exists; snapshot payload IO is absent",
            ),
            state_machine_atomic_apply: Capability::Blocked(
                "the facade does not provide atomic state-machine application",
            ),
            openraft_runtime: Capability::Blocked(
                "actual OpenRaft storage traits/runtime integration are absent",
            ),
            network_transport: Capability::Blocked(
                "consensus transport and peer authentication are absent",
            ),
            elections_and_quorum: Capability::Blocked(
                "elections, quorum commitment, and membership are absent",
            ),
        })
    }

    pub fn durable_primitives_ready(&self) -> bool {
        self.identity_bound_hard_state.is_ready()
            && self.term_vote_persistence.is_ready()
            && self.committed_range_replay.is_ready()
            && self.uncommitted_suffix_replacement.is_ready()
            && self.committed_truncation_rejection.is_ready()
    }

    /// This remains false by construction until the blocked runtime fields
    /// are implemented by a real consensus integration.
    pub fn release_ready(&self) -> bool {
        self.durable_primitives_ready()
            && self.membership_persistence.is_ready()
            && self.snapshot_payload_io.is_ready()
            && self.state_machine_atomic_apply.is_ready()
            && self.openraft_runtime.is_ready()
            && self.network_transport.is_ready()
            && self.elections_and_quorum.is_ready()
    }
}

/// Internal facade with names corresponding to the durable part of a future
/// Raft storage adapter.  It deliberately exposes no OpenRaft traits or
/// network/runtime types.
#[derive(Clone)]
pub struct InternalRaftLog {
    log: DurableConsensusLog,
}

impl InternalRaftLog {
    pub fn open(
        path: impl AsRef<Path>,
        cluster_id: [u8; 16],
        cluster_incarnation: u64,
    ) -> Result<Self> {
        Ok(Self {
            log: DurableConsensusLog::open_with_identity(path, cluster_id, cluster_incarnation)?,
        })
    }

    pub fn durable_log(&self) -> &DurableConsensusLog {
        &self.log
    }

    pub fn hard_state(&self) -> Result<HardState> {
        self.log.hard_state()
    }

    pub fn save_vote(&self, term: u64, node_id: Option<u64>) -> Result<()> {
        self.log.set_term_and_vote(term, node_id)
    }

    pub fn append(&self, entries: &[ConsensusLogEntry]) -> Result<()> {
        self.log.append(entries)
    }

    pub fn commit(&self, index: u64) -> Result<()> {
        self.log.set_commit_index(index)
    }

    pub fn mark_applied(&self, log_id: LogId) -> Result<()> {
        self.log.mark_applied(log_id)
    }

    pub fn committed_range(&self, start: u64, end: u64) -> Result<Vec<ConsensusLogEntry>> {
        self.log.read_range(start, end, true)
    }

    pub fn replay_committed(&self) -> Result<Vec<ConsensusLogEntry>> {
        self.log.replay_committed()
    }

    /// Replace only an uncommitted suffix.  The underlying durable log keeps
    /// the committed prefix protected and enforces contiguous replacement.
    pub fn replace_uncommitted_suffix(
        &self,
        from_index: u64,
        replacement: &[ConsensusLogEntry],
    ) -> Result<()> {
        let state = self.log.hard_state()?;
        if from_index <= state.commit_index || from_index <= state.purged_through.index {
            return Err(ChorusError::Protocol(
                "cannot replace a committed or snapshotted suffix".into(),
            ));
        }
        if let Some(first) = replacement.first() {
            if first.log_id.index != from_index {
                return Err(ChorusError::Protocol(
                    "replacement suffix does not start at from_index".into(),
                ));
            }
            let first_available = state
                .purged_through
                .index
                .checked_add(1)
                .ok_or_else(|| ChorusError::Limit("purged log index exhausted".into()))?;
            let previous_term = if from_index == first_available {
                state.purged_through.term
            } else {
                self.log
                    .read_range(from_index - 1, from_index - 1, false)?
                    .first()
                    .map(|entry| entry.log_id.term)
                    .ok_or_else(|| {
                        ChorusError::Storage(
                            "replacement predecessor is missing from durable log".into(),
                        )
                    })?
            };
            validate_replacement_identity(&state, previous_term, replacement)?;
        }
        self.log.truncate_suffix(from_index)?;
        self.log.append(replacement)
    }

    /// Keep the committed-boundary rejection visible at the adapter boundary.
    pub fn reject_committed_truncation(&self, from_index: u64) -> Result<()> {
        self.log.truncate_suffix(from_index)
    }

    pub fn readiness(&self) -> Result<ReadinessReport> {
        ReadinessReport::for_log(&self.log)
    }
}

fn validate_replacement_identity(
    state: &HardState,
    previous_term: u64,
    entries: &[ConsensusLogEntry],
) -> Result<()> {
    let mut expected = entries[0].log_id.index;
    let mut prior_term = previous_term;
    for entry in entries {
        if entry.cluster_id != state.cluster_id
            || entry.cluster_incarnation != state.cluster_incarnation
        {
            return Err(ChorusError::Protocol(
                "replacement entry identity does not match hard state".into(),
            ));
        }
        if entry.log_id.index != expected {
            return Err(ChorusError::Protocol(
                "replacement suffix contains a gap".into(),
            ));
        }
        if entry.log_id.term == 0 || entry.log_id.term > state.current_term {
            return Err(ChorusError::Protocol(
                "replacement entry term is not covered by hard state".into(),
            ));
        }
        if entry.log_id.term < prior_term {
            return Err(ChorusError::Protocol(
                "replacement suffix term regressed".into(),
            ));
        }
        expected = expected
            .checked_add(1)
            .ok_or_else(|| ChorusError::Limit("replacement index exhausted".into()))?;
        prior_term = entry.log_id.term;
    }
    Ok(())
}

/// Convenience constructor for tests and small adapters.
pub fn entry(
    cluster_id: [u8; 16],
    cluster_incarnation: u64,
    term: u64,
    index: u64,
    command: ReplicatedCommandV1,
) -> ConsensusLogEntry {
    ConsensusLogEntry {
        cluster_id,
        cluster_incarnation,
        log_id: LogId { term, index },
        command,
    }
}
