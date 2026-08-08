//! Recovery contract between the durable consensus log and state machine.
//!
//! Applying state and advancing the consensus hard-state cursor are separate
//! durable operations. This adapter orders them safely and reconciles the
//! crash window in which state was applied before the hard cursor was
//! persisted. It does not make the two files atomic and is not an OpenRaft
//! state-machine implementation.

use crate::InternalRaftLog;
use chorus_common::{ChorusError, LogId, Result};
use chorus_storage::{Membership, StateSnapshot, StateStore};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayProgress {
    /// Whether recovery advanced the hard cursor to state that was already
    /// durably applied before a crash.
    pub reconciled_hard_cursor: bool,
    /// Entries newly applied to the state store during this invocation.
    pub entries_applied: usize,
}

#[derive(Clone)]
pub struct StateMachineAdapter {
    log: InternalRaftLog,
    store: Arc<dyn StateStore>,
}

impl StateMachineAdapter {
    pub fn new(log: InternalRaftLog, store: Arc<dyn StateStore>) -> Self {
        Self { log, store }
    }

    pub fn log(&self) -> &InternalRaftLog {
        &self.log
    }

    pub fn store(&self) -> &Arc<dyn StateStore> {
        &self.store
    }

    /// Return membership from the same immutable state snapshot that carries
    /// the state-machine applied cursor.
    pub fn membership(&self) -> Result<Membership> {
        let hard = self.log.hard_state()?;
        let snapshot = self.validated_snapshot(&hard)?;
        let state_cursor = snapshot.last_applied();
        validate_cursor_relation(&hard, state_cursor)?;
        if state_cursor.index > hard.last_applied.index {
            let start = hard
                .last_applied
                .index
                .checked_add(1)
                .ok_or_else(|| ChorusError::Limit("hard applied index exhausted".into()))?;
            self.validate_committed_span(start, state_cursor, &hard)?;
        }
        Ok(snapshot.membership().clone())
    }

    /// Reconcile and apply every committed entry through the durable commit
    /// index. State is always applied before the hard applied cursor moves.
    pub fn replay_committed(&self) -> Result<ReplayProgress> {
        let mut hard = self.log.hard_state()?;
        let snapshot = self.validated_snapshot(&hard)?;
        let mut state_cursor = snapshot.last_applied();
        validate_cursor_relation(&hard, state_cursor)?;

        let mut reconciled_hard_cursor = false;
        if state_cursor.index > hard.last_applied.index {
            let reconciliation_start = hard
                .last_applied
                .index
                .checked_add(1)
                .ok_or_else(|| ChorusError::Limit("hard applied index exhausted".into()))?;
            self.validate_committed_span(reconciliation_start, state_cursor, &hard)?;
            self.log.mark_applied(state_cursor)?;
            hard = self.log.hard_state()?;
            reconciled_hard_cursor = true;
        }

        if state_cursor.index == hard.commit_index {
            return Ok(ReplayProgress {
                reconciled_hard_cursor,
                entries_applied: 0,
            });
        }

        let start = state_cursor
            .index
            .checked_add(1)
            .ok_or_else(|| ChorusError::Limit("state-machine index exhausted".into()))?;
        let entries = self
            .log
            .durable_log()
            .read_range(start, hard.commit_index, true)?;
        let expected_len = hard
            .commit_index
            .checked_sub(state_cursor.index)
            .and_then(|count| usize::try_from(count).ok())
            .ok_or_else(|| ChorusError::Limit("committed replay range is too large".into()))?;
        if entries.len() != expected_len {
            return Err(ChorusError::Storage(
                "committed replay range is not contiguous".into(),
            ));
        }

        let mut entries_applied = 0usize;
        for entry in entries {
            let expected_index = state_cursor
                .index
                .checked_add(1)
                .ok_or_else(|| ChorusError::Limit("state-machine index exhausted".into()))?;
            if entry.log_id.index != expected_index {
                return Err(ChorusError::Storage(format!(
                    "committed replay expected index {expected_index}, got {}",
                    entry.log_id.index
                )));
            }

            self.store.apply(entry.log_id, &entry.command)?;
            let applied = self.validated_snapshot(&hard)?.last_applied();
            if applied != entry.log_id {
                return Err(ChorusError::Storage(format!(
                    "state store reported applied cursor {:?} after entry {:?}",
                    applied, entry.log_id
                )));
            }
            self.log.mark_applied(entry.log_id)?;
            state_cursor = entry.log_id;
            entries_applied = entries_applied
                .checked_add(1)
                .ok_or_else(|| ChorusError::Limit("replay count exhausted".into()))?;
        }

        Ok(ReplayProgress {
            reconciled_hard_cursor,
            entries_applied,
        })
    }

    fn validated_snapshot(
        &self,
        hard: &chorus_storage::consensus_log::HardState,
    ) -> Result<StateSnapshot> {
        if !self.store.status().healthy {
            return Err(ChorusError::Storage(
                "state store is unhealthy during consensus replay".into(),
            ));
        }
        let snapshot = self.store.snapshot()?;
        let data = snapshot.to_data();
        if snapshot.cluster_id() != hard.cluster_id
            || data.cluster_incarnation != hard.cluster_incarnation
        {
            return Err(ChorusError::Protocol(
                "state store identity does not match consensus hard state".into(),
            ));
        }
        Ok(snapshot)
    }

    fn validate_committed_span(
        &self,
        start: u64,
        final_cursor: LogId,
        hard: &chorus_storage::consensus_log::HardState,
    ) -> Result<()> {
        if start > final_cursor.index {
            return Err(ChorusError::Protocol(
                "state cursor cannot precede the hard applied cursor".into(),
            ));
        }
        if final_cursor.index > hard.commit_index {
            return Err(ChorusError::Protocol(
                "state cursor is ahead of the durable commit index".into(),
            ));
        }
        let entries = self
            .log
            .durable_log()
            .read_range(start, final_cursor.index, true)?;
        let expected_len = final_cursor
            .index
            .checked_sub(start)
            .and_then(|count| count.checked_add(1))
            .and_then(|count| usize::try_from(count).ok())
            .ok_or_else(|| ChorusError::Limit("reconciliation range is too large".into()))?;
        if entries.len() != expected_len
            || entries.last().map(|entry| entry.log_id) != Some(final_cursor)
        {
            return Err(ChorusError::Protocol(
                "state cursor does not match a contiguous committed log span".into(),
            ));
        }
        Ok(())
    }
}

fn validate_cursor_relation(
    hard: &chorus_storage::consensus_log::HardState,
    state_cursor: LogId,
) -> Result<()> {
    if (state_cursor.index == 0) != (state_cursor == LogId::ZERO)
        || (state_cursor.index != 0 && state_cursor.term == 0)
    {
        return Err(ChorusError::Protocol(
            "state store has an invalid applied LogId".into(),
        ));
    }
    if state_cursor.index > hard.commit_index {
        return Err(ChorusError::Protocol(
            "state cursor is ahead of the durable commit index".into(),
        ));
    }
    if hard.last_applied.index > state_cursor.index {
        return Err(ChorusError::Protocol(
            "hard applied cursor is ahead of durable state".into(),
        ));
    }
    if hard.last_applied.index == state_cursor.index && hard.last_applied != state_cursor {
        return Err(ChorusError::Protocol(
            "hard and state applied cursors disagree on term".into(),
        ));
    }
    Ok(())
}
