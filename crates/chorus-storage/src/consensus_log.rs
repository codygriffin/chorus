#![forbid(unsafe_code)]

//! A small durable consensus-log boundary.
//!
//! This module is deliberately independent from `FileStateStore`'s
//! apply-intent recovery stream.  It models the storage contract that an
//! OpenRaft adapter needs: hard state is durable, entries are framed and
//! fsynced, committed reads are bounded by `commit_index`, and destructive
//! log operations are guarded by commit/application/snapshot progress.
//! It does not implement elections, quorum commitment, replication, or peer
//! authentication; OpenRaft integration and mTLS remain release blockers.

use chorus_codec::ReplicatedCommandV1;
use chorus_common::{ChorusError, LogId, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const HARD_MAGIC: &[u8] = b"CHORUS-HARD-STATE\0";
const LOG_MAGIC: &[u8] = b"CHORUS-CONSENSUS-LOG\0";
const FORMAT_VERSION: u8 = 1;
const MAX_LOG_BYTES: usize = 256 * 1024 * 1024;
const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HardState {
    pub cluster_id: [u8; 16],
    pub cluster_incarnation: u64,
    pub current_term: u64,
    pub voted_for: Option<u64>,
    pub commit_index: u64,
    pub last_applied: LogId,
    pub snapshot_last_included: LogId,
    /// Highest physical log prefix that may be absent from the entry file.
    /// This is deliberately independent from the latest durable snapshot:
    /// publishing a snapshot marker must not make retained log frames look
    /// like corruption after a crash before physical purge.
    pub purged_through: LogId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsensusLogEntry {
    pub cluster_id: [u8; 16],
    pub cluster_incarnation: u64,
    pub log_id: LogId,
    pub command: ReplicatedCommandV1,
}

#[derive(Clone, Debug)]
struct LogInner {
    entries_path: PathBuf,
    hard_path: PathBuf,
    hard_state: HardState,
    entries: Vec<ConsensusLogEntry>,
    unhealthy: Option<String>,
}

#[derive(Clone)]
pub struct DurableConsensusLog {
    inner: Arc<Mutex<LogInner>>,
}

impl DurableConsensusLog {
    pub fn open_with_identity(
        path: impl AsRef<Path>,
        cluster_id: [u8; 16],
        cluster_incarnation: u64,
    ) -> Result<Self> {
        validate_identity(cluster_id, cluster_incarnation)?;
        let entries_path = path.as_ref().to_path_buf();
        let hard_path = entries_path.with_extension("hard");
        let hard_state = if hard_path.exists() {
            let bytes = read_file(&hard_path, MAX_FRAME_BYTES)?;
            let state = decode_hard_state(&bytes)?;
            if state.cluster_id != cluster_id || state.cluster_incarnation != cluster_incarnation {
                return Err(ChorusError::Protocol(
                    "consensus hard state belongs to another cluster or incarnation".into(),
                ));
            }
            state
        } else {
            if entries_path.exists()
                && fs::metadata(&entries_path)
                    .map_err(|error| ChorusError::Storage(error.to_string()))?
                    .len()
                    != 0
            {
                return Err(ChorusError::Storage(
                    "consensus entry log exists without durable hard state".into(),
                ));
            }
            let state = HardState {
                cluster_id,
                cluster_incarnation,
                current_term: 0,
                voted_for: None,
                commit_index: 0,
                last_applied: LogId::ZERO,
                snapshot_last_included: LogId::ZERO,
                purged_through: LogId::ZERO,
            };
            // Identity is the first durable record. An entry file is never
            // allowed to become authoritative without this fsynced binding.
            persist_hard(&hard_path, &state)?;
            state
        };
        let (mut entries, valid_len) = read_entries(&entries_path)?;
        if entries_path.exists() {
            let file_len = fs::metadata(&entries_path)
                .map(|metadata| metadata.len())
                .map_err(|error| ChorusError::Storage(error.to_string()))?;
            if valid_len < file_len {
                truncate_file(&entries_path, valid_len)?;
            }
        }
        validate_physical_entries(&hard_state, &entries)?;
        let retained_redundant_prefix = entries
            .first()
            .is_some_and(|entry| entry.log_id.index <= hard_state.purged_through.index);
        entries.retain(|entry| entry.log_id.index > hard_state.purged_through.index);
        validate_log(&hard_state, &entries)?;
        if retained_redundant_prefix {
            // `purged_through` is published before rewriting the entry file.
            // A crash in that window leaves harmless old frames; normalize
            // them on reopen only after every frame and hard-state invariant
            // has validated successfully.
            rewrite_entries(&entries_path, &entries)?;
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(LogInner {
                entries_path,
                hard_path,
                hard_state,
                entries,
                unhealthy: None,
            })),
        })
    }

    pub fn hard_state(&self) -> Result<HardState> {
        let inner = self.lock()?;
        self.ensure_healthy(&inner)?;
        Ok(inner.hard_state.clone())
    }

    pub fn is_healthy(&self) -> bool {
        self.inner
            .lock()
            .map(|inner| inner.unhealthy.is_none())
            .unwrap_or(false)
    }

    pub fn last_log_id(&self) -> Result<LogId> {
        let inner = self.lock()?;
        self.ensure_healthy(&inner)?;
        Ok(inner
            .entries
            .last()
            .map(|entry| entry.log_id)
            .unwrap_or(inner.hard_state.purged_through))
    }

    /// Append a contiguous suffix and fsync it before returning.
    pub fn append(&self, new_entries: &[ConsensusLogEntry]) -> Result<()> {
        if new_entries.is_empty() {
            return Ok(());
        }
        let mut inner = self.lock_mut()?;
        self.ensure_healthy(&inner)?;
        let tail_index = inner
            .entries
            .last()
            .map(|entry| entry.log_id.index)
            .unwrap_or(inner.hard_state.purged_through.index);
        let mut expected = tail_index
            .checked_add(1)
            .ok_or_else(|| ChorusError::Limit("consensus log index exhausted".into()))?;
        let mut previous_term = inner
            .entries
            .last()
            .map(|entry| entry.log_id.term)
            .unwrap_or(inner.hard_state.purged_through.term);
        let mut bytes = Vec::new();
        for entry in new_entries {
            if entry.cluster_id != inner.hard_state.cluster_id
                || entry.cluster_incarnation != inner.hard_state.cluster_incarnation
            {
                return Err(ChorusError::Protocol(
                    "consensus entry identity does not match hard state".into(),
                ));
            }
            if entry.log_id.index != expected {
                return Err(ChorusError::Protocol(format!(
                    "consensus log gap: expected index {expected}, got {}",
                    entry.log_id.index
                )));
            }
            if entry.log_id.index <= inner.hard_state.commit_index {
                return Err(ChorusError::Protocol(
                    "cannot append over a committed consensus entry".into(),
                ));
            }
            if entry.log_id.term < previous_term {
                return Err(ChorusError::Protocol("consensus log term regressed".into()));
            }
            if entry.log_id.term == 0 || entry.log_id.term > inner.hard_state.current_term {
                return Err(ChorusError::Protocol(
                    "consensus entry term is not covered by durable current_term".into(),
                ));
            }
            let frame = encode_entry(entry)?;
            bytes.extend_from_slice(&frame);
            if bytes.len() > MAX_LOG_BYTES {
                return Err(ChorusError::Limit(
                    "consensus append batch exceeds 256 MiB".into(),
                ));
            }
            expected = expected
                .checked_add(1)
                .ok_or_else(|| ChorusError::Limit("consensus log index exhausted".into()))?;
            previous_term = entry.log_id.term;
        }
        let current_len = fs::metadata(&inner.entries_path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        let next_len = current_len
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| ChorusError::Limit("consensus log size exhausted".into()))?;
        if next_len > MAX_LOG_BYTES as u64 {
            return Err(ChorusError::Limit("consensus log exceeds 256 MiB".into()));
        }
        if let Err(error) = append_synced(&inner.entries_path, &bytes) {
            return Err(poison(&mut inner, error));
        }
        inner.entries.extend_from_slice(new_entries);
        Ok(())
    }

    pub fn set_term_and_vote(&self, term: u64, voted_for: Option<u64>) -> Result<()> {
        let mut inner = self.lock_mut()?;
        self.ensure_healthy(&inner)?;
        if voted_for == Some(0) || (term == 0 && voted_for.is_some()) {
            return Err(ChorusError::Protocol(
                "consensus vote requires a nonzero node id and term".into(),
            ));
        }
        if term < inner.hard_state.current_term {
            return Err(ChorusError::Protocol(
                "consensus term cannot move backwards".into(),
            ));
        }
        if term == inner.hard_state.current_term && voted_for != inner.hard_state.voted_for {
            return Err(ChorusError::Protocol(
                "vote is already recorded for the current term".into(),
            ));
        }
        let next = HardState {
            current_term: term,
            voted_for,
            ..inner.hard_state.clone()
        };
        if let Err(error) = persist_hard(&inner.hard_path, &next) {
            return Err(poison(&mut inner, error));
        }
        inner.hard_state = next;
        Ok(())
    }

    pub fn set_commit_index(&self, commit_index: u64) -> Result<()> {
        let mut inner = self.lock_mut()?;
        self.ensure_healthy(&inner)?;
        if commit_index < inner.hard_state.commit_index {
            return Err(ChorusError::Protocol(
                "commit index cannot move backwards".into(),
            ));
        }
        let last_index = inner
            .entries
            .last()
            .map(|entry| entry.log_id.index)
            .unwrap_or(inner.hard_state.purged_through.index);
        if commit_index > last_index {
            return Err(ChorusError::Protocol(
                "commit index is beyond the durable log".into(),
            ));
        }
        let next = HardState {
            commit_index,
            ..inner.hard_state.clone()
        };
        if let Err(error) = persist_hard(&inner.hard_path, &next) {
            return Err(poison(&mut inner, error));
        }
        inner.hard_state = next;
        Ok(())
    }

    /// Persist the state-machine cursor, but never beyond the durable commit.
    pub fn mark_applied(&self, log_id: LogId) -> Result<()> {
        let mut inner = self.lock_mut()?;
        self.ensure_healthy(&inner)?;
        validate_progress_log_id(log_id)?;
        if log_id.index < inner.hard_state.last_applied.index {
            return Err(ChorusError::Protocol(
                "last applied index cannot move backwards".into(),
            ));
        }
        if log_id.index > inner.hard_state.commit_index {
            return Err(ChorusError::Protocol(
                "cannot apply an uncommitted consensus entry".into(),
            ));
        }
        if log_id.index > inner.hard_state.snapshot_last_included.index
            && entry_at(&inner.entries, log_id.index).map(|entry| entry.log_id) != Some(log_id)
        {
            return Err(ChorusError::Protocol(
                "last applied log id is not present in the durable log".into(),
            ));
        }
        if log_id.index <= inner.hard_state.snapshot_last_included.index
            && log_id.index != 0
            && log_id != inner.hard_state.snapshot_last_included
            && log_id != inner.hard_state.purged_through
            && entry_at(&inner.entries, log_id.index).map(|entry| entry.log_id) != Some(log_id)
        {
            return Err(ChorusError::Protocol(
                "last applied log id does not match durable snapshot/log metadata".into(),
            ));
        }
        let next = HardState {
            last_applied: log_id,
            ..inner.hard_state.clone()
        };
        if let Err(error) = persist_hard(&inner.hard_path, &next) {
            return Err(poison(&mut inner, error));
        }
        inner.hard_state = next;
        Ok(())
    }

    /// Mark an already-applied snapshot boundary before purging old entries.
    pub fn install_snapshot_marker(&self, log_id: LogId) -> Result<()> {
        let mut inner = self.lock_mut()?;
        self.ensure_healthy(&inner)?;
        validate_progress_log_id(log_id)?;
        if log_id.index < inner.hard_state.snapshot_last_included.index
            || log_id.index > inner.hard_state.last_applied.index
            || log_id.index > inner.hard_state.commit_index
        {
            return Err(ChorusError::Protocol(
                "snapshot marker must be applied and committed".into(),
            ));
        }
        if log_id.index != 0
            && log_id != inner.hard_state.last_applied
            && entry_at(&inner.entries, log_id.index).map(|entry| entry.log_id) != Some(log_id)
        {
            return Err(ChorusError::Protocol(
                "snapshot marker log id is not present in durable progress".into(),
            ));
        }
        let next = HardState {
            snapshot_last_included: log_id,
            ..inner.hard_state.clone()
        };
        if let Err(error) = persist_hard(&inner.hard_path, &next) {
            return Err(poison(&mut inner, error));
        }
        inner.hard_state = next;
        Ok(())
    }

    pub fn read_range(
        &self,
        start: u64,
        end: u64,
        committed_only: bool,
    ) -> Result<Vec<ConsensusLogEntry>> {
        let inner = self.lock()?;
        self.ensure_healthy(&inner)?;
        if start > end {
            return Err(ChorusError::Protocol("invalid consensus log range".into()));
        }
        let first_available = inner
            .hard_state
            .purged_through
            .index
            .checked_add(1)
            .ok_or_else(|| ChorusError::Limit("purged log index exhausted".into()))?;
        if start < first_available {
            return Err(ChorusError::Protocol(
                "requested entries have been purged behind the snapshot boundary".into(),
            ));
        }
        let upper = if committed_only {
            end.min(inner.hard_state.commit_index)
        } else {
            end.min(
                inner
                    .entries
                    .last()
                    .map(|entry| entry.log_id.index)
                    .unwrap_or(inner.hard_state.purged_through.index),
            )
        };
        if upper < start {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        for index in start..=upper {
            let entry = entry_at(&inner.entries, index).ok_or_else(|| {
                ChorusError::Storage(format!(
                    "durable consensus log is missing required index {index}"
                ))
            })?;
            entries.push(entry.clone());
        }
        Ok(entries)
    }

    pub fn committed_entries(&self) -> Result<Vec<ConsensusLogEntry>> {
        let state = self.hard_state()?;
        if state.commit_index <= state.purged_through.index {
            return Ok(Vec::new());
        }
        self.read_range(state.purged_through.index + 1, state.commit_index, true)
    }

    /// Return only committed entries newer than durable `last_applied`.
    pub fn replay_committed(&self) -> Result<Vec<ConsensusLogEntry>> {
        let state = self.hard_state()?;
        if state.last_applied.index >= state.commit_index {
            return Ok(Vec::new());
        }
        let start = state
            .last_applied
            .index
            .checked_add(1)
            .ok_or_else(|| ChorusError::Limit("last applied index exhausted".into()))?;
        self.read_range(start, state.commit_index, true)
    }

    /// Remove an uncommitted suffix.  Truncating at or below commit is never
    /// allowed, even if the caller is trying to repair a stale replica.
    pub fn truncate_suffix(&self, from_index: u64) -> Result<()> {
        let mut inner = self.lock_mut()?;
        self.ensure_healthy(&inner)?;
        if from_index <= inner.hard_state.commit_index
            || from_index <= inner.hard_state.purged_through.index
        {
            return Err(ChorusError::Protocol(
                "cannot truncate a committed or snapshotted suffix".into(),
            ));
        }
        if !inner
            .entries
            .iter()
            .any(|entry| entry.log_id.index >= from_index)
        {
            return Ok(());
        }
        let keep = inner
            .entries
            .iter()
            .take_while(|entry| entry.log_id.index < from_index)
            .cloned()
            .collect::<Vec<_>>();
        if let Err(error) = rewrite_entries(&inner.entries_path, &keep) {
            return Err(poison(&mut inner, error));
        }
        inner.entries = keep;
        Ok(())
    }

    /// Purge only after both application and snapshot publication are
    /// durable.  The snapshot marker is persisted separately in hard state.
    pub fn purge_through(&self, log_id: LogId) -> Result<()> {
        let mut inner = self.lock_mut()?;
        self.ensure_healthy(&inner)?;
        validate_progress_log_id(log_id)?;
        if log_id.index < inner.hard_state.purged_through.index {
            return Err(ChorusError::Protocol(
                "purged consensus prefix cannot move backwards".into(),
            ));
        }
        if log_id.index == inner.hard_state.purged_through.index {
            if log_id != inner.hard_state.purged_through {
                return Err(ChorusError::Protocol(
                    "purged consensus prefix term does not match".into(),
                ));
            }
            return Ok(());
        }
        if log_id.index > inner.hard_state.last_applied.index
            || log_id.index > inner.hard_state.snapshot_last_included.index
        {
            return Err(ChorusError::Protocol(
                "cannot purge beyond durable applied/snapshot progress".into(),
            ));
        }
        if entry_at(&inner.entries, log_id.index).map(|entry| entry.log_id) != Some(log_id) {
            return Err(ChorusError::Protocol(
                "purge boundary is absent from the durable consensus log".into(),
            ));
        }
        let next_hard = HardState {
            purged_through: log_id,
            ..inner.hard_state.clone()
        };
        // Publish the logical purge boundary before rewriting the log file.
        // If the process dies after this fsync, reopen validates and removes
        // the now-redundant retained prefix. The reverse order could make a
        // crash look like unexplained committed-log loss.
        if let Err(error) = persist_hard(&inner.hard_path, &next_hard) {
            return Err(poison(&mut inner, error));
        }
        inner.hard_state = next_hard;
        let keep = inner
            .entries
            .iter()
            .filter(|entry| entry.log_id.index > log_id.index)
            .cloned()
            .collect::<Vec<_>>();
        if let Err(error) = rewrite_entries(&inner.entries_path, &keep) {
            return Err(poison(&mut inner, error));
        }
        inner.entries = keep;
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, LogInner>> {
        self.inner
            .lock()
            .map_err(|_| ChorusError::Storage("consensus log lock poisoned".into()))
    }

    fn lock_mut(&self) -> Result<std::sync::MutexGuard<'_, LogInner>> {
        self.lock()
    }

    fn ensure_healthy(&self, inner: &LogInner) -> Result<()> {
        if let Some(reason) = &inner.unhealthy {
            return Err(ChorusError::Storage(format!(
                "consensus log is unhealthy: {reason}"
            )));
        }
        Ok(())
    }
}

fn entry_at(entries: &[ConsensusLogEntry], index: u64) -> Option<&ConsensusLogEntry> {
    entries
        .binary_search_by_key(&index, |entry| entry.log_id.index)
        .ok()
        .map(|position| &entries[position])
}

fn validate_identity(cluster_id: [u8; 16], cluster_incarnation: u64) -> Result<()> {
    if cluster_id == [0; 16] || cluster_incarnation == 0 {
        return Err(ChorusError::Protocol(
            "consensus log requires a nonzero cluster identity and incarnation".into(),
        ));
    }
    Ok(())
}

fn validate_progress_log_id(log_id: LogId) -> Result<()> {
    if (log_id.index == 0) != (log_id == LogId::ZERO) || (log_id.index != 0 && log_id.term == 0) {
        return Err(ChorusError::Protocol(
            "consensus progress requires LogId::ZERO or a nonzero term and index".into(),
        ));
    }
    Ok(())
}

/// Validate every complete physical frame before dropping a prefix that a
/// previously-fsynced `purged_through` marker already makes redundant.
fn validate_physical_entries(hard: &HardState, entries: &[ConsensusLogEntry]) -> Result<()> {
    let mut previous: Option<LogId> = None;
    for entry in entries {
        if entry.cluster_id != hard.cluster_id
            || entry.cluster_incarnation != hard.cluster_incarnation
        {
            return Err(ChorusError::Protocol(
                "consensus entry belongs to another cluster or incarnation".into(),
            ));
        }
        if entry.log_id.index == 0 || entry.log_id.term == 0 {
            return Err(ChorusError::Protocol(
                "consensus entry has a zero term or index".into(),
            ));
        }
        if let Some(prior) = previous {
            let expected = prior
                .index
                .checked_add(1)
                .ok_or_else(|| ChorusError::Limit("consensus log index exhausted".into()))?;
            if entry.log_id.index != expected {
                return Err(ChorusError::Protocol(format!(
                    "physical consensus log gap after index {}",
                    prior.index
                )));
            }
            if entry.log_id.term < prior.term {
                return Err(ChorusError::Protocol("consensus log term regressed".into()));
            }
        }
        previous = Some(entry.log_id);
    }
    if let Some(first) = entries.first() {
        let latest_safe_start = hard
            .purged_through
            .index
            .checked_add(1)
            .ok_or_else(|| ChorusError::Limit("purged log index exhausted".into()))?;
        if first.log_id.index > latest_safe_start {
            return Err(ChorusError::Protocol(format!(
                "physical consensus log starts after required index {latest_safe_start}"
            )));
        }
    }
    if hard.purged_through.index != 0
        && let Some(entry) = entry_at(entries, hard.purged_through.index)
        && entry.log_id != hard.purged_through
    {
        return Err(ChorusError::Protocol(
            "retained purge-boundary frame has a different term".into(),
        ));
    }
    Ok(())
}

fn validate_log(hard: &HardState, entries: &[ConsensusLogEntry]) -> Result<()> {
    validate_identity(hard.cluster_id, hard.cluster_incarnation)?;
    if hard.voted_for == Some(0) {
        return Err(ChorusError::Protocol(
            "hard state contains an invalid vote node id".into(),
        ));
    }
    if hard.current_term == 0 && hard.voted_for.is_some() {
        return Err(ChorusError::Protocol(
            "hard state cannot record a vote in term zero".into(),
        ));
    }
    for marker in [
        hard.last_applied,
        hard.snapshot_last_included,
        hard.purged_through,
    ] {
        if (marker.index == 0) != (marker == LogId::ZERO) {
            return Err(ChorusError::Protocol(
                "hard-state zero-index markers must use LogId::ZERO".into(),
            ));
        }
        if marker.term > hard.current_term {
            return Err(ChorusError::Protocol(
                "hard-state marker term exceeds current term".into(),
            ));
        }
    }
    if hard.last_applied.index > hard.commit_index
        || hard.snapshot_last_included.index > hard.last_applied.index
        || hard.purged_through.index > hard.snapshot_last_included.index
    {
        return Err(ChorusError::Protocol(
            "hard state has impossible commit/application boundaries".into(),
        ));
    }
    let mut expected = hard
        .purged_through
        .index
        .checked_add(1)
        .or_else(|| entries.is_empty().then_some(u64::MAX))
        .ok_or_else(|| ChorusError::Limit("purged log index exhausted".into()))?;
    let mut previous_term = hard.purged_through.term;
    for entry in entries {
        if entry.cluster_id != hard.cluster_id
            || entry.cluster_incarnation != hard.cluster_incarnation
        {
            return Err(ChorusError::Protocol(
                "consensus entry identity does not match hard state".into(),
            ));
        }
        if entry.log_id.index != expected {
            return Err(ChorusError::Protocol(format!(
                "consensus log gap: expected index {expected}, got {}",
                entry.log_id.index
            )));
        }
        if entry.log_id.term < previous_term {
            return Err(ChorusError::Protocol("consensus log term regressed".into()));
        }
        if entry.log_id.term == 0 || entry.log_id.term > hard.current_term {
            return Err(ChorusError::Protocol(
                "consensus entry term is outside durable hard state".into(),
            ));
        }
        expected = expected
            .checked_add(1)
            .ok_or_else(|| ChorusError::Limit("consensus log index exhausted".into()))?;
        previous_term = entry.log_id.term;
    }
    let last = entries
        .last()
        .map(|entry| entry.log_id.index)
        .unwrap_or(hard.purged_through.index);
    if hard.commit_index > last {
        return Err(ChorusError::Protocol(
            "hard state commit index is beyond the durable log".into(),
        ));
    }
    for (name, marker) in [
        ("snapshot", hard.snapshot_last_included),
        ("last_applied", hard.last_applied),
    ] {
        if marker.index == 0 {
            continue;
        }
        let actual = if marker.index == hard.purged_through.index {
            Some(hard.purged_through)
        } else {
            entry_at(entries, marker.index).map(|entry| entry.log_id)
        };
        if actual != Some(marker) {
            return Err(ChorusError::Protocol(format!(
                "hard state {name} marker is absent or has a different term"
            )));
        }
    }
    Ok(())
}

fn poison(inner: &mut LogInner, error: ChorusError) -> ChorusError {
    if inner.unhealthy.is_none() {
        inner.unhealthy = Some(error.to_string());
    }
    error
}

fn read_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
    let file_len = fs::metadata(path)
        .map_err(|error| ChorusError::Storage(error.to_string()))?
        .len();
    if file_len > max_bytes as u64 {
        return Err(ChorusError::Limit(format!(
            "consensus metadata exceeds {max_bytes} bytes"
        )));
    }
    let mut file = File::open(path).map_err(|error| ChorusError::Storage(error.to_string()))?;
    let mut bytes = Vec::with_capacity(file_len as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| ChorusError::Storage(error.to_string()))?;
    if bytes.len() > max_bytes {
        return Err(ChorusError::Limit(format!(
            "consensus metadata exceeds {max_bytes} bytes"
        )));
    }
    Ok(bytes)
}

fn encode_hard_state(state: &HardState) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(state)
        .map_err(|error| ChorusError::Serialization(format!("hard state encode: {error}")))?;
    encode_envelope(HARD_MAGIC, &json)
}

fn decode_hard_state(bytes: &[u8]) -> Result<HardState> {
    let json = decode_envelope(HARD_MAGIC, bytes)?;
    serde_json::from_slice(json)
        .map_err(|error| ChorusError::Serialization(format!("hard state decode: {error}")))
}

fn encode_entry(entry: &ConsensusLogEntry) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(entry)
        .map_err(|error| ChorusError::Serialization(format!("log entry encode: {error}")))?;
    let frame = encode_envelope(LOG_MAGIC, &json)?;
    if frame.len() > MAX_FRAME_BYTES {
        return Err(ChorusError::Limit(
            "consensus log entry exceeds 8 MiB".into(),
        ));
    }
    Ok(frame)
}

fn encode_envelope(magic: &[u8], json: &[u8]) -> Result<Vec<u8>> {
    let length = u32::try_from(json.len())
        .map_err(|_| ChorusError::Limit("consensus frame exceeds u32".into()))?;
    let mut out = Vec::with_capacity(magic.len() + 1 + 4 + json.len() + 32);
    out.extend_from_slice(magic);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(json);
    out.extend_from_slice(&chorus_codec::hash32(json));
    Ok(out)
}

fn decode_envelope<'a>(magic: &[u8], bytes: &'a [u8]) -> Result<&'a [u8]> {
    let header_len = magic.len() + 1 + 4;
    if bytes.len() < header_len + 32 || &bytes[..magic.len()] != magic {
        return Err(ChorusError::Serialization(
            "consensus envelope magic or length is invalid".into(),
        ));
    }
    if bytes[magic.len()] != FORMAT_VERSION {
        return Err(ChorusError::Serialization(format!(
            "unsupported consensus envelope version {}",
            bytes[magic.len()]
        )));
    }
    let length_at = magic.len() + 1;
    let length = u32::from_be_bytes(
        bytes[length_at..length_at + 4]
            .try_into()
            .map_err(|_| ChorusError::Serialization("invalid consensus length".into()))?,
    ) as usize;
    let data_start = header_len;
    let data_end = data_start
        .checked_add(length)
        .ok_or_else(|| ChorusError::Limit("consensus envelope length exhausted".into()))?;
    if data_end + 32 != bytes.len() {
        return Err(ChorusError::Serialization(
            "consensus envelope length mismatch".into(),
        ));
    }
    let json = &bytes[data_start..data_end];
    if chorus_codec::hash32(json) != bytes[data_end..] {
        return Err(ChorusError::Serialization(
            "consensus envelope checksum mismatch".into(),
        ));
    }
    Ok(json)
}

fn persist_hard(path: &Path, state: &HardState) -> Result<()> {
    let bytes = encode_hard_state(state)?;
    let tmp = path.with_extension("hard.tmp");
    write_synced_file(&tmp, &bytes)?;
    fs::rename(&tmp, path).map_err(|error| ChorusError::Storage(error.to_string()))?;
    sync_parent(path)
}

fn append_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = usable_parent(path) {
        fs::create_dir_all(parent).map_err(|error| ChorusError::Storage(error.to_string()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| ChorusError::Storage(error.to_string()))?;
    file.write_all(bytes)
        .map_err(|error| ChorusError::Storage(error.to_string()))?;
    file.sync_all()
        .map_err(|error| ChorusError::Storage(error.to_string()))?;
    sync_parent(path)
}

fn write_synced_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = usable_parent(path) {
        fs::create_dir_all(parent).map_err(|error| ChorusError::Storage(error.to_string()))?;
    }
    let mut file = File::create(path).map_err(|error| ChorusError::Storage(error.to_string()))?;
    file.write_all(bytes)
        .map_err(|error| ChorusError::Storage(error.to_string()))?;
    file.sync_all()
        .map_err(|error| ChorusError::Storage(error.to_string()))
}

fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = usable_parent(path) {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| ChorusError::Storage(error.to_string()))?;
    }
    Ok(())
}

fn usable_parent(path: &Path) -> Option<&Path> {
    match path.parent() {
        Some(parent) if parent.as_os_str().is_empty() => Some(Path::new(".")),
        parent => parent,
    }
}

fn truncate_file(path: &Path, length: u64) -> Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|error| ChorusError::Storage(error.to_string()))?;
    file.set_len(length)
        .map_err(|error| ChorusError::Storage(error.to_string()))?;
    file.sync_all()
        .map_err(|error| ChorusError::Storage(error.to_string()))?;
    sync_parent(path)
}

fn rewrite_entries(path: &Path, entries: &[ConsensusLogEntry]) -> Result<()> {
    let mut bytes = Vec::new();
    for entry in entries {
        bytes.extend_from_slice(&encode_entry(entry)?);
    }
    if bytes.len() > MAX_LOG_BYTES {
        return Err(ChorusError::Limit("consensus log exceeds 256 MiB".into()));
    }
    let tmp = path.with_extension("rewrite.tmp");
    write_synced_file(&tmp, &bytes)?;
    fs::rename(&tmp, path).map_err(|error| ChorusError::Storage(error.to_string()))?;
    sync_parent(path)
}

fn read_entries(path: &Path) -> Result<(Vec<ConsensusLogEntry>, u64)> {
    if !path.exists() {
        return Ok((Vec::new(), 0));
    }
    let bytes = read_file(path, MAX_LOG_BYTES)?;
    let header_len = LOG_MAGIC.len() + 1 + 4;
    let mut cursor = 0usize;
    let mut entries = Vec::new();
    while cursor < bytes.len() {
        let remaining = bytes.len() - cursor;
        if remaining < header_len {
            return Ok((entries, cursor as u64));
        }
        if &bytes[cursor..cursor + LOG_MAGIC.len()] != LOG_MAGIC {
            return Err(ChorusError::Serialization(
                "consensus log magic mismatch".into(),
            ));
        }
        let version_at = cursor + LOG_MAGIC.len();
        if bytes[version_at] != FORMAT_VERSION {
            return Err(ChorusError::Serialization(
                "unsupported consensus log version".into(),
            ));
        }
        let length_at = version_at + 1;
        let length = u32::from_be_bytes(
            bytes[length_at..length_at + 4]
                .try_into()
                .map_err(|_| ChorusError::Serialization("invalid consensus log length".into()))?,
        ) as usize;
        let frame_len = header_len
            .checked_add(length)
            .and_then(|value| value.checked_add(32))
            .ok_or_else(|| ChorusError::Limit("consensus frame length exhausted".into()))?;
        if frame_len > MAX_FRAME_BYTES {
            return Err(ChorusError::Limit("consensus frame exceeds 8 MiB".into()));
        }
        if remaining < frame_len {
            return Ok((entries, cursor as u64));
        }
        let frame = &bytes[cursor..cursor + frame_len];
        let json = decode_envelope(LOG_MAGIC, frame)?;
        let entry = serde_json::from_slice(json).map_err(|error| {
            ChorusError::Serialization(format!("consensus log entry decode: {error}"))
        })?;
        entries.push(entry);
        cursor += frame_len;
    }
    Ok((entries, cursor as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chorus_codec::ReplicatedCommandV1;
    use std::time::{SystemTime, UNIX_EPOCH};

    const CLUSTER_ID: [u8; 16] = [0x2a; 16];
    const INCARNATION: u64 = 7;

    fn temp_path(label: &str) -> (PathBuf, PathBuf) {
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("chorus-consensus-log-{label}-{id}"));
        fs::create_dir_all(&root).unwrap();
        (root.join("entries.log"), root)
    }

    fn open(path: &Path) -> DurableConsensusLog {
        DurableConsensusLog::open_with_identity(path, CLUSTER_ID, INCARNATION).unwrap()
    }

    fn entry(index: u64) -> ConsensusLogEntry {
        ConsensusLogEntry {
            cluster_id: CLUSTER_ID,
            cluster_incarnation: INCARNATION,
            log_id: LogId { term: 1, index },
            command: ReplicatedCommandV1::Noop,
        }
    }

    #[test]
    fn hard_state_and_committed_replay_survive_reopen() {
        let (path, root) = temp_path("reopen");
        let log = open(&path);
        assert!(path.with_extension("hard").exists());
        log.set_term_and_vote(1, Some(1)).unwrap();
        log.append(&[entry(1), entry(2)]).unwrap();
        log.set_commit_index(2).unwrap();
        assert_eq!(
            log.replay_committed()
                .unwrap()
                .iter()
                .map(|entry| entry.log_id.index)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        drop(log);
        let reopened = open(&path);
        assert_eq!(reopened.hard_state().unwrap().current_term, 1);
        assert_eq!(reopened.hard_state().unwrap().voted_for, Some(1));
        assert_eq!(reopened.replay_committed().unwrap().len(), 2);
        reopened.mark_applied(LogId { term: 1, index: 2 }).unwrap();
        drop(reopened);
        let fully_applied = open(&path);
        assert!(fully_applied.replay_committed().unwrap().is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn torn_final_frame_is_discarded_but_valid_prefix_replays() {
        let (path, root) = temp_path("torn");
        let log = open(&path);
        log.set_term_and_vote(1, None).unwrap();
        log.append(&[entry(1)]).unwrap();
        let mut foreign_entry = entry(2);
        foreign_entry.cluster_id = [0x55; 16];
        assert!(matches!(
            log.append(&[foreign_entry]),
            Err(ChorusError::Protocol(_))
        ));
        drop(log);
        let valid_len = fs::metadata(&path).unwrap().len();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        let torn = encode_entry(&entry(2)).unwrap();
        file.write_all(&torn[..torn.len() / 2]).unwrap();
        file.sync_all().unwrap();
        let reopened = open(&path);
        assert_eq!(reopened.last_log_id().unwrap().index, 1);
        assert_eq!(fs::metadata(&path).unwrap().len(), valid_len);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn identity_mismatch_and_complete_checksum_corruption_fail_closed() {
        let (path, root) = temp_path("identity-corruption");
        let log = open(&path);
        log.set_term_and_vote(1, None).unwrap();
        log.append(&[entry(1)]).unwrap();
        drop(log);

        assert!(matches!(
            DurableConsensusLog::open_with_identity(&path, [0x55; 16], INCARNATION),
            Err(ChorusError::Protocol(_))
        ));
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 0xff;
        let mut file = File::create(&path).unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        assert!(matches!(
            DurableConsensusLog::open_with_identity(&path, CLUSTER_ID, INCARNATION),
            Err(ChorusError::Serialization(_))
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn progress_markers_reject_malformed_log_ids() {
        let (path, root) = temp_path("progress-id");
        let log = open(&path);
        for malformed in [LogId { term: 1, index: 0 }, LogId { term: 0, index: 1 }] {
            assert!(matches!(
                log.mark_applied(malformed),
                Err(ChorusError::Protocol(_))
            ));
            assert!(matches!(
                log.install_snapshot_marker(malformed),
                Err(ChorusError::Protocol(_))
            ));
            assert!(matches!(
                log.purge_through(malformed),
                Err(ChorusError::Protocol(_))
            ));
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn suffix_truncation_cannot_remove_committed_entries() {
        let (path, root) = temp_path("truncate");
        let log = open(&path);
        log.set_term_and_vote(1, None).unwrap();
        log.append(&[entry(1), entry(2), entry(3)]).unwrap();
        log.set_commit_index(2).unwrap();
        assert!(matches!(
            log.truncate_suffix(2),
            Err(ChorusError::Protocol(_))
        ));
        log.truncate_suffix(3).unwrap();
        assert_eq!(log.last_log_id().unwrap().index, 2);
        drop(log);
        let reopened = open(&path);
        reopened.append(&[entry(3)]).unwrap();
        assert_eq!(reopened.last_log_id().unwrap().index, 3);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn purge_requires_applied_snapshot_and_survives_marker_rewrite_window() {
        let (path, root) = temp_path("purge");
        let log = open(&path);
        log.set_term_and_vote(1, None).unwrap();
        log.append(&[entry(1), entry(2), entry(3)]).unwrap();
        log.set_commit_index(3).unwrap();
        log.mark_applied(LogId { term: 1, index: 2 }).unwrap();
        assert!(log.purge_through(LogId { term: 1, index: 1 }).is_err());
        log.install_snapshot_marker(LogId { term: 1, index: 2 })
            .unwrap();
        drop(log);
        let log = open(&path);
        assert_eq!(
            log.read_range(1, 3, false)
                .unwrap()
                .iter()
                .map(|entry| entry.log_id.index)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );

        // Model a crash after publishing `purged_through` but before the log
        // rewrite. Reopen must accept, validate, and remove retained frames
        // at or below the durable marker.
        {
            let mut inner = log.inner.lock().unwrap();
            let next = HardState {
                purged_through: LogId { term: 1, index: 1 },
                ..inner.hard_state.clone()
            };
            persist_hard(&inner.hard_path, &next).unwrap();
            inner.hard_state = next;
        }
        drop(log);
        let reopened = open(&path);
        assert_eq!(reopened.hard_state().unwrap().purged_through.index, 1);
        assert_eq!(reopened.last_log_id().unwrap().index, 3);
        assert_eq!(
            reopened
                .read_range(2, 3, false)
                .unwrap()
                .iter()
                .map(|entry| entry.log_id.index)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        reopened.purge_through(LogId { term: 1, index: 2 }).unwrap();
        drop(reopened);
        let purged = open(&path);
        assert_eq!(purged.hard_state().unwrap().purged_through.index, 2);
        purged.append(&[entry(4)]).unwrap();
        assert_eq!(purged.last_log_id().unwrap().index, 4);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn committed_range_never_silently_skips_a_missing_entry() {
        let (path, root) = temp_path("gap-read");
        let log = open(&path);
        log.set_term_and_vote(1, None).unwrap();
        log.append(&[entry(1), entry(2)]).unwrap();
        log.set_commit_index(2).unwrap();
        log.inner.lock().unwrap().entries.remove(0);
        assert!(matches!(
            log.read_range(1, 2, true),
            Err(ChorusError::Storage(_))
        ));
        let _ = fs::remove_dir_all(root);
    }
}
