use chorus_codec::ReplicatedCommandV1;
use chorus_common::LogId;
use chorus_raft_contract::{InternalRaftLog, entry};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const CLUSTER: [u8; 16] = [0x42; 16];
const INCARNATION: u64 = 9;

fn temp_path(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "chorus-raft-contract-{}-{}-{}.log",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
        label
    ))
}

fn clean(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("hard"));
}

fn noop(term: u64, index: u64) -> chorus_storage::consensus_log::ConsensusLogEntry {
    entry(CLUSTER, INCARNATION, term, index, ReplicatedCommandV1::Noop)
}

#[test]
fn term_vote_commit_reopen_and_replay_committed_entries() {
    let path = temp_path("replay");
    clean(&path);
    {
        let log = InternalRaftLog::open(&path, CLUSTER, INCARNATION).unwrap();
        log.save_vote(3, Some(7)).unwrap();
        log.append(&[noop(3, 1), noop(3, 2), noop(3, 3)]).unwrap();
        log.commit(2).unwrap();
        let report = log.readiness().unwrap();
        assert!(report.durable_primitives_ready());
        assert!(!report.release_ready());
        assert!(matches!(
            report.openraft_runtime,
            chorus_raft_contract::Capability::Blocked(_)
        ));
    }

    let reopened = InternalRaftLog::open(&path, CLUSTER, INCARNATION).unwrap();
    let state = reopened.hard_state().unwrap();
    assert_eq!(state.current_term, 3);
    assert_eq!(state.voted_for, Some(7));
    assert_eq!(state.commit_index, 2);
    assert_eq!(
        reopened.replay_committed().unwrap(),
        vec![noop(3, 1), noop(3, 2)]
    );
    assert_eq!(
        reopened.committed_range(1, 3).unwrap(),
        vec![noop(3, 1), noop(3, 2)]
    );
    clean(&path);
}

#[test]
fn replace_uncommitted_suffix_and_reject_committed_truncation() {
    let path = temp_path("suffix");
    clean(&path);
    let log = InternalRaftLog::open(&path, CLUSTER, INCARNATION).unwrap();
    log.save_vote(1, Some(7)).unwrap();
    log.append(&[noop(1, 1), noop(1, 2), noop(1, 3), noop(1, 4)])
        .unwrap();
    log.commit(2).unwrap();

    log.replace_uncommitted_suffix(4, &[noop(1, 4), noop(1, 5)])
        .unwrap();
    assert_eq!(
        log.durable_log().last_log_id().unwrap(),
        LogId { term: 1, index: 5 }
    );
    assert_eq!(
        log.durable_log().read_range(3, 5, false).unwrap(),
        vec![noop(1, 3), noop(1, 4), noop(1, 5)]
    );
    assert!(log.replace_uncommitted_suffix(2, &[noop(1, 2)]).is_err());
    assert!(log.reject_committed_truncation(2).is_err());
    clean(&path);
}
