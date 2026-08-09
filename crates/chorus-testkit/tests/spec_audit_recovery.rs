use chorus_codec::{
    ActivateOriginV1, ApplyResult, CommitTransactionV1, KvMutationV1, ReplicatedCommandV1,
    canonical_mutations, payload_hash,
};
use chorus_common::{ChorusError, LogId, OriginId, RequestId};
use chorus_storage::{FileStateStore, StateStore};
use chorus_testkit::{FaultPlan, FaultPoint, FaultingStore, fingerprint, recover_file_store};
use std::fs;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_root() -> std::path::PathBuf {
    static NEXT_ID: OnceLock<AtomicU64> = OnceLock::new();
    let sequence = NEXT_ID
        .get_or_init(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "chorus-testkit-recovery-{}-{nanos}-{sequence}",
        std::process::id()
    ))
}

fn commit_command(origin: OriginId) -> CommitTransactionV1 {
    let request_id = RequestId::new(origin, 1);
    let mutation = KvMutationV1::Put {
        // Short metadata keys avoid requiring a catalog/table setup in this
        // storage-level recovery gate.
        key: b"k".to_vec(),
        value: b"durable-value".to_vec(),
    };
    let canonical = canonical_mutations(std::slice::from_ref(&mutation)).unwrap();
    CommitTransactionV1 {
        request_id,
        payload_hash: payload_hash(1, &request_id, 0, &canonical),
        base_epoch: 0,
        mutations: vec![mutation],
    }
}

#[test]
fn post_apply_fault_reopens_to_one_deterministic_state_and_deduplicates_retry() {
    let root = unique_temp_root();
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let path = root.join("state");

    let file = Arc::new(FileStateStore::open(&path).unwrap());
    file.initialize_cluster([1; 16], 1).unwrap();
    let base = file.clone() as Arc<dyn StateStore>;
    // FileStateStore's bootstrap membership contains node 1.  Keep the
    // recovery scenario focused on durable apply/retry behavior by using the
    // authorized origin instead of requiring a separate membership command.
    let origin = OriginId::new(1);
    base.apply(
        LogId { term: 1, index: 1 },
        &ReplicatedCommandV1::ActivateOrigin(ActivateOriginV1 { origin }),
    )
    .unwrap();
    let before = fingerprint(base.as_ref()).unwrap();

    let plan = FaultPlan::new();
    // The activation is intentionally applied through the base store before
    // wrapping it, so the commit is the first call observed by the plan.
    plan.fail_once_at(1, FaultPoint::AfterApply).unwrap();
    let faulting = FaultingStore::new(base.clone(), plan.clone());
    let command = commit_command(origin);
    let error = faulting
        .apply(
            LogId { term: 1, index: 2 },
            &ReplicatedCommandV1::CommitTransaction(command.clone()),
        )
        .unwrap_err();
    match error {
        ChorusError::Storage(message) => {
            assert_eq!(message, "testkit fault at AfterApply on apply call 1")
        }
        other => panic!("expected injected AfterApply fault, got {other:?}"),
    }
    assert_eq!(plan.apply_calls().unwrap(), 1);

    // The wrapper reports a lost response, but FileStateStore published the
    // state before the injected post-apply fault.  Reopening must observe the
    // same state, not a partially applied generation.
    let recovered = recover_file_store(&path).unwrap();
    let after_fault = fingerprint(recovered.as_ref()).unwrap();
    assert_ne!(before, after_fault);
    assert_eq!(after_fault.db_epoch, 1);
    assert_eq!(
        recovered.snapshot().unwrap().get(b"k"),
        Some(&b"durable-value"[..])
    );

    let duplicate = recovered
        .apply(
            LogId { term: 1, index: 3 },
            &ReplicatedCommandV1::CommitTransaction(command),
        )
        .unwrap();
    assert!(matches!(duplicate, ApplyResult::Duplicate(_)));
    assert_eq!(recovered.snapshot().unwrap().db_epoch(), 1);

    let reopened_again = recover_file_store(&path).unwrap();
    assert_eq!(
        fingerprint(recovered.as_ref()).unwrap(),
        fingerprint(reopened_again.as_ref()).unwrap()
    );
    let _ = fs::remove_dir_all(root);
}
