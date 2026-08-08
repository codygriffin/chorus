use chorus_common::{Datum, Limits, OriginId};
use chorus_sql::{CancellationChecker, SqlEngine};
use chorus_storage::{MemoryStateStore, StateStore};
use chorus_txn::{Committer, LocalCommitter};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

struct CancelAfter {
    checks: AtomicUsize,
    cancel_after: usize,
}

impl CancelAfter {
    fn new(cancel_after: usize) -> Self {
        Self {
            checks: AtomicUsize::new(0),
            cancel_after,
        }
    }
}

impl CancellationChecker for CancelAfter {
    fn is_cancelled(&self) -> bool {
        self.checks.fetch_add(1, Ordering::AcqRel) + 1 >= self.cancel_after
    }
}

#[test]
fn cancellation_rolls_back_partially_staged_implicit_write() {
    let store: Arc<dyn StateStore> = Arc::new(MemoryStateStore::new());
    let committer: Arc<dyn Committer> =
        Arc::new(LocalCommitter::new(store.clone(), OriginId::new(91)).expect("local committer"));
    let engine = SqlEngine::new(store, committer, Limits::default());
    let mut session = engine.session();
    session
        .execute(
            "CREATE TABLE cancellation_rows (id integer primary key);",
            &[],
        )
        .unwrap();

    // The first row reaches the transaction overlay.  The next row's
    // checkpoint cancels before implicit commit, so no staged row is durable.
    // One outer statement checkpoint plus one checkpoint for the first row
    // precede the cancellation checkpoint for the second row.
    let checker = Arc::new(CancelAfter::new(3));
    session.set_cancellation_checker(Some(checker.clone()));
    let error = session
        .execute("INSERT INTO cancellation_rows VALUES (1),(2),(3);", &[])
        .expect_err("the deterministic checker should cancel the write");
    assert_eq!(error.code, "57014");
    assert_eq!(checker.checks.load(Ordering::Acquire), 3);

    session.set_cancellation_checker(None);
    let result = session
        .execute("SELECT id FROM cancellation_rows ORDER BY id;", &[])
        .unwrap();
    assert_eq!(result.rows, Vec::<Vec<Datum>>::new());
}
