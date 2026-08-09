use chorus_codec::{ApplyResult, CommitTransactionV1, SchemaCommandV1};
use chorus_common::{Datum, OriginId};
use chorus_sql::SqlEngine;
use chorus_storage::{MemoryStateStore, StateSnapshot, StateStore};
use chorus_txn::{Committer, LocalCommitter};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

struct SlowCommitter {
    inner: LocalCommitter,
    read_delay: Duration,
    submit_delay: Duration,
    reads: AtomicUsize,
    writes: AtomicUsize,
}

impl SlowCommitter {
    fn new(
        store: Arc<dyn StateStore>,
        origin: OriginId,
        read_delay: Duration,
        submit_delay: Duration,
    ) -> Self {
        Self {
            inner: LocalCommitter::new(store, origin).expect("local committer"),
            read_delay,
            submit_delay,
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
        }
    }
}

impl Committer for SlowCommitter {
    fn read_barrier(&self) -> chorus_common::Result<StateSnapshot> {
        self.reads.fetch_add(1, Ordering::AcqRel);
        if !self.read_delay.is_zero() {
            thread::sleep(self.read_delay);
        }
        self.inner.read_barrier()
    }

    fn submit(&self, command: CommitTransactionV1) -> chorus_common::Result<ApplyResult> {
        self.writes.fetch_add(1, Ordering::AcqRel);
        if !self.submit_delay.is_zero() {
            thread::sleep(self.submit_delay);
        }
        self.inner.submit(command)
    }

    fn submit_schema(&self, command: SchemaCommandV1) -> chorus_common::Result<ApplyResult> {
        self.inner.submit_schema(command)
    }

    fn origin(&self) -> OriginId {
        self.inner.origin()
    }
}

fn engine_with_delays(
    read_delay: Duration,
    submit_delay: Duration,
) -> (
    Arc<dyn StateStore>,
    Arc<SlowCommitter>,
    Arc<chorus_sql::SqlEngine>,
) {
    let store: Arc<dyn StateStore> = Arc::new(MemoryStateStore::new());
    let committer = Arc::new(SlowCommitter::new(
        Arc::clone(&store),
        OriginId::new(1),
        read_delay,
        submit_delay,
    ));
    let engine = SqlEngine::new(
        Arc::clone(&store),
        committer.clone(),
        chorus_common::Limits::default(),
    );
    (store, committer, engine)
}

#[test]
fn timeout_after_slow_read_barrier_prevents_submit_and_rolls_back_implicit_work() {
    let (_store, committer, engine) = engine_with_delays(Duration::from_millis(40), Duration::ZERO);
    let mut session = engine.session();
    session.set_param("statement_timeout", "5").unwrap();

    let error = session
        .execute("SELECT 1", &[])
        .expect_err("the delayed read barrier must exhaust the statement budget");
    assert_eq!(error.code, "57014");
    assert_eq!(
        error.message,
        "canceling statement due to statement timeout"
    );
    assert_eq!(committer.reads.load(Ordering::Acquire), 1);
    assert_eq!(committer.writes.load(Ordering::Acquire), 0);
    assert_eq!(
        session.transaction_status(),
        chorus_txn::TransactionStatus::Aborted
    );
}

#[test]
fn show_reset_and_zero_statement_timeout_are_supported_and_bounded() {
    let (_store, _committer, engine) = engine_with_delays(Duration::ZERO, Duration::ZERO);
    let mut session = engine.session();

    assert_eq!(
        session.execute("SHOW statement_timeout", &[]).unwrap().rows[0][0],
        Datum::Text("0".into())
    );
    session.execute("SET statement_timeout = 12", &[]).unwrap();
    assert_eq!(
        session.execute("SHOW statement_timeout", &[]).unwrap().rows[0][0],
        Datum::Text("12".into())
    );
    session.execute("RESET statement_timeout", &[]).unwrap();
    assert_eq!(
        session.execute("SHOW statement_timeout", &[]).unwrap().rows[0][0],
        Datum::Text("0".into())
    );
    session
        .execute("SET statement_timeout = 18446744073709551615", &[])
        .unwrap();
    let next = std::panic::catch_unwind(AssertUnwindSafe(|| {
        session.execute("SHOW statement_timeout", &[])
    }))
    .expect("checked deadline construction must never panic");
    if let Err(error) = next {
        assert_eq!(error.code, "22023");
    }
}

#[test]
fn successful_submit_is_not_relabelled_when_it_finishes_after_timeout() {
    let (store, committer, engine) = engine_with_delays(Duration::ZERO, Duration::from_millis(120));
    let mut session = engine.session();
    session
        .execute("CREATE TABLE timeout_commit (id integer primary key);", &[])
        .unwrap();
    session.set_param("statement_timeout", "50").unwrap();

    let result = session.execute("INSERT INTO timeout_commit VALUES (1)", &[]);
    assert!(
        result.is_ok(),
        "a submission that started before the deadline keeps its result"
    );
    session.set_param("statement_timeout", "0").unwrap();
    let rows = session
        .execute("SELECT id FROM timeout_commit", &[])
        .unwrap()
        .rows;
    assert_eq!(rows.len(), 1);
    assert_eq!(committer.writes.load(Ordering::Acquire), 1);
    assert_eq!(store.snapshot().unwrap().db_epoch(), 2);
}
