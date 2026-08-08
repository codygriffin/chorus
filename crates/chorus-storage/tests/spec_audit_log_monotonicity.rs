use chorus_codec::{ActivateOriginV1, ReplicatedCommandV1};
use chorus_common::{LogId, OriginId};
use chorus_storage::{MemoryStateStore, StateStore};

#[test]
fn applying_a_stale_noop_cannot_move_last_applied_backwards() {
    let store = MemoryStateStore::new();
    let origin = OriginId::new(1);
    store
        .apply(
            LogId { term: 4, index: 10 },
            &ReplicatedCommandV1::ActivateOrigin(ActivateOriginV1 { origin }),
        )
        .unwrap();
    assert_eq!(
        store.snapshot().unwrap().last_applied(),
        LogId { term: 4, index: 10 }
    );

    // Replay can deliver an old no-op after a restart or a duplicate log
    // response.  The state-machine cursor is part of the durable consensus
    // state and must remain monotonic even for Noop entries.
    store
        .apply(LogId { term: 3, index: 9 }, &ReplicatedCommandV1::Noop)
        .unwrap();
    assert_eq!(
        store.snapshot().unwrap().last_applied(),
        LogId { term: 4, index: 10 }
    );
}
