use chorus_codec::{NodeOriginState, PhysicalKey, ReplicatedCommandV1};
use chorus_common::{LogId, OriginId, SqlType};
use chorus_storage::{
    Catalog, ColumnDescriptor, ColumnState, IndexColumn, IndexDescriptor, Membership,
    MemoryStateStore, ObjectState, StateData, StateStore, TableDescriptor, snapshot_from_store,
};
use std::collections::BTreeMap;

fn hash(data: StateData) -> [u8; 32] {
    MemoryStateStore::from_data(data).state_hash().unwrap()
}

fn table(oid: u32, state: ObjectState) -> TableDescriptor {
    TableDescriptor {
        oid,
        schema_oid: 2200,
        name: format!("table_{oid}"),
        schema_version: 1,
        columns: vec![ColumnDescriptor {
            id: oid + 1,
            name: "id".into(),
            data_type: SqlType::Integer,
            nullable: false,
            default: None,
            state: ColumnState::Live,
        }],
        primary_key: Some(oid + 1),
        secondary_indexes: Vec::new(),
        row_count: 0,
        state,
    }
}

#[test]
fn hash_ignores_cluster_binding_and_log_cursor_but_detects_logical_changes() {
    let mut base = StateData::default();
    base.cluster_id = [1; 16];
    base.cluster_incarnation = 4;
    base.last_applied = LogId { term: 2, index: 9 };
    let baseline = hash(base.clone());

    let mut relocated = base.clone();
    relocated.cluster_id = [9; 16];
    relocated.cluster_incarnation = 77;
    relocated.last_applied = LogId {
        term: 10,
        index: 500,
    };
    assert_eq!(baseline, hash(relocated));

    let noop_store = MemoryStateStore::from_data(base.clone());
    noop_store
        .apply(LogId { term: 2, index: 10 }, &ReplicatedCommandV1::Noop)
        .unwrap();
    assert_eq!(baseline, noop_store.state_hash().unwrap());

    let mut changed = base.clone();
    changed.db_epoch += 1;
    assert_ne!(baseline, hash(changed));

    let mut changed = base.clone();
    changed.catalog_epoch += 1;
    assert_ne!(baseline, hash(changed));

    let mut changed = base.clone();
    changed.catalog.next_object_id += 1;
    assert_ne!(baseline, hash(changed));

    let mut changed = base.clone();
    let origin = OriginId {
        node_id: 8,
        boot_nonce: [8; 16],
    };
    changed.origins.insert(
        origin.node_id,
        NodeOriginState {
            active_origin: origin,
            last_sequence: 0,
            recent_results: Vec::new(),
        },
    );
    assert_ne!(baseline, hash(changed));

    let mut changed = base.clone();
    changed.membership = Membership {
        log_id: LogId { term: 2, index: 8 },
        voters: vec![1, 2, 3],
        learners: Vec::new(),
    };
    assert_ne!(baseline, hash(changed));

    let mut changed = base;
    changed.kv.insert(b"private".to_vec(), b"value".to_vec());
    assert_ne!(baseline, hash(changed));
}

#[test]
fn dropped_object_bytes_and_redundant_catalog_keys_do_not_change_hash() {
    let table_id = 100u32;
    let index_id = 200u32;
    let mut catalog = Catalog::default();
    let mut dropped_table = table(table_id, ObjectState::Dropped);
    dropped_table.secondary_indexes.push(index_id);
    catalog.tables.insert(table_id, dropped_table);
    catalog.indexes.insert(
        index_id,
        IndexDescriptor {
            oid: index_id,
            table_oid: table_id,
            name: "dropped_index".into(),
            columns: vec![IndexColumn {
                column_id: table_id + 1,
                descending: false,
            }],
            unique: false,
            state: ObjectState::Dropped,
        },
    );
    catalog.next_object_id = 300;

    let mut compacted = StateData::default();
    compacted.catalog = catalog;
    let mut retained = compacted.clone();
    retained.kv.insert(
        PhysicalKey::row(table_id, b"old-row").unwrap().0,
        b"old-value".to_vec(),
    );
    retained.kv.insert(
        PhysicalKey::index(index_id, b"old-index", b"old-row", false)
            .unwrap()
            .0,
        Vec::new(),
    );
    retained
        .kv
        .insert(PhysicalKey::table_desc(table_id).0, b"redundant".to_vec());
    assert_eq!(hash(compacted), hash(retained));

    let mut live_without_row = StateData::default();
    live_without_row
        .catalog
        .tables
        .insert(table_id, table(table_id, ObjectState::Live));
    live_without_row.catalog.next_object_id = 300;
    let mut live_with_row = live_without_row.clone();
    live_with_row.kv.insert(
        PhysicalKey::row(table_id, b"row").unwrap().0,
        b"value".to_vec(),
    );
    assert_ne!(hash(live_without_row), hash(live_with_row));
}

#[test]
fn snapshot_restore_converges_independent_of_metadata_layout() {
    let mut data = StateData::default();
    data.cluster_id = [0x44; 16];
    data.cluster_incarnation = 6;
    data.db_epoch = 3;
    data.catalog_epoch = 2;
    data.last_applied = LogId { term: 2, index: 7 };
    data.membership = Membership {
        log_id: LogId { term: 2, index: 6 },
        voters: vec![1, 2, 3],
        learners: vec![4],
    };
    data.kv = BTreeMap::from([
        (b"z-private".to_vec(), b"last".to_vec()),
        (b"a-private".to_vec(), b"first".to_vec()),
    ]);
    let source = MemoryStateStore::from_data(data);
    let snapshot = snapshot_from_store(&source).unwrap();
    let metadata: StateData = serde_json::from_slice(snapshot.meta.get("state").unwrap()).unwrap();
    assert!(metadata.kv.is_empty());

    let restored = MemoryStateStore::new();
    restored.install(&snapshot).unwrap();
    assert_eq!(source.state_hash().unwrap(), restored.state_hash().unwrap());
}
