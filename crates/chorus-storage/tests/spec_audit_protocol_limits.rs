use chorus_codec::{CommitTransactionV1, KvMutationV1, ReplicatedCommandV1, encode_command};
use chorus_common::{OriginId, RequestId};

#[test]
fn command_codec_rejects_oversized_user_payloads_before_replication() {
    let origin = OriginId::new(1);
    let command = ReplicatedCommandV1::CommitTransaction(CommitTransactionV1 {
        request_id: RequestId::new(origin, 1),
        payload_hash: [0; 32],
        base_epoch: 0,
        mutations: vec![KvMutationV1::Put {
            key: b"bounded-key".to_vec(),
            value: vec![b'x'; 16 * 1024 * 1024 + 1],
        }],
    });

    // Peer RPC frames are capped at 16 MiB.  Encoding a command above that
    // limit must fail at the command boundary rather than creating an
    // unbounded frame that a follower has to allocate and parse.
    assert!(encode_command(&command).is_err());
}
