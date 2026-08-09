#![forbid(unsafe_code)]

use chorus_admin::{
    Config, is_logical_backup, logical_backup_from_store, open_store, render_status,
    snapshot_file_within_limit, status as node_status,
};
use chorus_codec::{LogicalSnapshot, ReplicatedCommandV1};
use chorus_common::{LogId, OriginId};
use chorus_consensus::openraft_transport::{PeerTlsConfig, TransportTlsIdentity, leaf_fingerprint};
use chorus_consensus::{
    Consensus, ConsensusCommitter, NetworkConsensus, OpenRaftConsensus, OpenRaftRuntimeOptions,
    StandaloneConsensus,
};
use chorus_pg::{PgConfig, PgServer};
use chorus_sql::SqlEngine;
use chorus_storage::{Catalog, FileStateStore, StateStore};
use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

fn main() {
    if let Err(e) = dispatch(env::args().skip(1).collect()) {
        log_event("command_failed", serde_json::json!({ "error": e }));
        std::process::exit(1);
    }
}

fn dispatch(args: Vec<String>) -> Result<(), String> {
    let command = args.first().map(String::as_str).unwrap_or("run");
    let config_path = arg_value(&args, "--config").unwrap_or_else(|| "chorus.toml".into());
    match command {
        "bootstrap" => {
            let path = config_path;
            if has_flag(&args, "--openraft-mtls") {
                if !has_flag(&args, "--confirm") {
                    return Err("authenticated OpenRaft bootstrap requires --confirm".into());
                }
                if !Path::new(&path).exists() {
                    return Err(
                        "authenticated OpenRaft bootstrap requires an operator-provisioned config"
                            .into(),
                    );
                }
                let cfg = load_command_config(&args, &path, true)?;
                if cfg.node_id
                    != cfg
                        .openraft_bootstrap_node_id()
                        .map_err(|error| error.to_string())?
                {
                    return Err(
                        "only the lowest configured voter may bootstrap authenticated OpenRaft"
                            .into(),
                    );
                }
                let consensus = open_authenticated_consensus(&cfg, true)?;
                drop(consensus);
                log_event(
                    "openraft_mtls_bootstrapped",
                    serde_json::json!({ "config": path, "node_id": cfg.node_id }),
                );
                println!("bootstrapped authenticated OpenRaft {path}");
                return Ok(());
            }
            if Path::new(&path).exists() && !has_flag(&args, "--confirm") {
                return Err(format!(
                    "bootstrap refuses to overwrite existing {}; pass --confirm",
                    path
                ));
            }
            let node_id = arg_value(&args, "--node-id")
                .map(|x| x.parse().map_err(|_| "invalid --node-id".to_string()))
                .transpose()?
                .unwrap_or(1);
            let cfg = Config::defaults(
                arg_value(&args, "--data-dir").unwrap_or_else(|| "./chorus-data".into()),
                node_id,
            );
            cfg.save(&path).map_err(|e| e.to_string())?;
            let store = open_store(&cfg).map_err(|e| e.to_string())?;
            let snapshot = store.snapshot().map_err(|e| e.to_string())?;
            if snapshot.last_applied() != LogId::ZERO
                || snapshot.db_epoch() != 0
                || !snapshot.kv().is_empty()
            {
                return Err("bootstrap requires an empty durable state directory".into());
            }
            if has_flag(&args, "--openraft-single-node") {
                validate_openraft_single_node(&cfg)?;
                ensure_openraft_legacy_state_empty(&store)?;
                drop(store);
                let (raft_path, state_path) = openraft_paths(&cfg);
                validate_redb_target(&raft_path, "raft.redb")?;
                validate_redb_target(&state_path, "state/active.redb")?;
                let consensus = OpenRaftConsensus::open(
                    cfg.node_id,
                    &raft_path,
                    &state_path,
                    cfg.cluster_id().0,
                    cfg.cluster_incarnation,
                    true,
                )
                .map_err(|error| error.to_string())?;
                harden_file(&raft_path, false)?;
                harden_file(&state_path, false)?;
                drop(consensus);
                log_event(
                    "openraft_single_node_bootstrapped",
                    serde_json::json!({ "config": path, "node_id": cfg.node_id }),
                );
                println!("bootstrapped OpenRaft single-node {}", path);
                return Ok(());
            }
            let voters = cfg
                .initial_nodes
                .iter()
                .filter(|node| node.voter)
                .map(|node| node.node_id)
                .collect();
            let learners = cfg
                .initial_nodes
                .iter()
                .filter(|node| !node.voter)
                .map(|node| node.node_id)
                .collect();
            store
                .apply(
                    LogId { term: 1, index: 1 },
                    &ReplicatedCommandV1::Membership { voters, learners },
                )
                .map_err(|e| e.to_string())?;
            log_event(
                "bootstrapped",
                serde_json::json!({ "config": path, "node_id": cfg.node_id }),
            );
            println!("bootstrapped {}", path);
            Ok(())
        }
        "status" | "check" | "state-hash" | "metrics" => {
            let cfg = load_command_config(&args, &config_path, false)?;
            let store = open_store(&cfg).map_err(|e| e.to_string())?;
            match command {
                "state-hash" => {
                    println!("{}", hex(&store.state_hash().map_err(|e| e.to_string())?));
                }
                "check" => {
                    cfg.validate().map_err(|e| e.to_string())?;
                    let status = node_status(&cfg, &store, None);
                    if !status.local_ready || !status.identity_ok {
                        return Err(format!(
                            "local check failed: {}",
                            status.warnings.join("; ")
                        ));
                    }
                    println!("ok");
                }
                "metrics" => {
                    let status = node_status(&cfg, &store, None);
                    println!("{}", render_status(&status));
                }
                _ => println!("{}", render_status(&node_status(&cfg, &store, None))),
            }
            Ok(())
        }
        "snapshot" => snapshot_command(&args, &config_path),
        "restore" => restore_command(&args, &config_path),
        "member" => member_command(&args, &config_path),
        "run" => run_command(&args, &config_path),
        "--help" | "help" => {
            print_help();
            Ok(())
        }
        other => Err(format!("unknown command {other}; use --help")),
    }
}

fn run_command(args: &[String], path: &str) -> Result<(), String> {
    if !Path::new(path).exists() {
        return Err(format!(
            "configuration {} does not exist; run chorus bootstrap explicitly",
            path
        ));
    }
    let openraft_single_node = has_flag(args, "--openraft-single-node");
    let openraft_mtls = has_flag(args, "--openraft-mtls");
    let cfg = load_command_config(args, path, openraft_mtls)?;
    cfg.validate().map_err(|e| e.to_string())?;
    if openraft_single_node && openraft_mtls {
        return Err("choose only one OpenRaft serving mode".into());
    }
    if openraft_single_node {
        validate_openraft_single_node(&cfg)?;
    }
    if cfg.initial_nodes.len() > 1
        && !openraft_mtls
        && !cfg.allow_insecure_dev
        && !has_flag(args, "--allow-insecure-dev")
    {
        return Err(
            "multi-node startup requires the mTLS peer transport; current adapter is plaintext, so pass allow_insecure_dev in config or --allow-insecure-dev for an explicit development-only run".into(),
        );
    }
    if cfg.initial_nodes.len() > 1 && !openraft_mtls {
        log_event(
            "security_warning",
            serde_json::json!({
                "message": "internal peer transport is plaintext; development-only mode",
                "node_id": cfg.node_id,
            }),
        );
    }
    log_event(
        "node_starting",
        serde_json::json!({
            "node_id": cfg.node_id,
            "cluster_id": cfg.cluster_id,
            "cluster_incarnation": cfg.cluster_incarnation,
        }),
    );
    let origin = OriginId::new(cfg.node_id);
    let (store, committer): (Arc<dyn StateStore>, Arc<ConsensusCommitter>) = if openraft_mtls {
        let consensus = open_authenticated_consensus(&cfg, false)?;
        let store = consensus.store();
        let committer = match ConsensusCommitter::new_activated(consensus.clone(), origin) {
            Ok(committer) => committer,
            Err(error) => {
                log_event(
                    "openraft_gateway_waiting_for_leadership",
                    serde_json::json!({
                        "node_id": cfg.node_id,
                        "reason": error.to_string(),
                    }),
                );
                ConsensusCommitter::new_pending_activation(consensus, origin)
            }
        };
        (store, committer)
    } else if openraft_single_node {
        // `open_store` is deliberately opened first: it owns the hardened,
        // immutable installation identity checks. The compatibility state
        // must remain empty, so this mode can never reinterpret a legacy
        // standalone/custom-consensus installation as OpenRaft state.
        let legacy_store = open_store(&cfg).map_err(|error| error.to_string())?;
        ensure_openraft_legacy_state_empty(&legacy_store)?;
        drop(legacy_store);
        let (raft_path, state_path) = openraft_paths(&cfg);
        validate_redb_target(&raft_path, "raft.redb")?;
        validate_redb_target(&state_path, "state/active.redb")?;
        let consensus = OpenRaftConsensus::open(
            cfg.node_id,
            &raft_path,
            &state_path,
            cfg.cluster_id().0,
            cfg.cluster_incarnation,
            false,
        )
        .map_err(|error| error.to_string())?;
        harden_file(&raft_path, false)?;
        harden_file(&state_path, false)?;
        let store = consensus.store();
        let committer =
            ConsensusCommitter::new_activated(consensus, origin).map_err(|e| e.to_string())?;
        (store, committer)
    } else {
        let store = Arc::new(open_store(&cfg).map_err(|e| e.to_string())?);
        if store
            .snapshot()
            .map_err(|e| e.to_string())?
            .membership()
            .log_id
            == LogId::ZERO
        {
            return Err(
                "cluster is not bootstrapped; run chorus bootstrap (or an explicit admin bootstrap) before run".into(),
            );
        }
        let committer = if cfg.initial_nodes.len() > 1 {
            let endpoints = cfg
                .initial_nodes
                .iter()
                .map(|node| (node.node_id, node.endpoint.clone()))
                .collect();
            let voters = cfg
                .initial_nodes
                .iter()
                .filter(|node| node.voter)
                .map(|node| node.node_id)
                .collect();
            let learners = cfg
                .initial_nodes
                .iter()
                .filter(|node| !node.voter)
                .map(|node| node.node_id)
                .collect();
            let consensus = NetworkConsensus::new_with_identity(
                cfg.node_id,
                voters,
                learners,
                endpoints,
                cfg.cluster_id().0,
                cfg.cluster_incarnation,
                store.clone(),
            );
            consensus.start().map_err(|e| e.to_string())?;
            ConsensusCommitter::new_activated(consensus, origin).map_err(|e| e.to_string())?
        } else {
            let consensus = Arc::new(StandaloneConsensus::new(cfg.node_id, store.clone()));
            ConsensusCommitter::new_activated(consensus, origin).map_err(|e| e.to_string())?
        };
        (store, committer)
    };
    let engine = SqlEngine::new(store.clone(), committer, cfg.limits.clone());
    let socket = cfg.postgres.unix_socket_dir.as_ref().map(|dir| {
        let _ = fs::create_dir_all(dir);
        harden_directory(dir);
        dir.join(".s.PGSQL.5432").display().to_string()
    });
    let server = PgServer::new(
        engine,
        PgConfig {
            tcp_listen: cfg.postgres.listen.clone(),
            unix_socket: socket.clone(),
            max_connections: cfg.postgres.max_connections,
        },
    );
    log_event(
        "listeners_ready",
        serde_json::json!({
            "node_id": cfg.node_id,
            "tcp": cfg.postgres.listen,
            "unix_socket": socket,
        }),
    );
    server.serve().map_err(|e| e.to_string())
}

fn snapshot_command(args: &[String], config_path: &str) -> Result<(), String> {
    match args.get(1).map(String::as_str) {
        Some("create") | Some("export") => {
            let cfg = load_command_config(args, config_path, false)?;
            let store = open_store(&cfg).map_err(|e| e.to_string())?;
            let store_status = store.status();
            if !store_status.healthy {
                return Err("backup refused: local state is unhealthy".into());
            }
            if !has_flag(args, "--offline") {
                return Err(
                    "logical backup requires a stopped node or an admin barrier endpoint; pass --offline only when no writer can access this state directory".into(),
                );
            }
            let snap = logical_backup_from_store(&store).map_err(|e| e.to_string())?;
            let out = arg_value(args, "--output")
                .unwrap_or_else(|| cfg.data_dir.join("snapshot.chorus").display().to_string());
            let bytes = snap.encode().map_err(|e| e.to_string())?;
            write_atomic(Path::new(&out), &bytes)?;
            log_event(
                "logical_backup_created",
                serde_json::json!({
                    "output": out,
                    "bytes": bytes.len(),
                    "digest": hex(&snap.header.digest),
                }),
            );
            println!("{out}");
            Ok(())
        }
        Some("inspect") => {
            let input = arg_value(args, "--input")
                .ok_or_else(|| "snapshot inspect requires --input PATH".to_string())?;
            snapshot_file_within_limit(&input).map_err(|e| e.to_string())?;
            let bytes = fs::read(&input).map_err(|e| e.to_string())?;
            let snap = LogicalSnapshot::decode(&bytes).map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::json!({
                    "header": &snap.header,
                    "logical_backup": is_logical_backup(&snap),
                    "digest": hex(&snap.header.digest),
                })
            );
            Ok(())
        }
        _ => Err("usage: chorus snapshot create|export|inspect".into()),
    }
}

fn restore_command(args: &[String], config_path: &str) -> Result<(), String> {
    if !has_flag(args, "--confirm") || !has_flag(args, "--force-new-cluster") {
        return Err(
            "restore is destructive; pass --confirm and --force-new-cluster after fencing every old member".into(),
        );
    }
    let input =
        arg_value(args, "--input").ok_or_else(|| "restore requires --input PATH".to_string())?;
    let cfg = load_command_config(args, config_path, false)?;
    require_cluster_confirmation(args, &cfg)?;
    snapshot_file_within_limit(&input).map_err(|e| e.to_string())?;
    let bytes = fs::read(&input).map_err(|e| e.to_string())?;
    let source_snapshot = LogicalSnapshot::decode(&bytes).map_err(|e| e.to_string())?;
    if !is_logical_backup(&source_snapshot)
        && source_snapshot.header.cluster_id != cfg.cluster_id().0
    {
        return Err("recovery snapshot cluster_id does not match target configuration".into());
    }
    if !is_logical_backup(&source_snapshot)
        && cfg.cluster_incarnation <= source_snapshot.header.cluster_incarnation
    {
        return Err(
            "restore target cluster_incarnation must be greater than the snapshot incarnation"
                .into(),
        );
    }
    let snapshot = if is_logical_backup(&source_snapshot) {
        // Rebind a logical backup to the target identity. Source cluster
        // identity and membership are intentionally absent from the backup.
        LogicalSnapshot::new(
            cfg.cluster_id().0,
            cfg.cluster_incarnation,
            LogId::ZERO,
            LogId::ZERO,
            Vec::new(),
            Vec::new(),
            source_snapshot.header.db_epoch,
            source_snapshot.header.catalog_epoch,
            source_snapshot.meta.clone(),
            source_snapshot.entries.clone(),
        )
    } else {
        source_snapshot
    };
    let store = FileStateStore::open(cfg.state_path()).map_err(|e| e.to_string())?;
    let current = store.snapshot().map_err(|e| e.to_string())?;
    if current.cluster_id() != [0; 16] && current.cluster_id() != cfg.cluster_id().0 {
        return Err("restore target state belongs to a different cluster".into());
    }
    // This command is explicitly fenced and destructive; use the storage
    // rollback hook so an existing target generation can be replaced even
    // when its applied log is newer than the imported backup.
    store.rollback(&snapshot).map_err(|e| e.to_string())?;
    store
        .rebase_cluster(cfg.cluster_id().0, cfg.cluster_incarnation)
        .map_err(|e| e.to_string())?;
    let voters = cfg
        .initial_nodes
        .iter()
        .filter(|node| node.voter)
        .map(|node| node.node_id)
        .collect();
    let learners = cfg
        .initial_nodes
        .iter()
        .filter(|node| !node.voter)
        .map(|node| node.node_id)
        .collect();
    let next = store.snapshot().map_err(|e| e.to_string())?.last_applied();
    store
        .apply(
            LogId {
                term: next.term.saturating_add(1).max(1),
                index: next.index.saturating_add(1),
            },
            &ReplicatedCommandV1::Membership { voters, learners },
        )
        .map_err(|e| e.to_string())?;
    log_event(
        "cluster_restored",
        serde_json::json!({
            "config": config_path,
            "cluster_id": cfg.cluster_id,
            "cluster_incarnation": cfg.cluster_incarnation,
            "logical_backup": is_logical_backup(&snapshot),
        }),
    );
    println!("restored snapshot into {}", cfg.data_dir.display());
    Ok(())
}

fn member_command(args: &[String], config_path: &str) -> Result<(), String> {
    let cfg = load_command_config(args, config_path, false)?;
    let store = open_store(&cfg).map_err(|e| e.to_string())?;
    let snapshot = store.snapshot().map_err(|e| e.to_string())?;
    match args.get(1).map(String::as_str).unwrap_or("list") {
        "list" => {
            println!(
                "{}",
                serde_json::json!({
                    "log_id": snapshot.membership().log_id,
                    "voters": snapshot.membership().voters,
                    "learners": snapshot.membership().learners,
                })
            );
            Ok(())
        }
        "add-learner" | "promote" | "demote" | "remove" => {
            if !has_flag(args, "--confirm") || !has_flag(args, "--offline") {
                return Err(
                    "offline membership edits require --confirm and --offline; live consensus membership changes are not implemented".into(),
                );
            }
            require_cluster_confirmation(args, &cfg)?;
            let node_id = arg_value(args, "--node-id")
                .ok_or_else(|| "membership operation requires --node-id N".to_string())?
                .parse::<u64>()
                .map_err(|_| "invalid --node-id".to_string())?;
            if node_id == 0 {
                return Err("membership node id must be nonzero".into());
            }
            let mut voters = snapshot.membership().voters.clone();
            let mut learners = snapshot.membership().learners.clone();
            match args[1].as_str() {
                "add-learner" => {
                    if !voters.contains(&node_id) && !learners.contains(&node_id) {
                        learners.push(node_id);
                    }
                }
                "promote" => {
                    learners.retain(|id| *id != node_id);
                    if !voters.contains(&node_id) {
                        voters.push(node_id);
                    }
                }
                "demote" => {
                    voters.retain(|id| *id != node_id);
                    if !learners.contains(&node_id) {
                        learners.push(node_id);
                    }
                }
                "remove" => {
                    if node_id == cfg.node_id {
                        return Err(
                            "refusing to remove the local node from its own membership".into()
                        );
                    }
                    voters.retain(|id| *id != node_id);
                    learners.retain(|id| *id != node_id);
                }
                _ => unreachable!(),
            }
            voters.sort_unstable();
            voters.dedup();
            learners.sort_unstable();
            learners.dedup();
            if voters.is_empty() || voters.len() > 5 || (voters.len() > 1 && voters.len() % 2 == 0)
            {
                return Err(
                    "membership edit would leave an invalid voter set (expected 1, 3, or 5)".into(),
                );
            }
            if voters.iter().any(|id| learners.binary_search(id).is_ok()) {
                return Err("membership edit would overlap voters and learners".into());
            }
            let log_id = LogId {
                term: snapshot.last_applied().term.saturating_add(1),
                index: snapshot.last_applied().index.saturating_add(1),
            };
            let result = store
                .apply(
                    log_id,
                    &ReplicatedCommandV1::Membership { voters, learners },
                )
                .map_err(|e| e.to_string())?;
            if let chorus_codec::ApplyResult::Rejected(reason) = result {
                return Err(format!("membership edit rejected: {reason}"));
            }
            log_event(
                "membership_updated_offline",
                serde_json::json!({
                    "node_id": node_id,
                    "operation": args[1],
                    "log_index": log_id.index,
                }),
            );
            println!("membership updated at index {}", log_id.index);
            Ok(())
        }
        _ => Err("usage: chorus member list|add-learner|promote|demote|remove".into()),
    }
}

fn validate_openraft_single_node(cfg: &Config) -> Result<(), String> {
    if cfg.initial_nodes.len() != 1 {
        return Err(
            "OpenRaft multi-node serving requires the authenticated Tonic/Rustls transport; --openraft-single-node accepts exactly one configured voter"
                .into(),
        );
    }
    let member = &cfg.initial_nodes[0];
    if !member.voter || member.node_id != cfg.node_id {
        return Err(
            "--openraft-single-node requires the sole configured member to be the local voter"
                .into(),
        );
    }
    Ok(())
}

fn openraft_transport_identity(cfg: &Config) -> Result<Arc<TransportTlsIdentity>, String> {
    cfg.validate_openraft_mtls()
        .map_err(|error| error.to_string())?;
    let material = cfg
        .transport_tls_material()
        .map_err(|error| error.to_string())?;

    let mut ca_reader = material.ca_pem.as_slice();
    let ca_count = rustls_pemfile::certs(&mut ca_reader)
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|error| format!("could not parse tls.ca: {error}"))?
        .len();
    if ca_count == 0 {
        return Err("tls.ca contains no certificate".into());
    }
    let mut certificate_reader = material.certificate_pem.as_slice();
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|error| format!("could not parse tls.certificate: {error}"))?;
    let local_leaf = certificates
        .first()
        .ok_or_else(|| "tls.certificate contains no leaf certificate".to_string())?;
    let mut key_reader = material.private_key_pem.as_slice();
    if rustls_pemfile::private_key(&mut key_reader)
        .map_err(|error| format!("could not parse tls.private_key: {error}"))?
        .is_none()
    {
        return Err("tls.private_key contains no private key".into());
    }

    let local = cfg
        .initial_nodes
        .iter()
        .find(|node| node.node_id == cfg.node_id)
        .ok_or_else(|| "local node is missing from the peer manifest".to_string())?;
    if leaf_fingerprint(local_leaf.as_ref())
        != local
            .tls_leaf_fingerprint()
            .map_err(|error| error.to_string())?
    {
        return Err("local TLS leaf does not match the peer manifest fingerprint".into());
    }

    let peers =
        cfg.initial_nodes
            .iter()
            .filter(|node| node.node_id != cfg.node_id)
            .map(|node| {
                Ok((
                    node.node_id,
                    PeerTlsConfig {
                        node_id: node.node_id,
                        endpoint: node.endpoint.clone(),
                        dns_name: node.tls_dns_name.clone().ok_or_else(|| {
                            format!("node {} is missing tls_dns_name", node.node_id)
                        })?,
                        leaf_sha256: node
                            .tls_leaf_fingerprint()
                            .map_err(|error| error.to_string())?,
                    },
                ))
            })
            .collect::<Result<std::collections::BTreeMap<_, _>, String>>()?;
    let identity = Arc::new(TransportTlsIdentity {
        cluster_id: cfg.cluster_id().0,
        cluster_incarnation: cfg.cluster_incarnation,
        node_id: cfg.node_id,
        ca_pem: material.ca_pem,
        certificate_pem: material.certificate_pem,
        private_key_pem: material.private_key_pem,
        peers,
    });
    identity.validate().map_err(|error| error.to_string())?;
    Ok(identity)
}

fn open_authenticated_consensus(
    cfg: &Config,
    initialize: bool,
) -> Result<Arc<OpenRaftConsensus>, String> {
    let identity = openraft_transport_identity(cfg)?;
    if cfg.initial_nodes.iter().any(|node| !node.voter) {
        return Err(
            "authenticated static bootstrap currently requires every initial node to be a voter; add learners through live membership after bootstrap"
                .into(),
        );
    }
    // Open the compatibility store only to enforce the immutable installation
    // identity and to refuse reinterpretation of legacy state as OpenRaft.
    let legacy_store = open_store(cfg).map_err(|error| error.to_string())?;
    ensure_openraft_legacy_state_empty(&legacy_store)?;
    drop(legacy_store);

    let (raft_path, state_path) = openraft_paths(cfg);
    validate_redb_target(&raft_path, "raft.redb")?;
    validate_redb_target(&state_path, "state/active.redb")?;
    let initial_voters = cfg
        .initial_nodes
        .iter()
        .map(|node| (node.node_id, node.endpoint.clone()))
        .collect();
    let options = OpenRaftRuntimeOptions {
        listen: cfg
            .raft
            .listen
            .parse()
            .map_err(|_| "raft.listen is not a socket address".to_string())?,
        heartbeat_ms: cfg.raft.heartbeat_ms,
        election_timeout_min_ms: cfg.raft.election_timeout_min_ms,
        election_timeout_max_ms: cfg.raft.election_timeout_max_ms,
        snapshot_entries: cfg.raft.snapshot_entries,
    };
    let consensus = OpenRaftConsensus::open_authenticated(
        cfg.node_id,
        &raft_path,
        &state_path,
        cfg.cluster_id().0,
        cfg.cluster_incarnation,
        initialize,
        identity,
        initial_voters,
        options,
    )
    .map_err(|error| error.to_string())?;
    harden_file(&raft_path, false)?;
    harden_file(&state_path, false)?;
    Ok(consensus)
}

fn ensure_openraft_legacy_state_empty(store: &dyn StateStore) -> Result<(), String> {
    let snapshot = store.snapshot().map_err(|error| error.to_string())?;
    if snapshot.last_applied() != LogId::ZERO
        || snapshot.membership().log_id != LogId::ZERO
        || snapshot.db_epoch() != 0
        || snapshot.catalog_epoch() != 0
        || snapshot.catalog() != &Catalog::default()
        || !snapshot.kv().is_empty()
        || !snapshot.origins().is_empty()
    {
        return Err(
            "OpenRaft mode refuses nonempty legacy state; migrate or use a fresh data directory"
                .into(),
        );
    }
    Ok(())
}

fn openraft_paths(cfg: &Config) -> (std::path::PathBuf, std::path::PathBuf) {
    (
        cfg.data_dir.join("raft.redb"),
        cfg.data_dir.join("state").join("active.redb"),
    )
}

fn validate_redb_target(path: &Path, label: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(format!("{label} path must not be a symbolic link"))
        }
        Ok(metadata) if !metadata.is_file() => Err(format!("{label} path is not a regular file")),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("could not inspect {label} path: {error}")),
    }
}

fn load_command_config(
    args: &[String],
    path: &str,
    require_signed_manifest: bool,
) -> Result<Config, String> {
    let trust_key = arg_value(args, "--manifest-key");
    if let Some(trust_key) = trust_key {
        return Config::load_openraft_signed(path, trust_key).map_err(|error| error.to_string());
    }
    if require_signed_manifest {
        return Err(
            "authenticated OpenRaft requires --manifest-key PATH before state or listeners are opened"
                .to_string(),
        );
    }

    Config::load(path).map_err(|error| error.to_string())
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}
fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|arg| arg == name)
}
fn require_cluster_confirmation(args: &[String], cfg: &Config) -> Result<(), String> {
    let supplied = arg_value(args, "--cluster-id")
        .ok_or_else(|| "dangerous command requires --cluster-id matching the target".to_string())?;
    if supplied != cfg.cluster_id {
        return Err("--cluster-id does not match target configuration".into());
    }
    Ok(())
}
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("output path is empty".into());
    }
    if path.exists() && path.is_dir() {
        return Err(format!("output path {} is a directory", path.display()));
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("tmp");
    let mut f = fs::File::create(&tmp).map_err(|e| e.to_string())?;
    f.write_all(bytes).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    harden_file(&tmp, false)?;
    fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}
fn harden_directory(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
}
fn harden_file(path: &Path, directory: bool) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if directory { 0o700 } else { 0o600 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())?;
    }
    Ok(())
}
fn log_event(event: &str, fields: serde_json::Value) {
    eprintln!(
        "{}",
        serde_json::json!({
            "component": "chorus-node",
            "event": event,
            "fields": fields,
        })
    );
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn print_help() {
    println!(
        "Chorus MVP\n\nUSAGE:\n  chorus run --config PATH [--allow-insecure-dev | --openraft-single-node | --openraft-mtls --manifest-key PATH]\n  chorus bootstrap [--config PATH] [--data-dir PATH] [--node-id N] [--confirm] [--openraft-single-node | --openraft-mtls --manifest-key PATH]\n  chorus status|check|metrics|state-hash --config PATH [--manifest-key PATH]\n  chorus member list [--config PATH] [--manifest-key PATH]\n  chorus member add-learner|promote|demote|remove --node-id N --config PATH --cluster-id ID --confirm --offline [--manifest-key PATH]\n  chorus snapshot create|export --config PATH --output PATH --offline [--manifest-key PATH]\n  chorus snapshot inspect --input PATH\n  chorus restore --input PATH --config PATH --cluster-id ID --confirm --force-new-cluster [--manifest-key PATH]"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use chorus_admin::InitialNode;
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };

    fn test_ca() -> (Certificate, KeyPair) {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        (certificate, key)
    }

    fn test_leaf(
        ca: &Certificate,
        ca_key: &KeyPair,
        dns_name: &str,
    ) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        let mut params = CertificateParams::new(vec![dns_name.to_owned()]).unwrap();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let key = KeyPair::generate().unwrap();
        let certificate = params.signed_by(&key, ca, ca_key).unwrap();
        (
            certificate.pem().into_bytes(),
            key.serialize_pem().into_bytes(),
            leaf_fingerprint(certificate.der().as_ref()),
        )
    }

    fn authenticated_test_config(root: &Path) -> Config {
        let (ca, ca_key) = test_ca();
        let leaves: Vec<_> = (1..=3)
            .map(|node_id| test_leaf(&ca, &ca_key, &format!("node-{node_id}.chorus.test")))
            .collect();
        let ca_path = root.join("ca.pem");
        let certificate_path = root.join("node.pem");
        let key_path = root.join("node-key.pem");
        fs::write(&ca_path, ca.pem()).unwrap();
        fs::write(&certificate_path, &leaves[0].0).unwrap();
        fs::write(&key_path, &leaves[0].1).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut config = Config::defaults(root.join("data"), 1);
        config.tls.ca = Some(ca_path);
        config.tls.certificate = Some(certificate_path);
        config.tls.private_key = Some(key_path);
        config.initial_nodes = (1..=3)
            .map(|node_id| InitialNode {
                node_id,
                endpoint: format!("https://127.0.0.1:{}", 7000 + node_id),
                voter: true,
                tls_dns_name: Some(format!("node-{node_id}.chorus.test")),
                tls_leaf_sha256: Some(hex(&leaves[node_id as usize - 1].2)),
            })
            .collect();
        config
    }

    #[test]
    fn openraft_bootstrap_is_explicit_reopenable_and_keeps_legacy_state_empty() {
        let root = tempfile::tempdir().unwrap();
        let config_path = root.path().join("chorus.toml");
        let data_dir = root.path().join("data");
        dispatch(vec![
            "bootstrap".into(),
            "--config".into(),
            config_path.display().to_string(),
            "--data-dir".into(),
            data_dir.display().to_string(),
            "--node-id".into(),
            "1".into(),
            "--openraft-single-node".into(),
        ])
        .unwrap();

        let cfg = Config::load(&config_path).unwrap();
        let legacy = open_store(&cfg).unwrap();
        ensure_openraft_legacy_state_empty(&legacy).unwrap();
        drop(legacy);
        let (raft_path, state_path) = openraft_paths(&cfg);
        let reopened = OpenRaftConsensus::open(
            cfg.node_id,
            raft_path,
            state_path,
            cfg.cluster_id().0,
            cfg.cluster_incarnation,
            false,
        )
        .unwrap();
        assert_eq!(Some(cfg.node_id), reopened.status().leader_id);
        assert!(reopened.status().quorum);
    }

    #[test]
    fn openraft_mode_rejects_multi_node_without_authenticated_transport() {
        let mut cfg = Config::defaults("unused", 1);
        cfg.initial_nodes.push(InitialNode {
            node_id: 2,
            endpoint: "127.0.0.1:7002".into(),
            voter: true,
            tls_dns_name: None,
            tls_leaf_sha256: None,
        });
        let error = validate_openraft_single_node(&cfg).unwrap_err();
        assert!(error.contains("authenticated Tonic/Rustls transport"));

        cfg.initial_nodes.truncate(1);
        cfg.initial_nodes[0].voter = false;
        let error = validate_openraft_single_node(&cfg).unwrap_err();
        assert!(error.contains("sole configured member"));
    }

    #[test]
    fn openraft_run_refuses_legacy_bootstrap_before_creating_redb_files() {
        let root = tempfile::tempdir().unwrap();
        let config_path = root.path().join("chorus.toml");
        let cfg = Config::defaults(root.path().join("data"), 1);
        cfg.save(&config_path).unwrap();
        let legacy = open_store(&cfg).unwrap();
        legacy
            .apply(
                LogId { term: 1, index: 1 },
                &ReplicatedCommandV1::Membership {
                    voters: vec![1],
                    learners: Vec::new(),
                },
            )
            .unwrap();
        drop(legacy);

        let error = run_command(
            &["run".into(), "--openraft-single-node".into()],
            &config_path.display().to_string(),
        )
        .unwrap_err();
        assert!(error.contains("refuses nonempty legacy state"));
        let (raft_path, state_path) = openraft_paths(&cfg);
        assert!(!raft_path.exists());
        assert!(!state_path.exists());
    }

    #[test]
    fn openraft_mtls_identity_binds_local_leaf_and_peer_manifest_before_runtime() {
        let root = tempfile::tempdir().unwrap();
        let config = authenticated_test_config(root.path());
        let identity = openraft_transport_identity(&config).unwrap();
        assert_eq!(config.cluster_id().0, identity.cluster_id);
        assert_eq!(1, identity.node_id);
        assert_eq!(
            vec![2, 3],
            identity.peers.keys().copied().collect::<Vec<_>>()
        );
        assert!(!config.data_dir.join("raft.redb").exists());

        let mut wrong_leaf = config;
        wrong_leaf.initial_nodes[0].tls_leaf_sha256 = Some("00".repeat(32));
        let error = match openraft_transport_identity(&wrong_leaf) {
            Ok(_) => panic!("mismatched local leaf must be rejected"),
            Err(error) => error,
        };
        assert!(error.contains("local TLS leaf"));
    }

    #[test]
    fn openraft_mtls_requires_external_manifest_key_before_state_access() {
        let root = tempfile::tempdir().unwrap();
        let config = authenticated_test_config(root.path());
        let config_path = root.path().join("chorus.toml");
        config.save(&config_path).unwrap();

        let error = run_command(
            &["run".into(), "--openraft-mtls".into()],
            &config_path.display().to_string(),
        )
        .unwrap_err();
        assert!(error.contains("--manifest-key"));
        assert!(!config.data_dir.exists());
        assert!(!config.identity_path().exists());
        assert!(!config.data_dir.join("raft.redb").exists());
        assert!(!config.data_dir.join("state").join("active.redb").exists());
    }

    #[test]
    fn maintenance_command_cannot_downgrade_signed_config_without_manifest_key() {
        let root = tempfile::tempdir().unwrap();
        let mut config = authenticated_test_config(root.path());
        config.bootstrap_manifest = Some(chorus_admin::BootstrapManifestSignature {
            format_version: 1,
            algorithm: "ed25519".into(),
            generation: 1,
            key_id: "00".repeat(32),
            ca_sha256: "00".repeat(32),
            signature: "00".repeat(64),
        });
        let config_path = root.path().join("chorus.toml");
        config.save(&config_path).unwrap();

        let error = load_command_config(
            &["status".into()],
            &config_path.display().to_string(),
            false,
        )
        .unwrap_err();
        assert!(error.contains("load_openraft_signed"));
        assert!(!config.data_dir.exists());
        assert!(!config.identity_path().exists());
        assert!(!config.data_dir.join("raft.redb").exists());
        assert!(!config.data_dir.join("state").join("active.redb").exists());
    }
}
