#![forbid(unsafe_code)]

use chorus_admin::{
    Config, is_logical_backup, logical_backup_from_store, open_store, render_status,
    snapshot_file_within_limit, status as node_status,
};
use chorus_codec::{LogicalSnapshot, ReplicatedCommandV1};
use chorus_common::{LogId, OriginId};
use chorus_consensus::{ConsensusCommitter, NetworkConsensus, StandaloneConsensus};
use chorus_pg::{PgConfig, PgServer};
use chorus_sql::SqlEngine;
use chorus_storage::{FileStateStore, StateStore};
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
            let cfg = Config::load(&config_path).map_err(|e| e.to_string())?;
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
    let cfg = Config::load(path).map_err(|e| e.to_string())?;
    cfg.validate().map_err(|e| e.to_string())?;
    if cfg.initial_nodes.len() > 1
        && !cfg.allow_insecure_dev
        && !has_flag(args, "--allow-insecure-dev")
    {
        return Err(
            "multi-node startup requires the mTLS peer transport; current adapter is plaintext, so pass allow_insecure_dev in config or --allow-insecure-dev for an explicit development-only run".into(),
        );
    }
    if cfg.initial_nodes.len() > 1 {
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
    let origin = OriginId::new(cfg.node_id);
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
            let cfg = Config::load(config_path).map_err(|e| e.to_string())?;
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
    let cfg = Config::load(config_path).map_err(|e| e.to_string())?;
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
    let cfg = Config::load(config_path).map_err(|e| e.to_string())?;
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
        "Chorus MVP\n\nUSAGE:\n  chorus run --config PATH [--allow-insecure-dev]\n  chorus bootstrap [--config PATH] [--data-dir PATH] [--node-id N] [--confirm]\n  chorus status|check|metrics|state-hash --config PATH\n  chorus member list [--config PATH]\n  chorus member add-learner|promote|demote|remove --node-id N --config PATH --cluster-id ID --confirm --offline\n  chorus snapshot create|export --config PATH --output PATH --offline\n  chorus snapshot inspect --input PATH\n  chorus restore --input PATH --config PATH --cluster-id ID --confirm --force-new-cluster"
    );
}
