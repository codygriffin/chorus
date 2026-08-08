#![forbid(unsafe_code)]

use chorus_admin::{Config, open_store, render_status, status as node_status};
use chorus_codec::{LogicalSnapshot, ReplicatedCommandV1};
use chorus_common::{LogId, OriginId};
use chorus_consensus::{ConsensusCommitter, NetworkConsensus, StandaloneConsensus};
use chorus_pg::{PgConfig, PgServer};
use chorus_sql::SqlEngine;
use chorus_storage::{StateStore, snapshot_from_store};
use std::env;
use std::fs;
use std::sync::Arc;

fn main() {
    if let Err(e) = dispatch(env::args().skip(1).collect()) {
        eprintln!("chorus: {e}");
        std::process::exit(1);
    }
}

fn dispatch(args: Vec<String>) -> Result<(), String> {
    let command = args.first().map(String::as_str).unwrap_or("run");
    let config_path = arg_value(&args, "--config").unwrap_or_else(|| "chorus.toml".into());
    match command {
        "bootstrap" => {
            let path = config_path;
            let cfg = Config::defaults(
                arg_value(&args, "--data-dir").unwrap_or_else(|| "./chorus-data".into()),
                arg_value(&args, "--node-id")
                    .and_then(|x| x.parse().ok())
                    .unwrap_or(1),
            );
            cfg.save(&path).map_err(|e| e.to_string())?;
            fs::create_dir_all(&cfg.data_dir).map_err(|e| e.to_string())?;
            let _ = open_store(&cfg).map_err(|e| e.to_string())?;
            println!("bootstrapped {}", path);
            Ok(())
        }
        "status" | "check" | "state-hash" => {
            let cfg = Config::load(&config_path).map_err(|e| e.to_string())?;
            let store = open_store(&cfg).map_err(|e| e.to_string())?;
            match command {
                "state-hash" => {
                    println!("{}", hex(&store.state_hash().map_err(|e| e.to_string())?));
                }
                "check" => {
                    cfg.validate().map_err(|e| e.to_string())?;
                    println!("ok");
                }
                _ => println!("{}", render_status(&node_status(&cfg, &store, None))),
            }
            Ok(())
        }
        "snapshot" => snapshot_command(&args, &config_path),
        "restore" => restore_command(&args, &config_path),
        "member" => member_command(&args, &config_path),
        "run" => run_command(&config_path),
        "--help" | "help" => {
            print_help();
            Ok(())
        }
        other => Err(format!("unknown command {other}; use --help")),
    }
}

fn run_command(path: &str) -> Result<(), String> {
    let cfg = if std::path::Path::new(path).exists() {
        Config::load(path).map_err(|e| e.to_string())?
    } else {
        Config::defaults("./chorus-data", 1)
    };
    cfg.validate().map_err(|e| e.to_string())?;
    fs::create_dir_all(&cfg.data_dir).map_err(|e| e.to_string())?;
    let store = Arc::new(open_store(&cfg).map_err(|e| e.to_string())?);
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
        let consensus =
            NetworkConsensus::new(cfg.node_id, voters, learners, endpoints, store.clone());
        consensus.start().map_err(|e| e.to_string())?;
        ConsensusCommitter::new_activated(consensus, origin).map_err(|e| e.to_string())?
    } else {
        let consensus = Arc::new(StandaloneConsensus::new(cfg.node_id, store.clone()));
        ConsensusCommitter::new_activated(consensus, origin).map_err(|e| e.to_string())?
    };
    let engine = SqlEngine::new(store.clone(), committer, cfg.limits.clone());
    let socket = cfg.postgres.unix_socket_dir.as_ref().map(|dir| {
        let _ = fs::create_dir_all(dir);
        dir.join(".s.PGSQL.5432").display().to_string()
    });
    let server = PgServer::new(
        engine,
        PgConfig {
            tcp_listen: cfg.postgres.listen.clone(),
            unix_socket: socket,
            max_connections: cfg.postgres.max_connections,
        },
    );
    eprintln!("chorus node {} listening", cfg.node_id);
    server.serve().map_err(|e| e.to_string())
}

fn snapshot_command(args: &[String], config_path: &str) -> Result<(), String> {
    match args.get(1).map(String::as_str) {
        Some("create") | Some("export") => {
            let cfg = Config::load(config_path).map_err(|e| e.to_string())?;
            let store = open_store(&cfg).map_err(|e| e.to_string())?;
            let snap = snapshot_from_store(&store).map_err(|e| e.to_string())?;
            let out = arg_value(args, "--output")
                .unwrap_or_else(|| cfg.data_dir.join("snapshot.chorus").display().to_string());
            fs::write(&out, snap.encode().map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            println!("{out}");
            Ok(())
        }
        Some("inspect") => {
            let input = arg_value(args, "--input")
                .ok_or_else(|| "snapshot inspect requires --input PATH".to_string())?;
            let bytes = fs::read(&input).map_err(|e| e.to_string())?;
            let snap = LogicalSnapshot::decode(&bytes).map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&snap.header).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        _ => Err("usage: chorus snapshot create|export|inspect".into()),
    }
}

fn restore_command(args: &[String], config_path: &str) -> Result<(), String> {
    if !args.iter().any(|arg| arg == "--confirm") {
        return Err("restore is destructive; pass --confirm with an explicit target config".into());
    }
    let input =
        arg_value(args, "--input").ok_or_else(|| "restore requires --input PATH".to_string())?;
    let cfg = Config::load(config_path).map_err(|e| e.to_string())?;
    let bytes = fs::read(input).map_err(|e| e.to_string())?;
    let snapshot = LogicalSnapshot::decode(&bytes).map_err(|e| e.to_string())?;
    if cfg.cluster_incarnation <= snapshot.header.cluster_incarnation {
        return Err(
            "restore target cluster_incarnation must be greater than the snapshot incarnation"
                .into(),
        );
    }
    let store = open_store(&cfg).map_err(|e| e.to_string())?;
    store.install(&snapshot).map_err(|e| e.to_string())?;
    store
        .rebase_cluster(cfg.cluster_id().0, cfg.cluster_incarnation)
        .map_err(|e| e.to_string())?;
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
            let node_id = arg_value(args, "--node-id")
                .ok_or_else(|| "membership operation requires --node-id N".to_string())?
                .parse::<u64>()
                .map_err(|_| "invalid --node-id".to_string())?;
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
                    voters.retain(|id| *id != node_id);
                    learners.retain(|id| *id != node_id);
                }
                _ => unreachable!(),
            }
            let log_id = LogId {
                term: snapshot.last_applied().term.saturating_add(1),
                index: snapshot.last_applied().index.saturating_add(1),
            };
            store
                .apply(
                    log_id,
                    &ReplicatedCommandV1::Membership { voters, learners },
                )
                .map_err(|e| e.to_string())?;
            println!("membership updated at index {}", log_id.index);
            Ok(())
        }
        _ => Err("usage: chorus member list|add-learner|promote|demote|remove".into()),
    }
}
fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn print_help() {
    println!(
        "Chorus MVP\n\nUSAGE:\n  chorus run [--config PATH]\n  chorus bootstrap [--config PATH] [--data-dir PATH] [--node-id N]\n  chorus status|check|state-hash [--config PATH]\n  chorus member list|add-learner|promote|demote|remove [--node-id N]\n  chorus snapshot create|export [--config PATH] [--output PATH]\n  chorus snapshot inspect --input PATH\n  chorus restore --input PATH --config PATH --confirm"
    );
}
