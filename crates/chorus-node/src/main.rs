#![forbid(unsafe_code)]

use chorus_admin::{Config, open_store, render_status, status as node_status};
use chorus_codec::{ActivateOriginV1, LogicalSnapshot, ReplicatedCommandV1};
use chorus_common::{LogId, OriginId};
use chorus_consensus::{ConsensusCommitter, StandaloneConsensus};
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
        "bootstrap" => { let path = config_path; let cfg = Config::defaults(arg_value(&args, "--data-dir").unwrap_or_else(|| "./chorus-data".into()), arg_value(&args, "--node-id").and_then(|x| x.parse().ok()).unwrap_or(1)); cfg.save(&path).map_err(|e| e.to_string())?; fs::create_dir_all(&cfg.data_dir).map_err(|e| e.to_string())?; let _ = open_store(&cfg).map_err(|e| e.to_string())?; println!("bootstrapped {}", path); Ok(()) }
        "status" | "check" | "state-hash" => { let cfg = Config::load(&config_path).map_err(|e| e.to_string())?; let store = open_store(&cfg).map_err(|e| e.to_string())?; match command { "state-hash" => { println!("{}", hex(&store.state_hash().map_err(|e| e.to_string())?)); }, "check" => { cfg.validate().map_err(|e| e.to_string())?; println!("ok"); }, _ => println!("{}", render_status(&node_status(&cfg, &store, None))) } Ok(()) }
        "snapshot" => snapshot_command(&args, &config_path),
        "restore" => Err("restore requires an explicit target cluster in the MVP command-line wrapper".into()),
        "member" => Err("membership operations require the consensus admin service; use chorus member list after run".into()),
        "run" => run_command(&config_path),
        "--help" | "help" => { print_help(); Ok(()) }
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
    let next = store
        .snapshot()
        .map_err(|e| e.to_string())?
        .last_applied()
        .index
        + 1;
    store
        .apply(
            LogId {
                term: 1,
                index: next,
            },
            &ReplicatedCommandV1::ActivateOrigin(ActivateOriginV1 { origin }),
        )
        .map_err(|e| e.to_string())?;
    let consensus = Arc::new(StandaloneConsensus::new(cfg.node_id, store.clone()));
    let committer = ConsensusCommitter::new(consensus, origin);
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
    let cfg = Config::load(config_path).map_err(|e| e.to_string())?;
    let store = open_store(&cfg).map_err(|e| e.to_string())?;
    let snap = snapshot_from_store(&store).map_err(|e| e.to_string())?;
    match args.get(1).map(String::as_str) {
        Some("create") | Some("export") => {
            let out = arg_value(args, "--output")
                .unwrap_or_else(|| cfg.data_dir.join("snapshot.chorus").display().to_string());
            fs::write(&out, snap.encode().map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            println!("{out}");
            Ok(())
        }
        Some("inspect") => {
            println!(
                "{}",
                serde_json::to_string_pretty(&snap.header).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        _ => Err("usage: chorus snapshot create|export|inspect".into()),
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
        "Chorus MVP\n\nUSAGE:\n  chorus run [--config PATH]\n  chorus bootstrap [--config PATH] [--data-dir PATH] [--node-id N]\n  chorus status|check|state-hash [--config PATH]\n  chorus snapshot create|export|inspect [--config PATH] [--output PATH]"
    );
}
