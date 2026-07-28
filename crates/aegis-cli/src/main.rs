//! `aegis` — single operator front door for the suite kernel.

mod config;

use clap::{Parser, Subcommand};
use colored::*;
use config::SuiteConfig;
use s2o_fleet::{FleetPolicyBundle, FleetStore, HeartbeatPayload};
use s2o_kernel::{
    apply_policy, collect_platform_status, compute_posture_score, create_firewall_engine, demo_mode,
    host_id, load_policy_file, KERNEL_VERSION, PHASE_LABEL, TIER_CEILING,
};
use s2o_schema::{AegisEvent, HealthState, PolicyDocument, SCHEMA_VERSION};
use s2o_store::EventStore;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "aegis")]
#[command(author = "Split2ops Software")]
#[command(version = "0.1.0")]
#[command(about = "S2O Aegis operator CLI — one front door to the suite", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print suite / kernel versions
    Version {
        #[arg(long)]
        json: bool,
    },
    /// Honest platform matrix (same as aegisd status)
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Kernel / host doctor (suite data + module matrix)
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// Probe aegisd HTTP health endpoint (default 127.0.0.1:9090)
    Health {
        /// Base URL (no path)
        #[arg(long, default_value = "http://127.0.0.1:9090")]
        url: String,
        /// Also GET /status
        #[arg(long)]
        status: bool,
        /// Also GET /metrics (print first lines)
        #[arg(long)]
        metrics: bool,
        #[arg(long)]
        json: bool,
        #[arg(long, default_value_t = 3)]
        timeout_secs: u64,
    },
    /// Full audit report (status + posture + data files)
    Report {
        #[arg(long)]
        json: bool,
        /// Write report to path (in addition to stdout)
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Policy operations
    Policy {
        #[command(subcommand)]
        command: PolicyCmd,
    },
    /// Recent events from the local store
    Events {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        product: Option<String>,
        #[arg(long)]
        severity: Option<String>,
        /// Time lower bound: relative (`15m`, `1h`, `24h`, `7d`) or RFC3339
        #[arg(long)]
        since: Option<String>,
        /// Pretty text instead of JSON
        #[arg(long)]
        text: bool,
    },
    /// Emit an event to the local store and/or aegisd HTTP/UDP bus
    Emit {
        /// Event message body
        message: String,
        #[arg(long, default_value = "info")]
        severity: String,
        #[arg(long, default_value = "aegis")]
        product: String,
        #[arg(long, default_value = "alert")]
        kind: String,
        #[arg(long, default_value = "observed")]
        action: String,
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        /// Also POST to aegisd (e.g. http://127.0.0.1:9090/events)
        #[arg(long)]
        http: Option<String>,
        /// Also fan-out via UDP bus (default lab 127.0.0.1:9091)
        #[arg(long)]
        udp: Option<String>,
        /// Skip local JSONL append
        #[arg(long)]
        no_local: bool,
        #[arg(long)]
        json: bool,
    },
    /// Rotate the local event log now (archives to events.jsonl.1 …)
    Rotate {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 5)]
        keep: usize,
        #[arg(long)]
        json: bool,
    },
    /// Follow live events from the JSONL store
    Watch {
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 500)]
        interval_ms: u64,
        #[arg(long, default_value_t = 5)]
        from_recent: usize,
    },
    /// Run response playbooks against recent events (dry-run by default)
    Playbook {
        #[command(subcommand)]
        command: PlaybookCmd,
    },
    /// Zip the .aegis data directory
    Backup {
        #[arg(long, default_value = ".aegis")]
        data_dir: PathBuf,
        /// Output zip path (default .aegis-backup-<timestamp>.zip)
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Restore a backup zip into the data directory (merge)
    Restore {
        /// Path to backup zip
        zip: PathBuf,
        #[arg(long, default_value = ".aegis")]
        data_dir: PathBuf,
        /// Allow overwriting existing files
        #[arg(long)]
        force: bool,
    },
    /// Non-interactive self-test (exit 1 on failure)
    Selftest {
        #[arg(long, default_value_t = 40)]
        min_posture: u32,
        #[arg(long)]
        json: bool,
    },
    /// Housekeeping: session GC, fleet prune, event rotate, optional IOC/DNS hygiene
    Cleanup {
        #[arg(long, default_value = ".aegis/sessions.json")]
        sessions: PathBuf,
        #[arg(long, default_value = ".aegis/fleet.json")]
        fleet: PathBuf,
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value = ".aegis/ioc-store.json")]
        ioc_store: PathBuf,
        #[arg(long, default_value = ".aegis/dns-blocklist.txt")]
        dns_blocklist: PathBuf,
        /// Fleet stale window minutes (0 = skip fleet prune)
        #[arg(long, default_value_t = 10080)]
        fleet_stale_minutes: i64,
        /// Rotate event log if over this many bytes (0 = skip)
        #[arg(long, default_value_t = 10 * 1024 * 1024)]
        rotate_max_bytes: u64,
        /// Prune IOC entries older than N days (0 = skip)
        #[arg(long, default_value_t = 90)]
        ioc_older_days: i64,
        /// Rewrite DNS blocklist without duplicates
        #[arg(long, default_value_t = true)]
        dns_dedupe: bool,
        /// Actually mutate stores (default dry-run)
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        json: bool,
    },
    /// First-time bootstrap of .aegis data + starter policy/playbooks/gate
    Setup {
        #[arg(long, default_value = ".aegis")]
        data_dir: PathBuf,
        /// Apply edge policy pack after seeding
        #[arg(long, default_value_t = true)]
        apply_policy: bool,
        /// Skip policy apply
        #[arg(long)]
        no_policy: bool,
        #[arg(long)]
        json: bool,
    },
    /// Show or write suite config (.aegis/config.json)
    Config {
        #[command(subcommand)]
        command: ConfigCmd,
    },
    /// Run a product CLI if on PATH / target/debug (best-effort shim)
    Run {
        /// Product binary: cyberwall, cyberdns, cyberdefender, cyberedr, ...
        product: String,
        /// Args forwarded to the product
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Windows Service / Scheduled Task control for aegisd (T1 packaging)
    Service {
        #[command(subcommand)]
        command: ServiceCmd,
    },
    /// Local fleet host inventory (enroll / heartbeat / list)
    Fleet {
        #[command(subcommand)]
        command: FleetCmd,
    },
}

#[derive(Subcommand)]
enum FleetCmd {
    /// Enroll this host (or named host) into the fleet roster
    Enroll {
        #[arg(long, default_value = ".aegis/fleet.json")]
        fleet: PathBuf,
        /// Override host id (default: COMPUTERNAME/HOSTNAME)
        #[arg(long)]
        host_id: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        tag: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Refresh last_seen + posture/modules for this host
    Heartbeat {
        #[arg(long, default_value = ".aegis/fleet.json")]
        fleet: PathBuf,
        #[arg(long)]
        host_id: Option<String>,
        /// POST heartbeat to aegisd (e.g. http://127.0.0.1:9090/fleet/heartbeat)
        #[arg(long)]
        push: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// List enrolled hosts
    List {
        #[arg(long, default_value = ".aegis/fleet.json")]
        fleet: PathBuf,
        /// Minutes without heartbeat = stale (default 60)
        #[arg(long, default_value_t = 60)]
        stale_minutes: i64,
        #[arg(long)]
        json: bool,
    },
    /// Show one host
    Show {
        id: String,
        #[arg(long, default_value = ".aegis/fleet.json")]
        fleet: PathBuf,
    },
    /// Remove a host from the roster
    Remove {
        id: String,
        #[arg(long, default_value = ".aegis/fleet.json")]
        fleet: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Add tag(s) to a fleet host
    TagAdd {
        id: String,
        #[arg(required = true)]
        tags: Vec<String>,
        #[arg(long, default_value = ".aegis/fleet.json")]
        fleet: PathBuf,
    },
    /// Remove tag(s) from a fleet host
    TagRemove {
        id: String,
        #[arg(required = true)]
        tags: Vec<String>,
        #[arg(long, default_value = ".aegis/fleet.json")]
        fleet: PathBuf,
    },
    /// Drop hosts not seen within stale window
    Prune {
        #[arg(long, default_value = ".aegis/fleet.json")]
        fleet: PathBuf,
        /// Minutes without heartbeat (default 10080 = 7 days)
        #[arg(long, default_value_t = 10080)]
        stale_minutes: i64,
        /// Actually delete (default dry-run)
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        json: bool,
    },
    /// Export fleet roster (json/csv)
    #[command(name = "export")]
    Export {
        #[arg(long, default_value = ".aegis/fleet.json")]
        fleet: PathBuf,
        /// Minutes without heartbeat = stale (annotation only)
        #[arg(long, default_value_t = 60)]
        stale_minutes: i64,
        /// json | csv
        #[arg(long, default_value = "json")]
        format: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Summary counts
    Status {
        #[arg(long, default_value = ".aegis/fleet.json")]
        fleet: PathBuf,
        #[arg(long, default_value = ".aegis/fleet-policy.json")]
        policy: PathBuf,
        #[arg(long, default_value_t = 60)]
        stale_minutes: i64,
        #[arg(long)]
        json: bool,
    },
    /// Validate fleet roster + desired policy health
    Doctor {
        #[arg(long, default_value = ".aegis/fleet.json")]
        fleet: PathBuf,
        #[arg(long, default_value = ".aegis/fleet-policy.json")]
        policy: PathBuf,
        #[arg(long, default_value_t = 60)]
        stale_minutes: i64,
        #[arg(long)]
        json: bool,
    },
    /// Fleet policy distribution (set / show / apply / push / pull)
    Policy {
        #[command(subcommand)]
        command: FleetPolicyCmd,
    },
}

#[derive(Subcommand)]
enum FleetPolicyCmd {
    /// Publish a policy pack as the fleet desired policy (bumps version)
    Set {
        path: PathBuf,
        #[arg(long, default_value = ".aegis/fleet-policy.json")]
        policy: PathBuf,
    },
    /// Show current fleet policy bundle
    Show {
        #[arg(long, default_value = ".aegis/fleet-policy.json")]
        policy: PathBuf,
    },
    /// Apply local fleet policy through the kernel
    Apply {
        #[arg(long, default_value = ".aegis/fleet-policy.json")]
        policy: PathBuf,
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        /// Record applied version onto this host in fleet.json
        #[arg(long, default_value = ".aegis/fleet.json")]
        fleet: PathBuf,
    },
    /// Upload policy pack to aegisd (POST /fleet/policy)
    Push {
        path: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:9090/fleet/policy")]
        url: String,
    },
    /// Download policy from aegisd; optional --apply
    Pull {
        #[arg(long, default_value = "http://127.0.0.1:9090/fleet/policy")]
        url: String,
        #[arg(long, default_value = ".aegis/fleet-policy.json")]
        policy: PathBuf,
        #[arg(long)]
        apply: bool,
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value = ".aegis/fleet.json")]
        fleet: PathBuf,
    },
}

#[derive(Subcommand)]
enum ServiceCmd {
    /// Show SCM / Scheduled Task state for S2OAegisd
    Status {
        #[arg(long, default_value = "S2OAegisd")]
        name: String,
    },
    /// Register Windows Service (requires Administrator)
    Install {
        #[arg(long, default_value = "S2OAegisd")]
        name: String,
        /// Path to aegisd.exe (default: next to aegis / target)
        #[arg(long)]
        bin: Option<PathBuf>,
        /// Defaults to %LOCALAPPDATA%\S2O\Aegis\data
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:9090")]
        health_bind: String,
        /// Also register AtLogOn Scheduled Task (user-level fallback)
        #[arg(long)]
        task: bool,
    },
    /// Remove Windows Service registration
    Uninstall {
        #[arg(long, default_value = "S2OAegisd")]
        name: String,
        #[arg(long)]
        task: bool,
    },
    /// Start the service (or Scheduled Task)
    Start {
        #[arg(long, default_value = "S2OAegisd")]
        name: String,
    },
    /// Stop the service
    Stop {
        #[arg(long, default_value = "S2OAegisd")]
        name: String,
    },
}

fn default_service_data_dir() -> PathBuf {
    if let Ok(base) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(base).join("S2O").join("Aegis").join("data");
    }
    PathBuf::from(".aegis")
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Print effective config (file + defaults)
    Show {
        #[arg(long, default_value = ".aegis/config.json")]
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Write default config file
    Init {
        #[arg(long, default_value = ".aegis/config.json")]
        path: PathBuf,
    },
    /// Get one config key
    Get {
        /// Key: data_dir|event_log|health_bind|min_posture|playbooks|gate_config
        key: String,
        #[arg(long, default_value = ".aegis/config.json")]
        path: PathBuf,
    },
    /// Set one config key and save
    Set {
        /// Key: data_dir|event_log|health_bind|min_posture|playbooks|gate_config
        key: String,
        value: String,
        #[arg(long, default_value = ".aegis/config.json")]
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    Apply {
        path: PathBuf,
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Validate a policy pack JSON without applying (shape + soft path checks)
    Validate {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Describe planned apply steps without mutating the host
    Plan {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Example {
        /// wall | edge
        #[arg(long, default_value = "edge")]
        kind: String,
    },
}

#[derive(Subcommand)]
enum PlaybookCmd {
    /// Write a starter playbook file
    Init {
        #[arg(long, default_value = ".aegis/playbooks.json")]
        path: PathBuf,
    },
    /// List rules (enabled, when, actions)
    List {
        #[arg(long, default_value = ".aegis/playbooks.json")]
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Show one rule by name (full when/then)
    Show {
        name: String,
        #[arg(long, default_value = ".aegis/playbooks.json")]
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Validate playbook JSON + known action types
    Validate {
        #[arg(long, default_value = ".aegis/playbooks.json")]
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Enable a rule by name
    Enable {
        name: String,
        #[arg(long, default_value = ".aegis/playbooks.json")]
        path: PathBuf,
    },
    /// Disable a rule by name
    Disable {
        name: String,
        #[arg(long, default_value = ".aegis/playbooks.json")]
        path: PathBuf,
    },
    /// Remove a rule by name
    Remove {
        name: String,
        #[arg(long, default_value = ".aegis/playbooks.json")]
        path: PathBuf,
        /// Actually delete (default dry-run)
        #[arg(long)]
        apply: bool,
    },
    /// Evaluate playbooks against recent events
    Run {
        #[arg(long, default_value = ".aegis/playbooks.json")]
        path: PathBuf,
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 200)]
        limit: usize,
        /// Actually perform actions (default is dry-run)
        #[arg(long)]
        apply: bool,
        /// Machine-readable hit summary (dry-run skips action side effects)
        #[arg(long)]
        json: bool,
    },
    /// Continuously follow events and run matching playbooks
    Watch {
        #[arg(long, default_value = ".aegis/playbooks.json")]
        path: PathBuf,
        #[arg(long, default_value = ".aegis/events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value_t = 500)]
        interval_ms: u64,
        /// Actually perform actions (default is dry-run)
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct PlaybookFile {
    rules: Vec<PlaybookRule>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct PlaybookRule {
    name: String,
    #[serde(default)]
    enabled: bool,
    when: PlaybookWhen,
    then: Vec<PlaybookAction>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct PlaybookWhen {
    #[serde(default)]
    product: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    message_contains: Option<String>,
    /// Event kind filter (e.g. dns, alert, netflow)
    #[serde(default)]
    kind: Option<String>,
    /// Require this attr key to exist; pair with attr_equals / attr_contains
    #[serde(default)]
    attr: Option<String>,
    #[serde(default)]
    attr_equals: Option<String>,
    #[serde(default)]
    attr_contains: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct PlaybookAction {
    #[serde(rename = "type")]
    action_type: String,
    #[serde(default)]
    attr: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    /// Webhook URL for action_type = webhook
    #[serde(default)]
    url: Option<String>,
    /// Message template for action_type = emit (supports {message})
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    product: Option<String>,
    /// IOC kind for ioc_add / ioc_add_attr: domain|ip|hash|url
    #[serde(default)]
    kind: Option<String>,
    /// Static IOC value for action_type = ioc_add
    #[serde(default)]
    value: Option<String>,
    /// IOC source label (default: playbook)
    #[serde(default)]
    source: Option<String>,
    /// User for session_revoke_user (or static token for session_revoke)
    #[serde(default)]
    user: Option<String>,
    /// Session token/id for session_revoke
    #[serde(default)]
    token: Option<String>,
}

fn default_playbooks() -> PlaybookFile {
    PlaybookFile {
        rules: vec![
            PlaybookRule {
                name: "echo-dns-blocks".into(),
                enabled: true,
                when: PlaybookWhen {
                    product: Some("cyberdns".into()),
                    action: Some("blocked".into()),
                    severity: None,
                    message_contains: None,
                    kind: None,
                    attr: None,
                    attr_equals: None,
                    attr_contains: None,
                },
                then: vec![PlaybookAction {
                    action_type: "log".into(),
                    attr: None,
                    domain: None,
                    url: None,
                    message: None,
                    severity: None,
                    product: None,
                    kind: None,
                    value: None,
                    source: None,
                    user: None,
                    token: None,
                }],
            },
            PlaybookRule {
                name: "seed-blocklist-from-dns-attr".into(),
                enabled: true,
                when: PlaybookWhen {
                    product: Some("cyberdns".into()),
                    action: Some("blocked".into()),
                    severity: Some("high".into()),
                    message_contains: None,
                    kind: None,
                    attr: None,
                    attr_equals: None,
                    attr_contains: None,
                },
                then: vec![PlaybookAction {
                    action_type: "dns_block_attr".into(),
                    attr: Some("domain".into()),
                    domain: None,
                    url: None,
                    message: None,
                    severity: None,
                    product: None,
                    kind: None,
                    value: None,
                    source: None,
                    user: None,
                    token: None,
                }],
            },
            PlaybookRule {
                name: "emit-on-high-block".into(),
                enabled: true,
                when: PlaybookWhen {
                    product: None,
                    action: Some("blocked".into()),
                    severity: Some("high".into()),
                    message_contains: None,
                    kind: None,
                    attr: None,
                    attr_equals: None,
                    attr_contains: None,
                },
                then: vec![PlaybookAction {
                    action_type: "emit".into(),
                    attr: None,
                    domain: None,
                    url: None,
                    message: Some("playbook: {message}".into()),
                    severity: Some("high".into()),
                    product: Some("aegis".into()),
                    kind: None,
                    value: None,
                    source: None,
                    user: None,
                    token: None,
                }],
            },
            PlaybookRule {
                name: "webhook-on-high-block".into(),
                enabled: false,
                when: PlaybookWhen {
                    product: None,
                    action: Some("blocked".into()),
                    severity: Some("high".into()),
                    message_contains: None,
                    kind: None,
                    attr: None,
                    attr_equals: None,
                    attr_contains: None,
                },
                then: vec![PlaybookAction {
                    action_type: "webhook".into(),
                    attr: None,
                    domain: None,
                    url: Some("http://127.0.0.1:9999/hook".into()),
                    message: None,
                    severity: None,
                    product: None,
                    kind: None,
                    value: None,
                    source: None,
                    user: None,
                    token: None,
                }],
            },
            PlaybookRule {
                name: "ioc-from-dns-block".into(),
                enabled: true,
                when: PlaybookWhen {
                    product: Some("cyberdns".into()),
                    action: Some("blocked".into()),
                    severity: None,
                    message_contains: None,
                    kind: None,
                    attr: Some("domain".into()),
                    attr_equals: None,
                    attr_contains: None,
                },
                then: vec![PlaybookAction {
                    action_type: "ioc_add_attr".into(),
                    attr: Some("domain".into()),
                    domain: None,
                    url: None,
                    message: None,
                    severity: Some("high".into()),
                    product: None,
                    kind: Some("domain".into()),
                    value: None,
                    source: Some("playbook".into()),
                    user: None,
                    token: None,
                }],
            },
            PlaybookRule {
                name: "revoke-user-on-critical-auth".into(),
                enabled: false,
                when: PlaybookWhen {
                    product: Some("cyberid".into()),
                    action: None,
                    severity: Some("critical".into()),
                    message_contains: None,
                    kind: Some("auth".into()),
                    attr: Some("user".into()),
                    attr_equals: None,
                    attr_contains: None,
                },
                then: vec![PlaybookAction {
                    action_type: "session_revoke_attr".into(),
                    attr: Some("user".into()),
                    domain: None,
                    url: None,
                    message: None,
                    severity: None,
                    product: None,
                    kind: None,
                    value: None,
                    source: None,
                    user: None,
                    token: None,
                }],
            },
        ],
    }
}

fn event_matches(ev: &s2o_schema::AegisEvent, when: &PlaybookWhen) -> bool {
    if let Some(ref p) = when.product {
        let id = ev.product.as_str();
        let name = format!("{:?}", ev.product).to_ascii_lowercase();
        let pf = p.to_ascii_lowercase();
        if id != pf && !name.contains(&pf) {
            return false;
        }
    }
    if let Some(ref a) = when.action {
        if !format!("{:?}", ev.action).eq_ignore_ascii_case(a) {
            return false;
        }
    }
    if let Some(ref s) = when.severity {
        if !format!("{:?}", ev.severity).eq_ignore_ascii_case(s) {
            return false;
        }
    }
    if let Some(ref k) = when.kind {
        let kid = format!("{:?}", ev.kind).to_ascii_lowercase();
        let kf = k.to_ascii_lowercase();
        if kid != kf && !kid.contains(&kf) {
            return false;
        }
    }
    if let Some(ref m) = when.message_contains {
        if !ev.message.to_ascii_lowercase().contains(&m.to_ascii_lowercase()) {
            return false;
        }
    }
    if let Some(ref key) = when.attr {
        let raw = ev.attrs.get(key).and_then(|v| {
            v.as_str()
                .map(|s| s.to_string())
                .or_else(|| Some(v.to_string().trim_matches('"').to_string()))
        });
        let Some(val) = raw else {
            return false;
        };
        if let Some(ref eq) = when.attr_equals {
            if !val.eq_ignore_ascii_case(eq) {
                return false;
            }
        }
        if let Some(ref sub) = when.attr_contains {
            if !val.to_ascii_lowercase().contains(&sub.to_ascii_lowercase()) {
                return false;
            }
        }
    } else if when.attr_equals.is_some() || when.attr_contains.is_some() {
        // attr key required when equals/contains set
        return false;
    }
    true
}

fn known_playbook_actions() -> &'static [&'static str] {
    &[
        "log",
        "dns_block",
        "dns_block_attr",
        "dns_allow",
        "dns_allow_attr",
        "emit",
        "webhook",
        "ioc_add",
        "ioc_add_attr",
        "session_revoke",
        "session_revoke_user",
        "session_revoke_attr",
    ]
}

/// Parse relative duration (`15m`, `1h`, `24h`, `7d`) or RFC3339 into a UTC lower bound.
fn parse_since(s: &str) -> Result<chrono::DateTime<chrono::Utc>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty --since value".into());
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&chrono::Utc));
    }
    let bytes = s.as_bytes();
    if bytes.len() < 2 {
        return Err(format!(
            "invalid --since '{s}' (use 15m, 1h, 24h, 7d, or RFC3339)"
        ));
    }
    let unit = *bytes.last().unwrap() as char;
    let num_str = &s[..s.len() - 1];
    let n: i64 = num_str.parse().map_err(|_| {
        format!("invalid --since '{s}' (use 15m, 1h, 24h, 7d, or RFC3339)")
    })?;
    if n <= 0 {
        return Err("--since duration must be positive".into());
    }
    let now = chrono::Utc::now();
    match unit {
        's' | 'S' => Ok(now - chrono::Duration::seconds(n)),
        'm' | 'M' => Ok(now - chrono::Duration::minutes(n)),
        'h' | 'H' => Ok(now - chrono::Duration::hours(n)),
        'd' | 'D' => Ok(now - chrono::Duration::days(n)),
        'w' | 'W' => Ok(now - chrono::Duration::weeks(n)),
        _ => Err(format!(
            "invalid --since unit in '{s}' (use s/m/h/d/w or RFC3339)"
        )),
    }
}

fn parse_ioc_kind(s: &str) -> Option<s2o_ioc::IocKind> {
    match s.trim().to_ascii_lowercase().as_str() {
        "domain" | "dom" | "host" => Some(s2o_ioc::IocKind::Domain),
        "ip" | "ipv4" | "ipv6" => Some(s2o_ioc::IocKind::Ip),
        "hash" | "sha256" | "md5" | "sha1" => Some(s2o_ioc::IocKind::Hash),
        "url" | "uri" => Some(s2o_ioc::IocKind::Url),
        _ => None,
    }
}

fn parse_ioc_severity(s: Option<&str>) -> s2o_ioc::IocSeverity {
    match s.map(|x| x.to_ascii_lowercase()).as_deref() {
        Some("critical") => s2o_ioc::IocSeverity::Critical,
        Some("high") => s2o_ioc::IocSeverity::High,
        Some("low") => s2o_ioc::IocSeverity::Low,
        _ => s2o_ioc::IocSeverity::Medium,
    }
}

fn playbook_ioc_upsert(
    kind: s2o_ioc::IocKind,
    value: &str,
    source: &str,
    severity: s2o_ioc::IocSeverity,
    note: Option<String>,
) -> Result<bool, Box<dyn std::error::Error>> {
    let path = Path::new(".aegis/ioc-store.json");
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let mut store = s2o_ioc::IocStore::load(path)?;
    let inserted = store.upsert(s2o_ioc::IocEntry {
        kind,
        value: value.into(),
        source: source.into(),
        severity,
        note,
        added_at: chrono::Utc::now(),
    });
    store.save(path)?;
    Ok(inserted)
}

fn zip_dir(src_dir: &Path, zip_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::{Read, Write};
    use walkdir::WalkDir;
    use zip::write::FileOptions;
    use zip::ZipWriter;

    if let Some(p) = zip_path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let file = File::create(zip_path)?;
    let mut zip = ZipWriter::new(file);
    let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    let src_dir = src_dir.canonicalize().unwrap_or_else(|_| src_dir.to_path_buf());

    for entry in WalkDir::new(&src_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            continue;
        }
        let rel = path.strip_prefix(&src_dir).unwrap_or(path);
        let name = rel.to_string_lossy().replace('\\', "/");
        zip.start_file(name, options)?;
        let mut f = File::open(path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        zip.write_all(&buf)?;
    }
    zip.finish()?;
    Ok(())
}

fn unzip_to(zip_path: &Path, dest: &Path, force: bool) -> Result<usize, Box<dyn std::error::Error>> {
    use std::fs::File;
    let file = File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    let mut n = 0usize;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(p) => dest.join(p),
            None => continue,
        };
        if file.name().ends_with('/') {
            std::fs::create_dir_all(&outpath)?;
            continue;
        }
        if outpath.exists() && !force {
            continue;
        }
        if let Some(p) = outpath.parent() {
            std::fs::create_dir_all(p)?;
        }
        let mut outfile = File::create(&outpath)?;
        std::io::copy(&mut file, &mut outfile)?;
        n += 1;
    }
    Ok(n)
}

async fn run_playbook_actions(
    rule: &PlaybookRule,
    ev: &AegisEvent,
    apply: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    for act in &rule.then {
        match act.action_type.as_str() {
            "log" => {
                println!("    -> log (ok)");
            }
            "dns_block_attr" => {
                let key = act.attr.as_deref().unwrap_or("domain");
                let domain = ev
                    .attrs
                    .get(key)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| act.domain.clone());
                match domain {
                    Some(d) if apply => {
                        append_dns_block(&d)?;
                        println!("    -> dns_block {d} APPLIED");
                    }
                    Some(d) => {
                        println!("    -> dns_block {d} (dry-run)");
                    }
                    None => println!("    -> dns_block skipped (no domain)"),
                }
            }
            "dns_block" => {
                if let Some(d) = &act.domain {
                    if apply {
                        append_dns_block(d)?;
                        println!("    -> dns_block {d} APPLIED");
                    } else {
                        println!("    -> dns_block {d} (dry-run)");
                    }
                }
            }
            "dns_allow_attr" => {
                let key = act.attr.as_deref().unwrap_or("domain");
                let domain = ev
                    .attrs
                    .get(key)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| act.domain.clone());
                match domain {
                    Some(d) if apply => {
                        append_dns_allow(&d)?;
                        println!("    -> dns_allow {d} APPLIED");
                    }
                    Some(d) => println!("    -> dns_allow {d} (dry-run)"),
                    None => println!("    -> dns_allow skipped (no domain)"),
                }
            }
            "dns_allow" => {
                if let Some(d) = &act.domain {
                    if apply {
                        append_dns_allow(d)?;
                        println!("    -> dns_allow {d} APPLIED");
                    } else {
                        println!("    -> dns_allow {d} (dry-run)");
                    }
                }
            }
            "emit" => {
                let tmpl = act
                    .message
                    .clone()
                    .unwrap_or_else(|| "playbook matched: {message}".into());
                let msg = tmpl.replace("{message}", &ev.message);
                let severity = act
                    .severity
                    .as_deref()
                    .and_then(s2o_schema::Severity::parse_loose)
                    .unwrap_or(s2o_schema::Severity::Info);
                let product = act
                    .product
                    .as_deref()
                    .and_then(s2o_schema::ProductId::parse_loose)
                    .unwrap_or(s2o_schema::ProductId::Aegis);
                if apply {
                    let path = Path::new(".aegis/events.jsonl");
                    if let Some(p) = path.parent() {
                        std::fs::create_dir_all(p)?;
                    }
                    let store = EventStore::open(path)?;
                    let out = AegisEvent::new(
                        s2o_kernel::host_id(),
                        product,
                        s2o_schema::EventKind::Alert,
                        s2o_schema::EventAction::Observed,
                        severity,
                        msg.clone(),
                    )
                    .with_attr("playbook", serde_json::json!(rule.name))
                    .with_attr("source_event", serde_json::json!(ev.id.to_string()));
                    store.append(&out)?;
                    println!("    -> emit APPLIED ({msg})");
                } else {
                    println!("    -> emit (dry-run) {msg}");
                }
            }
            "webhook" => {
                let url = act.url.clone().unwrap_or_default();
                if url.is_empty() {
                    println!("    -> webhook skipped (no url)");
                } else if apply {
                    let body = serde_json::json!({
                        "rule": rule.name,
                        "event_id": ev.id.to_string(),
                        "product": ev.product.as_str(),
                        "action": format!("{:?}", ev.action),
                        "severity": format!("{:?}", ev.severity),
                        "message": ev.message,
                        "attrs": ev.attrs,
                        "host_id": ev.host_id,
                        "ts": ev.ts.to_rfc3339(),
                    });
                    match reqwest::Client::new()
                        .post(&url)
                        .json(&body)
                        .timeout(std::time::Duration::from_secs(5))
                        .send()
                        .await
                    {
                        Ok(r) => println!("    -> webhook {} status={}", url, r.status()),
                        Err(e) => println!("    -> webhook {} ERROR {e}", url),
                    }
                } else {
                    println!("    -> webhook {url} (dry-run)");
                }
            }
            "ioc_add" => {
                let kind_s = act.kind.as_deref().unwrap_or("domain");
                let Some(kind) = parse_ioc_kind(kind_s) else {
                    println!("    -> ioc_add skipped (bad kind {kind_s})");
                    continue;
                };
                let value = act
                    .value
                    .clone()
                    .or_else(|| act.domain.clone())
                    .unwrap_or_default();
                if value.trim().is_empty() {
                    println!("    -> ioc_add skipped (no value)");
                    continue;
                }
                let source = act.source.as_deref().unwrap_or("playbook");
                let sev = parse_ioc_severity(act.severity.as_deref());
                if apply {
                    match playbook_ioc_upsert(
                        kind,
                        &value,
                        source,
                        sev,
                        Some(format!("playbook:{}", rule.name)),
                    ) {
                        Ok(true) => println!("    -> ioc_add {kind_s}:{value} APPLIED"),
                        Ok(false) => println!("    -> ioc_add {kind_s}:{value} (already present)"),
                        Err(e) => println!("    -> ioc_add ERROR {e}"),
                    }
                } else {
                    println!("    -> ioc_add {kind_s}:{value} (dry-run)");
                }
            }
            "ioc_add_attr" => {
                let key = act.attr.as_deref().unwrap_or("domain");
                let value = ev
                    .attrs
                    .get(key)
                    .and_then(|v| {
                        v.as_str()
                            .map(|s| s.to_string())
                            .or_else(|| Some(v.to_string().trim_matches('"').to_string()))
                    })
                    .or_else(|| act.value.clone())
                    .or_else(|| act.domain.clone());
                let Some(value) = value.filter(|v| !v.trim().is_empty()) else {
                    println!("    -> ioc_add_attr skipped (no attr {key})");
                    continue;
                };
                let kind_s = act.kind.as_deref().unwrap_or(if key == "ip" || key == "remote_ip" {
                    "ip"
                } else if key == "hash" || key == "sha256" {
                    "hash"
                } else if key == "url" {
                    "url"
                } else {
                    "domain"
                });
                let Some(kind) = parse_ioc_kind(kind_s) else {
                    println!("    -> ioc_add_attr skipped (bad kind {kind_s})");
                    continue;
                };
                let source = act.source.as_deref().unwrap_or("playbook");
                let sev = parse_ioc_severity(act.severity.as_deref());
                if apply {
                    match playbook_ioc_upsert(
                        kind,
                        &value,
                        source,
                        sev,
                        Some(format!("playbook:{} attr={}", rule.name, key)),
                    ) {
                        Ok(true) => {
                            println!("    -> ioc_add_attr {kind_s}:{value} APPLIED")
                        }
                        Ok(false) => {
                            println!("    -> ioc_add_attr {kind_s}:{value} (already present)")
                        }
                        Err(e) => println!("    -> ioc_add_attr ERROR {e}"),
                    }
                } else {
                    println!("    -> ioc_add_attr {kind_s}:{value} (dry-run)");
                }
            }
            "session_revoke" => {
                let tok = act
                    .token
                    .clone()
                    .or_else(|| act.value.clone())
                    .unwrap_or_default();
                if tok.trim().is_empty() {
                    println!("    -> session_revoke skipped (no token)");
                    continue;
                }
                if apply {
                    let path = Path::new(".aegis/sessions.json");
                    let mut store = s2o_session::SessionStore::load(path);
                    if store.revoke_token(&tok) {
                        store.save(path)?;
                        println!("    -> session_revoke APPLIED");
                    } else {
                        println!("    -> session_revoke token not found");
                    }
                } else {
                    println!(
                        "    -> session_revoke (dry-run) {}",
                        &tok[..tok.len().min(16)]
                    );
                }
            }
            "session_revoke_user" => {
                let user = act.user.clone().or_else(|| act.value.clone()).unwrap_or_default();
                if user.trim().is_empty() {
                    println!("    -> session_revoke_user skipped (no user)");
                    continue;
                }
                if apply {
                    let path = Path::new(".aegis/sessions.json");
                    let mut store = s2o_session::SessionStore::load(path);
                    let n = store.revoke_user(&user);
                    store.save(path)?;
                    println!("    -> session_revoke_user {user} APPLIED n={n}");
                } else {
                    println!("    -> session_revoke_user {user} (dry-run)");
                }
            }
            "session_revoke_attr" => {
                let key = act.attr.as_deref().unwrap_or("user");
                let value = ev
                    .attrs
                    .get(key)
                    .and_then(|v| {
                        v.as_str()
                            .map(|s| s.to_string())
                            .or_else(|| Some(v.to_string().trim_matches('"').to_string()))
                    })
                    .or_else(|| act.user.clone())
                    .or_else(|| act.value.clone());
                let Some(value) = value.filter(|v| !v.trim().is_empty()) else {
                    println!("    -> session_revoke_attr skipped (no attr {key})");
                    continue;
                };
                // token-like attrs revoke by token; otherwise by user
                let by_token = key.eq_ignore_ascii_case("token")
                    || key.eq_ignore_ascii_case("session")
                    || key.eq_ignore_ascii_case("session_token");
                if apply {
                    let path = Path::new(".aegis/sessions.json");
                    let mut store = s2o_session::SessionStore::load(path);
                    if by_token {
                        if store.revoke_token(&value) {
                            store.save(path)?;
                            println!("    -> session_revoke_attr token APPLIED");
                        } else {
                            println!("    -> session_revoke_attr token not found");
                        }
                    } else {
                        let n = store.revoke_user(&value);
                        store.save(path)?;
                        println!("    -> session_revoke_attr user={value} APPLIED n={n}");
                    }
                } else {
                    println!(
                        "    -> session_revoke_attr {}={} (dry-run)",
                        if by_token { "token" } else { "user" },
                        value
                    );
                }
            }
            other => println!("    -> unknown action {other}"),
        }
    }
    Ok(())
}

fn append_dns_allow(domain: &str) -> std::io::Result<()> {
    let path = Path::new(".aegis/dns-allowlist.txt");
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() {
        return Ok(());
    }
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    if existing.lines().any(|l| {
        l.split('#').next().unwrap_or("").trim().eq_ignore_ascii_case(&d)
    }) {
        return Ok(());
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    if existing.is_empty() {
        writeln!(f, "# S2O CyberDNS local allowlist")?;
    }
    writeln!(f, "{d}")?;
    Ok(())
}

fn append_dns_block(domain: &str) -> std::io::Result<()> {
    let path = Path::new(".aegis/dns-blocklist.txt");
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() {
        return Ok(());
    }
    let existing = if path.exists() {
        std::fs::read_to_string(path)?
    } else {
        String::new()
    };
    if existing.lines().any(|l| l.trim().eq_ignore_ascii_case(&d)) {
        return Ok(());
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{d}")?;
    Ok(())
}

fn find_product_bin(name: &str) -> Option<PathBuf> {
    let suffixes = ["", ".exe"];
    let candidates = [
        format!("target/debug/{name}"),
        format!("target/release/{name}"),
        name.to_string(),
    ];
    for c in &candidates {
        for suf in &suffixes {
            let p = PathBuf::from(format!("{c}{suf}"));
            if p.exists() {
                return Some(p);
            }
        }
    }
    None
}

fn resolve_aegisd_bin(explicit: Option<PathBuf>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        if p.exists() {
            return Some(p);
        }
    }
    find_product_bin("aegisd")
}

fn sc_query(name: &str) -> Option<String> {
    let out = Command::new("sc").args(["query", name]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    if out.status.success() || text.contains("STATE") {
        Some(text)
    } else {
        None
    }
}

fn run_sc(args: &[&str]) -> Result<(i32, String, String), Box<dyn std::error::Error>> {
    let out = Command::new("sc").args(args).output()?;
    let code = out.status.code().unwrap_or(1);
    Ok((
        code,
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    ))
}

async fn build_local_heartbeat(
    fw: &s2o_kernel::FirewallEngineHandle,
    host_override: Option<String>,
    name: Option<String>,
    tags: Vec<String>,
    policy_version: Option<u64>,
) -> Result<HeartbeatPayload, Box<dyn std::error::Error>> {
    let st = collect_platform_status(fw).await;
    let posture = compute_posture_score(fw).await?;
    let mut implemented = 0u32;
    let mut partial = 0u32;
    let mut other = 0u32;
    for m in &st.modules {
        match m.state.as_str() {
            "implemented" => implemented += 1,
            "partial" => partial += 1,
            _ => other += 1,
        }
    }
    let hid = host_override.unwrap_or_else(host_id);
    Ok(HeartbeatPayload {
        host_id: hid.clone(),
        display_name: Some(name.unwrap_or_else(|| hid.clone())),
        os: Some(st.os.as_str().to_string()),
        phase: Some(st.phase.clone()),
        kernel: Some(KERNEL_VERSION.to_string()),
        posture_score: Some(posture.score),
        modules_implemented: Some(implemented),
        modules_partial: Some(partial),
        modules_other: Some(other),
        tags: if tags.is_empty() { None } else { Some(tags) },
        last_ip: None,
        policy_version,
    })
}

fn local_policy_version(policy_path: &Path) -> u64 {
    FleetPolicyBundle::load(policy_path)
        .map(|b| b.version)
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let fw = create_firewall_engine();

    match cli.command {
        Commands::Version { json } => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "aegis_cli": "0.1.0",
                        "kernel": KERNEL_VERSION,
                        "schema": SCHEMA_VERSION,
                        "phase": PHASE_LABEL,
                        "tier_ceiling": TIER_CEILING.as_str(),
                    }))?
                );
            } else {
                println!("aegis-cli          0.1.0");
                println!("s2o-kernel         {KERNEL_VERSION}");
                println!("s2o-schema         {SCHEMA_VERSION}");
                println!("phase              {PHASE_LABEL}");
                println!("tier_ceiling       {}", TIER_CEILING.as_str());
            }
        }
        Commands::Status { json } => {
            let status = collect_platform_status(&fw).await;
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(
                    "{}",
                    "    S2O AEGIS  (operator front door)                      "
                        .bold()
                        .green()
                );
                println!(
                    "{}",
                    "=========================================================".cyan()
                );
                println!(" Phase        : {}", status.phase);
                println!(" OS           : {}", status.os.as_str());
                println!(" Tier ceiling : {}", status.tier_ceiling.as_str());
                println!(" Host         : {}", status.host_id);
                println!(
                    " Demo mode    : {}",
                    if status.demo_mode { "ON" } else { "OFF" }
                );
                println!(
                    "{}",
                    "---------------------------------------------------------".cyan()
                );
                for m in &status.modules {
                    let state_col = match m.state {
                        HealthState::Implemented => m.state.as_str().green().bold(),
                        HealthState::Partial => m.state.as_str().yellow().bold(),
                        HealthState::Demo => m.state.as_str().yellow().bold(),
                        HealthState::Degraded => m.state.as_str().red().bold(),
                        _ => m.state.as_str().red(),
                    };
                    println!(" {:<16} {}", m.id.bold(), state_col);
                    println!("                  {}", m.detail);
                }
            }
        }
        Commands::Health {
            url,
            status,
            metrics,
            json,
            timeout_secs,
        } => {
            let base = url.trim_end_matches('/');
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(timeout_secs.max(1)))
                .build()?;
            let health_url = format!("{base}/health");
            let started = std::time::Instant::now();
            let health_res = client.get(&health_url).send().await;
            let ms = started.elapsed().as_millis() as u64;

            let (health_ok, health_code, health_body) = match health_res {
                Ok(r) => {
                    let code = r.status().as_u16();
                    let body = r.text().await.unwrap_or_default();
                    (code == 200, code, body)
                }
                Err(e) => (false, 0, e.to_string()),
            };

            let mut status_body = None;
            let mut status_code = 0u16;
            if status {
                let u = format!("{base}/status");
                match client.get(&u).send().await {
                    Ok(r) => {
                        status_code = r.status().as_u16();
                        status_body = Some(r.text().await.unwrap_or_default());
                    }
                    Err(e) => {
                        status_body = Some(e.to_string());
                    }
                }
            }

            let mut metrics_body = None;
            let mut metrics_code = 0u16;
            if metrics {
                let u = format!("{base}/metrics");
                match client.get(&u).send().await {
                    Ok(r) => {
                        metrics_code = r.status().as_u16();
                        metrics_body = Some(r.text().await.unwrap_or_default());
                    }
                    Err(e) => {
                        metrics_body = Some(e.to_string());
                    }
                }
            }

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "base": base,
                        "health": {
                            "url": health_url,
                            "ok": health_ok,
                            "status": health_code,
                            "latency_ms": ms,
                            "body": health_body,
                        },
                        "status": status_body.as_ref().map(|b| serde_json::json!({
                            "status": status_code,
                            "body": b,
                        })),
                        "metrics": metrics_body.as_ref().map(|b| serde_json::json!({
                            "status": metrics_code,
                            "body_preview": b.lines().take(20).collect::<Vec<_>>().join("\n"),
                        })),
                    }))?
                );
            } else {
                println!("{}", "Aegis health probe".bold().green());
                println!(" Base   : {base}");
                if health_ok {
                    println!(
                        " {} /health — HTTP {health_code} ({}ms) {}",
                        "OK".green().bold(),
                        ms,
                        health_body.trim().chars().take(80).collect::<String>()
                    );
                } else {
                    println!(
                        " {} /health — {} ({}ms) {}",
                        "FAIL".red().bold(),
                        if health_code == 0 {
                            "unreachable".into()
                        } else {
                            format!("HTTP {health_code}")
                        },
                        ms,
                        health_body.chars().take(120).collect::<String>()
                    );
                    println!(
                        " {}",
                        "Hint: cargo run -p aegisd -- start".dimmed()
                    );
                }
                if let Some(body) = &status_body {
                    if status_code == 200 {
                        println!(
                            " {} /status — HTTP {status_code}",
                            "OK".green().bold()
                        );
                        // show compact host/phase if JSON
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
                            if let Some(h) = v.get("host_id").and_then(|x| x.as_str()) {
                                println!("   host_id : {h}");
                            }
                            if let Some(p) = v.get("phase").and_then(|x| x.as_str()) {
                                println!("   phase   : {p}");
                            }
                        }
                    } else {
                        println!(
                            " {} /status — HTTP {status_code} {}",
                            "FAIL".red().bold(),
                            body.chars().take(80).collect::<String>()
                        );
                    }
                }
                if let Some(body) = &metrics_body {
                    if metrics_code == 200 {
                        println!(
                            " {} /metrics — HTTP {metrics_code}",
                            "OK".green().bold()
                        );
                        for line in body.lines().take(8) {
                            println!("   {line}");
                        }
                    } else {
                        println!(
                            " {} /metrics — HTTP {metrics_code}",
                            "FAIL".red().bold()
                        );
                    }
                }
            }
            if !health_ok {
                std::process::exit(1);
            }
        }
        Commands::Doctor { json } => {
            let mut ok = 0u32;
            let mut warn = 0u32;
            let mut fail = 0u32;
            let mut notes: Vec<serde_json::Value> = Vec::new();
            let mut check = |label: &str, good: bool, soft: bool, detail: &str| {
                notes.push(serde_json::json!({
                    "label": label,
                    "ok": good,
                    "warn": soft && !good,
                    "detail": detail,
                }));
                if good {
                    ok += 1;
                    if !json {
                        println!("  {} {} — {}", "OK".green().bold(), label, detail);
                    }
                } else if soft {
                    warn += 1;
                    if !json {
                        println!("  {} {} — {}", "WARN".yellow().bold(), label, detail);
                    }
                } else {
                    fail += 1;
                    if !json {
                        println!("  {} {} — {}", "FAIL".red().bold(), label, detail);
                    }
                }
            };

            if !json {
                println!("{}", "Aegis suite doctor".bold().green());
                println!(
                    " kernel={} schema={} phase={} tier={}",
                    KERNEL_VERSION,
                    SCHEMA_VERSION,
                    PHASE_LABEL,
                    TIER_CEILING.as_str()
                );
                println!(
                    " host={} demo={}",
                    host_id(),
                    if demo_mode() { "ON" } else { "OFF" }
                );
            }

            let status = collect_platform_status(&fw).await;
            let by_state = {
                let mut m = std::collections::BTreeMap::new();
                for modu in &status.modules {
                    *m.entry(modu.state.as_str().to_string()).or_insert(0u32) += 1;
                }
                m
            };
            check(
                "module matrix",
                !status.modules.is_empty(),
                false,
                &format!(
                    "{} modules ({})",
                    status.modules.len(),
                    by_state
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
            );
            for m in &status.modules {
                let (good, soft) = match m.state.as_str() {
                    "implemented" => (true, false),
                    "partial" => (true, false),
                    "demo" => (true, true),
                    "degraded" => (false, true),
                    // not_implemented / unsupported_on_os — expected gaps, warn only
                    _ => (false, true),
                };
                check(
                    &format!("module {}", m.id),
                    good,
                    soft,
                    &format!("{} — {}", m.state.as_str(), m.detail.replace('\n', " ")),
                );
            }

            let event_log = PathBuf::from(".aegis/events.jsonl");
            if event_log.exists() {
                match EventStore::open(&event_log) {
                    Ok(store) => {
                        let n = store.count().unwrap_or(0);
                        let b = store.len_bytes().unwrap_or(0);
                        check(
                            "event log",
                            true,
                            false,
                            &format!("{} ({} events, {} bytes)", event_log.display(), n, b),
                        );
                    }
                    Err(e) => check("event log", false, false, &format!("open error: {e}")),
                }
            } else {
                check(
                    "event log",
                    false,
                    true,
                    &format!("{} missing", event_log.display()),
                );
            }

            let data_checks = [
                (".aegis/dns-blocklist.txt", true),
                (".aegis/ioc-store.json", true),
                (".aegis/playbooks.json", true),
                (".aegis/gate-routes.json", true),
                (".aegis/fleet.json", true),
                (".aegis/sessions.json", true),
                (".aegis/config.json", true),
            ];
            for (p, soft_missing) in data_checks {
                let path = Path::new(p);
                check(
                    p,
                    path.exists(),
                    soft_missing,
                    if path.exists() { "present" } else { "missing" },
                );
            }

            let fleet = s2o_fleet::FleetStore::load(Path::new(".aegis/fleet.json"));
            let fsum = fleet.summary(60);
            check(
                "fleet roster",
                fsum.total > 0,
                true,
                &format!(
                    "{} hosts (online={} stale@60m={})",
                    fsum.total, fsum.online, fsum.stale
                ),
            );

            let posture = compute_posture_score(&fw).await?;
            check(
                "posture@50",
                posture.passes(50),
                true,
                &format!("{}/{}", posture.score, posture.max_score),
            );

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": fail == 0,
                        "ok_count": ok,
                        "warn_count": warn,
                        "fail_count": fail,
                        "kernel_version": KERNEL_VERSION,
                        "schema_version": SCHEMA_VERSION,
                        "phase": PHASE_LABEL,
                        "host_id": host_id(),
                        "module_state_counts": by_state,
                        "posture_score": posture.score,
                        "fleet_hosts": fsum.total,
                        "checks": notes,
                    }))?
                );
            } else {
                println!(
                    " Summary: {} ok, {} warn, {} fail",
                    ok.to_string().green(),
                    warn.to_string().yellow(),
                    fail.to_string().red()
                );
                println!(
                    " {}",
                    "Tip: cyberwall/dns/edr/defender/gate/mesh doctor for world-depth checks."
                        .dimmed()
                );
            }
            if fail > 0 {
                std::process::exit(1);
            }
        }
        Commands::Report { json, out } => {
            let status = collect_platform_status(&fw).await;
            let posture = compute_posture_score(&fw).await?;
            let event_log = PathBuf::from(".aegis/events.jsonl");
            let event_count = if event_log.exists() {
                EventStore::open(&event_log)?.count().unwrap_or(0)
            } else {
                0
            };
            let event_bytes = if event_log.exists() {
                EventStore::open(&event_log)?.len_bytes().unwrap_or(0)
            } else {
                0
            };
            // Suite inventory (file-backed; honest counts only)
            let ioc_path = Path::new(".aegis/ioc-store.json");
            let ioc_count = if ioc_path.exists() {
                std::fs::read_to_string(ioc_path)
                    .ok()
                    .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
                    .and_then(|v| v.get("entries").and_then(|e| e.as_array()).map(|a| a.len()))
                    .unwrap_or(0)
            } else {
                0
            };
            let fleet = s2o_fleet::FleetStore::load(Path::new(".aegis/fleet.json"));
            let fleet_summary = fleet.summary(60);
            let sessions = s2o_session::SessionStore::load(Path::new(".aegis/sessions.json"));
            let session_total = sessions.sessions.len();
            let session_active = sessions.active().count();
            let mesh_peers = {
                let p = Path::new(".aegis/mesh-peers.json");
                if p.exists() {
                    std::fs::read_to_string(p)
                        .ok()
                        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
                        .and_then(|v| v.get("peers").and_then(|e| e.as_array()).map(|a| a.len()))
                        .unwrap_or(0)
                } else {
                    0
                }
            };
            let quarantine_dir = Path::new(".aegis/quarantine");
            let quarantine_files = if quarantine_dir.is_dir() {
                std::fs::read_dir(quarantine_dir)
                    .map(|rd| {
                        rd.filter_map(|e| e.ok())
                            .filter(|e| {
                                let n = e.file_name().to_string_lossy().to_string();
                                e.path().is_file() && !n.ends_with(".meta.json")
                            })
                            .count()
                    })
                    .unwrap_or(0)
            } else {
                0
            };
            let gate_access = Path::new(".aegis/gate-access.log");
            let gate_access_lines = if gate_access.exists() {
                std::fs::read_to_string(gate_access)
                    .map(|t| t.lines().filter(|l| !l.trim().is_empty()).count())
                    .unwrap_or(0)
            } else {
                0
            };
            let dns_block_lines = {
                let p = Path::new(".aegis/dns-blocklist.txt");
                if p.exists() {
                    std::fs::read_to_string(p)
                        .map(|t| {
                            t.lines()
                                .filter(|l| {
                                    let s = l.split('#').next().unwrap_or("").trim();
                                    !s.is_empty()
                                })
                                .count()
                        })
                        .unwrap_or(0)
                } else {
                    0
                }
            };
            let dns_allow_lines = {
                let p = Path::new(".aegis/dns-allowlist.txt");
                if p.exists() {
                    std::fs::read_to_string(p)
                        .map(|t| {
                            t.lines()
                                .filter(|l| {
                                    let s = l.split('#').next().unwrap_or("").trim();
                                    !s.is_empty()
                                })
                                .count()
                        })
                        .unwrap_or(0)
                } else {
                    0
                }
            };
            let inventory = serde_json::json!({
                "ioc_entries": ioc_count,
                "fleet_hosts": fleet_summary.total,
                "fleet_stale": fleet_summary.stale,
                "sessions_total": session_total,
                "sessions_active": session_active,
                "mesh_peers": mesh_peers,
                "quarantine_files": quarantine_files,
                "gate_access_lines": gate_access_lines,
                "dns_blocklist_entries": dns_block_lines,
                "dns_allowlist_entries": dns_allow_lines,
            });
            let files = [
                (".aegis/events.jsonl", event_log.exists()),
                (".aegis/dns-blocklist.txt", Path::new(".aegis/dns-blocklist.txt").exists()),
                (".aegis/dns-allowlist.txt", Path::new(".aegis/dns-allowlist.txt").exists()),
                (".aegis/ioc-store.json", Path::new(".aegis/ioc-store.json").exists()),
                (".aegis/gate-routes.json", Path::new(".aegis/gate-routes.json").exists()),
                (".aegis/gate-access.log", gate_access.exists()),
                (".aegis/wg0.conf", Path::new(".aegis/wg0.conf").exists()),
                (".aegis/mesh-peers.json", Path::new(".aegis/mesh-peers.json").exists()),
                (".aegis/defender-rules.json", Path::new(".aegis/defender-rules.json").exists()),
                (".aegis/fleet.json", Path::new(".aegis/fleet.json").exists()),
                (".aegis/sessions.json", Path::new(".aegis/sessions.json").exists()),
                (".aegis/quarantine", quarantine_dir.is_dir()),
            ];
            let by_state = {
                let mut m = std::collections::BTreeMap::new();
                for modu in &status.modules {
                    *m.entry(modu.state.as_str().to_string()).or_insert(0u32) += 1;
                }
                m
            };
            let report = serde_json::json!({
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "platform": status,
                "posture": posture,
                "event_log": {
                    "path": event_log.display().to_string(),
                    "events": event_count,
                    "bytes": event_bytes,
                },
                "inventory": inventory,
                "data_files": files.iter().map(|(p, ok)| serde_json::json!({"path": p, "present": ok})).collect::<Vec<_>>(),
                "module_state_counts": by_state,
                "kernel_version": KERNEL_VERSION,
                "schema_version": SCHEMA_VERSION,
                "phase": PHASE_LABEL,
                "tier_ceiling": TIER_CEILING.as_str(),
            });
            let text = if json {
                serde_json::to_string_pretty(&report)?
            } else {
                let mut md = String::new();
                md.push_str("# S2O Aegis Audit Report\n\n");
                md.push_str(&format!("- **Host:** {}\n", status.host_id));
                md.push_str(&format!("- **OS:** {}\n", status.os.as_str()));
                md.push_str(&format!("- **Phase:** {}\n", status.phase));
                md.push_str(&format!("- **Tier:** {}\n", status.tier_ceiling.as_str()));
                md.push_str(&format!(
                    "- **Posture:** {} / {} {}\n",
                    posture.score,
                    posture.max_score,
                    if posture.passes(50) { "PASS@50" } else { "BELOW 50" }
                ));
                md.push_str(&format!("- **Events:** {event_count} ({event_bytes} bytes)\n\n"));
                md.push_str("## Suite inventory\n\n");
                md.push_str(&format!("- IOC entries: {ioc_count}\n"));
                md.push_str(&format!(
                    "- Fleet hosts: {} (stale@60m: {})\n",
                    fleet_summary.total, fleet_summary.stale
                ));
                md.push_str(&format!(
                    "- Sessions: {session_total} total / {session_active} active\n"
                ));
                md.push_str(&format!("- Mesh peers: {mesh_peers}\n"));
                md.push_str(&format!("- Quarantine files: {quarantine_files}\n"));
                md.push_str(&format!("- Gate access log lines: {gate_access_lines}\n"));
                md.push_str(&format!(
                    "- DNS blocklist / allowlist: {dns_block_lines} / {dns_allow_lines}\n\n"
                ));
                md.push_str("## Modules\n\n");
                md.push_str("| ID | State | Detail |\n|----|-------|--------|\n");
                for m in &status.modules {
                    md.push_str(&format!(
                        "| {} | {} | {} |\n",
                        m.id,
                        m.state.as_str(),
                        m.detail.replace('|', "/")
                    ));
                }
                md.push_str("\n## Data files\n\n");
                for (p, ok) in &files {
                    md.push_str(&format!(
                        "- `{}`: {}\n",
                        p,
                        if *ok { "present" } else { "missing" }
                    ));
                }
                md.push_str("\n## Posture checks\n\n");
                for c in &posture.checks {
                    md.push_str(&format!(
                        "- [{}] **{}** ({}) — {}\n",
                        if c.pass { "PASS" } else { "FAIL" },
                        c.id,
                        c.weight,
                        c.detail
                    ));
                }
                md
            };
            if let Some(path) = out {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&path, &text)?;
                eprintln!("[aegis] wrote {}", path.display());
            }
            print!("{text}");
            if !text.ends_with('\n') {
                println!();
            }
        }
        Commands::Policy { command } => match command {
            PolicyCmd::Example { kind } => {
                let doc = if kind.eq_ignore_ascii_case("wall") {
                    PolicyDocument::example_wall_enable()
                } else {
                    PolicyDocument::example_edge_pack()
                };
                println!("{}", serde_json::to_string_pretty(&doc)?);
            }
            PolicyCmd::Validate { path, json } => {
                use s2o_schema::POLICY_SCHEMA_VERSION;
                let mut issues: Vec<String> = Vec::new();
                let mut warns: Vec<String> = Vec::new();
                if !path.exists() {
                    eprintln!("[aegis] missing policy file {}", path.display());
                    std::process::exit(2);
                }
                let text = std::fs::read_to_string(&path)?;
                let doc: PolicyDocument = match serde_json::from_str(&text) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("[aegis] policy JSON invalid: {e}");
                        std::process::exit(2);
                    }
                };
                if doc.name.trim().is_empty() {
                    issues.push("name is empty".into());
                }
                if doc.schema_version.is_empty() {
                    issues.push("schema_version is empty".into());
                } else if !doc.schema_version.starts_with('0')
                    && doc.schema_version != POLICY_SCHEMA_VERSION
                {
                    warns.push(format!(
                        "schema_version '{}' (suite expects {})",
                        doc.schema_version, POLICY_SCHEMA_VERSION
                    ));
                }
                let mut fragments = 0u32;
                if let Some(ref fw) = doc.firewall {
                    fragments += 1;
                    if fw.enabled.is_none()
                        && fw.outbound_block.is_none()
                        && fw.rules.is_empty()
                    {
                        warns.push("firewall: empty intent (no enabled/outbound/rules)".into());
                    }
                    for (i, r) in fw.rules.iter().enumerate() {
                        if r.name.trim().is_empty() {
                            issues.push(format!("firewall.rules[{i}]: empty name"));
                        }
                        let act = r.action.to_ascii_lowercase();
                        if act != "allow" && act != "block" {
                            issues.push(format!(
                                "firewall.rules[{i}]: action must be allow|block (got {})",
                                r.action
                            ));
                        }
                    }
                }
                if let Some(ref dns) = doc.dns {
                    fragments += 1;
                    let bl = dns
                        .blocklist_path
                        .as_deref()
                        .unwrap_or(".aegis/dns-blocklist.txt");
                    if !Path::new(bl).exists()
                        && dns.block_domains.is_empty()
                        && dns.allow_domains.is_empty()
                    {
                        warns.push(format!(
                            "dns: blocklist path '{bl}' missing and no domains listed"
                        ));
                    }
                    for d in dns
                        .block_domains
                        .iter()
                        .chain(dns.allow_domains.iter())
                    {
                        if d.trim().is_empty() {
                            issues.push("dns: empty domain entry".into());
                        }
                    }
                }
                if let Some(ref intel) = doc.intel {
                    fragments += 1;
                    if intel.sync_blocklist {
                        let bl = intel
                            .blocklist_path
                            .as_deref()
                            .unwrap_or(".aegis/dns-blocklist.txt");
                        if !Path::new(bl).exists() {
                            warns.push(format!(
                                "intel: sync_blocklist true but '{bl}' missing"
                            ));
                        }
                    }
                }
                if let Some(ref p) = doc.posture {
                    fragments += 1;
                    if let Some(ms) = p.min_score {
                        if ms > 100 {
                            issues.push(format!("posture.min_score {ms} > 100"));
                        }
                    }
                }
                if let Some(ref g) = doc.gate {
                    fragments += 1;
                    if let Some(ms) = g.min_score {
                        if ms > 100 {
                            issues.push(format!("gate.min_score {ms} > 100"));
                        }
                    }
                    if let Some(ref cp) = g.config_path {
                        if !Path::new(cp).exists() {
                            warns.push(format!(
                                "gate.config_path '{cp}' missing (created on gate init/serve)"
                            ));
                        }
                    }
                }
                if fragments == 0 {
                    issues.push("no policy fragments (firewall/dns/intel/posture/gate)".into());
                }
                let ok = issues.is_empty();
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "path": path.display().to_string(),
                            "ok": ok,
                            "name": doc.name,
                            "schema_version": doc.schema_version,
                            "fragments": fragments,
                            "issues": issues,
                            "warnings": warns,
                        }))?
                    );
                } else {
                    println!(
                        "[aegis] policy validate {} name={} fragments={fragments}",
                        path.display(),
                        doc.name
                    );
                    for w in &warns {
                        println!("  {} {w}", "WARN".yellow().bold());
                    }
                    if ok {
                        println!("{}", "  OK — no blocking issues".green().bold());
                    } else {
                        for i in &issues {
                            println!("  {} {i}", "ISSUE".red().bold());
                        }
                    }
                }
                if !ok {
                    std::process::exit(3);
                }
            }
            PolicyCmd::Plan { path, json } => {
                if !path.exists() {
                    eprintln!("[aegis] missing policy file {}", path.display());
                    std::process::exit(2);
                }
                let doc = load_policy_file(&path)?;
                let mut steps: Vec<String> = Vec::new();
                if let Some(ref fw) = doc.firewall {
                    if let Some(en) = fw.enabled {
                        steps.push(format!("firewall.set_enabled({en})"));
                    }
                    if let Some(ob) = fw.outbound_block {
                        steps.push(format!("firewall.set_outbound_block({ob})"));
                    }
                    if !fw.rules.is_empty() {
                        steps.push(format!(
                            "firewall.apply_rules(n={}, prefix=S2O-Aegis-*)",
                            fw.rules.len()
                        ));
                        for r in fw.rules.iter().take(8) {
                            steps.push(format!(
                                "  rule name={} action={} dir={} port={:?}",
                                r.name, r.action, r.direction, r.local_port
                            ));
                        }
                        if fw.rules.len() > 8 {
                            steps.push(format!("  … +{} more rules", fw.rules.len() - 8));
                        }
                    }
                } else {
                    steps.push("firewall: (no fragment — skip)".into());
                }
                if let Some(ref dns) = doc.dns {
                    let bl = dns
                        .blocklist_path
                        .as_deref()
                        .unwrap_or(".aegis/dns-blocklist.txt");
                    if !dns.block_domains.is_empty() {
                        steps.push(format!(
                            "dns.blocklist_add({} domains) → {bl}",
                            dns.block_domains.len()
                        ));
                    }
                    if !dns.unblock_domains.is_empty() {
                        steps.push(format!(
                            "dns.blocklist_remove({} domains)",
                            dns.unblock_domains.len()
                        ));
                    }
                    if !dns.allow_domains.is_empty() {
                        steps.push(format!(
                            "dns.allowlist_add({} domains)",
                            dns.allow_domains.len()
                        ));
                    }
                    if !dns.unallow_domains.is_empty() {
                        steps.push(format!(
                            "dns.allowlist_remove({} domains)",
                            dns.unallow_domains.len()
                        ));
                    }
                    if dns.block_domains.is_empty()
                        && dns.unblock_domains.is_empty()
                        && dns.allow_domains.is_empty()
                        && dns.unallow_domains.is_empty()
                    {
                        steps.push("dns: fragment present but empty ops".into());
                    }
                } else {
                    steps.push("dns: (no fragment — skip)".into());
                }
                if let Some(ref intel) = doc.intel {
                    if intel.sync_blocklist {
                        let bl = intel
                            .blocklist_path
                            .as_deref()
                            .unwrap_or(".aegis/dns-blocklist.txt");
                        let ioc = intel
                            .ioc_store_path
                            .as_deref()
                            .unwrap_or(".aegis/ioc-store.json");
                        steps.push(format!("intel.sync_blocklist {bl} → {ioc}"));
                    } else {
                        steps.push("intel: sync_blocklist=false".into());
                    }
                } else {
                    steps.push("intel: (no fragment — skip)".into());
                }
                if let Some(ref p) = doc.posture {
                    if let Some(ms) = p.min_score {
                        steps.push(format!("posture.gate min_score={ms} (record/check only)"));
                    }
                } else {
                    steps.push("posture: (no fragment — skip)".into());
                }
                if let Some(ref g) = doc.gate {
                    let mut bits = Vec::new();
                    if let Some(ms) = g.min_score {
                        bits.push(format!("min_score={ms}"));
                    }
                    if let Some(rs) = g.require_session {
                        bits.push(format!("require_session={rs}"));
                    }
                    if let Some(rl) = g.rate_limit_per_minute {
                        bits.push(format!("rate_limit={rl}/min"));
                    }
                    if !g.allow_ips.is_empty() {
                        bits.push(format!("allow_ips={}", g.allow_ips.len()));
                    }
                    let cp = g
                        .config_path
                        .as_deref()
                        .unwrap_or(".aegis/gate-routes.json");
                    steps.push(format!("gate.update_config({}) [{}]", cp, bits.join(" ")));
                } else {
                    steps.push("gate: (no fragment — skip)".into());
                }
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "path": path.display().to_string(),
                            "name": doc.name,
                            "schema_version": doc.schema_version,
                            "description": doc.description,
                            "steps": steps,
                            "note": "plan only — no host mutation",
                        }))?
                    );
                } else {
                    println!(
                        "[aegis] policy plan {} name={}",
                        path.display(),
                        doc.name
                    );
                    if let Some(ref d) = doc.description {
                        println!("  desc: {d}");
                    }
                    println!("  (no host changes — dry plan)");
                    for s in &steps {
                        println!("  → {s}");
                    }
                    println!(
                        "  apply with: aegis policy apply {}",
                        path.display()
                    );
                }
            }
            PolicyCmd::Apply { path, event_log, json } => {
                let doc = load_policy_file(&path)?;
                let store = Arc::new(EventStore::open(&event_log)?);
                let result = apply_policy(&doc, &fw, Some(store)).await?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                } else {
                    if result.ok {
                        println!(
                            "{}",
                            format!("[aegis] policy OK: {}", result.policy_name)
                                .green()
                                .bold()
                        );
                    } else {
                        println!(
                            "{}",
                            format!("[aegis] policy incomplete: {}", result.policy_name)
                                .yellow()
                                .bold()
                        );
                    }
                    for a in &result.applied {
                        println!("  applied : {}", a.green());
                    }
                    for s in &result.skipped {
                        println!("  skipped : {}", s.dimmed());
                    }
                    for e in &result.errors {
                        println!("  error   : {}", e.red());
                    }
                }
                if !result.ok {
                    std::process::exit(1);
                }
            }
        },
        Commands::Emit {
            message,
            severity,
            product,
            kind,
            action,
            event_log,
            http,
            udp,
            no_local,
            json,
        } => {
            use s2o_schema::{
                EventAction, EventKind, ProductId, Severity,
            };
            let product = ProductId::parse_loose(&product).unwrap_or(ProductId::Aegis);
            let severity = Severity::parse_loose(&severity).unwrap_or(Severity::Info);
            let kind = EventKind::parse_loose(&kind).unwrap_or(EventKind::Alert);
            let action = EventAction::parse_loose(&action).unwrap_or(EventAction::Observed);
            let ev = s2o_schema::AegisEvent::new(
                s2o_kernel::host_id(),
                product,
                kind,
                action,
                severity,
                message,
            )
            .with_attr("source", serde_json::json!("aegis_emit"));
            let mut local_ok = false;
            if !no_local {
                if let Some(p) = event_log.parent() {
                    let _ = std::fs::create_dir_all(p);
                }
                let store = EventStore::open(&event_log)?;
                store.append(&ev)?;
                local_ok = true;
                if !json {
                    println!(
                        "{}",
                        format!(
                            "[aegis] local append id={} → {}",
                            ev.id,
                            event_log.display()
                        )
                        .green()
                    );
                }
            }
            let mut http_status: Option<String> = None;
            if let Some(url) = http {
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()?;
                let res = client.post(&url).json(&ev).send().await?;
                let status = res.status();
                let text = res.text().await.unwrap_or_default();
                http_status = Some(status.to_string());
                if status.is_success() {
                    if !json {
                        println!(
                            "{}",
                            format!("[aegis] HTTP POST {url} → {status}").green().bold()
                        );
                    }
                } else {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "ok": false,
                                "id": ev.id,
                                "error": format!("HTTP POST failed {status}: {text}"),
                                "event": ev,
                            }))?
                        );
                    } else {
                        eprintln!("[aegis] HTTP POST failed {status}: {text}");
                    }
                    std::process::exit(1);
                }
            }
            let mut udp_sent = false;
            if let Some(addr) = udp {
                s2o_bus::udp_send(&addr, &ev)?;
                udp_sent = true;
                if !json {
                    println!(
                        "{}",
                        format!("[aegis] UDP send → {addr}").green()
                    );
                }
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "id": ev.id,
                        "local": local_ok,
                        "http_status": http_status,
                        "udp": udp_sent,
                        "event": ev,
                    }))?
                );
            }
        }
        Commands::Events {
            event_log,
            limit,
            product,
            severity,
            since,
            text,
        } => {
            if !event_log.exists() {
                eprintln!("[aegis] no event log at {}", event_log.display());
                std::process::exit(1);
            }
            let store = EventStore::open(&event_log)?;
            let over = if since.is_some() || product.is_some() || severity.is_some() {
                limit.saturating_mul(50).max(limit * 5)
            } else {
                limit
            };
            let mut events = store.recent(over)?;
            if let Some(ref s) = since {
                let bound = match parse_since(s) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("[aegis] {e}");
                        std::process::exit(2);
                    }
                };
                events.retain(|e| e.ts >= bound);
            }
            if let Some(ref p) = product {
                let pf = p.to_ascii_lowercase();
                events.retain(|e| {
                    let id = e.product.as_str();
                    let name = format!("{:?}", e.product).to_ascii_lowercase();
                    id == pf || name.contains(&pf) || e.product.display_name().to_ascii_lowercase().contains(&pf)
                });
            }
            if let Some(ref s) = severity {
                events.retain(|e| format!("{:?}", e.severity).eq_ignore_ascii_case(s));
            }
            if events.len() > limit {
                events = events.split_off(events.len() - limit);
            }
            if text {
                if events.is_empty() {
                    println!("[aegis] no matching events");
                }
                for ev in &events {
                    println!(
                        "[{}] {:?} {:?} / {:?} | {}",
                        ev.ts.to_rfc3339(),
                        ev.severity,
                        ev.product,
                        ev.action,
                        ev.message
                    );
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&events)?);
            }
        }
        Commands::Rotate {
            event_log,
            keep,
            json,
        } => {
            let store = EventStore::open_with_rotation(&event_log, 0, keep)?;
            let before = store.len_bytes().unwrap_or(0);
            store.rotate()?;
            let after = store.len_bytes().unwrap_or(0);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "event_log": event_log.display().to_string(),
                        "keep": keep,
                        "bytes_before": before,
                        "bytes_after": after,
                        "archive": format!("{}.1", event_log.display()),
                    }))?
                );
            } else {
                println!(
                    "[aegis] rotated {} (was {} bytes) → {}.1",
                    event_log.display(),
                    before,
                    event_log.display()
                );
            }
        }
        Commands::Watch {
            event_log,
            interval_ms,
            from_recent,
        } => {
            println!(
                "[aegis] watching {} (Ctrl+C to stop)",
                event_log.display()
            );
            let store = EventStore::open(&event_log)?;
            if from_recent > 0 {
                for ev in store.recent(from_recent)? {
                    println!(
                        "[{}] {:?} {:?} | {}",
                        ev.ts.to_rfc3339().cyan(),
                        ev.product,
                        ev.action,
                        ev.message
                    );
                }
                println!("{}", "---- live ----".dimmed());
            }
            let mut offset = store.byte_len().unwrap_or(0);
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
                let store = EventStore::open(&event_log)?;
                let (next, events) = store.read_since(offset)?;
                offset = next;
                for ev in events {
                    println!(
                        "[{}] {:?} {:?} | {}",
                        ev.ts.to_rfc3339().cyan(),
                        ev.product,
                        ev.action,
                        ev.message
                    );
                }
            }
        }
        Commands::Playbook { command } => match command {
            PlaybookCmd::Init { path } => {
                if let Some(p) = path.parent() {
                    std::fs::create_dir_all(p)?;
                }
                let pb = default_playbooks();
                std::fs::write(&path, serde_json::to_string_pretty(&pb)?)?;
                println!(
                    "{}",
                    format!("[aegis] wrote playbook {}", path.display())
                        .green()
                        .bold()
                );
            }
            PlaybookCmd::List { path, json } => {
                if !path.exists() {
                    eprintln!(
                        "[aegis] missing {} — run: aegis playbook init",
                        path.display()
                    );
                    std::process::exit(1);
                }
                let pb: PlaybookFile = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
                if json {
                    let rows: Vec<_> = pb
                        .rules
                        .iter()
                        .map(|r| {
                            serde_json::json!({
                                "name": r.name,
                                "enabled": r.enabled,
                                "when": r.when,
                                "actions": r.then.iter().map(|a| &a.action_type).collect::<Vec<_>>(),
                            })
                        })
                        .collect();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "path": path.display().to_string(),
                            "rules": rows,
                            "enabled": pb.rules.iter().filter(|r| r.enabled).count(),
                            "total": pb.rules.len(),
                        }))?
                    );
                } else {
                    println!(
                        "[aegis] playbook {} ({} rules, {} enabled)",
                        path.display(),
                        pb.rules.len(),
                        pb.rules.iter().filter(|r| r.enabled).count()
                    );
                    for r in &pb.rules {
                        let flag = if r.enabled {
                            "ON ".green().bold().to_string()
                        } else {
                            "OFF".yellow().to_string()
                        };
                        let when_bits: Vec<String> = [
                            r.when.product.as_ref().map(|p| format!("product={p}")),
                            r.when.action.as_ref().map(|a| format!("action={a}")),
                            r.when.severity.as_ref().map(|s| format!("sev={s}")),
                            r.when.kind.as_ref().map(|k| format!("kind={k}")),
                            r.when.attr.as_ref().map(|a| format!("attr={a}")),
                            r.when
                                .message_contains
                                .as_ref()
                                .map(|m| format!("msg~{m}")),
                        ]
                        .into_iter()
                        .flatten()
                        .collect();
                        let when_s = if when_bits.is_empty() {
                            "*".into()
                        } else {
                            when_bits.join(" ")
                        };
                        let acts: Vec<_> =
                            r.then.iter().map(|a| a.action_type.as_str()).collect();
                        println!(
                            "  [{flag}] {} | when: {when_s} | then: {}",
                            r.name,
                            acts.join(",")
                        );
                    }
                }
            }
            PlaybookCmd::Show { name, path, json } => {
                if !path.exists() {
                    eprintln!(
                        "[aegis] missing {} — run: aegis playbook init",
                        path.display()
                    );
                    std::process::exit(1);
                }
                let pb: PlaybookFile = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
                let rule = pb.rules.iter().find(|r| r.name.eq_ignore_ascii_case(&name));
                let Some(r) = rule else {
                    eprintln!(
                        "[aegis] rule '{}' not found in {} ({} rules)",
                        name,
                        path.display(),
                        pb.rules.len()
                    );
                    std::process::exit(1);
                };
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "path": path.display().to_string(),
                            "rule": r,
                        }))?
                    );
                } else {
                    let flag = if r.enabled {
                        "enabled".green().bold().to_string()
                    } else {
                        "disabled".yellow().to_string()
                    };
                    println!(
                        "[aegis] playbook rule '{}' ({flag}) — {}",
                        r.name,
                        path.display()
                    );
                    println!("  when:");
                    println!(
                        "    product={} action={} severity={} kind={}",
                        r.when.product.as_deref().unwrap_or("-"),
                        r.when.action.as_deref().unwrap_or("-"),
                        r.when.severity.as_deref().unwrap_or("-"),
                        r.when.kind.as_deref().unwrap_or("-"),
                    );
                    if r.when.message_contains.is_some()
                        || r.when.attr.is_some()
                        || r.when.attr_equals.is_some()
                        || r.when.attr_contains.is_some()
                    {
                        println!(
                            "    msg~{} attr={} equals={} contains={}",
                            r.when.message_contains.as_deref().unwrap_or("-"),
                            r.when.attr.as_deref().unwrap_or("-"),
                            r.when.attr_equals.as_deref().unwrap_or("-"),
                            r.when.attr_contains.as_deref().unwrap_or("-"),
                        );
                    }
                    println!("  then ({} action(s)):", r.then.len());
                    for (i, a) in r.then.iter().enumerate() {
                        println!(
                            "    [{}] type={} attr={} domain={} url={} value={} user={} token={}",
                            i + 1,
                            a.action_type,
                            a.attr.as_deref().unwrap_or("-"),
                            a.domain.as_deref().unwrap_or("-"),
                            a.url.as_deref().unwrap_or("-"),
                            a.value.as_deref().unwrap_or("-"),
                            a.user.as_deref().unwrap_or("-"),
                            a.token.as_deref().unwrap_or("-"),
                        );
                        if a.message.is_some() || a.severity.is_some() || a.kind.is_some() {
                            println!(
                                "        message={} severity={} kind={} source={} product={}",
                                a.message.as_deref().unwrap_or("-"),
                                a.severity.as_deref().unwrap_or("-"),
                                a.kind.as_deref().unwrap_or("-"),
                                a.source.as_deref().unwrap_or("-"),
                                a.product.as_deref().unwrap_or("-"),
                            );
                        }
                    }
                }
            }
            PlaybookCmd::Validate { path, json } => {
                if !path.exists() {
                    eprintln!(
                        "[aegis] missing {} — run: aegis playbook init",
                        path.display()
                    );
                    std::process::exit(1);
                }
                let text = std::fs::read_to_string(&path)?;
                let pb: PlaybookFile = match serde_json::from_str(&text) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("[aegis] playbook JSON invalid: {e}");
                        std::process::exit(2);
                    }
                };
                let known: std::collections::BTreeSet<&str> =
                    known_playbook_actions().iter().copied().collect();
                let mut issues: Vec<String> = Vec::new();
                let mut names = std::collections::BTreeSet::new();
                if pb.rules.is_empty() {
                    issues.push("no rules defined".into());
                }
                for (i, r) in pb.rules.iter().enumerate() {
                    if r.name.trim().is_empty() {
                        issues.push(format!("rule[{i}]: empty name"));
                    } else if !names.insert(r.name.clone()) {
                        issues.push(format!("duplicate rule name '{}'", r.name));
                    }
                    if r.then.is_empty() {
                        issues.push(format!("rule '{}': no actions", r.name));
                    }
                    for (j, a) in r.then.iter().enumerate() {
                        if !known.contains(a.action_type.as_str()) {
                            issues.push(format!(
                                "rule '{}' action[{j}]: unknown type '{}'",
                                r.name, a.action_type
                            ));
                        }
                        match a.action_type.as_str() {
                            "webhook" if a.url.as_ref().map(|u| u.is_empty()).unwrap_or(true) => {
                                issues.push(format!(
                                    "rule '{}': webhook missing url",
                                    r.name
                                ));
                            }
                            "ioc_add"
                                if a.value.as_ref().map(|v| v.is_empty()).unwrap_or(true)
                                    && a.domain.as_ref().map(|v| v.is_empty()).unwrap_or(true) =>
                            {
                                issues.push(format!(
                                    "rule '{}': ioc_add needs value or domain",
                                    r.name
                                ));
                            }
                            "dns_block"
                                if a.domain.as_ref().map(|v| v.is_empty()).unwrap_or(true) =>
                            {
                                issues.push(format!(
                                    "rule '{}': dns_block needs domain",
                                    r.name
                                ));
                            }
                            "dns_allow"
                                if a.domain.as_ref().map(|v| v.is_empty()).unwrap_or(true) =>
                            {
                                issues.push(format!(
                                    "rule '{}': dns_allow needs domain",
                                    r.name
                                ));
                            }
                            _ => {}
                        }
                    }
                    if r.when.attr.is_none()
                        && (r.when.attr_equals.is_some() || r.when.attr_contains.is_some())
                    {
                        issues.push(format!(
                            "rule '{}': attr_equals/attr_contains require when.attr",
                            r.name
                        ));
                    }
                }
                let ok = issues.is_empty();
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "path": path.display().to_string(),
                            "ok": ok,
                            "rules": pb.rules.len(),
                            "enabled": pb.rules.iter().filter(|r| r.enabled).count(),
                            "known_actions": known_playbook_actions(),
                            "issues": issues,
                        }))?
                    );
                } else {
                    println!(
                        "[aegis] playbook validate {} ({} rules)",
                        path.display(),
                        pb.rules.len()
                    );
                    if ok {
                        println!("{}", "  OK — no issues".green().bold());
                    } else {
                        for iss in &issues {
                            println!("  {} {iss}", "ISSUE".red().bold());
                        }
                    }
                }
                if !ok {
                    std::process::exit(3);
                }
            }
            PlaybookCmd::Enable { name, path } => {
                if !path.exists() {
                    eprintln!(
                        "[aegis] missing {} — run: aegis playbook init",
                        path.display()
                    );
                    std::process::exit(1);
                }
                let mut pb: PlaybookFile =
                    serde_json::from_str(&std::fs::read_to_string(&path)?)?;
                let Some(rule) = pb
                    .rules
                    .iter_mut()
                    .find(|r| r.name.eq_ignore_ascii_case(&name))
                else {
                    eprintln!("[aegis] playbook rule not found: {name}");
                    std::process::exit(1);
                };
                if rule.enabled {
                    println!("[aegis] rule '{name}' already enabled");
                } else {
                    rule.enabled = true;
                    std::fs::write(&path, serde_json::to_string_pretty(&pb)?)?;
                    println!(
                        "{}",
                        format!("[aegis] enabled rule '{name}' → {}", path.display())
                            .green()
                            .bold()
                    );
                }
            }
            PlaybookCmd::Disable { name, path } => {
                if !path.exists() {
                    eprintln!(
                        "[aegis] missing {} — run: aegis playbook init",
                        path.display()
                    );
                    std::process::exit(1);
                }
                let mut pb: PlaybookFile =
                    serde_json::from_str(&std::fs::read_to_string(&path)?)?;
                let Some(rule) = pb
                    .rules
                    .iter_mut()
                    .find(|r| r.name.eq_ignore_ascii_case(&name))
                else {
                    eprintln!("[aegis] playbook rule not found: {name}");
                    std::process::exit(1);
                };
                if !rule.enabled {
                    println!("[aegis] rule '{name}' already disabled");
                } else {
                    rule.enabled = false;
                    std::fs::write(&path, serde_json::to_string_pretty(&pb)?)?;
                    println!(
                        "{}",
                        format!("[aegis] disabled rule '{name}' → {}", path.display())
                            .yellow()
                            .bold()
                    );
                }
            }
            PlaybookCmd::Remove { name, path, apply } => {
                if !path.exists() {
                    eprintln!(
                        "[aegis] missing {} — run: aegis playbook init",
                        path.display()
                    );
                    std::process::exit(1);
                }
                let mut pb: PlaybookFile =
                    serde_json::from_str(&std::fs::read_to_string(&path)?)?;
                let before = pb.rules.len();
                let idx = pb
                    .rules
                    .iter()
                    .position(|r| r.name.eq_ignore_ascii_case(&name));
                let Some(i) = idx else {
                    eprintln!("[aegis] playbook rule not found: {name}");
                    std::process::exit(1);
                };
                let removed = pb.rules[i].name.clone();
                let enabled = pb.rules[i].enabled;
                if apply {
                    pb.rules.remove(i);
                    std::fs::write(&path, serde_json::to_string_pretty(&pb)?)?;
                    println!(
                        "{}",
                        format!(
                            "[aegis] removed rule '{removed}' (was enabled={enabled}) → {} ({} remaining)",
                            path.display(),
                            pb.rules.len()
                        )
                        .yellow()
                        .bold()
                    );
                } else {
                    println!(
                        "[aegis] playbook remove dry-run: would remove '{removed}' (enabled={enabled}) from {} ({before} rules; use --apply)",
                        path.display()
                    );
                }
            }
            PlaybookCmd::Run {
                path,
                event_log,
                limit,
                apply,
                json,
            } => {
                if !path.exists() {
                    eprintln!(
                        "[aegis] missing {} — run: aegis playbook init",
                        path.display()
                    );
                    std::process::exit(1);
                }
                let pb: PlaybookFile = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
                if !event_log.exists() {
                    eprintln!("[aegis] no event log");
                    std::process::exit(1);
                }
                let store = EventStore::open(&event_log)?;
                let events = store.recent(limit)?;
                let mode = if apply { "APPLY" } else { "DRY-RUN" };
                if !json {
                    println!(
                        "[aegis] playbook {} ({} rules, {} events window)",
                        mode,
                        pb.rules.len(),
                        events.len()
                    );
                }
                let mut fired = 0u32;
                let mut hits: Vec<serde_json::Value> = Vec::new();
                let mut by_rule: std::collections::BTreeMap<String, u32> =
                    std::collections::BTreeMap::new();
                for rule in pb.rules.iter().filter(|r| r.enabled) {
                    for ev in &events {
                        if !event_matches(ev, &rule.when) {
                            continue;
                        }
                        fired += 1;
                        *by_rule.entry(rule.name.clone()).or_default() += 1;
                        hits.push(serde_json::json!({
                            "rule": rule.name,
                            "event_id": ev.id.to_string(),
                            "ts": ev.ts.to_rfc3339(),
                            "product": ev.product.as_str(),
                            "severity": format!("{:?}", ev.severity),
                            "action": format!("{:?}", ev.action),
                            "message": ev.message,
                            "actions": rule.then.iter().map(|a| &a.action_type).collect::<Vec<_>>(),
                        }));
                        if !json {
                            println!(
                                "  rule={} event={} | {}",
                                rule.name.yellow(),
                                ev.id,
                                ev.message
                            );
                        }
                        if apply || !json {
                            run_playbook_actions(rule, ev, apply).await?;
                        }
                    }
                }
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "mode": mode,
                            "path": path.display().to_string(),
                            "rules_enabled": pb.rules.iter().filter(|r| r.enabled).count(),
                            "events_window": events.len(),
                            "hits": fired,
                            "by_rule": by_rule,
                            "matches": hits,
                        }))?
                    );
                } else {
                    println!("[aegis] playbook complete: {fired} rule hits");
                }
            }
            PlaybookCmd::Watch {
                path,
                event_log,
                interval_ms,
                apply,
            } => {
                if !path.exists() {
                    eprintln!(
                        "[aegis] missing {} — run: aegis playbook init",
                        path.display()
                    );
                    std::process::exit(1);
                }
                let pb: PlaybookFile = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
                let mode = if apply { "APPLY" } else { "DRY-RUN" };
                println!(
                    "[aegis] playbook watch {} on {} (Ctrl+C to stop)",
                    mode,
                    event_log.display()
                );
                let store = EventStore::open(&event_log)?;
                let mut offset = store.byte_len().unwrap_or(0);
                // de-dupe rule+event pairs within process lifetime
                let mut seen: HashSet<String> = HashSet::new();
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
                    // reload playbooks each tick so edits apply live
                    let pb = match std::fs::read_to_string(&path) {
                        Ok(t) => serde_json::from_str::<PlaybookFile>(&t).unwrap_or(pb.clone()),
                        Err(_) => pb.clone(),
                    };
                    let store = EventStore::open(&event_log)?;
                    let (next, events) = store.read_since(offset)?;
                    offset = next;
                    for ev in events {
                        for rule in pb.rules.iter().filter(|r| r.enabled) {
                            if !event_matches(&ev, &rule.when) {
                                continue;
                            }
                            let key = format!("{}:{}", rule.name, ev.id);
                            if !seen.insert(key) {
                                continue;
                            }
                            println!(
                                "  rule={} event={} | {}",
                                rule.name.yellow(),
                                ev.id,
                                ev.message
                            );
                            run_playbook_actions(rule, &ev, apply).await?;
                        }
                    }
                }
            }
        },
        Commands::Config { command } => match command {
            ConfigCmd::Show { path, json } => {
                let cfg = SuiteConfig::load(&path);
                let present = path.exists();
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "path": path.display().to_string(),
                            "present": present,
                            "config": cfg,
                        }))?
                    );
                } else {
                    println!("{}", serde_json::to_string_pretty(&cfg)?);
                    if present {
                        eprintln!("(from {})", path.display());
                    } else {
                        eprintln!("(defaults; no file at {})", path.display());
                    }
                }
            }
            ConfigCmd::Init { path } => {
                let cfg = SuiteConfig::default();
                cfg.save(&path)?;
                println!(
                    "{}",
                    format!("[aegis] wrote {}", path.display()).green().bold()
                );
            }
            ConfigCmd::Get { key, path } => {
                let cfg = SuiteConfig::load(&path);
                let k = key.trim().to_ascii_lowercase();
                let val = match k.as_str() {
                    "data_dir" | "data-dir" => cfg.data_dir,
                    "event_log" | "event-log" | "events" => cfg.event_log,
                    "health_bind" | "health-bind" | "health" => cfg.health_bind,
                    "min_posture" | "min-posture" | "posture" => cfg.min_posture.to_string(),
                    "playbooks" | "playbook" => cfg.playbooks,
                    "gate_config" | "gate-config" | "gate" => cfg.gate_config,
                    _ => {
                        eprintln!(
                            "[aegis] unknown key '{key}' (data_dir|event_log|health_bind|min_posture|playbooks|gate_config)"
                        );
                        std::process::exit(2);
                    }
                };
                println!("{val}");
            }
            ConfigCmd::Set { key, value, path } => {
                let mut cfg = SuiteConfig::load(&path);
                let k = key.trim().to_ascii_lowercase();
                match k.as_str() {
                    "data_dir" | "data-dir" => cfg.data_dir = value.clone(),
                    "event_log" | "event-log" | "events" => cfg.event_log = value.clone(),
                    "health_bind" | "health-bind" | "health" => cfg.health_bind = value.clone(),
                    "min_posture" | "min-posture" | "posture" => {
                        match value.parse::<u32>() {
                            Ok(n) if n <= 100 => cfg.min_posture = n,
                            Ok(_) => {
                                eprintln!("[aegis] min_posture must be 0..=100");
                                std::process::exit(2);
                            }
                            Err(_) => {
                                eprintln!("[aegis] min_posture must be an integer");
                                std::process::exit(2);
                            }
                        }
                    }
                    "playbooks" | "playbook" => cfg.playbooks = value.clone(),
                    "gate_config" | "gate-config" | "gate" => cfg.gate_config = value.clone(),
                    _ => {
                        eprintln!(
                            "[aegis] unknown key '{key}' (data_dir|event_log|health_bind|min_posture|playbooks|gate_config)"
                        );
                        std::process::exit(2);
                    }
                }
                cfg.save(&path)?;
                println!(
                    "{}",
                    format!("[aegis] set {k}={value} → {}", path.display())
                        .green()
                        .bold()
                );
            }
        },
        Commands::Setup {
            data_dir,
            apply_policy,
            no_policy,
            json,
        } => {
            std::fs::create_dir_all(&data_dir)?;
            let mut created: Vec<String> = Vec::new();
            let mut note = |path: &Path| {
                created.push(path.display().to_string());
                if !json {
                    println!("  + {}", path.display());
                }
            };
            if !json {
                println!(
                    "{}",
                    format!("[aegis] setup data dir {}", data_dir.display())
                        .green()
                        .bold()
                );
            }

            // Touch event log
            let event_log = data_dir.join("events.jsonl");
            let _ = EventStore::open(&event_log)?;

            // Suite config
            let cfg_path = data_dir.join("config.json");
            if !cfg_path.exists() {
                let mut cfg = SuiteConfig::default();
                cfg.data_dir = data_dir.display().to_string();
                cfg.event_log = event_log.display().to_string();
                cfg.playbooks = data_dir.join("playbooks.json").display().to_string();
                cfg.gate_config = data_dir.join("gate-routes.json").display().to_string();
                cfg.save(&cfg_path)?;
                note(&cfg_path);
            }

            // DNS blocklist seed
            let bl = data_dir.join("dns-blocklist.txt");
            if !bl.exists() {
                std::fs::write(
                    &bl,
                    "# S2O CyberDNS blocklist\nmalware.test.s2o\nphishing.test.s2o\n",
                )?;
                note(&bl);
            }

            // Defender rules
            let rules = data_dir.join("defender-rules.json");
            if !rules.exists() {
                let seed = serde_json::json!({
                    "version": "0.1.0",
                    "blocked_hashes": [],
                    "blocked_name_substrings": ["eicar"]
                });
                std::fs::write(&rules, serde_json::to_string_pretty(&seed)?)?;
                note(&rules);
            }

            // yara-lite (substr / re / hex)
            let yara = data_dir.join("yara-lite.rules");
            if !yara.exists() {
                std::fs::write(
                    &yara,
                    concat!(
                        "# S2O yara-lite (not full YARA-X)\n",
                        "# name: substr | re:regex | hex:DE AD BE EF | [high] name: ...\n",
                        "eicar_string: EICAR-STANDARD-ANTIVIRUS-TEST-FILE\n",
                        "[high] powershell_enc: re:(?i)powershell.{0,80}-e(nc|ncodedcommand)\n",
                        "[medium] shellcode_nop_sled: hex:90 90 90 90 90 90 90 90\n",
                    ),
                )?;
                note(&yara);
            }

            // playbooks
            let pb = data_dir.join("playbooks.json");
            if !pb.exists() {
                std::fs::write(&pb, serde_json::to_string_pretty(&default_playbooks())?)?;
                note(&pb);
            }

            // gate routes
            let gate = data_dir.join("gate-routes.json");
            if !gate.exists() {
                let g = serde_json::json!({
                    "listen": "127.0.0.1:18443",
                    "min_score": 50,
                    "routes": [{
                        "name": "demo",
                        "path_prefix": "/",
                        "upstream": "https://example.com"
                    }]
                });
                std::fs::write(&gate, serde_json::to_string_pretty(&g)?)?;
                note(&gate);
            }

            // IOC store empty
            let ioc = data_dir.join("ioc-store.json");
            if !ioc.exists() {
                let s = serde_json::json!({
                    "version": "0.1.0",
                    "updated_at": chrono::Utc::now().to_rfc3339(),
                    "entries": []
                });
                std::fs::write(&ioc, serde_json::to_string_pretty(&s)?)?;
                note(&ioc);
            }

            // edge policy example copy
            let policy_src = PathBuf::from("policies/examples/edge-pack.json");
            let policy_dst = data_dir.join("edge-pack.json");
            if policy_src.exists() && !policy_dst.exists() {
                std::fs::copy(&policy_src, &policy_dst)?;
                note(&policy_dst);
            }

            let do_policy = apply_policy && !no_policy;
            let mut policy_ok: Option<bool> = None;
            let mut policy_path_s: Option<String> = None;
            if do_policy {
                let path = if policy_dst.exists() {
                    policy_dst
                } else {
                    policy_src
                };
                if path.exists() {
                    policy_path_s = Some(path.display().to_string());
                    if !json {
                        println!("[aegis] applying policy {} ...", path.display());
                    }
                    let doc = load_policy_file(&path)?;
                    let store = Arc::new(EventStore::open(&event_log)?);
                    let result = s2o_kernel::apply_policy(&doc, &fw, Some(store)).await?;
                    policy_ok = Some(result.ok);
                    if !json {
                        if result.ok {
                            println!("{}", "[aegis] policy OK".green().bold());
                        } else {
                            println!("{}", "[aegis] policy incomplete".yellow().bold());
                            for e in &result.errors {
                                println!("  error: {e}");
                            }
                        }
                    }
                }
            }

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "data_dir": data_dir.display().to_string(),
                        "created": created,
                        "policy_applied": do_policy,
                        "policy_path": policy_path_s,
                        "policy_ok": policy_ok,
                    }))?
                );
            } else {
                println!("{}", "[aegis] setup complete".green().bold());
                println!("Next:");
                println!("  aegis doctor");
                println!("  aegis selftest");
                println!("  aegis status");
                println!("  cyberztna serve --tls");
            }
        }
        Commands::Backup {
            data_dir,
            out,
            json,
        } => {
            if !data_dir.exists() {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": false,
                            "error": format!("data dir missing: {}", data_dir.display()),
                        }))?
                    );
                } else {
                    eprintln!("[aegis] data dir missing: {}", data_dir.display());
                }
                std::process::exit(1);
            }
            let out = out.unwrap_or_else(|| {
                let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
                PathBuf::from(format!(".aegis-backup-{ts}.zip"))
            });
            zip_dir(&data_dir, &out)?;
            let bytes = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "data_dir": data_dir.display().to_string(),
                        "out": out.display().to_string(),
                        "bytes": bytes,
                    }))?
                );
            } else {
                println!(
                    "{}",
                    format!("[aegis] backup wrote {}", out.display())
                        .green()
                        .bold()
                );
            }
        }
        Commands::Restore {
            zip,
            data_dir,
            force,
        } => {
            if !zip.exists() {
                eprintln!("[aegis] zip missing: {}", zip.display());
                std::process::exit(1);
            }
            std::fs::create_dir_all(&data_dir)?;
            let n = unzip_to(&zip, &data_dir, force)?;
            println!(
                "{}",
                format!(
                    "[aegis] restored {n} files into {} (force={force})",
                    data_dir.display()
                )
                .green()
                .bold()
            );
        }
        Commands::Selftest { min_posture, json } => {
            let mut failed = 0u32;
            let mut checks = Vec::new();
            let mut posture_score: Option<u32> = None;
            checks.push(("kernel_version", !KERNEL_VERSION.is_empty()));
            checks.push(("schema_version", !SCHEMA_VERSION.is_empty()));
            let status = collect_platform_status(&fw).await;
            checks.push(("modules_count_9", status.modules.len() == 9));
            let wall_ok = status
                .modules
                .iter()
                .any(|m| m.id == "cyberwall" && matches!(m.state, HealthState::Implemented | HealthState::Partial));
            checks.push(("cyberwall_present", wall_ok));
            match compute_posture_score(&fw).await {
                Ok(p) => {
                    checks.push(("posture_compute", true));
                    checks.push(("posture_min", p.score >= min_posture));
                    posture_score = Some(p.score);
                    if !json {
                        println!(
                            " posture_score={} min={} {}",
                            p.score,
                            min_posture,
                            if p.score >= min_posture {
                                "PASS".green().bold()
                            } else {
                                "FAIL".red().bold()
                            }
                        );
                    }
                }
                Err(e) => {
                    checks.push(("posture_compute", false));
                    checks.push(("posture_min", false));
                    if !json {
                        eprintln!(" posture error: {e}");
                    }
                }
            }
            let el = PathBuf::from(".aegis/events.jsonl");
            match EventStore::open(&el) {
                Ok(s) => {
                    let _ = s.count();
                    // emit round-trip
                    let ev = s2o_schema::AegisEvent::new(
                        s2o_kernel::host_id(),
                        s2o_schema::ProductId::Aegis,
                        s2o_schema::EventKind::Health,
                        s2o_schema::EventAction::Observed,
                        s2o_schema::Severity::Info,
                        "selftest emit",
                    )
                    .with_attr("selftest", serde_json::json!(true));
                    checks.push(("event_store_append", s.append(&ev).is_ok()));
                    checks.push(("event_store", true));
                }
                Err(_) => {
                    checks.push(("event_store", false));
                    checks.push(("event_store_append", false));
                }
            }
            // schema ingest decode
            let ingest_ok = s2o_schema::decode_event_json(
                r#"{"message":"selftest","severity":"info","product":"aegis"}"#,
                "selftest-host",
            )
            .is_ok();
            checks.push(("event_ingest_decode", ingest_ok));
            // UDP bus round-trip
            let bus_ok = (|| {
                let sock = s2o_bus::udp_bind("127.0.0.1:0").ok()?;
                let addr = sock.local_addr().ok()?.to_string();
                let ev = s2o_schema::AegisEvent::new(
                    "selftest",
                    s2o_schema::ProductId::Aegis,
                    s2o_schema::EventKind::Alert,
                    s2o_schema::EventAction::Observed,
                    s2o_schema::Severity::Low,
                    "bus-selftest",
                );
                s2o_bus::udp_send(&addr, &ev).ok()?;
                let mut buf = [0u8; 65535];
                sock.set_read_timeout(Some(std::time::Duration::from_millis(500)))
                    .ok()?;
                let (n, _) = sock.recv_from(&mut buf).ok()?;
                let back = s2o_bus::udp_decode(&buf[..n], "selftest").ok()?;
                Some(back.message == "bus-selftest")
            })()
            .unwrap_or(false);
            checks.push(("event_bus_udp", bus_ok));
            // data dir writability
            let qdir = PathBuf::from(".aegis/quarantine");
            checks.push((
                "quarantine_dir",
                std::fs::create_dir_all(&qdir).is_ok(),
            ));
            // policy example present (optional warn as pass if missing in checkout)
            checks.push((
                "policy_examples",
                PathBuf::from("policies/examples/edge-pack.json").exists()
                    || PathBuf::from("policies/examples/wall-enable.json").exists(),
            ));
            // managed firewall rule model
            let pol = cyberwall_core::FirewallPolicy {
                name: "selftest".into(),
                version: "0".into(),
                rules: vec![cyberwall_core::FirewallRule::simple(
                    "selftest-port",
                    cyberwall_core::RuleAction::Block,
                    cyberwall_core::RuleDirection::Inbound,
                )],
            }
            .ensure_managed_names();
            checks.push((
                "wall_managed_prefix",
                pol.rules[0]
                    .name
                    .starts_with(cyberwall_core::MANAGED_RULE_PREFIX),
            ));
            // policy pack load + shape
            let edge = PathBuf::from("policies/examples/edge-pack.json");
            let policy_ok = if edge.exists() {
                load_policy_file(&edge).is_ok()
            } else {
                true // optional when run outside repo root
            };
            checks.push(("policy_load_edge", policy_ok));
            // relative --since parser
            checks.push((
                "parse_since_1h",
                parse_since("1h").is_ok() && parse_since("bogus").is_err(),
            ));
            // session revoke_user round-trip (temp store under .aegis)
            let sess_ok = (|| {
                let path = PathBuf::from(".aegis/selftest-sessions.json");
                let mut store = s2o_session::SessionStore::default();
                store.mint("selftest-user", "selftest-host", 80, 1);
                store.mint("other", "selftest-host", 80, 1);
                let n = store.revoke_user("selftest-user");
                store.save(&path).ok()?;
                let _ = std::fs::remove_file(&path);
                Some(n == 1 && store.active().count() == 1)
            })()
            .unwrap_or(false);
            checks.push(("session_revoke_user", sess_ok));
            // IOC remove round-trip (in-memory)
            let ioc_ok = {
                let mut s = s2o_ioc::IocStore::default();
                s.upsert(s2o_ioc::IocEntry {
                    kind: s2o_ioc::IocKind::Domain,
                    value: "selftest.drop.s2o".into(),
                    source: "selftest".into(),
                    severity: s2o_ioc::IocSeverity::Low,
                    note: None,
                    added_at: chrono::Utc::now(),
                });
                s.remove("selftest.drop.s2o", Some(s2o_ioc::IocKind::Domain)) == 1
                    && s.entries.is_empty()
            };
            checks.push(("ioc_remove", ioc_ok));
            // playbook known actions non-empty
            checks.push((
                "playbook_actions",
                !known_playbook_actions().is_empty()
                    && known_playbook_actions().contains(&"session_revoke_attr"),
            ));

            for (_name, ok) in &checks {
                if !*ok {
                    failed += 1;
                }
            }
            if json {
                let rows: Vec<_> = checks
                    .iter()
                    .map(|(name, ok)| {
                        serde_json::json!({
                            "name": name,
                            "ok": ok,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": failed == 0,
                        "failed": failed,
                        "min_posture": min_posture,
                        "posture_score": posture_score,
                        "checks": rows,
                    }))?
                );
            } else {
                println!("{}", "Aegis selftest".bold().green());
                for (name, ok) in &checks {
                    if *ok {
                        println!("  [PASS] {name}");
                    } else {
                        println!("  [FAIL] {}", name.red());
                    }
                }
                if failed > 0 {
                    println!(
                        "{}",
                        format!("SELFTEST FAIL ({failed} checks)").red().bold()
                    );
                } else {
                    println!("{}", "SELFTEST PASS".green().bold());
                }
            }
            if failed > 0 {
                std::process::exit(1);
            }
        }
        Commands::Cleanup {
            sessions,
            fleet,
            event_log,
            ioc_store,
            dns_blocklist,
            fleet_stale_minutes,
            rotate_max_bytes,
            ioc_older_days,
            dns_dedupe,
            apply,
            json,
        } => {
            use s2o_session::SessionStore;
            if !json {
                println!(
                    "{}",
                    format!(
                        "Aegis cleanup ({})",
                        if apply { "APPLY" } else { "dry-run" }
                    )
                    .bold()
                    .green()
                );
            }

            // Sessions GC
            let mut sess = SessionStore::load(&sessions);
            let before_s = sess.sessions.len();
            let removed_s = if apply {
                let n = sess.gc();
                if n > 0 || sessions.exists() {
                    sess.save(&sessions)?;
                }
                n
            } else {
                // dry-run: count non-active
                let active = sess.active().count();
                before_s.saturating_sub(active)
            };
            if !json {
                println!(
                    "  sessions : would/did remove {removed_s} of {before_s} → {}",
                    sessions.display()
                );
            }

            // Fleet prune
            let mut fleet_removed = 0usize;
            let mut fleet_before = 0usize;
            let mut fleet_skipped = false;
            if fleet_stale_minutes > 0 {
                let mut fl = FleetStore::load(&fleet);
                fleet_before = fl.hosts.len();
                fleet_removed = if apply {
                    let r = fl.prune_stale(fleet_stale_minutes);
                    fl.save(&fleet)?;
                    r.len()
                } else {
                    let mut probe = fl.clone();
                    probe.prune_stale(fleet_stale_minutes).len()
                };
                if !json {
                    println!(
                        "  fleet    : would/did remove {fleet_removed} of {fleet_before} (stale>{fleet_stale_minutes}m) → {}",
                        fleet.display()
                    );
                }
            } else {
                fleet_skipped = true;
                if !json {
                    println!("  fleet    : skipped (--fleet-stale-minutes 0)");
                }
            }

            // Event log size / rotate
            let mut events_size: Option<u64> = None;
            let mut events_would_rotate = false;
            let mut events_rotated = false;
            if event_log.exists() {
                let meta = std::fs::metadata(&event_log)?;
                let len = meta.len();
                events_size = Some(len);
                if rotate_max_bytes > 0 && len >= rotate_max_bytes {
                    events_would_rotate = true;
                    if apply {
                        let store = EventStore::open_with_rotation(
                            &event_log,
                            rotate_max_bytes,
                            5,
                        )?;
                        events_rotated = store.rotate_if_needed()?;
                        if !json {
                            println!(
                                "  events   : size={len} max={rotate_max_bytes} rotated={events_rotated} → {}",
                                event_log.display()
                            );
                        }
                    } else if !json {
                        println!(
                            "  events   : size={len} >= max={rotate_max_bytes} (would rotate) → {}",
                            event_log.display()
                        );
                    }
                } else if !json {
                    println!(
                        "  events   : size={len} (under max={rotate_max_bytes}) → {}",
                        event_log.display()
                    );
                }
            } else if !json {
                println!("  events   : missing {}", event_log.display());
            }

            // IOC age prune
            let mut ioc_removed = 0usize;
            let mut ioc_before = 0usize;
            let mut ioc_skipped = false;
            if ioc_older_days > 0 {
                if ioc_store.exists() {
                    match s2o_ioc::IocStore::load(&ioc_store) {
                        Ok(mut store) => {
                            ioc_before = store.entries.len();
                            ioc_removed = store.prune_older_than(ioc_older_days);
                            if apply && ioc_removed > 0 {
                                store.save(&ioc_store)?;
                            }
                            if !json {
                                println!(
                                    "  ioc      : would/did remove {ioc_removed} of {ioc_before} (older>{ioc_older_days}d) → {}",
                                    ioc_store.display()
                                );
                            }
                        }
                        Err(e) => {
                            if !json {
                                println!("  ioc      : load error {e}");
                            }
                        }
                    }
                } else if !json {
                    println!("  ioc      : missing {}", ioc_store.display());
                }
            } else {
                ioc_skipped = true;
                if !json {
                    println!("  ioc      : skipped (--ioc-older-days 0)");
                }
            }

            // DNS blocklist dedupe
            let mut dns_raw = 0usize;
            let mut dns_unique = 0usize;
            let mut dns_dups = 0usize;
            let mut dns_skipped = false;
            if dns_dedupe {
                if dns_blocklist.exists() {
                    let text = std::fs::read_to_string(&dns_blocklist).unwrap_or_default();
                    let mut seen = std::collections::BTreeSet::new();
                    let mut unique_lines: Vec<String> = Vec::new();
                    let mut header: Vec<String> = Vec::new();
                    for line in text.lines() {
                        let trimmed = line.trim();
                        if trimmed.is_empty() || trimmed.starts_with('#') {
                            if unique_lines.is_empty() && header.len() < 5 {
                                header.push(line.to_string());
                            }
                            continue;
                        }
                        dns_raw += 1;
                        let domain = trimmed
                            .split('#')
                            .next()
                            .unwrap_or("")
                            .trim()
                            .trim_end_matches('.')
                            .to_ascii_lowercase();
                        if domain.is_empty() {
                            continue;
                        }
                        if !seen.insert(domain.clone()) {
                            dns_dups += 1;
                        } else {
                            unique_lines.push(domain);
                        }
                    }
                    dns_unique = unique_lines.len();
                    if apply && dns_dups > 0 {
                        let mut out = String::new();
                        if header.is_empty() {
                            out.push_str("# S2O CyberDNS local blocklist\n");
                        } else {
                            for h in &header {
                                out.push_str(h);
                                out.push('\n');
                            }
                        }
                        for d in &unique_lines {
                            out.push_str(d);
                            out.push('\n');
                        }
                        std::fs::write(&dns_blocklist, out)?;
                    }
                    if !json {
                        println!(
                            "  dns      : raw={dns_raw} unique={dns_unique} dups={dns_dups} → {}",
                            dns_blocklist.display()
                        );
                    }
                } else if !json {
                    println!("  dns      : missing {}", dns_blocklist.display());
                }
            } else {
                dns_skipped = true;
                if !json {
                    println!("  dns      : skipped (--no-dns-dedupe)");
                }
            }

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "apply": apply,
                        "sessions": {
                            "before": before_s,
                            "removed": removed_s,
                            "path": sessions.display().to_string(),
                        },
                        "fleet": {
                            "skipped": fleet_skipped,
                            "before": fleet_before,
                            "removed": fleet_removed,
                            "stale_minutes": fleet_stale_minutes,
                        },
                        "events": {
                            "size": events_size,
                            "would_rotate": events_would_rotate,
                            "rotated": events_rotated,
                            "max_bytes": rotate_max_bytes,
                        },
                        "ioc": {
                            "skipped": ioc_skipped,
                            "before": ioc_before,
                            "removed": ioc_removed,
                            "older_days": ioc_older_days,
                        },
                        "dns": {
                            "skipped": dns_skipped,
                            "raw": dns_raw,
                            "unique": dns_unique,
                            "dups": dns_dups,
                        },
                    }))?
                );
            } else if apply {
                println!("{}", "[aegis] cleanup applied".green().bold());
            } else {
                println!("[aegis] cleanup dry-run complete (use --apply)");
            }
        }
        Commands::Fleet { command } => match command {
            FleetCmd::Enroll {
                fleet,
                host_id: hid,
                name,
                tag,
                json,
            } => {
                let pv = local_policy_version(Path::new(".aegis/fleet-policy.json"));
                let hb = build_local_heartbeat(&fw, hid, name, tag, Some(pv)).await?;
                let mut store = FleetStore::load(&fleet);
                let h = store.upsert_heartbeat(hb);
                store.save(&fleet)?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": true,
                            "action": "enroll",
                            "fleet": fleet.display().to_string(),
                            "host": h,
                        }))?
                    );
                } else {
                    println!(
                        "{}",
                        format!(
                            "[aegis] fleet enrolled host={} posture={} modules={}/{}/{} policy_v={}",
                            h.host_id,
                            h.posture_score,
                            h.modules_implemented,
                            h.modules_partial,
                            h.modules_other,
                            h.policy_version
                        )
                        .green()
                        .bold()
                    );
                    println!("  store : {}", fleet.display());
                }
            }
            FleetCmd::Heartbeat {
                fleet,
                host_id: hid,
                push,
                json,
            } => {
                let pv = local_policy_version(Path::new(".aegis/fleet-policy.json"));
                let hb = build_local_heartbeat(&fw, hid, None, vec![], Some(pv)).await?;
                if let Some(url) = push {
                    let client = reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(10))
                        .build()?;
                    let res = client.post(&url).json(&hb).send().await?;
                    let status = res.status();
                    let text = res.text().await.unwrap_or_default();
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "ok": status.is_success(),
                                "action": "heartbeat_push",
                                "url": url,
                                "status": status.as_u16(),
                                "body": text,
                                "payload": hb,
                            }))?
                        );
                    } else {
                        println!("[aegis] fleet push {url} -> {status} {text}");
                    }
                    if !status.is_success() {
                        std::process::exit(1);
                    }
                } else {
                    let mut store = FleetStore::load(&fleet);
                    let h = store.upsert_heartbeat(hb);
                    store.save(&fleet)?;
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "ok": true,
                                "action": "heartbeat",
                                "fleet": fleet.display().to_string(),
                                "host": h,
                            }))?
                        );
                    } else {
                        println!(
                            "[aegis] fleet heartbeat host={} posture={} last_seen={} policy_v={}",
                            h.host_id, h.posture_score, h.last_seen, h.policy_version
                        );
                    }
                }
            }
            FleetCmd::List {
                fleet,
                stale_minutes,
                json,
            } => {
                let store = FleetStore::load(&fleet);
                if json {
                    println!("{}", serde_json::to_string_pretty(&store)?);
                } else if store.hosts.is_empty() {
                    println!("[aegis] fleet empty — run: aegis fleet enroll");
                } else {
                    println!(
                        "{:<20} {:<12} {:>7} {:>8} {}",
                        "HOST", "OS", "POSTURE", "STATE", "LAST_SEEN"
                    );
                    for h in &store.hosts {
                        let state = if FleetStore::is_stale(h, stale_minutes) {
                            "stale".yellow().to_string()
                        } else {
                            "online".green().to_string()
                        };
                        let name = if h.display_name.is_empty() {
                            h.host_id.as_str()
                        } else {
                            h.display_name.as_str()
                        };
                        println!(
                            "{:<20} {:<12} {:>7} {:>8} {}",
                            name, h.os, h.posture_score, state, h.last_seen
                        );
                    }
                    let s = store.summary(stale_minutes);
                    println!(
                        "--- total={} online={} stale={} avg_posture={:.0}",
                        s.total, s.online, s.stale, s.avg_posture
                    );
                }
            }
            FleetCmd::Show { id, fleet } => {
                let store = FleetStore::load(&fleet);
                match store.get(&id) {
                    Some(h) => println!("{}", serde_json::to_string_pretty(h)?),
                    None => {
                        eprintln!("[aegis] host not found: {id}");
                        std::process::exit(1);
                    }
                }
            }
            FleetCmd::TagAdd { id, tags, fleet } => {
                let mut store = FleetStore::load(&fleet);
                let Some(h) = store.hosts.iter_mut().find(|h| h.host_id == id || h.display_name.eq_ignore_ascii_case(&id)) else {
                    eprintln!("[aegis] host not found: {id}");
                    std::process::exit(1);
                };
                let mut added = Vec::new();
                for t in tags {
                    let t = t.trim();
                    if t.is_empty() {
                        continue;
                    }
                    if !h.tags.iter().any(|x| x.eq_ignore_ascii_case(t)) {
                        h.tags.push(t.to_string());
                        added.push(t.to_string());
                    }
                }
                let host = h.host_id.clone();
                let all = h.tags.clone();
                store.save(&fleet)?;
                if added.is_empty() {
                    println!("[aegis] fleet host '{host}' tags unchanged: {}", all.join(","));
                } else {
                    println!(
                        "{}",
                        format!(
                            "[aegis] fleet host '{host}' tags +{} → [{}]",
                            added.join(","),
                            all.join(",")
                        )
                        .green()
                        .bold()
                    );
                }
            }
            FleetCmd::TagRemove { id, tags, fleet } => {
                let mut store = FleetStore::load(&fleet);
                let Some(h) = store.hosts.iter_mut().find(|h| h.host_id == id || h.display_name.eq_ignore_ascii_case(&id)) else {
                    eprintln!("[aegis] host not found: {id}");
                    std::process::exit(1);
                };
                let remove: Vec<String> = tags
                    .iter()
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect();
                let before = h.tags.len();
                h.tags.retain(|x| {
                    !remove
                        .iter()
                        .any(|r| r.eq_ignore_ascii_case(x))
                });
                let host = h.host_id.clone();
                let all = h.tags.clone();
                let n = before.saturating_sub(h.tags.len());
                store.save(&fleet)?;
                println!(
                    "{}",
                    format!(
                        "[aegis] fleet host '{host}' removed {n} tag(s) → [{}]",
                        all.join(",")
                    )
                    .yellow()
                    .bold()
                );
            }
            FleetCmd::Prune {
                fleet,
                stale_minutes,
                apply,
                json,
            } => {
                let mut store = FleetStore::load(&fleet);
                // dry-run: clone prune without save
                let mut probe = store.clone();
                let removed = probe.prune_stale(stale_minutes);
                if json {
                    if apply && !removed.is_empty() {
                        let _ = store.prune_stale(stale_minutes);
                        store.save(&fleet)?;
                    }
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": true,
                            "apply": apply,
                            "stale_minutes": stale_minutes,
                            "removed_count": removed.len(),
                            "removed": removed,
                            "remaining": store.hosts.len(),
                            "fleet": fleet.display().to_string(),
                        }))?
                    );
                } else if removed.is_empty() {
                    println!(
                        "[aegis] fleet prune: no hosts older than {stale_minutes}m"
                    );
                } else {
                    for h in &removed {
                        println!(
                            "  {} last_seen={} posture={}",
                            h.host_id, h.last_seen, h.posture_score
                        );
                    }
                    if apply {
                        let _ = store.prune_stale(stale_minutes);
                        store.save(&fleet)?;
                        println!(
                            "{}",
                            format!(
                                "[aegis] fleet prune removed {} host(s) → {}",
                                removed.len(),
                                fleet.display()
                            )
                            .green()
                            .bold()
                        );
                    } else {
                        println!(
                            "[aegis] fleet prune dry-run: {} host(s) (use --apply)",
                            removed.len()
                        );
                    }
                }
            }
            FleetCmd::Remove { id, fleet, json } => {
                let mut store = FleetStore::load(&fleet);
                if store.remove(&id) {
                    store.save(&fleet)?;
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "ok": true,
                                "removed": id,
                                "remaining": store.hosts.len(),
                                "fleet": fleet.display().to_string(),
                            }))?
                        );
                    } else {
                        println!("{}", format!("[aegis] removed {id}").yellow());
                    }
                } else {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "ok": false,
                                "error": "host not found",
                                "id": id,
                            }))?
                        );
                    } else {
                        eprintln!("[aegis] host not found: {id}");
                    }
                    std::process::exit(1);
                }
            }
            FleetCmd::Export {
                fleet,
                stale_minutes,
                format,
                out,
            } => {
                let store = FleetStore::load(&fleet);
                let text = if format.eq_ignore_ascii_case("csv") {
                    let mut s = String::from(
                        "host_id,display_name,os,phase,posture_score,last_seen,stale,policy_version,tags\n",
                    );
                    for h in &store.hosts {
                        let stale = FleetStore::is_stale(h, stale_minutes);
                        s.push_str(&format!(
                            "{},{},{},{},{},{},{},{},{}\n",
                            h.host_id,
                            h.display_name.replace(',', " "),
                            h.os.replace(',', " "),
                            h.phase.replace(',', " "),
                            h.posture_score,
                            h.last_seen,
                            stale,
                            h.policy_version,
                            h.tags.join("|").replace(',', " "),
                        ));
                    }
                    s
                } else {
                    let rows: Vec<_> = store
                        .hosts
                        .iter()
                        .map(|h| {
                            serde_json::json!({
                                "host_id": h.host_id,
                                "display_name": h.display_name,
                                "os": h.os,
                                "phase": h.phase,
                                "kernel": h.kernel,
                                "posture_score": h.posture_score,
                                "last_seen": h.last_seen,
                                "enrolled_at": h.enrolled_at,
                                "stale": FleetStore::is_stale(h, stale_minutes),
                                "policy_version": h.policy_version,
                                "tags": h.tags,
                                "last_ip": h.last_ip,
                            })
                        })
                        .collect();
                    serde_json::to_string_pretty(&serde_json::json!({
                        "path": fleet.display().to_string(),
                        "stale_minutes": stale_minutes,
                        "count": rows.len(),
                        "hosts": rows,
                    }))?
                };
                if let Some(path) = out {
                    if let Some(p) = path.parent() {
                        std::fs::create_dir_all(p)?;
                    }
                    std::fs::write(&path, &text)?;
                    println!(
                        "{}",
                        format!(
                            "[aegis] fleet exported {} host(s) → {}",
                            store.hosts.len(),
                            path.display()
                        )
                        .green()
                        .bold()
                    );
                } else {
                    print!("{text}");
                    if !text.ends_with('\n') {
                        println!();
                    }
                }
            }
            FleetCmd::Status {
                fleet,
                policy,
                stale_minutes,
                json,
            } => {
                let store = FleetStore::load(&fleet);
                let pv = local_policy_version(&policy);
                let s = store.summary_with_policy(stale_minutes, pv);
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "fleet": fleet.display().to_string(),
                            "policy": policy.display().to_string(),
                            "stale_minutes": stale_minutes,
                            "summary": s,
                            "policy_version": pv,
                        }))?
                    );
                } else {
                    println!("{}", "Aegis fleet status".bold().green());
                    println!(" Store   : {}", fleet.display());
                    println!(" Total   : {}", s.total);
                    println!(" Online  : {}", s.online.to_string().green());
                    println!(" Stale   : {}", s.stale.to_string().yellow());
                    println!(" Avg posture : {:.0}", s.avg_posture);
                    println!(" Policy v: {pv}");
                    if pv > 0 {
                        println!(
                            " On policy: {}  behind: {}",
                            s.hosts_on_policy, s.hosts_behind_policy
                        );
                    }
                }
            }
            FleetCmd::Doctor {
                fleet,
                policy,
                stale_minutes,
                json,
            } => {
                let mut ok = 0u32;
                let mut warn = 0u32;
                let mut fail = 0u32;
                let mut notes: Vec<serde_json::Value> = Vec::new();
                let mut check = |label: &str, good: bool, soft: bool, detail: &str| {
                    notes.push(serde_json::json!({
                        "label": label,
                        "ok": good,
                        "warn": soft && !good,
                        "detail": detail,
                    }));
                    if good {
                        ok += 1;
                        if !json {
                            println!("  {} {} — {}", "OK".green().bold(), label, detail);
                        }
                    } else if soft {
                        warn += 1;
                        if !json {
                            println!("  {} {} — {}", "WARN".yellow().bold(), label, detail);
                        }
                    } else {
                        fail += 1;
                        if !json {
                            println!("  {} {} — {}", "FAIL".red().bold(), label, detail);
                        }
                    }
                };

                if !json {
                    println!("{}", "Aegis fleet doctor".bold().green());
                }

                let store = FleetStore::load(&fleet);
                check(
                    "fleet store",
                    fleet.exists() || store.hosts.is_empty(),
                    true,
                    &if fleet.exists() {
                        format!("{} (v{})", fleet.display(), store.version)
                    } else {
                        format!("{} missing (run: aegis fleet enroll)", fleet.display())
                    },
                );

                let pv = local_policy_version(&policy);
                let s = store.summary_with_policy(stale_minutes, pv);
                check(
                    "hosts enrolled",
                    s.total > 0,
                    true,
                    &if s.total > 0 {
                        format!("{} hosts", s.total)
                    } else {
                        "empty roster".into()
                    },
                );
                check(
                    "online window",
                    s.total == 0 || s.online > 0,
                    true,
                    &format!(
                        "online={} stale={} (window={}m) avg_posture={:.0}",
                        s.online, s.stale, stale_minutes, s.avg_posture
                    ),
                );
                if s.stale > 0 {
                    check(
                        "stale hosts",
                        false,
                        true,
                        &format!(
                            "{}/{} stale — prune: aegis fleet prune --stale-minutes {stale_minutes}",
                            s.stale, s.total
                        ),
                    );
                }

                let bundle = FleetPolicyBundle::load(&policy);
                check(
                    "desired policy",
                    bundle.is_some(),
                    true,
                    &match &bundle {
                        Some(b) => format!(
                            "{} name={} version={}",
                            policy.display(),
                            b.name,
                            b.version
                        ),
                        None => format!(
                            "{} missing (set: aegis fleet policy set <pack.json>)",
                            policy.display()
                        ),
                    },
                );
                if let Some(ref b) = bundle {
                    check(
                        "policy sync",
                        s.hosts_behind_policy == 0 || s.total == 0,
                        true,
                        &format!(
                            "on_policy={} behind={} desired_v={}",
                            s.hosts_on_policy, s.hosts_behind_policy, b.version
                        ),
                    );
                }

                // Duplicate host ids
                let mut seen = std::collections::BTreeSet::new();
                let mut dups = 0u32;
                for h in &store.hosts {
                    if !seen.insert(h.host_id.clone()) {
                        dups += 1;
                    }
                }
                check(
                    "host_id uniqueness",
                    dups == 0,
                    false,
                    &if dups == 0 {
                        "no duplicates".into()
                    } else {
                        format!("{dups} duplicate host_id row(s)")
                    },
                );

                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": fail == 0,
                            "ok_count": ok,
                            "warn_count": warn,
                            "fail_count": fail,
                            "total": s.total,
                            "online": s.online,
                            "stale": s.stale,
                            "policy_version": pv,
                            "hosts_on_policy": s.hosts_on_policy,
                            "hosts_behind_policy": s.hosts_behind_policy,
                            "checks": notes,
                        }))?
                    );
                } else {
                    println!(
                        " Summary: {} ok, {} warn, {} fail",
                        ok.to_string().green(),
                        warn.to_string().yellow(),
                        fail.to_string().red()
                    );
                }
                if fail > 0 {
                    std::process::exit(1);
                }
            }
            FleetCmd::Policy { command } => match command {
                FleetPolicyCmd::Set { path, policy } => {
                    let text = std::fs::read_to_string(&path)?;
                    let doc: serde_json::Value = serde_json::from_str(&text)?;
                    let prev = FleetPolicyBundle::load(&policy);
                    let bundle = FleetPolicyBundle::from_document(doc, prev.as_ref());
                    bundle.save(&policy)?;
                    println!(
                        "{}",
                        format!(
                            "[aegis] fleet policy set name={} version={} -> {}",
                            bundle.name,
                            bundle.version,
                            policy.display()
                        )
                        .green()
                        .bold()
                    );
                }
                FleetPolicyCmd::Show { policy } => match FleetPolicyBundle::load(&policy) {
                    Some(b) => {
                        println!("version     : {}", b.version);
                        println!("name        : {}", b.name);
                        println!("updated_at  : {}", b.updated_at);
                        println!("document    :");
                        println!("{}", serde_json::to_string_pretty(&b.document)?);
                    }
                    None => {
                        println!("[aegis] no fleet policy at {}", policy.display());
                        println!("  set with: aegis fleet policy set policies/examples/gate-pack.json");
                    }
                },
                FleetPolicyCmd::Apply {
                    policy,
                    event_log,
                    fleet,
                } => {
                    let Some(bundle) = FleetPolicyBundle::load(&policy) else {
                        eprintln!("[aegis] missing {}", policy.display());
                        std::process::exit(2);
                    };
                    let doc: PolicyDocument = serde_json::from_value(bundle.document.clone())?;
                    let store = Arc::new(EventStore::open(&event_log)?);
                    let result = apply_policy(&doc, &fw, Some(store)).await?;
                    if result.ok {
                        println!(
                            "{}",
                            format!(
                                "[aegis] fleet policy applied v{} name={}",
                                bundle.version, result.policy_name
                            )
                            .green()
                            .bold()
                        );
                    } else {
                        println!(
                            "{}",
                            format!("[aegis] fleet policy incomplete: {}", result.policy_name)
                                .yellow()
                        );
                    }
                    for a in &result.applied {
                        println!("  applied : {}", a.green());
                    }
                    for e in &result.errors {
                        println!("  error   : {}", e.red());
                    }
                    // stamp host policy_version
                    let mut roster = FleetStore::load(&fleet);
                    let hb = build_local_heartbeat(
                        &fw,
                        None,
                        None,
                        vec![],
                        Some(bundle.version),
                    )
                    .await?;
                    roster.upsert_heartbeat(hb);
                    roster.save(&fleet)?;
                    if !result.ok {
                        std::process::exit(1);
                    }
                }
                FleetPolicyCmd::Push { path, url } => {
                    let text = std::fs::read_to_string(&path)?;
                    let doc: serde_json::Value = serde_json::from_str(&text)?;
                    let client = reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(15))
                        .build()?;
                    let res = client.post(&url).json(&doc).send().await?;
                    let status = res.status();
                    let body = res.text().await.unwrap_or_default();
                    println!("[aegis] fleet policy push {url} -> {status}");
                    println!("{body}");
                    if !status.is_success() {
                        std::process::exit(1);
                    }
                }
                FleetPolicyCmd::Pull {
                    url,
                    policy,
                    apply,
                    event_log,
                    fleet,
                } => {
                    let client = reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(15))
                        .build()?;
                    let res = client.get(&url).send().await?;
                    if !res.status().is_success() {
                        eprintln!("[aegis] pull failed: {}", res.status());
                        std::process::exit(1);
                    }
                    let bundle: FleetPolicyBundle = res.json().await?;
                    bundle.save(&policy)?;
                    println!(
                        "[aegis] fleet policy pulled v{} name={} -> {}",
                        bundle.version,
                        bundle.name,
                        policy.display()
                    );
                    if apply {
                        let doc: PolicyDocument = serde_json::from_value(bundle.document.clone())?;
                        let store = Arc::new(EventStore::open(&event_log)?);
                        let result = apply_policy(&doc, &fw, Some(store)).await?;
                        println!(
                            "[aegis] apply ok={} applied={}",
                            result.ok,
                            result.applied.len()
                        );
                        let mut roster = FleetStore::load(&fleet);
                        let hb = build_local_heartbeat(
                            &fw,
                            None,
                            None,
                            vec![],
                            Some(bundle.version),
                        )
                        .await?;
                        roster.upsert_heartbeat(hb);
                        roster.save(&fleet)?;
                        if !result.ok {
                            std::process::exit(1);
                        }
                    }
                }
            },
        },
        Commands::Service { command } => {
            if !cfg!(windows) {
                eprintln!("[aegis] service commands are Windows-only (use systemd unit on Linux later)");
                std::process::exit(2);
            }
            match command {
                ServiceCmd::Status { name } => {
                    println!("{}", "Aegis service status".bold().green());
                    println!(" Service name : {name}");
                    match sc_query(&name) {
                        Some(text) => {
                            for line in text.lines().take(12) {
                                println!("  {line}");
                            }
                            let running = text.to_ascii_uppercase().contains("RUNNING");
                            println!(
                                " Summary      : {}",
                                if running {
                                    "RUNNING".green().bold().to_string()
                                } else {
                                    "installed (not running or stopped)".yellow().to_string()
                                }
                            );
                        }
                        None => {
                            println!(" SCM          : {}", "not installed".yellow());
                        }
                    }
                    // Scheduled task probe
                    let task = Command::new("schtasks")
                        .args(["/Query", "/TN", "S2O-Aegisd", "/FO", "LIST"])
                        .output();
                    match task {
                        Ok(o) if o.status.success() => {
                            println!(" Task S2O-Aegisd: {}", "registered".green());
                        }
                        _ => println!(" Task S2O-Aegisd: {}", "not registered".dimmed()),
                    }
                }
                ServiceCmd::Install {
                    name,
                    bin,
                    data_dir,
                    health_bind,
                    task,
                } => {
                    let Some(exe) = resolve_aegisd_bin(bin) else {
                        eprintln!("[aegis] aegisd.exe not found — build first or pass --bin");
                        std::process::exit(2);
                    };
                    let data_dir = data_dir.unwrap_or_else(default_service_data_dir);
                    std::fs::create_dir_all(&data_dir)?;
                    let event_log = data_dir.join("events.jsonl");
                    // binPath for sc: quoted exe + --run-as-service + flags
                    let bin_path = format!(
                        "\"{}\" --run-as-service --event-log \"{}\" --health-bind {}",
                        exe.display(),
                        event_log.display(),
                        health_bind
                    );
                    println!("[aegis] installing service {name}");
                    println!("  binPath : {bin_path}");
                    let (code, stdout, stderr) = run_sc(&[
                        "create",
                        &name,
                        &format!("binPath= {bin_path}"),
                        "start= auto",
                        "DisplayName= S2O Aegis Suite Kernel (aegisd)",
                    ])?;
                    print!("{stdout}{stderr}");
                    if code != 0 {
                        eprintln!(
                            "[aegis] sc create failed (exit {code}). Run elevated Administrator shell."
                        );
                        std::process::exit(code);
                    }
                    let _ = run_sc(&[
                        "description",
                        &name,
                        "S2O Aegis control plane: health HTTP, status matrix, event store",
                    ]);
                    println!("{}", format!("[aegis] service {name} installed").green().bold());
                    println!("  start : aegis service start --name {name}");
                    if task {
                        let action = format!(
                            "\"{}\" start --event-log \"{}\" --health-bind {}",
                            exe.display(),
                            event_log.display(),
                            health_bind
                        );
                        let out = Command::new("schtasks")
                            .args([
                                "/Create",
                                "/TN",
                                "S2O-Aegisd",
                                "/SC",
                                "ONLOGON",
                                "/RL",
                                "LIMITED",
                                "/F",
                                "/TR",
                                &action,
                            ])
                            .output()?;
                        if out.status.success() {
                            println!("  task  : S2O-Aegisd registered (AtLogOn)");
                        } else {
                            eprintln!(
                                "  task  : failed: {}",
                                String::from_utf8_lossy(&out.stderr)
                            );
                        }
                    }
                }
                ServiceCmd::Uninstall { name, task } => {
                    let _ = run_sc(&["stop", &name]);
                    let (code, stdout, stderr) = run_sc(&["delete", &name])?;
                    print!("{stdout}{stderr}");
                    if code != 0 {
                        eprintln!("[aegis] sc delete exit {code} (may need Administrator)");
                    } else {
                        println!("{}", format!("[aegis] service {name} removed").yellow());
                    }
                    if task {
                        let _ = Command::new("schtasks")
                            .args(["/Delete", "/TN", "S2O-Aegisd", "/F"])
                            .status();
                        println!("[aegis] task S2O-Aegisd delete attempted");
                    }
                }
                ServiceCmd::Start { name } => {
                    let (code, stdout, stderr) = run_sc(&["start", &name])?;
                    print!("{stdout}{stderr}");
                    if code != 0 {
                        // fallback task
                        let t = Command::new("schtasks")
                            .args(["/Run", "/TN", "S2O-Aegisd"])
                            .output()?;
                        if t.status.success() {
                            println!("[aegis] started via Scheduled Task S2O-Aegisd");
                        } else {
                            eprintln!("[aegis] service start failed (exit {code})");
                            std::process::exit(code);
                        }
                    } else {
                        println!("{}", format!("[aegis] service {name} started").green().bold());
                    }
                }
                ServiceCmd::Stop { name } => {
                    let (code, stdout, stderr) = run_sc(&["stop", &name])?;
                    print!("{stdout}{stderr}");
                    if code != 0 {
                        eprintln!("[aegis] service stop exit {code}");
                        std::process::exit(code);
                    }
                    println!("{}", format!("[aegis] service {name} stopped").yellow());
                }
            }
        }
        Commands::Run { product, args } => {
            let bin = find_product_bin(&product).ok_or_else(|| {
                format!(
                    "product binary '{product}' not found (build with cargo build -p {product} or similar)"
                )
            })?;
            let status = Command::new(&bin).args(&args).status()?;
            std::process::exit(status.code().unwrap_or(1));
        }
    }

    Ok(())
}
