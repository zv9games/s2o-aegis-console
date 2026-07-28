//! S2O Aegis suite kernel — control plane (T0; Phase 1 foundation + Phase 2 shell).
//!
//! Owns: host identity, honesty matrix, policy routing, event emission hooks.
//! Does not own: OS firewall COM / nft details (worlds do).

mod dns_policy;
mod gate_policy;
mod host;
mod intel_policy;
mod mesh_policy;
mod platform;
mod policy;
mod posture_policy;
mod registry;
mod status;
mod wall;

pub use host::{demo_mode, host_id};
pub use platform::{create_firewall_engine, FirewallEngineHandle};
pub use policy::{apply_policy, load_policy_file, KernelError, KernelResult};
pub use posture_policy::{compute_posture_score, PostureCheck, PostureScore};
pub use registry::{world_baseline, PHASE_LABEL, TIER_CEILING};
pub use status::collect_platform_status;
pub use wall::{
    open_default_store, wall_apply_rules, wall_set_enabled, wall_set_outbound_block,
};

pub const KERNEL_VERSION: &str = "0.1.0";
