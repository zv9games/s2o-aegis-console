use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProfileType {
    Private,
    Public,
    Domain,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    Allow,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleProtocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperatingSystem {
    Windows,
    Linux,
    Darwin,
    FreeBSD,
    Unknown,
}

impl OperatingSystem {
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            OperatingSystem::Windows
        } else if cfg!(target_os = "linux") {
            OperatingSystem::Linux
        } else if cfg!(target_os = "macos") {
            OperatingSystem::Darwin
        } else if cfg!(target_os = "freebsd") {
            OperatingSystem::FreeBSD
        } else {
            OperatingSystem::Unknown
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriverSubstrate {
    /// Native OS Userspace APIs (Tier-0: $0/year, no driver signing required)
    /// Windows: COM INetFwPolicy2, WFP User API, IP Helper
    /// Linux: nftables, iptables, /proc
    /// macOS: pfctl, scutil
    UserspaceNative,
    /// Future Kernel-Mode Engine
    /// Windows: Kernel Callout Driver (.sys via WFP / NDIS)
    /// Linux: eBPF (XDP / TC / LSM) or Kernel Module
    /// macOS: NetworkExtension / EndpointSecurity SystemExtension
    KernelDriver,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverCapabilities {
    pub substrate: DriverSubstrate,
    pub os: OperatingSystem,
    pub supports_packet_injection: bool,
    pub supports_process_lineage: bool,
    pub supports_kernel_bypass: bool,
    pub driver_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallStatus {
    pub enabled: bool,
    pub outbound_blocked: bool,
    pub defender_active: bool,
    pub profile_private: bool,
    pub profile_public: bool,
    pub profile_domain: bool,
    pub platform: String,
    pub backend_driver: String,
    pub substrate: DriverSubstrate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub name: String,
    pub enabled: bool,
    pub action: RuleAction,
    pub direction: RuleDirection,
    pub profile: ProfileType,
    #[serde(default)]
    pub protocol: Option<RuleProtocol>,
    #[serde(default)]
    pub local_ports: Option<String>,
    #[serde(default)]
    pub remote_ports: Option<String>,
    #[serde(default)]
    pub remote_addresses: Option<String>,
    #[serde(default)]
    pub application: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct RuleFilter {
    pub direction: Option<RuleDirection>,
    pub action: Option<RuleAction>,
    pub protocol: Option<RuleProtocol>,
    pub port: Option<u16>,
    pub search: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallPolicy {
    pub name: String,
    pub version: String,
    pub rules: Vec<FirewallRule>,
}
