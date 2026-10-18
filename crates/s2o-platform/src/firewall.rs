//! Windows Defender Firewall control via `netsh` / `Get-NetFirewall*`.

#[cfg(windows)]
use crate::cmd;
#[cfg(not(windows))]
use crate::windows_only;
use crate::PlatformResult;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProfileStatus {
    pub domain: bool,
    pub private: bool,
    pub public: bool,
}

impl ProfileStatus {
    /// True when the private or public profile (the ones interactive users hit) is on.
    pub fn any_interactive_enabled(&self) -> bool {
        self.private || self.public
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRule {
    pub name: String,
    pub enabled: bool,
    /// "Allow" or "Block"
    pub action: String,
    /// "Inbound" or "Outbound"
    pub direction: String,
}

#[cfg(windows)]
fn profiles_json() -> PlatformResult<Vec<serde_json::Value>> {
    cmd::json_list(&cmd::powershell(
        "Get-NetFirewallProfile | Select-Object Name,@{n='Enabled';e={[string]$_.Enabled}},@{n='Outbound';e={[string]$_.DefaultOutboundAction}} | ConvertTo-Json -Compress",
    )?)
}

pub fn get_profile_status() -> PlatformResult<ProfileStatus> {
    #[cfg(windows)]
    {
        let mut st = ProfileStatus::default();
        for p in profiles_json()? {
            let on = p["Enabled"].as_str() == Some("True");
            match p["Name"].as_str() {
                Some("Domain") => st.domain = on,
                Some("Private") => st.private = on,
                Some("Public") => st.public = on,
                _ => {}
            }
        }
        Ok(st)
    }
    #[cfg(not(windows))]
    windows_only("firewall profile status")
}

/// True when any enabled profile has DefaultOutboundAction = Block.
pub fn is_outbound_blocked() -> PlatformResult<bool> {
    #[cfg(windows)]
    {
        Ok(profiles_json()?.iter().any(|p| {
            p["Enabled"].as_str() == Some("True") && p["Outbound"].as_str() == Some("Block")
        }))
    }
    #[cfg(not(windows))]
    windows_only("outbound block status")
}

fn netsh_set(args: &[&str]) -> PlatformResult<()> {
    #[cfg(windows)]
    {
        let mut a = vec!["advfirewall", "set", "allprofiles"];
        a.extend_from_slice(args);
        cmd::run("netsh", &a).map(|_| ())
    }
    #[cfg(not(windows))]
    {
        let _ = args;
        windows_only("netsh advfirewall")
    }
}

pub fn enable_firewall() -> PlatformResult<()> {
    netsh_set(&["state", "on"])
}

pub fn disable_firewall() -> PlatformResult<()> {
    netsh_set(&["state", "off"])
}

/// "Airplane mode": block inbound and outbound by default on all profiles.
pub fn airplane_mode_enable() -> PlatformResult<()> {
    netsh_set(&["firewallpolicy", "blockinbound,blockoutbound"])
}

pub fn airplane_mode_disable() -> PlatformResult<()> {
    netsh_set(&["firewallpolicy", "blockinbound,allowoutbound"])
}

pub fn get_rules() -> PlatformResult<Vec<RawRule>> {
    #[cfg(windows)]
    {
        let rows = cmd::json_list(&cmd::powershell(
            "Get-NetFirewallRule | Select-Object DisplayName,@{n='Enabled';e={[string]$_.Enabled}},@{n='Action';e={[string]$_.Action}},@{n='Direction';e={[string]$_.Direction}} | ConvertTo-Json -Compress",
        )?)?;
        Ok(rows
            .into_iter()
            .map(|r| RawRule {
                name: r["DisplayName"].as_str().unwrap_or_default().to_string(),
                enabled: r["Enabled"].as_str() == Some("True"),
                action: r["Action"].as_str().unwrap_or("Allow").to_string(),
                direction: r["Direction"].as_str().unwrap_or("Inbound").to_string(),
            })
            .collect())
    }
    #[cfg(not(windows))]
    windows_only("firewall rule listing")
}

pub fn remove_firewall_rule_by_name(name: &str) -> PlatformResult<()> {
    #[cfg(windows)]
    {
        let n = format!("name={name}");
        cmd::run("netsh", &["advfirewall", "firewall", "delete", "rule", &n]).map(|_| ())
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        windows_only("firewall rule removal")
    }
}
