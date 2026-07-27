//! Mesh peer registry (file-backed) for multi-peer WireGuard conf.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshPeer {
    pub name: String,
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default = "default_allowed")]
    pub allowed_ips: String,
    #[serde(default = "default_keepalive")]
    pub keepalive: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

fn default_allowed() -> String {
    "10.220.0.0/24".into()
}
fn default_keepalive() -> u16 {
    25
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerRegistry {
    pub version: String,
    pub peers: Vec<MeshPeer>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self {
            version: "0.1.0".into(),
            peers: Vec::new(),
        }
    }

    pub fn load(path: &Path) -> Self {
        if !path.exists() {
            return Self::new();
        }
        fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_else(Self::new)
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p)?;
        }
        let mut out = self.clone();
        if out.version.is_empty() {
            out.version = "0.1.0".into();
        }
        fs::write(
            path,
            serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".into()),
        )
    }

    pub fn add(&mut self, peer: MeshPeer) {
        if let Some(p) = self.peers.iter_mut().find(|p| p.name == peer.name) {
            *p = peer;
        } else {
            self.peers.push(peer);
        }
    }

    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.peers.len();
        self.peers.retain(|p| p.name != name);
        self.peers.len() < before
    }

    pub fn render_peer_sections(&self) -> String {
        let mut conf = String::new();
        for p in &self.peers {
            conf.push_str("\n[Peer]\n");
            conf.push_str(&format!("# {}\n", p.name));
            conf.push_str(&format!("PublicKey = {}\n", p.public_key));
            conf.push_str(&format!("AllowedIPs = {}\n", p.allowed_ips));
            if let Some(ref ep) = p.endpoint {
                conf.push_str(&format!("Endpoint = {ep}\n"));
            }
            conf.push_str(&format!("PersistentKeepalive = {}\n", p.keepalive));
        }
        conf
    }
}
