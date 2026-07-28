//! Mesh policy fragment — seeds CyberMesh peer registry file (no tunnel up).

use std::fs;
use std::path::Path;

use s2o_schema::MeshPolicyIntent;
use s2o_store::EventStore;

use crate::policy::{KernelError, KernelResult};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct PeerRegistryFile {
    #[serde(default)]
    version: String,
    #[serde(default)]
    peers: Vec<PeerFile>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PeerFile {
    name: String,
    public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    endpoint: Option<String>,
    #[serde(default = "default_allowed")]
    allowed_ips: String,
    #[serde(default = "default_keepalive")]
    keepalive: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
}

fn default_allowed() -> String {
    "10.220.0.0/24".into()
}
fn default_keepalive() -> u16 {
    25
}

pub fn apply_mesh_intent(
    intent: &MeshPolicyIntent,
    _store: Option<&EventStore>,
) -> KernelResult<Vec<String>> {
    if intent.peers.is_empty() && !intent.replace {
        return Ok(Vec::new());
    }

    let path = Path::new(
        intent
            .peers_file
            .as_deref()
            .unwrap_or(".aegis/mesh-peers.json"),
    );
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut reg = if intent.replace || !path.exists() {
        PeerRegistryFile {
            version: "0.1.0".into(),
            peers: Vec::new(),
        }
    } else {
        let text = fs::read_to_string(path)?;
        serde_json::from_str::<PeerRegistryFile>(&text).unwrap_or_else(|_| PeerRegistryFile {
            version: "0.1.0".into(),
            peers: Vec::new(),
        })
    };
    if reg.version.is_empty() {
        reg.version = "0.1.0".into();
    }

    let mut applied = Vec::new();
    if intent.replace {
        applied.push("mesh.replace=true".into());
    }

    let mut upserted = 0u32;
    for p in &intent.peers {
        let name = p.name.trim();
        let pk = p.public_key.trim();
        if name.is_empty() || pk.is_empty() {
            return Err(KernelError::Policy(
                "mesh peer requires non-empty name and public_key".into(),
            ));
        }
        let peer = PeerFile {
            name: name.to_string(),
            public_key: pk.to_string(),
            endpoint: p.endpoint.clone(),
            allowed_ips: if p.allowed_ips.trim().is_empty() {
                default_allowed()
            } else {
                p.allowed_ips.clone()
            },
            keepalive: if p.keepalive == 0 { 25 } else { p.keepalive },
            notes: p.notes.clone(),
        };
        if let Some(existing) = reg.peers.iter_mut().find(|e| e.name == peer.name) {
            *existing = peer;
        } else {
            reg.peers.push(peer);
        }
        upserted += 1;
    }
    applied.push(format!("mesh.peers_upserted={upserted}"));
    applied.push(format!("mesh.peers_total={}", reg.peers.len()));

    let text = serde_json::to_string_pretty(&reg).map_err(KernelError::Json)?;
    fs::write(path, text)?;
    applied.push(format!("mesh.peers_file={}", path.display()));
    Ok(applied)
}
