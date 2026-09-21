use serde::{Deserialize, Serialize};

pub const AEGIS_PIPE_NAME: &str = r"\\.\pipe\s2o_aegis_ipc";
pub const AEGIS_UNIX_SOCKET: &str = "/tmp/s2o_aegis.sock";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequest {
    pub id: u64,
    pub method: String,
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    pub id: u64,
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
}

impl IpcResponse {
    pub fn ok(id: u64, data: serde_json::Value) -> Self {
        Self {
            id,
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(id: u64, msg: impl Into<String>) -> Self {
        Self {
            id,
            success: false,
            data: None,
            error: Some(msg.into()),
        }
    }
}
