//! OS integration layer for S2O Aegis.
//!
//! Replaces the out-of-tree `net-lib` dependency. Everything here compiles on
//! every platform; operations that only exist on Windows return
//! [`PlatformError::Unsupported`] elsewhere instead of pretending to succeed.

pub mod defender;
pub mod firewall;
pub mod packet;
pub mod telemetry;

mod cmd;

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformError {
    /// The operation does not exist on this OS / build configuration.
    Unsupported(String),
    /// An external command or OS call failed.
    Command(String),
    /// Output could not be parsed.
    Parse(String),
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlatformError::Unsupported(m) => write!(f, "unsupported: {m}"),
            PlatformError::Command(m) => write!(f, "command failed: {m}"),
            PlatformError::Parse(m) => write!(f, "parse error: {m}"),
        }
    }
}

impl std::error::Error for PlatformError {}

pub type PlatformResult<T> = Result<T, PlatformError>;

pub(crate) fn windows_only<T>(what: &str) -> PlatformResult<T> {
    Err(PlatformError::Unsupported(format!(
        "{what} is only implemented on Windows"
    )))
}
