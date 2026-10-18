//! Packet-capture port.
//!
//! Aegis does not ship a kernel packet driver. Capture goes through the
//! [`PacketBackend`] trait so a driver can be plugged in later without
//! touching callers:
//!
//! * [`NoDriver`] (default): always compiled, reports capture unavailable.
//! * `packet-driver` feature: compiles the [`driver::DriverBackend`] slot
//!   intended for WinDivert (see `lib/README.md`) or a future CA-signed
//!   custom driver/DLL. The binding itself is **not implemented yet**; the
//!   slot returns `Unsupported` rather than faking packets.

use crate::{PlatformError, PlatformResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureAvailability {
    Available,
    Unavailable(String),
}

pub trait PacketBackend: Send {
    fn name(&self) -> &'static str;
    fn availability(&self) -> CaptureAvailability;
    /// Open a capture handle with a driver-specific filter expression.
    fn open(&mut self, filter: &str) -> PlatformResult<()>;
    /// Receive one packet into `buf`, returning its length.
    fn recv(&mut self, buf: &mut [u8]) -> PlatformResult<usize>;
    /// Re-inject a (possibly modified) packet.
    fn send(&mut self, packet: &[u8]) -> PlatformResult<()>;
}

/// Default backend: no kernel driver present.
#[derive(Debug, Default)]
pub struct NoDriver;

const NO_DRIVER: &str =
    "no packet driver in this build (rebuild with --features packet-driver once a driver binding exists)";

impl PacketBackend for NoDriver {
    fn name(&self) -> &'static str {
        "none"
    }
    fn availability(&self) -> CaptureAvailability {
        CaptureAvailability::Unavailable(NO_DRIVER.into())
    }
    fn open(&mut self, _filter: &str) -> PlatformResult<()> {
        Err(PlatformError::Unsupported(NO_DRIVER.into()))
    }
    fn recv(&mut self, _buf: &mut [u8]) -> PlatformResult<usize> {
        Err(PlatformError::Unsupported(NO_DRIVER.into()))
    }
    fn send(&mut self, _packet: &[u8]) -> PlatformResult<()> {
        Err(PlatformError::Unsupported(NO_DRIVER.into()))
    }
}

#[cfg(feature = "packet-driver")]
pub mod driver {
    use super::*;

    const TODO: &str =
        "packet-driver feature enabled, but the WinDivert / licensed-driver binding is not implemented yet";

    /// Slot for the kernel driver binding (WinDivert or future CA-signed DLL).
    #[derive(Debug, Default)]
    pub struct DriverBackend;

    impl PacketBackend for DriverBackend {
        fn name(&self) -> &'static str {
            "driver (unbound)"
        }
        fn availability(&self) -> CaptureAvailability {
            CaptureAvailability::Unavailable(TODO.into())
        }
        fn open(&mut self, _filter: &str) -> PlatformResult<()> {
            Err(PlatformError::Unsupported(TODO.into()))
        }
        fn recv(&mut self, _buf: &mut [u8]) -> PlatformResult<usize> {
            Err(PlatformError::Unsupported(TODO.into()))
        }
        fn send(&mut self, _packet: &[u8]) -> PlatformResult<()> {
            Err(PlatformError::Unsupported(TODO.into()))
        }
    }
}

/// Backend selected by build configuration.
pub fn default_backend() -> Box<dyn PacketBackend> {
    #[cfg(feature = "packet-driver")]
    {
        Box::new(driver::DriverBackend)
    }
    #[cfg(not(feature = "packet-driver"))]
    {
        Box::new(NoDriver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_backend_never_fakes_capture() {
        let mut b = default_backend();
        assert!(matches!(b.availability(), CaptureAvailability::Unavailable(_)));
        assert!(b.open("true").is_err());
    }
}
