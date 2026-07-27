//! Aegis event bus: in-process handlers + optional multi-process UDP relay.
//!
//! Phase 0: broadcast callbacks + durable JSONL store.
//! Phase 3: localhost UDP JSON lines for multi-process agents (not gRPC).

use parking_lot::RwLock;
use s2o_schema::{decode_event_json, AegisEvent};
use s2o_store::{EventStore, StoreResult};
use std::net::UdpSocket;
use std::sync::Arc;
use std::time::Duration;

/// Default multi-process event UDP bind (lab).
pub const DEFAULT_EVENT_UDP: &str = "127.0.0.1:9091";

pub type EventHandler = Arc<dyn Fn(&AegisEvent) + Send + Sync + 'static>;

#[derive(Clone)]
pub struct EventBus {
    inner: Arc<Inner>,
}

struct Inner {
    handlers: RwLock<Vec<EventHandler>>,
    store: RwLock<Option<EventStore>>,
}

impl EventBus {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                handlers: RwLock::new(Vec::new()),
                store: RwLock::new(None),
            }),
        }
    }

    /// Attach a durable JSONL store; every publish is appended.
    pub fn with_store(store: EventStore) -> Self {
        let bus = Self::new();
        *bus.inner.store.write() = Some(store);
        bus
    }

    pub fn subscribe(&self, handler: EventHandler) {
        self.inner.handlers.write().push(handler);
    }

    pub fn publish(&self, event: AegisEvent) -> StoreResult<()> {
        if let Some(store) = self.inner.store.read().as_ref() {
            store.append(&event)?;
        }
        for handler in self.inner.handlers.read().iter() {
            handler(&event);
        }
        Ok(())
    }

    pub fn store_count(&self) -> StoreResult<Option<usize>> {
        match self.inner.store.read().as_ref() {
            Some(s) => Ok(Some(s.count()?)),
            None => Ok(None),
        }
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Multi-process UDP JSON-line relay
// ---------------------------------------------------------------------------

/// Send one event as a JSON datagram to a peer (e.g. aegisd `--event-udp`).
pub fn udp_send(addr: &str, event: &AegisEvent) -> Result<(), String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec(event).map_err(|e| e.to_string())?;
    if bytes.len() > 60_000 {
        return Err("event too large for UDP datagram".into());
    }
    sock.send_to(&bytes, addr).map_err(|e| e.to_string())?;
    Ok(())
}

/// Bind a UDP socket for receiving event datagrams.
pub fn udp_bind(addr: &str) -> Result<UdpSocket, String> {
    let sock = UdpSocket::bind(addr).map_err(|e| format!("udp bind {addr}: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|e| e.to_string())?;
    Ok(sock)
}

/// Decode a UDP payload as AegisEvent or compact EventIngest.
pub fn udp_decode(buf: &[u8], default_host: &str) -> Result<AegisEvent, String> {
    let s = std::str::from_utf8(buf).map_err(|e| e.to_string())?;
    decode_event_json(s, default_host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use s2o_schema::{EventAction, EventKind, ProductId, Severity};

    #[test]
    fn udp_roundtrip_localhost() {
        let sock = udp_bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        let ev = AegisEvent::new(
            "host-t",
            ProductId::Aegis,
            EventKind::Alert,
            EventAction::Observed,
            Severity::High,
            "bus test",
        );
        udp_send(&addr, &ev).unwrap();
        let mut buf = [0u8; 65535];
        let (n, _) = sock.recv_from(&mut buf).unwrap();
        let back = udp_decode(&buf[..n], "host-t").unwrap();
        assert_eq!(back.message, "bus test");
        assert_eq!(back.severity, Severity::High);
    }
}
