//! In-process Aegis event bus with optional durable store fan-out.
//!
//! Phase 0: broadcast channel via callbacks + optional JSONL store.
//! Later: named pipe / gRPC for multi-process agents.

use parking_lot::RwLock;
use s2o_schema::AegisEvent;
use s2o_store::{EventStore, StoreResult};
use std::sync::Arc;

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
