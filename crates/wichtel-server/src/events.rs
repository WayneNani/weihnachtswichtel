//! Per-group broadcast of [`UpdateEvent`]s for the SSE endpoint.

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::broadcast;
use wichtel_api::UpdateEvent;

use crate::store::Gid;

const CHANNEL_CAPACITY: usize = 16;

/// One `broadcast` channel per group with at least one listener.
#[derive(Default)]
pub struct Hub {
    channels: Mutex<HashMap<Gid, broadcast::Sender<UpdateEvent>>>,
}

impl Hub {
    /// Subscribe to updates of `gid`; `None` if `limit` listeners are already connected.
    pub fn subscribe(&self, gid: Gid, limit: usize) -> Option<broadcast::Receiver<UpdateEvent>> {
        let mut map = self.channels.lock().expect("hub lock");
        let tx = map
            .entry(gid)
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0);
        if tx.receiver_count() >= limit {
            return None;
        }
        Some(tx.subscribe())
    }

    /// Whether anybody listens on `gid` (avoids building events nobody receives).
    pub fn has_listeners(&self, gid: &Gid) -> bool {
        self.channels
            .lock()
            .expect("hub lock")
            .get(gid)
            .is_some_and(|tx| tx.receiver_count() > 0)
    }

    /// Send an event to all listeners of `gid`.
    pub fn publish(&self, gid: &Gid, event: UpdateEvent) {
        let mut map = self.channels.lock().expect("hub lock");
        if let Some(tx) = map.get(gid)
            && tx.send(event).is_err()
        {
            map.remove(gid);
        }
    }

    /// Drop the channel of a deleted group; listeners' streams end.
    pub fn close(&self, gid: &Gid) {
        self.channels.lock().expect("hub lock").remove(gid);
    }

    /// Remove channels without listeners.
    pub fn cleanup(&self) {
        self.channels
            .lock()
            .expect("hub lock")
            .retain(|_, tx| tx.receiver_count() > 0);
    }

    /// Total number of connected listeners.
    pub fn listener_count(&self) -> usize {
        self.channels
            .lock()
            .expect("hub lock")
            .values()
            .map(|tx| tx.receiver_count())
            .sum()
    }
}
