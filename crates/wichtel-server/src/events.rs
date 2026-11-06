//! Per-group broadcast of [`UpdateEvent`]s for the SSE endpoint, with connection limits
//! (per group, per client IP, in total) and shutdown.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;
use wichtel_api::UpdateEvent;

use crate::ratelimit::client_key;
use crate::store::Gid;

const CHANNEL_CAPACITY: usize = 16;

/// Connection limits for [`Hub::subscribe`].
#[derive(Clone, Copy, Debug)]
pub struct SseLimits {
    pub per_group: usize,
    pub per_ip: usize,
    pub total: usize,
}

/// Why a subscription was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// A connection limit is reached.
    Limit,
    /// The server is shutting down.
    ShuttingDown,
}

#[derive(Default)]
struct Counts {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

/// One SSE connection slot; released on drop (when the stream ends).
pub struct SseSlot {
    counts: Arc<Mutex<Counts>>,
    ip: Option<IpAddr>,
}

impl Drop for SseSlot {
    fn drop(&mut self) {
        let mut c = self.counts.lock().expect("sse counts");
        c.total = c.total.saturating_sub(1);
        if let Some(ip) = self.ip
            && let Some(n) = c.per_ip.get_mut(&ip)
        {
            *n -= 1;
            if *n == 0 {
                c.per_ip.remove(&ip);
            }
        }
    }
}

/// A live subscription: the receiver plus its connection slot.
pub struct Subscription {
    pub rx: broadcast::Receiver<UpdateEvent>,
    pub slot: SseSlot,
}

/// One `broadcast` channel per group with at least one listener.
#[derive(Default)]
pub struct Hub {
    channels: Mutex<HashMap<Gid, broadcast::Sender<UpdateEvent>>>,
    counts: Arc<Mutex<Counts>>,
    closed: AtomicBool,
}

impl Hub {
    /// Subscribe to updates of `gid` for a client at `ip`.
    pub fn subscribe(
        &self,
        gid: Gid,
        ip: Option<IpAddr>,
        limits: SseLimits,
    ) -> Result<Subscription, Refused> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Refused::ShuttingDown);
        }
        let ip = ip.map(|ip| client_key(ip, 64));
        let mut counts = self.counts.lock().expect("sse counts");
        if counts.total >= limits.total
            || ip.is_some_and(|ip| counts.per_ip.get(&ip).copied().unwrap_or(0) >= limits.per_ip)
        {
            return Err(Refused::Limit);
        }
        let mut map = self.channels.lock().expect("hub lock");
        let tx = map
            .entry(gid)
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0);
        if tx.receiver_count() >= limits.per_group {
            return Err(Refused::Limit);
        }
        let rx = tx.subscribe();
        counts.total += 1;
        if let Some(ip) = ip {
            *counts.per_ip.entry(ip).or_default() += 1;
        }
        Ok(Subscription {
            rx,
            slot: SseSlot {
                counts: self.counts.clone(),
                ip,
            },
        })
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

    /// End every stream and refuse new subscriptions (graceful shutdown).
    pub fn shutdown(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.channels.lock().expect("hub lock").clear();
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
        self.counts.lock().expect("sse counts").total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_and_release() {
        let hub = Hub::default();
        let lim = SseLimits {
            per_group: 3,
            per_ip: 2,
            total: 4,
        };
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let s1 = hub.subscribe([1; 16], Some(a), lim).unwrap();
        let _s2 = hub.subscribe([2; 16], Some(a), lim).unwrap();
        assert_eq!(
            hub.subscribe([3; 16], Some(a), lim).err(),
            Some(Refused::Limit),
            "per IP"
        );
        let _s3 = hub.subscribe([1; 16], Some(b), lim).unwrap();
        let _s4 = hub.subscribe([1; 16], None, lim).unwrap();
        assert_eq!(hub.listener_count(), 4);
        assert_eq!(
            hub.subscribe([9; 16], None, lim).err(),
            Some(Refused::Limit),
            "total"
        );
        drop(s1);
        assert_eq!(hub.listener_count(), 3);
        let _s5 = hub.subscribe([3; 16], Some(a), lim).unwrap();
        hub.shutdown();
        assert_eq!(
            hub.subscribe([3; 16], None, lim).err(),
            Some(Refused::ShuttingDown)
        );
    }
}
