//! Fixed-window rate limits per client IP, **only in RAM** (Review D2). IPv6 addresses are
//! grouped by their /64 prefix. Nothing is logged or persisted.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

/// What is being limited.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Bucket {
    CreateGroup,
    Join,
}

#[derive(Default)]
pub struct RateLimiter {
    windows: Mutex<HashMap<(IpAddr, Bucket), (i64, u32)>>,
}

impl RateLimiter {
    /// Count one request; `false` if `limit` requests in the current `window` seconds are
    /// already used.
    pub fn check(&self, ip: IpAddr, bucket: Bucket, limit: u32, window: i64, now: i64) -> bool {
        let key = (normalize(ip), bucket);
        let mut map = self.windows.lock().expect("rate lock");
        let entry = map.entry(key).or_insert((now, 0));
        if now - entry.0 >= window {
            *entry = (now, 0);
        }
        if entry.1 >= limit {
            return false;
        }
        entry.1 += 1;
        true
    }

    /// Forget expired windows.
    pub fn cleanup(&self, now: i64, window: i64) {
        self.windows
            .lock()
            .expect("rate lock")
            .retain(|_, (start, _)| now - *start < window);
    }
}

fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            let mut seg = v6.segments();
            seg[4..].fill(0);
            IpAddr::V6(seg.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_and_prefix() {
        let rl = RateLimiter::default();
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let b: IpAddr = "2001:db8::2".parse().unwrap();
        assert!(rl.check(a, Bucket::Join, 2, 60, 0));
        assert!(rl.check(b, Bucket::Join, 2, 60, 1));
        assert!(!rl.check(a, Bucket::Join, 2, 60, 2), "same /64");
        assert!(rl.check(a, Bucket::CreateGroup, 2, 60, 2), "other bucket");
        assert!(rl.check(a, Bucket::Join, 2, 60, 60), "new window");
        rl.cleanup(1000, 60);
        assert!(rl.windows.lock().unwrap().is_empty());
    }
}
