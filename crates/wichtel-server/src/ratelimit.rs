//! Fixed-window rate limits per client IP, **only in RAM** (Review D2). IPv6 addresses are
//! grouped by their /64 prefix (group creation: /48, since one end customer often gets a
//! whole /48 or /56). Nothing is logged or persisted.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

/// What is being limited.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Bucket {
    CreateGroup,
    /// Group creations over all clients (key: the unspecified address).
    CreateGroupGlobal,
    Join,
    /// Large downloads (`R`, reveal release).
    Download,
}

impl Bucket {
    /// IPv6 prefix length that identifies one client for this bucket.
    fn v6_prefix(self) -> u8 {
        match self {
            Bucket::CreateGroup => 48,
            _ => 64,
        }
    }
}

#[derive(Default)]
pub struct RateLimiter {
    windows: Mutex<HashMap<(IpAddr, Bucket), (i64, u32)>>,
}

impl RateLimiter {
    /// Count one request; `false` if `limit` requests in the current `window` seconds are
    /// already used.
    pub fn check(&self, ip: IpAddr, bucket: Bucket, limit: u32, window: i64, now: i64) -> bool {
        let key = (client_key(ip, bucket.v6_prefix()), bucket);
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

    /// Like [`RateLimiter::check`] for a limit shared by all clients.
    pub fn check_global(&self, bucket: Bucket, limit: u32, window: i64, now: i64) -> bool {
        self.check(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            bucket,
            limit,
            window,
            now,
        )
    }

    /// Forget expired windows.
    pub fn cleanup(&self, now: i64, window: i64) {
        self.windows
            .lock()
            .expect("rate lock")
            .retain(|_, (start, _)| now - *start < window);
    }
}

/// The address identifying one client: IPv4 as is (also IPv4-mapped IPv6), IPv6 truncated to
/// `v6_prefix` bits.
pub fn client_key(ip: IpAddr, v6_prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            let bits = u128::from(v6);
            let mask = u128::MAX
                .checked_shl(128 - u32::from(v6_prefix.min(128)))
                .unwrap_or(0);
            IpAddr::V6((bits & mask).into())
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

    #[test]
    fn create_uses_slash_48_and_global_limit() {
        let rl = RateLimiter::default();
        let a: IpAddr = "2001:db8:1:1::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:ffff::1".parse().unwrap();
        let c: IpAddr = "2001:db8:2::1".parse().unwrap();
        assert!(rl.check(a, Bucket::CreateGroup, 1, 60, 0));
        assert!(!rl.check(b, Bucket::CreateGroup, 1, 60, 0), "same /48");
        assert!(rl.check(c, Bucket::CreateGroup, 1, 60, 0), "other /48");
        assert!(rl.check(b, Bucket::Join, 1, 60, 0), "joins: /64");
        assert!(rl.check_global(Bucket::CreateGroupGlobal, 2, 60, 0));
        assert!(rl.check_global(Bucket::CreateGroupGlobal, 2, 60, 0));
        assert!(!rl.check_global(Bucket::CreateGroupGlobal, 2, 60, 0));
        assert_eq!(
            client_key("2001:db8:aaaa:bbbb::1".parse().unwrap(), 48),
            "2001:db8:aaaa::".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            client_key("::ffff:10.1.2.3".parse().unwrap(), 48),
            "10.1.2.3".parse::<IpAddr>().unwrap()
        );
    }
}
