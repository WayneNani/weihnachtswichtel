//! Configuration from environment variables.
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `WICHTEL_ADDR` | `127.0.0.1:8080` | listen address |
//! | `WICHTEL_PORT` | – | overrides the port of `WICHTEL_ADDR` |
//! | `WICHTEL_DB` | `wichtel.db` | database file |
//! | `WICHTEL_PUBLIC_URL` | `http://127.0.0.1:8080` | public base URL (VAPID subject fallback) |
//! | `WICHTEL_VAPID_SUBJECT` | public URL | VAPID `sub` claim (`mailto:` or `https:`) |
//! | `WICHTEL_TRUST_PROXY` | `false` | take the client IP for rate limits from the last `X-Forwarded-For` entry |
//! | `WICHTEL_MAX_GROUPS` | `10000` | global cap on stored groups |
//! | `WICHTEL_PUSH_HOSTS` | known push services | comma-separated allowed push host suffixes, `*` = any public host |

use std::net::SocketAddr;

/// Default push service host suffixes (Google FCM, Mozilla autopush, Apple, Microsoft WNS).
pub const DEFAULT_PUSH_HOSTS: &[&str] = &[
    "fcm.googleapis.com",
    "push.services.mozilla.com",
    "push.apple.com",
    "notify.windows.com",
];

#[derive(Clone, Debug)]
pub struct Config {
    pub addr: SocketAddr,
    pub db_path: String,
    pub public_url: String,
    pub vapid_subject: String,
    pub trust_proxy: bool,
    pub max_groups: u64,
    /// Allowed push endpoint host suffixes; `["*"]` allows any non-local host.
    pub push_hosts: Vec<String>,
    /// Group creations per IP and hour.
    pub create_limit_per_hour: u32,
    /// Joins per IP and hour.
    pub join_limit_per_hour: u32,
    /// Maximum concurrent SSE connections per group.
    pub sse_per_group: usize,
    /// Minimum seconds between two `VACUUM` runs (Spec §14: at most every 5 minutes).
    pub vacuum_interval_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            addr: SocketAddr::from(([127, 0, 0, 1], 8080)),
            db_path: "wichtel.db".into(),
            public_url: "http://127.0.0.1:8080".into(),
            vapid_subject: "http://127.0.0.1:8080".into(),
            trust_proxy: false,
            max_groups: 10_000,
            push_hosts: DEFAULT_PUSH_HOSTS.iter().map(|s| s.to_string()).collect(),
            create_limit_per_hour: 10,
            join_limit_per_hour: 120,
            sse_per_group: 100,
            vacuum_interval_secs: 300,
        }
    }
}

impl Config {
    /// Read the configuration from `WICHTEL_*` environment variables.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Like [`Config::from_env`] with an explicit lookup function (testable).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let mut c = Self::default();
        if let Some(a) = get("WICHTEL_ADDR") {
            c.addr = a.parse().map_err(|e| format!("WICHTEL_ADDR {a:?}: {e}"))?;
        }
        if let Some(p) = get("WICHTEL_PORT") {
            let port: u16 = p.parse().map_err(|e| format!("WICHTEL_PORT {p:?}: {e}"))?;
            c.addr.set_port(port);
        }
        if let Some(d) = get("WICHTEL_DB") {
            c.db_path = d;
        }
        if let Some(u) = get("WICHTEL_PUBLIC_URL") {
            c.public_url = u.trim_end_matches('/').to_owned();
        }
        c.vapid_subject = get("WICHTEL_VAPID_SUBJECT").unwrap_or_else(|| c.public_url.clone());
        if !(c.vapid_subject.starts_with("mailto:") || c.vapid_subject.starts_with("https://")) {
            tracing::warn!("WICHTEL_VAPID_SUBJECT should be a mailto: or https: URL");
        }
        if let Some(t) = get("WICHTEL_TRUST_PROXY") {
            c.trust_proxy = matches!(t.as_str(), "1" | "true" | "yes" | "on");
        }
        if let Some(m) = get("WICHTEL_MAX_GROUPS") {
            c.max_groups = m
                .parse()
                .map_err(|e| format!("WICHTEL_MAX_GROUPS {m:?}: {e}"))?;
        }
        if let Some(h) = get("WICHTEL_PUSH_HOSTS") {
            c.push_hosts = h
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_parsing() {
        let c = Config::from_lookup(|k| match k {
            "WICHTEL_ADDR" => Some("0.0.0.0:1".into()),
            "WICHTEL_PORT" => Some("9000".into()),
            "WICHTEL_DB" => Some("/tmp/x.db".into()),
            "WICHTEL_PUBLIC_URL" => Some("https://wichteln.example/".into()),
            "WICHTEL_PUSH_HOSTS" => Some("a.example, B.example".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(c.addr.to_string(), "0.0.0.0:9000");
        assert_eq!(c.db_path, "/tmp/x.db");
        assert_eq!(c.public_url, "https://wichteln.example");
        assert_eq!(c.vapid_subject, "https://wichteln.example");
        assert_eq!(c.push_hosts, vec!["a.example", "b.example"]);
        assert!(Config::from_lookup(|k| (k == "WICHTEL_PORT").then(|| "x".into())).is_err());
    }
}
