//! Configuration from environment variables.
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `WICHTEL_ADDR` | `127.0.0.1:8080` | listen address |
//! | `WICHTEL_PORT` | – | overrides the port of `WICHTEL_ADDR` |
//! | `WICHTEL_DB` | `wichtel.db` | database file |
//! | `WICHTEL_PUBLIC_URL` | `http://127.0.0.1:8080` | public base URL (VAPID subject fallback; `https://` ⇒ HSTS header) |
//! | `WICHTEL_VAPID_SUBJECT` | public URL if it is a public `https:` URL, else none (warning) | VAPID `sub` claim (`mailto:` or `https:`) |
//! | `WICHTEL_TRUST_PROXY` | `false` | take the client IP for rate limits from the last `X-Forwarded-For` entry |
//! | `WICHTEL_MAX_GROUPS` | `10000` | global cap on stored groups |
//! | `WICHTEL_PUSH_HOSTS` | known push services | comma-separated allowed push host suffixes; empty = push off |

use std::net::SocketAddr;
use std::time::Duration;

use reqwest::Url;

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
    /// VAPID `sub` claim; empty = none configured (the claim is omitted).
    pub vapid_subject: String,
    pub trust_proxy: bool,
    pub max_groups: u64,
    /// Allowed push endpoint host suffixes (exact host or subdomain); empty = push off.
    pub push_hosts: Vec<String>,
    /// Group creations per client (IPv4 address or IPv6 /48) and hour.
    pub create_limit_per_hour: u32,
    /// Group creations per hour over all clients.
    pub create_limit_global_per_hour: u32,
    /// Joins per IP and hour.
    pub join_limit_per_hour: u32,
    /// Large downloads (`GET …/roles`, `GET …/reveal`) per IP and hour.
    pub download_limit_per_hour: u32,
    /// Maximum concurrent SSE connections per group.
    pub sse_per_group: usize,
    /// Maximum concurrent SSE connections per IP (IPv6: /64).
    pub sse_per_ip: usize,
    /// Maximum concurrent SSE connections in total.
    pub sse_total: usize,
    /// Maximum requests processed at the same time; more are rejected with 503.
    pub max_concurrent_requests: usize,
    /// Upper bound for handling one request, including reading its body.
    pub request_timeout: Duration,
    /// Maximum pause between two chunks of a request body.
    pub body_idle_timeout: Duration,
    /// Minimum time between two push fan-outs of the same group (later ones are merged).
    pub push_min_interval: Duration,
    /// Minimum seconds between two `VACUUM` runs (Spec §14: at most every 5 minutes).
    pub vacuum_interval_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            addr: SocketAddr::from(([127, 0, 0, 1], 8080)),
            db_path: "wichtel.db".into(),
            public_url: "http://127.0.0.1:8080".into(),
            vapid_subject: String::new(),
            trust_proxy: false,
            max_groups: 10_000,
            push_hosts: DEFAULT_PUSH_HOSTS.iter().map(|s| s.to_string()).collect(),
            create_limit_per_hour: 10,
            create_limit_global_per_hour: 500,
            join_limit_per_hour: 120,
            download_limit_per_hour: 300,
            sse_per_group: 100,
            sse_per_ip: 40,
            sse_total: 2000,
            max_concurrent_requests: 256,
            request_timeout: Duration::from_secs(120),
            body_idle_timeout: Duration::from_secs(30),
            push_min_interval: Duration::from_secs(60),
            vacuum_interval_secs: 300,
        }
    }
}

/// `mailto:<address>` or an `https://` URL with a public DNS host name (RFC 8292 §2.1).
pub fn valid_vapid_subject(s: &str) -> bool {
    if let Some(addr) = s.strip_prefix("mailto:") {
        return addr
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'))
            && !addr.chars().any(char::is_whitespace);
    }
    let Ok(url) = Url::parse(s) else {
        return false;
    };
    // `domain()` is `None` for IP literals.
    let Some(host) = url.domain().map(str::to_ascii_lowercase) else {
        return false;
    };
    url.scheme() == "https"
        && host.contains('.')
        && host != "localhost"
        && !host.ends_with(".localhost")
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
                .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            // Review finding 12: "*" (any host) made the server a request relay towards
            // whatever a client registers. Push services are a short, known list, so only
            // explicit host suffixes are accepted.
            if let Some(bad) = c.push_hosts.iter().find(|h| {
                h.contains('*') || !h.contains('.') || h.parse::<std::net::IpAddr>().is_ok()
            }) {
                return Err(format!(
                    "WICHTEL_PUSH_HOSTS {bad:?}: list push service host names explicitly \
                     (e.g. fcm.googleapis.com); wildcards, IP addresses and single labels \
                     are not allowed"
                ));
            }
        }
        match get("WICHTEL_VAPID_SUBJECT") {
            Some(s) if valid_vapid_subject(&s) => c.vapid_subject = s,
            Some(s) => {
                return Err(format!(
                    "WICHTEL_VAPID_SUBJECT {s:?}: must be mailto:<address> or an https:// URL \
                     with a public host name"
                ));
            }
            None if valid_vapid_subject(&c.public_url) => c.vapid_subject = c.public_url.clone(),
            None => {}
        }
        if c.push_enabled() && c.vapid_subject.is_empty() {
            tracing::warn!(
                "Web-Push is enabled but no valid VAPID subject is configured: set \
                 WICHTEL_VAPID_SUBJECT=mailto:<operator address> (or an https WICHTEL_PUBLIC_URL); \
                 push services may reject notifications without it"
            );
        }
        Ok(c)
    }

    /// Whether Web-Push can be used at all.
    pub fn push_enabled(&self) -> bool {
        !self.push_hosts.is_empty()
    }

    /// Whether the public URL is HTTPS (⇒ `Strict-Transport-Security`).
    pub fn is_https(&self) -> bool {
        self.public_url.starts_with("https://")
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
        assert!(c.is_https());
        assert_eq!(c.push_hosts, vec!["a.example", "b.example"]);
        assert!(Config::from_lookup(|k| (k == "WICHTEL_PORT").then(|| "x".into())).is_err());
    }

    #[test]
    fn push_hosts_wildcard_is_rejected() {
        for bad in ["*", "*.example.org", "localhost", "10.0.0.1", "a.example,*"] {
            let r = Config::from_lookup(|k| (k == "WICHTEL_PUSH_HOSTS").then(|| bad.into()));
            assert!(r.is_err(), "{bad}");
        }
        let c = Config::from_lookup(|k| (k == "WICHTEL_PUSH_HOSTS").then(String::new)).unwrap();
        assert!(!c.push_enabled());
    }

    #[test]
    fn vapid_subject_rules() {
        // Default: local http URL ⇒ no subject (only a warning), never 127.0.0.1.
        let c = Config::from_lookup(|_| None).unwrap();
        assert_eq!(c.vapid_subject, "");
        assert!(!c.is_https());
        let c = Config::from_lookup(|k| match k {
            "WICHTEL_PUBLIC_URL" => Some("https://wichteln.example".into()),
            "WICHTEL_VAPID_SUBJECT" => Some("mailto:ops@wichteln.example".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(c.vapid_subject, "mailto:ops@wichteln.example");
        for bad in [
            "http://wichteln.example",
            "https://127.0.0.1",
            "https://localhost",
            "mailto:nobody",
            "ops@example.org",
        ] {
            assert!(!valid_vapid_subject(bad), "{bad}");
            let r = Config::from_lookup(|k| (k == "WICHTEL_VAPID_SUBJECT").then(|| bad.into()));
            assert!(r.is_err(), "{bad}");
        }
        let c = Config::from_lookup(|k| {
            (k == "WICHTEL_PUBLIC_URL").then(|| "https://127.0.0.1:8443".into())
        })
        .unwrap();
        assert_eq!(c.vapid_subject, "");
    }
}
