//! Web-Push without content (Konzept §7.4).
//!
//! - VAPID key pair (P-256) generated on first start and stored in the database.
//! - Every push is an empty `POST` with `TTL` and `Authorization: vapid t=<JWT>, k=<key>`
//!   (RFC 8292, ES256). No payload, hence no encryption and no personal content.
//! - Fan-out goes to *all* subscribers of a group at once; 404/410 ⇒ subscription deleted.
//! - At most one fan-out per group and `push_min_interval`; notifications in between are
//!   merged into one delayed fan-out (pushes carry no content, so the latest state wins).
//! - Delivery runs in a background queue with timeouts; failures are ignored.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use reqwest::Url;
use tokio::sync::mpsc;

use crate::app::Clock;
use crate::store::{Gid, Store, StoreError, WriteOp};

/// `TTL` header of every push (seconds).
pub const PUSH_TTL: u32 = 3600;
/// Lifetime of a VAPID JWT (seconds, RFC 8292 allows at most 24 h).
const JWT_LIFETIME: i64 = 12 * 3600;
const VAPID_KEY_NAME: &str = "vapid_p256_v1";
/// Upper bound on queued group fan-outs; beyond that pushes are dropped (best effort).
const QUEUE_CAPACITY: usize = 1024;

/// The server's VAPID identity.
pub struct Vapid {
    key: SigningKey,
    public: [u8; 65],
    subject: String,
}

impl Vapid {
    /// Load the key from the store or create and persist a new one.
    pub async fn load_or_create(store: &dyn Store, subject: String) -> Result<Self, StoreError> {
        if let Some(raw) = store.get_server_key(VAPID_KEY_NAME).await? {
            let key = SigningKey::from_slice(&raw).map_err(|_| StoreError::Corrupt("vapid key"))?;
            return Ok(Self::from_key(key, subject));
        }
        let key = loop {
            let mut raw = [0u8; 32];
            getrandom::fill(&mut raw).map_err(|_| StoreError::Corrupt("no randomness"))?;
            if let Ok(k) = SigningKey::from_slice(&raw) {
                break k;
            }
        };
        store
            .commit(vec![WriteOp::PutServerKey {
                name: VAPID_KEY_NAME.into(),
                value: key.to_bytes().to_vec(),
            }])
            .await?;
        tracing::info!("generated new VAPID key pair");
        Ok(Self::from_key(key, subject))
    }

    fn from_key(key: SigningKey, subject: String) -> Self {
        let point = key.verifying_key().to_sec1_point(false);
        let public: [u8; 65] = point
            .as_bytes()
            .try_into()
            .expect("uncompressed P-256 point has 65 bytes");
        Self {
            key,
            public,
            subject,
        }
    }

    /// Uncompressed public key (65 bytes) for `PushManager.subscribe`.
    pub fn public_key(&self) -> &[u8; 65] {
        &self.public
    }

    /// `Authorization` header value for a push to `endpoint` (RFC 8292 §3).
    pub fn authorization(&self, endpoint: &Url, now: i64) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
        let mut claims = serde_json::json!({
            "aud": endpoint.origin().ascii_serialization(),
            "exp": now + JWT_LIFETIME,
        });
        if !self.subject.is_empty() {
            claims["sub"] = self.subject.clone().into();
        }
        let claims = URL_SAFE_NO_PAD.encode(claims.to_string());
        let signing_input = format!("{header}.{claims}");
        let sig: Signature = self.key.sign(signing_input.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!(
            "vapid t={signing_input}.{sig}, k={}",
            URL_SAFE_NO_PAD.encode(self.public)
        )
    }
}

/// Check a subscription endpoint: HTTPS, ≤ 1024 chars, DNS host on the allow list
/// (no IP literals, no localhost – the server must not become an SSRF relay). The allow list
/// holds explicit host suffixes only; a wildcard is rejected by the configuration, so no
/// endpoint can point to an attacker-chosen host (or one resolving to a private address).
pub fn validate_endpoint(endpoint: &str, allowed_hosts: &[String]) -> Result<Url, &'static str> {
    if endpoint.len() > 1024 {
        return Err("endpoint too long");
    }
    let url = Url::parse(endpoint).map_err(|_| "endpoint is not a URL")?;
    if url.scheme() != "https" {
        return Err("endpoint must use https");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("endpoint must not contain credentials");
    }
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    // IPv6 literals are bracketed; IPv4 literals parse as addresses.
    if host.is_empty() || host.starts_with('[') || host.parse::<std::net::Ipv4Addr>().is_ok() {
        return Err("endpoint host must be a DNS name");
    }
    if host == "localhost" || host.ends_with(".localhost") || !host.contains('.') {
        return Err("endpoint host not allowed");
    }
    let ok = allowed_hosts
        .iter()
        .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")));
    if !ok {
        return Err("push service not allowed");
    }
    Ok(url)
}

/// One outgoing push request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushMessage {
    pub endpoint: String,
    /// `vapid t=…, k=…`
    pub authorization: String,
    pub ttl: u32,
}

/// Result of a push attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushOutcome {
    Delivered,
    /// 404/410: subscription is gone and must be deleted.
    Gone,
    Failed,
}

/// Transport for pushes (real HTTP client or test mock).
pub trait PushClient: Send + Sync + 'static {
    fn send(&self, msg: PushMessage) -> Pin<Box<dyn Future<Output = PushOutcome> + Send + '_>>;
}

/// HTTPS push client (`reqwest` + rustls/ring) with timeouts and without redirects.
pub struct ReqwestPushClient {
    client: reqwest::Client,
}

impl ReqwestPushClient {
    pub fn new() -> Result<Self, reqwest::Error> {
        // `rustls-no-provider`: install ring as process default (ignored if already set).
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .user_agent("wichtel-server")
            .build()?;
        Ok(Self { client })
    }
}

impl PushClient for ReqwestPushClient {
    fn send(&self, msg: PushMessage) -> Pin<Box<dyn Future<Output = PushOutcome> + Send + '_>> {
        Box::pin(async move {
            let res = self
                .client
                .post(&msg.endpoint)
                .header("TTL", msg.ttl.to_string())
                .header("Urgency", "normal")
                .header("Authorization", msg.authorization)
                .header("Content-Length", "0")
                .body(Vec::<u8>::new())
                .send()
                .await;
            match res {
                Ok(r) if r.status().is_success() => PushOutcome::Delivered,
                Ok(r) if r.status().as_u16() == 404 || r.status().as_u16() == 410 => {
                    PushOutcome::Gone
                }
                Ok(r) => {
                    tracing::debug!(status = r.status().as_u16(), "push rejected");
                    PushOutcome::Failed
                }
                Err(_) => {
                    tracing::debug!("push request failed");
                    PushOutcome::Failed
                }
            }
        })
    }
}

/// Queue for group-wide fan-outs. Notifications for a group that is already queued (or
/// waiting for its rate limit) are merged.
pub struct PushDispatcher {
    tx: mpsc::Sender<Gid>,
    pending: Arc<Mutex<HashSet<Gid>>>,
}

/// Collaborators of the delivery worker.
pub struct PushWorker {
    pub store: Arc<dyn Store>,
    pub vapid: Arc<Vapid>,
    pub client: Arc<dyn PushClient>,
    pub clock: Arc<dyn Clock>,
    /// Minimum time between two fan-outs of the same group.
    pub min_interval: Duration,
    /// Set when gone subscriptions were deleted (bundled `VACUUM`).
    pub vacuum_pending: Arc<AtomicBool>,
}

impl PushDispatcher {
    /// Start the delivery worker. It ends when the dispatcher is dropped.
    pub fn spawn(w: PushWorker) -> Self {
        let (tx, mut rx) = mpsc::channel::<Gid>(QUEUE_CAPACITY);
        let pending: Arc<Mutex<HashSet<Gid>>> = Arc::default();
        let pending2 = pending.clone();
        // Weak: delayed re-queues must not keep the worker alive.
        let requeue = tx.downgrade();
        tokio::spawn(async move {
            let mut last: HashMap<Gid, tokio::time::Instant> = HashMap::new();
            while let Some(gid) = rx.recv().await {
                let now = tokio::time::Instant::now();
                last.retain(|_, t| now.duration_since(*t) < w.min_interval);
                if let Some(t) = last.get(&gid) {
                    // Too early: deliver once the interval has passed. The gid stays in
                    // `pending`, so further notifications are merged into this one.
                    let at = *t + w.min_interval;
                    let requeue = requeue.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep_until(at).await;
                        if let Some(tx) = requeue.upgrade() {
                            let _ = tx.send(gid).await;
                        }
                    });
                    continue;
                }
                pending2.lock().expect("pending lock").remove(&gid);
                if !w.min_interval.is_zero() {
                    last.insert(gid, now);
                }
                if fan_out(&*w.store, &w.vapid, &w.client, w.clock.now(), gid).await {
                    w.vacuum_pending.store(true, Ordering::SeqCst);
                }
            }
        });
        Self { tx, pending }
    }

    /// Queue a push to every subscriber of `gid`.
    pub fn notify(&self, gid: Gid) {
        let mut pending = self.pending.lock().expect("pending lock");
        if !pending.insert(gid) {
            return;
        }
        if self.tx.try_send(gid).is_err() {
            pending.remove(&gid);
            tracing::warn!("push queue full, dropping notification");
        }
    }
}

/// Push to every subscriber of `gid`; `true` if gone subscriptions were deleted.
async fn fan_out(
    store: &dyn Store,
    vapid: &Vapid,
    client: &Arc<dyn PushClient>,
    now: i64,
    gid: Gid,
) -> bool {
    let subs = match store.list_push_subs(&gid).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "push: cannot list subscriptions");
            return false;
        }
    };
    let mut tasks = tokio::task::JoinSet::new();
    for sub in subs {
        let Ok(url) = Url::parse(&sub.endpoint) else {
            continue;
        };
        let msg = PushMessage {
            endpoint: sub.endpoint.clone(),
            authorization: vapid.authorization(&url, now),
            ttl: PUSH_TTL,
        };
        let client = client.clone();
        tasks.spawn(async move { (sub, client.send(msg).await) });
    }
    let mut gone = Vec::new();
    while let Some(res) = tasks.join_next().await {
        if let Ok((sub, PushOutcome::Gone)) = res {
            gone.push(WriteOp::DeletePushSubIfEndpoint {
                gid: sub.gid,
                pid: sub.pid,
                endpoint: sub.endpoint,
            });
        }
    }
    if gone.is_empty() {
        return false;
    }
    match store.commit(gone).await {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(error = %e, "push: cannot delete gone subscriptions");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier;

    #[test]
    fn endpoint_validation() {
        let allowed: Vec<String> = crate::config::DEFAULT_PUSH_HOSTS
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(validate_endpoint("https://fcm.googleapis.com/fcm/send/abc", &allowed).is_ok());
        assert!(
            validate_endpoint(
                "https://updates.push.services.mozilla.com/wpush/v2/x",
                &allowed
            )
            .is_ok()
        );
        assert!(validate_endpoint("https://web.push.apple.com/abc", &allowed).is_ok());
        assert!(validate_endpoint("http://fcm.googleapis.com/x", &allowed).is_err());
        assert!(validate_endpoint("https://evil.example/x", &allowed).is_err());
        assert!(validate_endpoint("https://notfcm.googleapis.com.evil/x", &allowed).is_err());
        assert!(validate_endpoint("https://user:pw@fcm.googleapis.com/x", &allowed).is_err());
        // "*" is no wildcard (and rejected by the configuration anyway).
        let star = vec!["*".to_string()];
        assert!(validate_endpoint("https://push.example.org/x", &star).is_err());
        let custom = vec!["example.org".to_string()];
        assert!(validate_endpoint("https://127.0.0.1/x", &custom).is_err());
        assert!(validate_endpoint("https://[::1]/x", &custom).is_err());
        assert!(validate_endpoint("https://localhost/x", &custom).is_err());
        assert!(validate_endpoint("https://push.example.org/x", &custom).is_ok());
        let long = format!("https://fcm.googleapis.com/{}", "a".repeat(1024));
        assert!(validate_endpoint(&long, &allowed).is_err());
    }

    #[test]
    fn vapid_jwt_is_valid_es256() {
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let v = Vapid::from_key(key, "mailto:ops@example.org".into());
        assert_eq!(v.public_key()[0], 0x04);
        let url = Url::parse("https://fcm.googleapis.com:443/fcm/send/abc").unwrap();
        let auth = v.authorization(&url, 1_000);
        let rest = auth.strip_prefix("vapid t=").unwrap();
        let (jwt, k) = rest.split_once(", k=").unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(k).unwrap(), v.public_key().to_vec());
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["aud"], "https://fcm.googleapis.com");
        assert_eq!(claims["exp"], 1_000 + JWT_LIFETIME);
        assert_eq!(claims["sub"], "mailto:ops@example.org");
        let sig = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        let vk = VerifyingKey::from_sec1_bytes(v.public_key()).unwrap();
        vk.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
            .unwrap();
    }
}
