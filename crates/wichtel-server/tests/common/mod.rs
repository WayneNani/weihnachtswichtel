//! Shared test harness: temporary Turso file, mock clock, mock push client, fake protocol ops.
#![allow(dead_code)]

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use wichtel_core::dcnet::RolesOutcome;
use wichtel_core::keys::UploadKind;
use wichtel_core::roster::RosterEntry;
use wichtel_server::app::Clock;
use wichtel_server::protocol::ProtocolOps;
use wichtel_server::push::{PushClient, PushMessage, PushOutcome};
use wichtel_server::store::TursoStore;
use wichtel_server::{App, Config, routes};

pub const T0: i64 = 1_790_000_000;

pub fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

pub fn unb64(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).unwrap()
}

pub fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

// ---------------------------------------------------------------- clock

#[derive(Default)]
pub struct MockClock(pub AtomicI64);

impl MockClock {
    pub fn set(&self, t: i64) {
        self.0.store(t, Ordering::SeqCst);
    }
    pub fn advance(&self, d: i64) {
        self.0.fetch_add(d, Ordering::SeqCst);
    }
}

impl Clock for MockClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------- push

#[derive(Default)]
pub struct MockPush {
    pub sent: Mutex<Vec<PushMessage>>,
    pub gone: Mutex<HashSet<String>>,
}

impl MockPush {
    pub fn count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }

    /// Wait until at least `n` pushes were sent (the dispatcher runs in the background).
    pub async fn wait_for(&self, n: usize) -> Vec<PushMessage> {
        for _ in 0..200 {
            if self.count() >= n {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Give stray extra deliveries a moment to show up as well.
        tokio::time::sleep(Duration::from_millis(30)).await;
        self.sent.lock().unwrap().clone()
    }
}

impl PushClient for MockPush {
    fn send(&self, msg: PushMessage) -> Pin<Box<dyn Future<Output = PushOutcome> + Send + '_>> {
        Box::pin(async move {
            let gone = self.gone.lock().unwrap().contains(&msg.endpoint);
            self.sent.lock().unwrap().push(msg);
            if gone {
                PushOutcome::Gone
            } else {
                PushOutcome::Delivered
            }
        })
    }
}

// ---------------------------------------------------------------- fake protocol ops

/// Fake protocol: real hashes for admin/auth/pid (Spec §3/§4), toy signatures and a toy
/// evaluation of `R`:
/// - area E invalid (collision) iff `R[0] == 0xFF`;
/// - attempt `t` valid iff `R[t] == 0`;
/// - `t*` = smallest valid attempt whose 16-byte slot in `SD` is zero.
pub struct FakeOps;

pub fn fake_join_sig(
    gid: &[u8; 16],
    ipk: &[u8; 32],
    idh: &[u8; 32],
    auth_hash: &[u8; 32],
    enc_name: &[u8],
    enc_wish: &[u8],
) -> [u8; 64] {
    let h = sha(&[b"fake-join", gid, ipk, idh, auth_hash, enc_name, enc_wish]);
    let mut s = [0u8; 64];
    s[..32].copy_from_slice(&h);
    s[32..].copy_from_slice(&h);
    s
}

pub fn fake_upload_sig(
    gid: &[u8; 16],
    pid: &[u8; 16],
    ipk: &[u8; 32],
    kind: UploadKind,
    round: u32,
    body: &[u8],
) -> [u8; 64] {
    fake_upload_sig_byte(gid, pid, ipk, kind as u8, round, body)
}

/// Kind byte of a contact upload (Spec §12).
pub const KIND_CONTACT: u8 = 3;

pub fn fake_upload_sig_byte(
    gid: &[u8; 16],
    pid: &[u8; 16],
    ipk: &[u8; 32],
    kind: u8,
    round: u32,
    body: &[u8],
) -> [u8; 64] {
    let h = sha(&[
        b"fake-upload",
        &[kind],
        gid,
        &round.to_be_bytes(),
        pid,
        ipk,
        &sha(&[body]),
    ]);
    let mut s = [0u8; 64];
    s[..32].copy_from_slice(&h);
    s[32..].copy_from_slice(&h);
    s
}

pub fn spec_pid(gid: &[u8; 16], ipk: &[u8; 32]) -> [u8; 16] {
    sha(&[b"wichtel/v1/pid", gid, ipk])[..16]
        .try_into()
        .unwrap()
}

impl ProtocolOps for FakeOps {
    fn admin_hash(&self, s: &[u8; 32]) -> [u8; 32] {
        sha(&[b"wichtel/v1/admin-hash", s])
    }
    fn auth_hash(&self, t: &[u8; 32]) -> [u8; 32] {
        sha(&[b"wichtel/v1/auth-hash", t])
    }
    fn ct_eq(&self, a: &[u8], b: &[u8]) -> bool {
        a == b
    }
    fn verify_join(
        &self,
        gid: &[u8; 16],
        ipk: &[u8; 32],
        idh: &[u8; 32],
        auth_hash: &[u8; 32],
        enc_name: &[u8],
        enc_wish: &[u8],
        join_sig: &[u8; 64],
    ) -> Option<[u8; 16]> {
        (idh != &[0u8; 32]
            && *join_sig == fake_join_sig(gid, ipk, idh, auth_hash, enc_name, enc_wish))
        .then(|| spec_pid(gid, ipk))
    }
    fn verify_upload(
        &self,
        gid: &[u8; 16],
        pid: &[u8; 16],
        ipk: &[u8; 32],
        kind: UploadKind,
        round: u32,
        body: &[u8],
        sig: &[u8; 64],
    ) -> bool {
        *sig == fake_upload_sig(gid, pid, ipk, kind, round, body)
    }
    fn verify_contact_upload(
        &self,
        gid: &[u8; 16],
        pid: &[u8; 16],
        ipk: &[u8; 32],
        round: u32,
        body: &[u8],
        sig: &[u8; 64],
    ) -> bool {
        *sig == fake_upload_sig_byte(gid, pid, ipk, KIND_CONTACT, round, body)
    }
    fn xor_into(&self, acc: &mut [u8], src: &[u8]) -> bool {
        if acc.len() != src.len() {
            return false;
        }
        acc.iter_mut().zip(src).for_each(|(a, b)| *a ^= b);
        true
    }
    fn group_context(
        &self,
        gid: &[u8; 16],
        round: u32,
        mut roster: Vec<RosterEntry>,
    ) -> Option<[u8; 32]> {
        roster.sort_by_key(|a| a.pid);
        let mut h = Sha256::new();
        h.update(gid);
        h.update(round.to_be_bytes());
        for e in &roster {
            h.update(e.pid.0);
            h.update(e.enc_name_hash);
        }
        Some(h.finalize().into())
    }
    fn evaluate_roles(&self, _g_r: &[u8; 32], _n: usize, r: &[u8]) -> Option<RolesOutcome> {
        if r[0] == 0xFF {
            return None;
        }
        Some(RolesOutcome {
            recipients: Vec::new(),
            givers: std::array::from_fn(|i| (r[i + 1] == 0).then(Vec::new)),
            rho: [0; 32],
        })
    }
    fn split_reveal_upload<'a>(&self, body: &'a [u8]) -> Option<(&'a [u8], Vec<&'a [u8]>)> {
        if body.len() != wichtel_core::L_REVEAL_UPLOAD {
            return None;
        }
        let (sd, rest) = body.split_at(wichtel_core::L_SD);
        Some((sd, rest.chunks(wichtel_core::L_CT).collect()))
    }
    fn select_attempt(&self, outcome: &RolesOutcome, sd: &[u8]) -> Option<u8> {
        (1..=16u8).find(|&t| {
            let i = usize::from(t - 1);
            outcome.givers[i].is_some() && sd[i * 16..(i + 1) * 16].iter().all(|&b| b == 0)
        })
    }
}

// ---------------------------------------------------------------- app harness

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn temp_db_path(name: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "wichtel-test-{name}-{}-{}.db",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    let s = p.to_string_lossy().into_owned();
    remove_db(&s);
    s
}

pub fn remove_db(path: &str) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{path}{suffix}"));
    }
}

pub fn test_config() -> Config {
    Config {
        push_hosts: vec!["push.example.org".into()],
        // Push throttling has its own test; elsewhere every fan-out goes out at once.
        push_min_interval: Duration::ZERO,
        ..Config::default()
    }
}

pub struct TestApp {
    pub app: Arc<App>,
    pub router: Router,
    pub clock: Arc<MockClock>,
    pub push: Arc<MockPush>,
    pub db_path: String,
}

impl Drop for TestApp {
    fn drop(&mut self) {
        remove_db(&self.db_path);
    }
}

pub struct Resp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl Resp {
    pub fn json<T: DeserializeOwned>(&self) -> T {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("bad json {e}: {}", String::from_utf8_lossy(&self.body)))
    }
    pub fn error_code(&self) -> String {
        let v: serde_json::Value = self.json();
        v["error"].as_str().unwrap().to_owned()
    }
}

impl TestApp {
    pub async fn new() -> Self {
        Self::with(test_config(), Arc::new(FakeOps), &temp_db_path("app")).await
    }

    pub async fn with(cfg: Config, ops: Arc<dyn ProtocolOps>, db_path: &str) -> Self {
        let clock = Arc::new(MockClock::default());
        clock.set(T0);
        let push = Arc::new(MockPush::default());
        let store = TursoStore::open(db_path).await.expect("open store");
        let app = App::new(cfg, Arc::new(store), ops, clock.clone(), push.clone())
            .await
            .expect("app");
        let router = routes::router(app.clone());
        Self {
            app,
            router,
            clock,
            push,
            db_path: db_path.to_owned(),
        }
    }

    pub async fn send(&self, req: Request<Body>) -> Resp {
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        Resp {
            status,
            headers,
            body,
        }
    }

    pub async fn call(&self, method: Method, uri: &str, token: Option<&[u8; 32]>) -> Resp {
        self.send(build(method, uri, token, None, Body::empty(), None))
            .await
    }

    pub async fn json<B: Serialize>(
        &self,
        method: Method,
        uri: &str,
        token: Option<&[u8; 32]>,
        body: &B,
    ) -> Resp {
        let b = serde_json::to_vec(body).unwrap();
        self.send(build(
            method,
            uri,
            token,
            None,
            Body::from(b),
            Some("application/json"),
        ))
        .await
    }

    pub async fn upload(
        &self,
        uri: &str,
        token: &[u8; 32],
        sig: Option<&[u8; 64]>,
        body: Vec<u8>,
    ) -> Resp {
        self.send(build(
            Method::PUT,
            uri,
            Some(token),
            sig,
            Body::from(body),
            Some("application/octet-stream"),
        ))
        .await
    }
}

pub fn build(
    method: Method,
    uri: &str,
    token: Option<&[u8; 32]>,
    sig: Option<&[u8; 64]>,
    body: Body,
    content_type: Option<&str>,
) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {}", b64(t)));
    }
    if let Some(s) = sig {
        b = b.header("x-wichtel-signature", b64(s));
    }
    if let Some(ct) = content_type {
        b = b.header("content-type", ct);
    }
    b.body(body).unwrap()
}

// ---------------------------------------------------------------- fake participants

/// A participant for [`FakeOps`].
#[derive(Clone)]
pub struct FakeClient {
    pub ipk: [u8; 32],
    pub idh: [u8; 32],
    pub tok: [u8; 32],
    pub pid: [u8; 16],
    pub enc_name: Vec<u8>,
    pub enc_wish: Vec<u8>,
}

impl FakeClient {
    pub fn new(gid: &[u8; 16], seed: u8) -> Self {
        let ipk = sha(&[b"ipk", &[seed]]);
        Self {
            ipk,
            idh: sha(&[b"idh", &[seed]]),
            tok: sha(&[b"tok", &[seed]]),
            pid: spec_pid(gid, &ipk),
            enc_name: vec![seed; 40],
            enc_wish: vec![seed ^ 0x55; 60],
        }
    }

    pub fn auth_hash(&self) -> [u8; 32] {
        sha(&[b"wichtel/v1/auth-hash", &self.tok])
    }

    pub fn join_request(&self, gid: &[u8; 16]) -> serde_json::Value {
        let ah = self.auth_hash();
        let sig = fake_join_sig(
            gid,
            &self.ipk,
            &self.idh,
            &ah,
            &self.enc_name,
            &self.enc_wish,
        );
        serde_json::json!({
            "ipk": b64(&self.ipk),
            "idh": b64(&self.idh),
            "auth_hash": b64(&ah),
            "enc_name": b64(&self.enc_name),
            "enc_wish": b64(&self.enc_wish),
            "join_sig": b64(&sig),
        })
    }

    pub fn sig(&self, gid: &[u8; 16], kind: UploadKind, round: u32, body: &[u8]) -> [u8; 64] {
        fake_upload_sig(gid, &self.pid, &self.ipk, kind, round, body)
    }

    /// Kind-3 signature of a contact upload (`round` = round of `Done`).
    pub fn contact_sig(&self, gid: &[u8; 16], round: u32, body: &[u8]) -> [u8; 64] {
        fake_upload_sig_byte(gid, &self.pid, &self.ipk, KIND_CONTACT, round, body)
    }
}

/// A group created through the API with an admin secret.
pub struct Group {
    pub gid: [u8; 16],
    pub gid_s: String,
    pub admin: [u8; 32],
}

impl Group {
    pub fn url(&self, rest: &str) -> String {
        format!("/api/groups/{}{rest}", self.gid_s)
    }
}

pub async fn create_group(t: &TestApp, draw_at: Option<i64>) -> Group {
    let admin = sha(&[
        b"admin",
        &COUNTER.fetch_add(1, Ordering::SeqCst).to_be_bytes(),
    ]);
    let req = serde_json::json!({
        "admin_hash": b64(&sha(&[b"wichtel/v1/admin-hash", &admin])),
        "enc_meta": b64(&[0xC3; 100]),
        "delete_after": T0 + 30 * 86_400,
        "draw_at": draw_at,
    });
    let r = t.json(Method::POST, "/api/groups", None, &req).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let v: serde_json::Value = r.json();
    let gid_s = v["gid"].as_str().unwrap().to_owned();
    let gid: [u8; 16] = unb64(&gid_s).try_into().unwrap();
    Group { gid, gid_s, admin }
}

pub async fn join(t: &TestApp, g: &Group, c: &FakeClient) -> Resp {
    t.json(
        Method::POST,
        &g.url("/participants"),
        None,
        &c.join_request(&g.gid),
    )
    .await
}

/// Create a group with `n` joined fake participants.
pub async fn group_with(t: &TestApp, n: u8) -> (Group, Vec<FakeClient>) {
    let g = create_group(t, None).await;
    let mut clients = Vec::new();
    for i in 0..n {
        let c = FakeClient::new(&g.gid, i + 1);
        let r = join(t, &g, &c).await;
        assert_eq!(r.status, StatusCode::CREATED);
        clients.push(c);
    }
    (g, clients)
}

pub async fn view(t: &TestApp, g: &Group) -> serde_json::Value {
    let r = t.call(Method::GET, &g.url(""), None).await;
    assert_eq!(r.status, StatusCode::OK);
    r.json()
}
