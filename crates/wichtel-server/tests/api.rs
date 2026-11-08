//! HTTP, state machine, store, push, schedule and deletion tests (with [`common::FakeOps`]).

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, StatusCode};
use common::*;
use futures_util::StreamExt;
use serde_json::json;
use tower::ServiceExt;
use wichtel_api::{RevealRelease, UpdateEvent};
use wichtel_core::keys::UploadKind;
use wichtel_core::{L_CT, L_REVEAL_UPLOAD, L_SD, roles_vector_len};
use wichtel_server::store::{Store, TursoStore};

fn roles_body(n: usize, seed: u8) -> Vec<u8> {
    let mut v: Vec<u8> = (0..roles_vector_len(n))
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect();
    v[..17].fill(0);
    v
}

fn reveal_body(client: u8, sd_prefix: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; L_REVEAL_UPLOAD];
    v[..sd_prefix.len()].copy_from_slice(sd_prefix);
    for t in 0..16usize {
        let off = L_SD + t * L_CT;
        v[off..off + L_CT].fill(client.wrapping_mul(16).wrapping_add(t as u8 + 1));
    }
    v
}

async fn upload_roles(t: &TestApp, g: &Group, c: &FakeClient, round: u32, body: Vec<u8>) -> Resp {
    let sig = c.sig(&g.gid, UploadKind::Roles, round, &body);
    t.upload(
        &g.url(&format!("/rounds/{round}/roles")),
        &c.tok,
        Some(&sig),
        body,
    )
    .await
}

async fn upload_reveal(t: &TestApp, g: &Group, c: &FakeClient, round: u32, body: Vec<u8>) -> Resp {
    let sig = c.sig(&g.gid, UploadKind::Reveal, round, &body);
    t.upload(
        &g.url(&format!("/rounds/{round}/reveal")),
        &c.tok,
        Some(&sig),
        body,
    )
    .await
}

async fn start(t: &TestApp, g: &Group) {
    let r = t.call(Method::POST, &g.url("/start"), Some(&g.admin)).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
}

/// All participants upload role vectors that evaluate as valid (no collision, all attempts valid).
async fn complete_roles(t: &TestApp, g: &Group, cs: &[FakeClient], round: u32) {
    for (i, c) in cs.iter().enumerate() {
        let r = upload_roles(t, g, c, round, roles_body(cs.len(), i as u8)).await;
        assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
    }
}

// ---------------------------------------------------------------- basics

#[tokio::test]
async fn health_and_security_headers() {
    let t = TestApp::new().await;
    let r = t.call(Method::GET, "/api/health", None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(&r.body[..], b"ok");
    let h = &r.headers;
    let csp = h["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("default-src 'none'"));
    assert!(csp.contains("'wasm-unsafe-eval'"));
    assert!(!csp.contains("http"), "no external sources");
    assert_eq!(h["referrer-policy"], "no-referrer");
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert!(h.contains_key("permissions-policy"));
    assert_eq!(h["cache-control"], "no-store");
    assert!(!h.contains_key("set-cookie"));
}

#[tokio::test]
async fn static_assets_and_spa_fallback() {
    let t = TestApp::new().await;
    for path in ["/", "/g/3q2-7wAAAAAAAAAAAAAAAA", "/index.html"] {
        let r = t.call(Method::GET, path, None).await;
        assert_eq!(r.status, StatusCode::OK, "{path}");
        assert!(
            r.headers["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        assert!(r.headers.contains_key("content-security-policy"));
    }
    let r = t.call(Method::GET, "/does-not-exist.js", None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = t.call(Method::GET, "/../Cargo.toml", None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = t.call(Method::GET, "/api/nope", None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(r.error_code(), "not_found");
}

#[tokio::test]
async fn create_group_validation() {
    let t = TestApp::new().await;
    let base = json!({
        "admin_hash": b64(&[1; 32]),
        "enc_meta": b64(&[2; 64]),
        "delete_after": T0 + 400 * 86_400,
        "draw_at": null,
    });
    let r = t.json(Method::POST, "/api/groups", None, &base).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let gid = r.json::<serde_json::Value>()["gid"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(gid.len(), 22);
    let v = t
        .call(Method::GET, &format!("/api/groups/{gid}"), None)
        .await
        .json::<serde_json::Value>();
    assert_eq!(v["state"], "open");
    assert_eq!(v["delete_after"], T0 + 60 * 86_400, "capped at +60 days");
    assert_eq!(v["created_at"], T0);
    assert_eq!(v["draw_no"], 0);
    assert_eq!(v["schedule_missed"], false);
    assert!(v["progress"].is_null());

    let mut big = base.clone();
    big["enc_meta"] = json!(b64(&[0; 2049]));
    let r = t.json(Method::POST, "/api/groups", None, &big).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(r.error_code(), "payload_too_large");

    let mut past = base.clone();
    past["delete_after"] = json!(T0 - 1);
    let r = t.json(Method::POST, "/api/groups", None, &past).await;
    assert_eq!(r.error_code(), "bad_request");

    let mut bad_draw = base.clone();
    bad_draw["draw_at"] = json!(T0 - 10);
    let r = t.json(Method::POST, "/api/groups", None, &bad_draw).await;
    assert_eq!(r.error_code(), "bad_request");

    // Body over 16 KB.
    let mut huge = base.clone();
    huge["enc_meta"] = json!(b64(&[0; 20_000]));
    let r = t.json(Method::POST, "/api/groups", None, &huge).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);

    // Wrong content type / malformed JSON.
    let r = t
        .send(build(
            Method::POST,
            "/api/groups",
            None,
            None,
            Body::from("{}"),
            Some("text/plain"),
        ))
        .await;
    assert_eq!(r.error_code(), "bad_request");
    let r = t
        .json(
            Method::POST,
            "/api/groups",
            None,
            &json!({"admin_hash": "x"}),
        )
        .await;
    assert_eq!(r.error_code(), "bad_request");

    let r = t.call(Method::GET, "/api/groups/not-a-gid", None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = t
        .call(Method::GET, "/api/groups/AAAAAAAAAAAAAAAAAAAAAA", None)
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_group_rate_limit_per_ip_and_global_cap() {
    let t = TestApp::new().await;
    let req = json!({
        "admin_hash": b64(&[1; 32]),
        "enc_meta": b64(&[2; 64]),
        "delete_after": T0 + 86_400,
        "draw_at": null,
    });
    let with_ip = |ip: [u8; 4]| {
        let mut r = build(
            Method::POST,
            "/api/groups",
            None,
            None,
            Body::from(serde_json::to_vec(&req).unwrap()),
            Some("application/json"),
        );
        r.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((ip, 4711))));
        r
    };
    for _ in 0..10 {
        assert_eq!(
            t.send(with_ip([10, 0, 0, 1])).await.status,
            StatusCode::CREATED
        );
    }
    let r = t.send(with_ip([10, 0, 0, 1])).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.error_code(), "too_many_requests");
    assert_eq!(
        t.send(with_ip([10, 0, 0, 2])).await.status,
        StatusCode::CREATED
    );
    // New window after an hour.
    t.clock.advance(3600);
    assert_eq!(
        t.send(with_ip([10, 0, 0, 1])).await.status,
        StatusCode::CREATED
    );

    // Global cap.
    let cfg = wichtel_server::Config {
        max_groups: 1,
        ..test_config()
    };
    let t2 = TestApp::with(cfg, Arc::new(FakeOps), &temp_db_path("cap")).await;
    assert_eq!(
        t2.send(with_ip([10, 0, 0, 3])).await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        t2.send(with_ip([10, 0, 0, 4])).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

// ---------------------------------------------------------------- participants

#[tokio::test]
async fn join_rules() {
    let t = TestApp::new().await;
    let g = create_group(&t, None).await;
    let a = FakeClient::new(&g.gid, 1);
    let r = join(&t, &g, &a).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let pid = r.json::<serde_json::Value>()["pid"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(unb64(&pid), a.pid, "pid = H(… ‖ IPK)[0..16]");

    // Duplicate.
    assert_eq!(join(&t, &g, &a).await.status, StatusCode::CONFLICT);

    // Another identity reusing A's IDH (Spec §5: IDH unique per group).
    let mut same_idh = FakeClient::new(&g.gid, 8);
    same_idh.idh = a.idh;
    let r = join(&t, &g, &same_idh).await;
    assert_eq!(r.status, StatusCode::CONFLICT);

    // Bad signature.
    let b = FakeClient::new(&g.gid, 2);
    let mut req = b.join_request(&g.gid);
    req["join_sig"] = json!(b64(&[9; 64]));
    let r = t
        .json(Method::POST, &g.url("/participants"), None, &req)
        .await;
    assert_eq!(r.error_code(), "bad_request");

    // Low-order IDH (fake: all zero) is rejected.
    let mut z = FakeClient::new(&g.gid, 3);
    z.idh = [0; 32];
    assert_eq!(join(&t, &g, &z).await.error_code(), "bad_request");

    // Size limits.
    let mut big = FakeClient::new(&g.gid, 4);
    big.enc_name = vec![1; 129];
    assert_eq!(join(&t, &g, &big).await.error_code(), "payload_too_large");
    let mut big = FakeClient::new(&g.gid, 5);
    big.enc_wish = vec![1; 1101];
    assert_eq!(join(&t, &g, &big).await.error_code(), "payload_too_large");
    let mut ok = FakeClient::new(&g.gid, 6);
    ok.enc_name = vec![1; 128];
    ok.enc_wish = vec![1; 1100];
    assert_eq!(join(&t, &g, &ok).await.status, StatusCode::CREATED);

    // Wrong length of fixed fields.
    let mut req = FakeClient::new(&g.gid, 7).join_request(&g.gid);
    req["ipk"] = json!(b64(&[1; 31]));
    let r = t
        .json(Method::POST, &g.url("/participants"), None, &req)
        .await;
    assert_eq!(r.error_code(), "bad_request");

    // Group full at 30.
    for i in 10..38u8 {
        assert_eq!(
            join(&t, &g, &FakeClient::new(&g.gid, i)).await.status,
            StatusCode::CREATED
        );
    }
    let v = view(&t, &g).await;
    let parts = v["participants"].as_array().unwrap();
    assert_eq!(parts.len(), 30);
    let pids: Vec<Vec<u8>> = parts
        .iter()
        .map(|p| unb64(p["pid"].as_str().unwrap()))
        .collect();
    let mut sorted = pids.clone();
    sorted.sort();
    assert_eq!(pids, sorted, "roster sorted by pid");
    assert!(
        parts[0].get("auth_hash").is_none(),
        "auth_hash is never served"
    );
    let r = join(&t, &g, &FakeClient::new(&g.gid, 99)).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.error_code(), "group_full");

    // No joins after the start.
    start(&t, &g).await;
    let (g2, _) = group_with(&t, 4).await;
    start(&t, &g2).await;
    let r = join(&t, &g2, &FakeClient::new(&g2.gid, 50)).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn update_participant_name_before_start_only() {
    let t = TestApp::new().await;
    let (g, cs) = group_with(&t, 4).await;
    let mut a = cs[0].clone();
    a.enc_name = vec![0xAB; 50];
    a.enc_wish = vec![];
    let url = g.url(&format!("/participants/{}", b64(&a.pid)));

    let r = t
        .json(Method::PUT, &url, Some(&cs[1].tok), &a.join_request(&g.gid))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = t
        .json(Method::PUT, &url, None, &a.join_request(&g.gid))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    let mut changed = a.clone();
    changed.idh = [7; 32];
    let r = t
        .json(
            Method::PUT,
            &url,
            Some(&a.tok),
            &changed.join_request(&g.gid),
        )
        .await;
    assert_eq!(r.error_code(), "bad_request");

    let r = t
        .json(Method::PUT, &url, Some(&a.tok), &a.join_request(&g.gid))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let v = view(&t, &g).await;
    let me = v["participants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| unb64(p["pid"].as_str().unwrap()) == a.pid)
        .unwrap()
        .clone();
    assert_eq!(unb64(me["enc_name"].as_str().unwrap()), vec![0xAB; 50]);
    assert_eq!(me["enc_wish"], "");

    // Spec §16.1: after the start only the wish list may change.
    start(&t, &g).await;
    let r = t
        .json(Method::PUT, &url, Some(&a.tok), &a.join_request(&g.gid))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let mut renamed = a.clone();
    renamed.enc_name = vec![0xAC; 50];
    let r = t
        .json(
            Method::PUT,
            &url,
            Some(&a.tok),
            &renamed.join_request(&g.gid),
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
}

// ---------------------------------------------------------------- admin & state machine

#[tokio::test]
async fn start_requires_admin_and_enough_participants() {
    let t = TestApp::new().await;
    let (g, cs) = group_with(&t, 3).await;
    let r = t.call(Method::POST, &g.url("/start"), None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = t
        .call(Method::POST, &g.url("/start"), Some(&cs[0].tok))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = t.call(Method::POST, &g.url("/start"), Some(&g.admin)).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.error_code(), "too_few_participants");

    assert_eq!(
        join(&t, &g, &FakeClient::new(&g.gid, 9)).await.status,
        StatusCode::CREATED
    );
    start(&t, &g).await;
    let v = view(&t, &g).await;
    assert_eq!(v["state"], "drawing");
    assert_eq!(v["round"], 1);
    assert_eq!(v["phase"], "roles");
    assert_eq!(v["draw_no"], 1);
    assert_eq!(v["progress"]["submitted"], json!([]));
    let r = t.call(Method::POST, &g.url("/start"), Some(&g.admin)).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = t
        .call(Method::POST, &g.url("/restart"), Some(&cs[0].tok))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn full_round_with_running_xor_and_reveal_release() {
    let t = TestApp::new().await;
    let (g, cs) = group_with(&t, 4).await;
    let n = cs.len();

    // Uploads before the start.
    let r = upload_roles(&t, &g, &cs[0], 1, roles_body(n, 0)).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    start(&t, &g).await;

    // Wrong round, wrong length, missing/bad signature, bad token.
    assert_eq!(
        upload_roles(&t, &g, &cs[0], 2, roles_body(n, 0))
            .await
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        upload_roles(&t, &g, &cs[0], 1, roles_body(n, 0)[1..].to_vec())
            .await
            .error_code(),
        "bad_request"
    );
    let url = g.url("/rounds/1/roles");
    let r = t.upload(&url, &cs[0].tok, None, roles_body(n, 0)).await;
    assert_eq!(r.error_code(), "bad_request");
    let r = t
        .upload(&url, &cs[0].tok, Some(&[1; 64]), roles_body(n, 0))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let body = roles_body(n, 0);
    let sig = cs[0].sig(&g.gid, UploadKind::Roles, 1, &body);
    let r = t.upload(&url, &[0x42; 32], Some(&sig), body).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // Body larger than L_V(30).
    let r = t
        .upload(
            &url,
            &cs[0].tok,
            Some(&sig),
            vec![0; roles_vector_len(30) + 1],
        )
        .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);

    // R not available while incomplete.
    let mut expected_r = vec![0u8; roles_vector_len(n)];
    for (i, c) in cs.iter().enumerate() {
        let r = t.call(Method::GET, &url, None).await;
        assert_eq!(r.status, StatusCode::CONFLICT);
        let body = roles_body(n, i as u8);
        expected_r.iter_mut().zip(&body).for_each(|(a, b)| *a ^= b);
        assert_eq!(
            upload_roles(&t, &g, c, 1, body.clone()).await.status,
            StatusCode::NO_CONTENT
        );
        if i == 0 {
            // Duplicate upload ⇒ 409, first one counts.
            assert_eq!(
                upload_roles(&t, &g, c, 1, body).await.status,
                StatusCode::CONFLICT
            );
            let v = view(&t, &g).await;
            assert_eq!(v["progress"]["submitted"], json!([b64(&c.pid)]));
        }
    }
    let v = view(&t, &g).await;
    assert_eq!(v["phase"], "reveal");
    assert_eq!(v["round"], 1);
    let r = t.call(Method::GET, &url, None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.headers["content-type"], "application/octet-stream");
    assert_eq!(&r.body[..], &expected_r[..], "R = XOR of all V_i");

    // Step 2. Client 0 marks attempts 1 and 2 as self-draws ⇒ t* = 3.
    let rurl = g.url("/rounds/1/reveal");
    assert_eq!(
        t.call(Method::GET, &rurl, None).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        upload_reveal(&t, &g, &cs[0], 1, vec![0; L_REVEAL_UPLOAD - 1])
            .await
            .error_code(),
        "bad_request"
    );
    for (i, c) in cs.iter().enumerate() {
        let sd: &[u8] = if i == 0 { &[1u8; 32] } else { &[] };
        let r = upload_reveal(&t, &g, c, 1, reveal_body(i as u8, sd)).await;
        assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
        if i == 0 {
            assert_eq!(
                upload_reveal(&t, &g, c, 1, reveal_body(0, sd)).await.status,
                StatusCode::CONFLICT
            );
            assert_eq!(
                t.store_reveals(&g, 1).await,
                16,
                "all attempts stored until complete"
            );
        }
    }
    let v = view(&t, &g).await;
    assert_eq!(v["state"], "done");
    assert_eq!(v["round"], 1);
    assert_eq!(v["t_star"], 3);
    assert!(v["progress"].is_null());

    let rel: RevealRelease = t.call(Method::GET, &rurl, None).await.json();
    assert_eq!(rel.round, 1);
    assert_eq!(rel.t_star, 3);
    let mut sd = vec![0u8; L_SD];
    sd[..32].fill(1);
    assert_eq!(rel.selfdraw_aggregate.0, sd);
    assert_eq!(rel.reveals.len(), 4);
    let mut pids: Vec<_> = cs.iter().map(|c| c.pid).collect();
    pids.sort();
    for (e, pid) in rel.reveals.iter().zip(&pids) {
        assert_eq!(&e.pid.0, pid, "roster order");
        let i = cs.iter().position(|c| c.pid == *pid).unwrap() as u8;
        assert_eq!(e.ciphertext.0, vec![i * 16 + 3; L_CT], "C_{{j,t*}}");
    }
    // Only the reveals of t* remain stored.
    assert_eq!(t.store_reveals(&g, 1).await, 4);
    assert!(t.app.vacuum_pending());
    // R stays available for late clients; uploads are closed.
    assert_eq!(t.call(Method::GET, &url, None).await.status, StatusCode::OK);
    assert_eq!(
        upload_reveal(&t, &g, &cs[1], 1, reveal_body(1, &[]))
            .await
            .status,
        StatusCode::CONFLICT
    );
}

trait StoreProbe {
    async fn store_reveals(&self, g: &Group, round: u32) -> u64;
}

impl StoreProbe for TestApp {
    async fn store_reveals(&self, g: &Group, round: u32) -> u64 {
        self.app.store.count_reveals(&g.gid, round).await.unwrap()
    }
}

#[tokio::test]
async fn collision_starts_next_round_automatically() {
    let t = TestApp::new().await;
    let (g, cs) = group_with(&t, 4).await;
    start(&t, &g).await;
    for (i, c) in cs.iter().enumerate() {
        let mut body = roles_body(4, i as u8);
        if i == 2 {
            body[0] = 0xFF; // fake: area E invalid
        }
        assert_eq!(
            upload_roles(&t, &g, c, 1, body).await.status,
            StatusCode::NO_CONTENT
        );
    }
    let v = view(&t, &g).await;
    assert_eq!(v["state"], "drawing");
    assert_eq!(v["round"], 2);
    assert_eq!(v["phase"], "roles");
    assert_eq!(v["draw_no"], 1, "collision rounds are not counted as draws");
    assert_eq!(
        t.call(Method::GET, &g.url("/rounds/1/roles"), None)
            .await
            .status,
        StatusCode::CONFLICT
    );
    assert!(
        t.app
            .store
            .get_aggregate(&g.gid, 1, wichtel_api::Phase::Roles)
            .await
            .unwrap()
            .is_none(),
        "aggregate of the collided round is deleted"
    );
    assert_eq!(
        upload_roles(&t, &g, &cs[0], 1, roles_body(4, 0))
            .await
            .status,
        StatusCode::CONFLICT
    );
    complete_roles(&t, &g, &cs, 2).await;
    assert_eq!(view(&t, &g).await["phase"], "reveal");
}

#[tokio::test]
async fn no_valid_attempt_starts_next_round() {
    let t = TestApp::new().await;
    let (g, cs) = group_with(&t, 4).await;
    start(&t, &g).await;
    complete_roles(&t, &g, &cs, 1).await;
    // Every attempt reported as self-draw.
    for (i, c) in cs.iter().enumerate() {
        let sd: &[u8] = if i == 0 { &[1u8; L_SD] } else { &[] };
        assert_eq!(
            upload_reveal(&t, &g, c, 1, reveal_body(i as u8, sd))
                .await
                .status,
            StatusCode::NO_CONTENT
        );
    }
    let v = view(&t, &g).await;
    assert_eq!(v["state"], "drawing");
    assert_eq!(v["round"], 2);
    assert_eq!(v["draw_no"], 1);
    assert_eq!(t.store_reveals(&g, 1).await, 0, "all reveals deleted");
    assert_eq!(
        t.call(Method::GET, &g.url("/rounds/1/reveal"), None)
            .await
            .status,
        StatusCode::CONFLICT
    );
}

async fn run_to_done(t: &TestApp, g: &Group, cs: &[FakeClient], round: u32) {
    complete_roles(t, g, cs, round).await;
    for (i, c) in cs.iter().enumerate() {
        assert_eq!(
            upload_reveal(t, g, c, round, reveal_body(i as u8, &[]))
                .await
                .status,
            StatusCode::NO_CONTENT
        );
    }
    assert_eq!(view(t, g).await["state"], "done");
}

#[tokio::test]
async fn leave_and_remove_rules() {
    let t = TestApp::new().await;
    let (g, cs) = group_with(&t, 6).await;
    let purl = |c: &FakeClient| g.url(&format!("/participants/{}", b64(&c.pid)));

    // Open: self-leave; others may not remove; admin may.
    let r = t
        .call(Method::DELETE, &purl(&cs[0]), Some(&cs[1].tok))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = t
        .call(Method::DELETE, &purl(&cs[0]), Some(&cs[0].tok))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let r = t.call(Method::DELETE, &purl(&cs[0]), Some(&g.admin)).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let v = view(&t, &g).await;
    assert_eq!(v["participants"].as_array().unwrap().len(), 5);
    assert_eq!(v["state"], "open");

    // Drawing: leaving ⇒ immediate new draw (r+1, draw_no+1), uploads of the old round void.
    start(&t, &g).await;
    assert_eq!(
        upload_roles(&t, &g, &cs[1], 1, roles_body(5, 1))
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    let r = t
        .call(Method::DELETE, &purl(&cs[5]), Some(&cs[5].tok))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let v = view(&t, &g).await;
    assert_eq!(v["state"], "drawing");
    assert_eq!(v["round"], 2);
    assert_eq!(v["draw_no"], 2);
    assert_eq!(v["progress"]["submitted"], json!([]));

    // Done: admin removes ⇒ complete new draw; with n < 4 ⇒ back to open.
    let rest: Vec<FakeClient> = cs[1..5].to_vec();
    run_to_done(&t, &g, &rest, 2).await;
    let r = t
        .call(Method::DELETE, &purl(&rest[0]), Some(&g.admin))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let v = view(&t, &g).await;
    assert_eq!(v["state"], "open");
    assert_eq!(v["draw_no"], 2);
    assert_eq!(t.store_reveals(&g, 2).await, 0);

    // Rejoin is possible again, the round counter continues.
    assert_eq!(join(&t, &g, &cs[0]).await.status, StatusCode::CREATED);
    start(&t, &g).await;
    let v = view(&t, &g).await;
    assert_eq!(v["round"], 3);
    assert_eq!(v["draw_no"], 3);
}

#[tokio::test]
async fn admin_restart() {
    let t = TestApp::new().await;
    let (g, cs) = group_with(&t, 4).await;
    let r = t
        .call(Method::POST, &g.url("/restart"), Some(&g.admin))
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    start(&t, &g).await;
    run_to_done(&t, &g, &cs, 1).await;
    let r = t
        .call(Method::POST, &g.url("/restart"), Some(&g.admin))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let v = view(&t, &g).await;
    assert_eq!(v["state"], "drawing");
    assert_eq!(v["round"], 2);
    assert_eq!(v["draw_no"], 2);
    assert_eq!(
        t.call(Method::GET, &g.url("/rounds/1/reveal"), None)
            .await
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(t.store_reveals(&g, 1).await, 0);
}

// ---------------------------------------------------------------- schedule & jobs

#[tokio::test]
async fn schedule_endpoint() {
    let t = TestApp::new().await;
    let (g, cs) = group_with(&t, 4).await;
    let url = g.url("/schedule");
    let body = json!({"draw_at": T0 + 3600});
    assert_eq!(
        t.json(Method::PUT, &url, Some(&cs[0].tok), &body)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        t.json(Method::PUT, &url, Some(&g.admin), &json!({"draw_at": T0}))
            .await
            .error_code(),
        "bad_request"
    );
    assert_eq!(
        t.json(
            Method::PUT,
            &url,
            Some(&g.admin),
            &json!({"draw_at": T0 + 31 * 86_400})
        )
        .await
        .error_code(),
        "bad_request",
        "after delete_after"
    );
    assert_eq!(
        t.json(Method::PUT, &url, Some(&g.admin), &body)
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(view(&t, &g).await["draw_at"], T0 + 3600);
    assert_eq!(
        t.json(Method::PUT, &url, Some(&g.admin), &json!({"draw_at": null}))
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert!(view(&t, &g).await["draw_at"].is_null());
    start(&t, &g).await;
    assert_eq!(
        t.json(Method::PUT, &url, Some(&g.admin), &body)
            .await
            .status,
        StatusCode::CONFLICT
    );
}

async fn subscribe_push(t: &TestApp, g: &Group, c: &FakeClient, endpoint: &str) -> Resp {
    t.json(
        Method::PUT,
        &g.url(&format!("/participants/{}/push", b64(&c.pid))),
        Some(&c.tok),
        &json!({"endpoint": endpoint, "p256dh": b64(&[4; 65]), "auth": b64(&[5; 16])}),
    )
    .await
}

#[tokio::test]
async fn scheduled_draw_reminder_and_start() {
    let t = TestApp::new().await;
    let draw_at = T0 + 3600;
    let g = create_group(&t, Some(draw_at)).await;
    let mut cs = Vec::new();
    for i in 0..4u8 {
        let c = FakeClient::new(&g.gid, i + 1);
        join(&t, &g, &c).await;
        cs.push(c);
    }
    assert_eq!(
        subscribe_push(&t, &g, &cs[0], "https://push.example.org/a")
            .await
            .status,
        StatusCode::NO_CONTENT
    );

    t.app.run_jobs().await;
    assert_eq!(view(&t, &g).await["state"], "open");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(t.push.count(), 0, "no push an hour before");

    // 10 minutes before: one reminder, only once.
    t.clock.set(draw_at - 600);
    t.app.run_jobs().await;
    t.app.run_jobs().await;
    let sent = t.push.wait_for(1).await;
    assert_eq!(sent.len(), 1);

    // At draw_at: started, push to subscribers.
    t.clock.set(draw_at);
    t.app.run_jobs().await;
    let v = view(&t, &g).await;
    assert_eq!(v["state"], "drawing");
    assert_eq!(v["round"], 1);
    assert_eq!(v["draw_no"], 1);
    assert!(v["draw_at"].is_null());
    assert_eq!(v["schedule_missed"], false);
    assert_eq!(t.push.wait_for(2).await.len(), 2);
}

#[tokio::test]
async fn scheduled_draw_missed_with_too_few() {
    let t = TestApp::new().await;
    let draw_at = T0 + 120;
    let g = create_group(&t, Some(draw_at)).await;
    for i in 0..3u8 {
        join(&t, &g, &FakeClient::new(&g.gid, i + 1)).await;
    }
    t.clock.set(draw_at + 30);
    t.app.run_jobs().await;
    let v = view(&t, &g).await;
    assert_eq!(v["state"], "open");
    assert_eq!(v["schedule_missed"], true);
    assert!(v["draw_at"].is_null());
    // Admin sets a new date ⇒ flag cleared.
    let r = t
        .json(
            Method::PUT,
            &g.url("/schedule"),
            Some(&g.admin),
            &json!({"draw_at": draw_at + 7200}),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(view(&t, &g).await["schedule_missed"], false);
}

#[tokio::test]
async fn expiry_and_unused_groups_are_deleted() {
    let t = TestApp::new().await;
    // Expires via delete_after (T0 + 30 days).
    let (g_exp, _) = group_with(&t, 4).await;
    // Unused: open, fewer than N_MIN participants (groups without any participant are
    // already deleted after 24 h, see tests/hardening.rs).
    let g_idle = create_group(&t, None).await;
    join(&t, &g_idle, &FakeClient::new(&g_idle.gid, 1)).await;
    // Unused but with a future draw date: kept.
    let g_sched = create_group(&t, Some(T0 + 20 * 86_400)).await;
    join(&t, &g_sched, &FakeClient::new(&g_sched.gid, 1)).await;

    t.clock.advance(7 * 86_400 - 10);
    t.app.run_jobs().await;
    assert_eq!(view(&t, &g_idle).await["state"], "open", "not yet idle");

    t.clock.advance(20);
    t.app.run_jobs().await;
    assert_eq!(
        t.call(Method::GET, &g_idle.url(""), None).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        view(&t, &g_exp).await["state"],
        "open",
        "4 participants: kept"
    );
    assert_eq!(view(&t, &g_sched).await["state"], "open");

    t.clock.set(T0 + 30 * 86_400);
    t.app.run_jobs().await;
    assert_eq!(
        t.call(Method::GET, &g_exp.url(""), None).await.status,
        StatusCode::NOT_FOUND
    );
    assert!(
        t.app
            .store
            .list_participants(&g_exp.gid)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn delete_group_immediately() {
    let t = TestApp::new().await;
    let (g, cs) = group_with(&t, 4).await;
    subscribe_push(&t, &g, &cs[0], "https://push.example.org/x").await;
    assert_eq!(
        t.call(Method::DELETE, &g.url(""), Some(&cs[0].tok))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        t.call(Method::DELETE, &g.url(""), Some(&g.admin))
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        t.call(Method::GET, &g.url(""), None).await.status,
        StatusCode::NOT_FOUND
    );
    assert!(t.app.store.list_push_subs(&g.gid).await.unwrap().is_empty());
    assert!(t.app.vacuum_pending());
    t.app.maybe_vacuum(true).await;
    assert!(!t.app.vacuum_pending());
}

/// Deleted data must not survive in the database file after the bundled VACUUM (Spec §14).
#[tokio::test]
async fn no_residue_after_delete_and_vacuum() {
    let path = temp_db_path("residue");
    let t = TestApp::with(test_config(), Arc::new(FakeOps), &path).await;
    let marker = [0xE7u8; 2000];
    let req = json!({
        "admin_hash": b64(&sha(&[b"wichtel/v1/admin-hash", &[1; 32]])),
        "enc_meta": b64(&marker),
        "delete_after": T0 + 86_400,
        "draw_at": null,
    });
    let r = t.json(Method::POST, "/api/groups", None, &req).await;
    let gid = r.json::<serde_json::Value>()["gid"]
        .as_str()
        .unwrap()
        .to_owned();
    let r = t
        .call(
            Method::DELETE,
            &format!("/api/groups/{gid}"),
            Some(&[1; 32]),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    t.app.maybe_vacuum(true).await;
    let mut runs = 0;
    for f in [path.clone(), format!("{path}-wal")] {
        if let Ok(bytes) = std::fs::read(&f) {
            runs += bytes
                .windows(64)
                .filter(|w| w.iter().all(|&b| b == 0xE7))
                .count();
        }
    }
    assert_eq!(runs, 0, "deleted enc_meta still on disk");
}

#[tokio::test]
async fn vacuum_is_bundled() {
    let t = TestApp::new().await;
    let (g, _) = group_with(&t, 4).await;
    t.call(Method::DELETE, &g.url(""), Some(&g.admin)).await;
    t.app.run_jobs().await; // first run vacuums
    assert!(!t.app.vacuum_pending());
    let g2 = create_group(&t, None).await;
    t.call(Method::DELETE, &g2.url(""), Some(&g2.admin)).await;
    t.clock.advance(60);
    t.app.run_jobs().await;
    assert!(t.app.vacuum_pending(), "at most every 5 minutes");
    t.clock.advance(300);
    t.app.run_jobs().await;
    assert!(!t.app.vacuum_pending());
}

// ---------------------------------------------------------------- push

#[tokio::test]
async fn vapid_key_is_persistent() {
    let path = temp_db_path("vapid");
    let key1 = {
        let mut t = TestApp::with(test_config(), Arc::new(FakeOps), &path).await;
        let r = t.call(Method::GET, "/api/push/vapid-key", None).await;
        assert_eq!(r.status, StatusCode::OK);
        let k = unb64(
            r.json::<serde_json::Value>()["public_key"]
                .as_str()
                .unwrap(),
        );
        assert_eq!(k.len(), 65);
        assert_eq!(k[0], 4);
        t.db_path = temp_db_path("unused"); // keep the real file on drop
        k
    };
    // Let the push worker of the first instance shut down and release the database.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let t = TestApp::with(test_config(), Arc::new(FakeOps), &path).await;
    let r = t.call(Method::GET, "/api/push/vapid-key", None).await;
    let k2 = unb64(
        r.json::<serde_json::Value>()["public_key"]
            .as_str()
            .unwrap(),
    );
    assert_eq!(key1, k2);
}

#[tokio::test]
async fn push_subscription_and_fanout() {
    let t = TestApp::new().await;
    let (g, cs) = group_with(&t, 4).await;
    let url = |c: &FakeClient| g.url(&format!("/participants/{}/push", b64(&c.pid)));
    let sub = |ep: &str| json!({"endpoint": ep, "p256dh": b64(&[4; 65]), "auth": b64(&[5; 16])});

    // Validation.
    for ep in [
        "http://push.example.org/a",
        "https://evil.example/a",
        "https://127.0.0.1/a",
        "not a url",
    ] {
        let r = t
            .json(Method::PUT, &url(&cs[0]), Some(&cs[0].tok), &sub(ep))
            .await;
        assert_eq!(r.error_code(), "bad_request", "{ep}");
    }
    let r = t
        .json(
            Method::PUT,
            &url(&cs[0]),
            Some(&cs[0].tok),
            &json!({"endpoint": "https://push.example.org/a", "p256dh": b64(&[4; 64]), "auth": b64(&[5; 16])}),
        )
        .await;
    assert_eq!(r.error_code(), "bad_request");
    let r = t
        .json(
            Method::PUT,
            &url(&cs[0]),
            Some(&cs[1].tok),
            &sub("https://push.example.org/a"),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    for (i, c) in cs.iter().enumerate().take(3) {
        let r = subscribe_push(&t, &g, c, &format!("https://push.example.org/{i}")).await;
        assert_eq!(r.status, StatusCode::NO_CONTENT);
    }
    // Unsubscribe the third again.
    let r = t.call(Method::DELETE, &url(&cs[2]), Some(&cs[2].tok)).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    // The second one's subscription has expired at the push service.
    t.push
        .gone
        .lock()
        .unwrap()
        .insert("https://push.example.org/1".into());

    // Joins do not push; the start does (to all subscribers at once).
    join(&t, &g, &FakeClient::new(&g.gid, 77)).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(t.push.count(), 0);
    start(&t, &g).await;
    let sent = t.push.wait_for(2).await;
    assert_eq!(sent.len(), 2);
    let mut eps: Vec<_> = sent.iter().map(|m| m.endpoint.clone()).collect();
    eps.sort();
    assert_eq!(
        eps,
        vec!["https://push.example.org/0", "https://push.example.org/1"]
    );
    for m in &sent {
        assert_eq!(m.ttl, 3600);
        assert!(m.authorization.starts_with("vapid t="));
        assert!(m.authorization.contains(", k="));
        let jwt = m
            .authorization
            .strip_prefix("vapid t=")
            .unwrap()
            .split(", k=")
            .next()
            .unwrap();
        let claims: serde_json::Value =
            serde_json::from_slice(&unb64(jwt.split('.').nth(1).unwrap())).unwrap();
        assert_eq!(claims["aud"], "https://push.example.org");
        assert_eq!(claims["exp"], T0 + 12 * 3600);
    }
    // 410 ⇒ deleted.
    let subs = t.app.store.list_push_subs(&g.gid).await.unwrap();
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0].endpoint, "https://push.example.org/0");

    // Upload progress does not push; completing a phase does.
    let n = 5;
    let all: Vec<FakeClient> = {
        let v = view(&t, &g).await;
        let pids: Vec<Vec<u8>> = v["participants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| unb64(p["pid"].as_str().unwrap()))
            .collect();
        let mut all = cs.clone();
        all.push(FakeClient::new(&g.gid, 77));
        assert!(all.iter().all(|c| pids.contains(&c.pid.to_vec())));
        all
    };
    for (i, c) in all.iter().enumerate().take(n - 1) {
        upload_roles(&t, &g, c, 1, roles_body(n, i as u8)).await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(t.push.count(), 2);
    upload_roles(&t, &g, &all[n - 1], 1, roles_body(n, 9)).await;
    assert_eq!(t.push.wait_for(3).await.len(), 3);
}

// ---------------------------------------------------------------- SSE

#[tokio::test]
async fn sse_streams_updates() {
    let t = TestApp::new().await;
    let (g, _) = group_with(&t, 3).await;
    let res = t
        .router
        .clone()
        .oneshot(build(
            Method::GET,
            &g.url("/events"),
            None,
            None,
            Body::empty(),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["content-type"], "text/event-stream");
    let mut stream = res.into_body().into_data_stream();
    let mut next_event = async || -> UpdateEvent {
        let mut buf = String::new();
        loop {
            let chunk = tokio::time::timeout(Duration::from_secs(2), stream.next())
                .await
                .expect("event in time")
                .expect("stream open")
                .unwrap();
            buf.push_str(std::str::from_utf8(&chunk).unwrap());
            if let Some(end) = buf.find("\n\n") {
                let block = &buf[..end];
                if block.starts_with(':') {
                    buf.drain(..end + 2);
                    continue;
                }
                assert!(block.contains("event: update"), "{block}");
                let data = block
                    .lines()
                    .find_map(|l| l.strip_prefix("data: "))
                    .unwrap();
                return serde_json::from_str(data).unwrap();
            }
        }
    };
    let ev = next_event().await;
    assert_eq!(ev.state, wichtel_api::GroupState::Open);
    assert_eq!(ev.participant_count, 3);

    join(&t, &g, &FakeClient::new(&g.gid, 42)).await;
    let ev = next_event().await;
    assert_eq!(ev.participant_count, 4);

    start(&t, &g).await;
    let ev = next_event().await;
    assert_eq!(
        ev.state,
        wichtel_api::GroupState::Drawing {
            round: 1,
            phase: wichtel_api::Phase::Roles
        }
    );
    assert_eq!(ev.draw_no, 1);
    assert_eq!(ev.submitted_count, 0);

    let r = t
        .call(
            Method::GET,
            "/api/groups/AAAAAAAAAAAAAAAAAAAAAA/events",
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------- store

#[tokio::test]
async fn store_migrations_are_idempotent() {
    let path = temp_db_path("migr");
    {
        let s = TursoStore::open(&path).await.unwrap();
        assert_eq!(s.count_groups().await.unwrap(), 0);
    }
    let s = TursoStore::open(&path).await.unwrap();
    assert_eq!(s.count_groups().await.unwrap(), 0);
    drop(s);
    remove_db(&path);
}
