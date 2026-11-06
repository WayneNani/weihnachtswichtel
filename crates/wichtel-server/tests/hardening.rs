//! Tests for the server hardening (security review findings 1–15).

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use common::*;
use futures_util::StreamExt;
use serde_json::json;
use tower::ServiceExt;
use wichtel_core::keys::UploadKind;
use wichtel_core::roles_vector_len;
use wichtel_server::Config;
use wichtel_server::store::{Store, TursoStore, WriteOp};

const IN_TIME: Duration = Duration::from_secs(3);

fn with_peer(mut req: Request<Body>, ip: &str) -> Request<Body> {
    let ip: std::net::IpAddr = ip.parse().unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(ip, 4711)));
    req
}

fn create_req(ip: &str) -> Request<Body> {
    let body = json!({
        "admin_hash": b64(&[1; 32]),
        "enc_meta": b64(&[2; 64]),
        "delete_after": T0 + 86_400,
        "draw_at": null,
    });
    with_peer(
        build(
            Method::POST,
            "/api/groups",
            None,
            None,
            Body::from(serde_json::to_vec(&body).unwrap()),
            Some("application/json"),
        ),
        ip,
    )
}

/// A body that never yields a byte (a client that announces an upload and stalls).
fn stalled_body() -> Body {
    Body::from_stream(futures_util::stream::pending::<Result<Bytes, std::io::Error>>())
}

fn upload_req(
    url: &str,
    token: &[u8; 32],
    sig: Option<&[u8; 64]>,
    body: Body,
    content_length: Option<usize>,
) -> Request<Body> {
    let mut r = build(
        Method::PUT,
        url,
        Some(token),
        sig,
        body,
        Some("application/octet-stream"),
    );
    if let Some(n) = content_length {
        r.headers_mut()
            .insert("content-length", n.to_string().parse().unwrap());
    }
    r
}

async fn app_with(cfg: Config) -> TestApp {
    TestApp::with(cfg, Arc::new(FakeOps), &temp_db_path("hard")).await
}

async fn started_group(t: &TestApp) -> (Group, Vec<FakeClient>) {
    let (g, cs) = group_with(t, 4).await;
    let r = t.call(Method::POST, &g.url("/start"), Some(&g.admin)).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    (g, cs)
}

// ---------------------------------------------------------------- 1: cancel-safe commits

#[tokio::test]
async fn cancelled_commit_does_not_block_the_store() {
    let path = temp_db_path("cancel");
    let store = TursoStore::open(&path).await.unwrap();
    let ops: Vec<WriteOp> = (0..300u32)
        .map(|i| WriteOp::PutServerKey {
            name: format!("k{i}"),
            value: vec![7; 64],
        })
        .collect();
    // Poll the commit once, then drop it – like a handler whose client went away.
    let mut fut = store.commit(ops);
    std::future::poll_fn(|cx| {
        let _ = fut.as_mut().poll(cx);
        Poll::Ready(())
    })
    .await;
    drop(fut);
    let after = WriteOp::PutServerKey {
        name: "after".into(),
        value: vec![1],
    };
    tokio::time::timeout(IN_TIME, store.commit(vec![after]))
        .await
        .expect("store not blocked")
        .unwrap();
    // The detached transaction ran to completion (all or nothing).
    assert_eq!(store.get_server_key("k0").await.unwrap(), Some(vec![7; 64]));
    assert_eq!(
        store.get_server_key("k299").await.unwrap(),
        Some(vec![7; 64])
    );
    assert_eq!(store.get_server_key("after").await.unwrap(), Some(vec![1]));
    drop(store);
    remove_db(&path);
}

// ---------------------------------------------------------------- 2: bodies, timeouts, limits

#[tokio::test]
async fn upload_is_authorized_before_the_body_is_read() {
    let t = TestApp::new().await;
    let (g, cs) = started_group(&t).await;
    let url = g.url("/rounds/1/roles");
    let sig = [1u8; 64];
    // Wrong token: rejected at once although the body never arrives.
    let r = tokio::time::timeout(
        IN_TIME,
        t.send(upload_req(
            &url,
            &[0x42; 32],
            Some(&sig),
            stalled_body(),
            Some(2_000_000),
        )),
    )
    .await
    .expect("rejected without reading the body");
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // Wrong round / not accepting: 409 without reading.
    let r = tokio::time::timeout(
        IN_TIME,
        t.send(upload_req(
            &g.url("/rounds/7/roles"),
            &cs[0].tok,
            Some(&sig),
            stalled_body(),
            None,
        )),
    )
    .await
    .expect("rejected without reading the body");
    assert_eq!(r.status, StatusCode::CONFLICT);
    // Content-Length other than L_V(n): rejected before reading.
    let expected = roles_vector_len(4);
    let r = tokio::time::timeout(
        IN_TIME,
        t.send(upload_req(
            &url,
            &cs[0].tok,
            Some(&sig),
            stalled_body(),
            Some(expected + 1),
        )),
    )
    .await
    .expect("rejected without reading the body");
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    let r = tokio::time::timeout(
        IN_TIME,
        t.send(upload_req(
            &url,
            &cs[0].tok,
            Some(&sig),
            stalled_body(),
            Some(expected - 1),
        )),
    )
    .await
    .expect("rejected without reading the body");
    assert_eq!(r.error_code(), "bad_request");
    // Missing signature: rejected before reading.
    let r = tokio::time::timeout(
        IN_TIME,
        t.send(upload_req(
            &url,
            &cs[0].tok,
            None,
            stalled_body(),
            Some(expected),
        )),
    )
    .await
    .expect("rejected without reading the body");
    assert_eq!(r.error_code(), "bad_request");
    // A body longer than announced/expected without Content-Length: 413.
    let r = t
        .send(upload_req(
            &url,
            &cs[0].tok,
            Some(&sig),
            Body::from(vec![0u8; expected + 10]),
            None,
        ))
        .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    // The correct upload with Content-Length still works.
    let body = vec![0u8; expected];
    let sig = cs[0].sig(&g.gid, UploadKind::Roles, 1, &body);
    let r = t
        .send(upload_req(
            &url,
            &cs[0].tok,
            Some(&sig),
            Body::from(body),
            Some(expected),
        ))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
}

#[tokio::test]
async fn stalled_bodies_time_out() {
    // Idle body: no chunk within body_idle_timeout ⇒ 400.
    let t = app_with(Config {
        body_idle_timeout: Duration::from_millis(200),
        ..test_config()
    })
    .await;
    let (g, cs) = started_group(&t).await;
    let n = roles_vector_len(4);
    let r = tokio::time::timeout(
        IN_TIME,
        t.send(upload_req(
            &g.url("/rounds/1/roles"),
            &cs[0].tok,
            Some(&[1; 64]),
            stalled_body(),
            Some(n),
        )),
    )
    .await
    .expect("body idle timeout");
    assert_eq!(r.error_code(), "bad_request");

    // Overall request timeout ⇒ 408.
    let t = app_with(Config {
        request_timeout: Duration::from_millis(200),
        ..test_config()
    })
    .await;
    let (g, cs) = started_group(&t).await;
    let r = tokio::time::timeout(
        IN_TIME,
        t.send(upload_req(
            &g.url("/rounds/1/roles"),
            &cs[0].tok,
            Some(&[1; 64]),
            stalled_body(),
            Some(n),
        )),
    )
    .await
    .expect("request timeout");
    assert_eq!(r.status, StatusCode::REQUEST_TIMEOUT);
}

#[tokio::test]
async fn global_concurrency_limit_sheds_load() {
    let t = app_with(Config {
        max_concurrent_requests: 1,
        ..test_config()
    })
    .await;
    let (g, cs) = started_group(&t).await;
    // One request stays in progress (stalled upload).
    let busy = tokio::spawn(t.router.clone().oneshot(upload_req(
        &g.url("/rounds/1/roles"),
        &cs[0].tok,
        Some(&[1; 64]),
        stalled_body(),
        Some(roles_vector_len(4)),
    )));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let r = t.call(Method::GET, "/api/health", None).await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.headers["retry-after"], "5");
    busy.abort();
    let _ = busy.await;
    let r = t.call(Method::GET, "/api/health", None).await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn large_downloads_are_rate_limited() {
    let t = app_with(Config {
        download_limit_per_hour: 2,
        ..test_config()
    })
    .await;
    let (g, _) = started_group(&t).await;
    let get = |path: &str, ip: &str| {
        with_peer(
            build(Method::GET, &g.url(path), None, None, Body::empty(), None),
            ip,
        )
    };
    assert_eq!(
        t.send(get("/rounds/1/roles", "10.0.0.1")).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        t.send(get("/rounds/1/reveal", "10.0.0.1")).await.status,
        StatusCode::CONFLICT
    );
    let r = t.send(get("/rounds/1/roles", "10.0.0.1")).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        t.send(get("/rounds/1/roles", "10.0.0.2")).await.status,
        StatusCode::CONFLICT
    );
}

// ---------------------------------------------------------------- 3: proxy warning

#[tokio::test]
async fn warns_once_about_an_untrusted_proxy() {
    let t = TestApp::new().await;
    t.send(create_req("10.0.0.1")).await;
    assert!(!t.app.proxy_warning_emitted());
    t.send(create_req("127.0.0.1")).await;
    assert!(t.app.proxy_warning_emitted());
    assert!(
        !t.app
            .note_untrusted_peer(Some("127.0.0.1".parse().unwrap()), false),
        "only once"
    );

    let t = TestApp::new().await;
    let mut req = create_req("10.0.0.9");
    req.headers_mut()
        .insert("x-forwarded-for", "192.0.2.1".parse().unwrap());
    t.send(req).await;
    assert!(t.app.proxy_warning_emitted(), "X-Forwarded-For present");

    let t = app_with(Config {
        trust_proxy: true,
        ..test_config()
    })
    .await;
    t.send(create_req("127.0.0.1")).await;
    assert!(!t.app.proxy_warning_emitted());
}

// ---------------------------------------------------------------- 5: VACUUM, shutdown

#[tokio::test]
async fn every_deletion_or_overwrite_marks_vacuum() {
    let t = TestApp::new().await;
    let (g, cs) = group_with(&t, 3).await;
    assert!(!t.app.vacuum_pending());

    // Name/wish update (open).
    let mut changed = cs[0].clone();
    changed.enc_name = vec![0x99; 40];
    let r = t
        .json(
            Method::PUT,
            &g.url(&format!("/participants/{}", b64(&cs[0].pid))),
            Some(&cs[0].tok),
            &changed.join_request(&g.gid),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
    assert!(t.app.vacuum_pending(), "update");
    t.app.maybe_vacuum(true).await;

    // Leave while open.
    let r = t
        .call(
            Method::DELETE,
            &g.url(&format!("/participants/{}", b64(&cs[2].pid))),
            Some(&cs[2].tok),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(t.app.vacuum_pending(), "leave in open");
    t.app.maybe_vacuum(true).await;

    // Push subscription replaced, then deleted.
    let push_url = g.url(&format!("/participants/{}/push", b64(&cs[0].pid)));
    let sub = |ep: &str| json!({"endpoint": ep, "p256dh": b64(&[4; 65]), "auth": b64(&[5; 16])});
    t.json(
        Method::PUT,
        &push_url,
        Some(&cs[0].tok),
        &sub("https://push.example.org/a"),
    )
    .await;
    t.app.maybe_vacuum(true).await;
    t.json(
        Method::PUT,
        &push_url,
        Some(&cs[0].tok),
        &sub("https://push.example.org/b"),
    )
    .await;
    assert!(t.app.vacuum_pending(), "subscription replaced");
    t.app.maybe_vacuum(true).await;
    let r = t.call(Method::DELETE, &push_url, Some(&cs[0].tok)).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(t.app.vacuum_pending(), "unsubscribe");
    t.app.maybe_vacuum(true).await;

    // Subscription gone at the push service (deleted by the fan-out worker).
    t.json(
        Method::PUT,
        &push_url,
        Some(&cs[0].tok),
        &sub("https://push.example.org/gone"),
    )
    .await;
    t.app.maybe_vacuum(true).await;
    t.push
        .gone
        .lock()
        .unwrap()
        .insert("https://push.example.org/gone".into());
    join(&t, &g, &FakeClient::new(&g.gid, 50)).await;
    join(&t, &g, &FakeClient::new(&g.gid, 51)).await;
    let r = t.call(Method::POST, &g.url("/start"), Some(&g.admin)).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    t.push.wait_for(1).await;
    for _ in 0..100 {
        if t.app.vacuum_pending() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(t.app.vacuum_pending(), "gone subscription deleted");
}

#[tokio::test]
async fn startup_vacuums_free_pages_from_before_a_restart() {
    let path = temp_db_path("startup-vacuum");
    let marker = [0xE7u8; 2000];
    {
        let mut t = TestApp::with(test_config(), Arc::new(FakeOps), &path).await;
        for i in 0..12u8 {
            let admin = [i; 32];
            let req = json!({
                "admin_hash": b64(&sha(&[b"wichtel/v1/admin-hash", &admin])),
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
                .call(Method::DELETE, &format!("/api/groups/{gid}"), Some(&admin))
                .await;
            assert_eq!(r.status, StatusCode::NO_CONTENT);
        }
        assert!(t.app.vacuum_pending());
        assert!(t.app.store.needs_vacuum().await.unwrap());
        // "Crash" before the bundled VACUUM: the in-RAM flag is lost with the process.
        t.db_path = temp_db_path("unused");
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let t = TestApp::with(test_config(), Arc::new(FakeOps), &path).await;
    assert!(!t.app.store.needs_vacuum().await.unwrap());
    let mut runs = 0;
    for f in [path.clone(), format!("{path}-wal")] {
        if let Ok(bytes) = std::fs::read(&f) {
            runs += bytes
                .windows(64)
                .filter(|w| w.iter().all(|&b| b == 0xE7))
                .count();
        }
    }
    assert_eq!(runs, 0, "deleted enc_meta still on disk after restart");
}

async fn open_sse(t: &TestApp, g: &Group, ip: &str) -> axum::response::Response {
    t.router
        .clone()
        .oneshot(with_peer(
            build(
                Method::GET,
                &g.url("/events"),
                None,
                None,
                Body::empty(),
                None,
            ),
            ip,
        ))
        .await
        .unwrap()
}

#[tokio::test]
async fn shutdown_ends_sse_streams() {
    let t = TestApp::new().await;
    let g = create_group(&t, None).await;
    let res = open_sse(&t, &g, "10.0.0.1").await;
    assert_eq!(res.status(), StatusCode::OK);
    let mut stream = res.into_body().into_data_stream();
    let first = tokio::time::timeout(IN_TIME, stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        std::str::from_utf8(&first)
            .unwrap()
            .contains("event: update")
    );
    t.app.shutdown();
    let end = tokio::time::timeout(IN_TIME, async {
        while let Some(chunk) = stream.next().await {
            chunk.unwrap();
        }
    })
    .await;
    assert!(end.is_ok(), "stream ended");
    assert_eq!(t.app.hub.listener_count(), 0);
    let res = open_sse(&t, &g, "10.0.0.1").await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
}

// ---------------------------------------------------------------- 6: creation limits, empty groups

#[tokio::test]
async fn create_limit_per_ipv6_slash_48_and_global() {
    let t = TestApp::new().await;
    for i in 0..10 {
        let r = t.send(create_req(&format!("2001:db8:1:{i}::1"))).await;
        assert_eq!(r.status, StatusCode::CREATED);
    }
    let r = t.send(create_req("2001:db8:1:ff::1")).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "same /48");
    let r = t.send(create_req("2001:db8:2::1")).await;
    assert_eq!(r.status, StatusCode::CREATED, "other /48");

    let t = app_with(Config {
        create_limit_global_per_hour: 3,
        ..test_config()
    })
    .await;
    for i in 1..=3 {
        let r = t.send(create_req(&format!("10.0.0.{i}"))).await;
        assert_eq!(r.status, StatusCode::CREATED);
    }
    let r = t.send(create_req("10.0.0.4")).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "global limit");
    t.clock.advance(3600);
    let r = t.send(create_req("10.0.0.4")).await;
    assert_eq!(r.status, StatusCode::CREATED);
}

#[tokio::test]
async fn empty_groups_are_deleted_after_a_day() {
    let t = TestApp::new().await;
    let empty = create_group(&t, Some(T0 + 20 * 86_400)).await;
    let used = create_group(&t, None).await;
    join(&t, &used, &FakeClient::new(&used.gid, 1)).await;
    t.clock.advance(86_400 - 10);
    t.app.run_jobs().await;
    assert_eq!(view(&t, &empty).await["state"], "open");
    t.clock.advance(20);
    t.app.run_jobs().await;
    assert_eq!(
        t.call(Method::GET, &empty.url(""), None).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(view(&t, &used).await["state"], "open", "has a participant");
    // Deleted and compacted by the same job run.
    assert!(!t.app.vacuum_pending());
    assert!(!t.app.store.needs_vacuum().await.unwrap());
}

// ---------------------------------------------------------------- 7: SSE limits

#[tokio::test]
async fn sse_limits_per_ip_and_existence_check() {
    let t = app_with(Config {
        sse_per_ip: 1,
        ..test_config()
    })
    .await;
    let g = create_group(&t, None).await;
    // Unknown group: 404, no slot used.
    let unknown = Group {
        gid: [0; 16],
        gid_s: "AAAAAAAAAAAAAAAAAAAAAA".into(),
        admin: [0; 32],
    };
    assert_eq!(
        open_sse(&t, &unknown, "10.0.0.1").await.status(),
        StatusCode::NOT_FOUND
    );
    assert!(!t.app.hub.has_listeners(&unknown.gid));
    let first = open_sse(&t, &g, "10.0.0.1").await;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(
        open_sse(&t, &g, "10.0.0.1").await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let other = open_sse(&t, &g, "10.0.0.2").await;
    assert_eq!(other.status(), StatusCode::OK);
    assert_eq!(t.app.hub.listener_count(), 2);
    drop(first);
    assert_eq!(t.app.hub.listener_count(), 1);
    assert_eq!(
        open_sse(&t, &g, "10.0.0.1").await.status(),
        StatusCode::OK,
        "slot released"
    );

    let t = app_with(Config {
        sse_total: 1,
        ..test_config()
    })
    .await;
    let g = create_group(&t, None).await;
    let _a = open_sse(&t, &g, "10.0.0.1").await;
    assert_eq!(
        open_sse(&t, &g, "10.0.0.2").await.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "global cap"
    );
}

// ---------------------------------------------------------------- 11: push throttling

#[tokio::test]
async fn push_fan_out_is_throttled_per_group() {
    let t = app_with(Config {
        push_min_interval: Duration::from_millis(400),
        ..test_config()
    })
    .await;
    let (g, cs) = group_with(&t, 4).await;
    let r = t
        .json(
            Method::PUT,
            &g.url(&format!("/participants/{}/push", b64(&cs[0].pid))),
            Some(&cs[0].tok),
            &json!({"endpoint": "https://push.example.org/p", "p256dh": b64(&[4; 65]), "auth": b64(&[5; 16])}),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let r = t.call(Method::POST, &g.url("/start"), Some(&g.admin)).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(t.push.wait_for(1).await.len(), 1, "first push at once");
    for _ in 0..3 {
        let r = t
            .call(Method::POST, &g.url("/restart"), Some(&g.admin))
            .await;
        assert_eq!(r.status, StatusCode::NO_CONTENT);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(t.push.count(), 1, "throttled");
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(t.push.count(), 2, "one merged push after the interval");
    // No `sub` claim without a configured VAPID subject (never 127.0.0.1).
    let msg = &t.push.sent.lock().unwrap()[0];
    let jwt = msg.authorization.strip_prefix("vapid t=").unwrap();
    let claims: serde_json::Value =
        serde_json::from_slice(&unb64(jwt.split('.').nth(1).unwrap())).unwrap();
    assert!(claims.get("sub").is_none());
}

// ---------------------------------------------------------------- 13, 15: view, headers

#[tokio::test]
async fn roster_has_no_join_time() {
    let t = TestApp::new().await;
    let (g, _) = group_with(&t, 2).await;
    let v = view(&t, &g).await;
    let p = v["participants"][0].as_object().unwrap();
    assert!(!p.contains_key("joined_at"));
    assert!(p.contains_key("enc_name"));
}

#[tokio::test]
async fn hsts_only_for_https_deployments() {
    let t = TestApp::new().await;
    let r = t.call(Method::GET, "/api/health", None).await;
    assert!(!r.headers.contains_key("strict-transport-security"));
    let t = app_with(Config {
        public_url: "https://wichteln.example".into(),
        ..test_config()
    })
    .await;
    for path in ["/api/health", "/"] {
        let r = t.call(Method::GET, path, None).await;
        assert_eq!(
            r.headers["strict-transport-security"], "max-age=31536000",
            "{path}"
        );
    }
}
