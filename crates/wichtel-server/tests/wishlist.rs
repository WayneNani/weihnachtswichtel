//! Spec §16: wish list changes after the start, contacts and the anonymous giver
//! notification (with [`common::FakeOps`]).

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use common::*;
use serde_json::json;
use wichtel_core::keys::UploadKind;
use wichtel_core::{L_CT, L_REVEAL_UPLOAD, L_SD, roles_vector_len};
use wichtel_server::Config;
use wichtel_server::app::L_CONTACT;

const IN_TIME: Duration = Duration::from_secs(3);
/// Endpoint of a normal group subscription (fan-out on state changes).
const GROUP_SUB: &str = "https://push.example.org/group-sub";

// ---------------------------------------------------------------- helpers

fn roles_body(n: usize, seed: u8) -> Vec<u8> {
    let mut v: Vec<u8> = (0..roles_vector_len(n))
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect();
    v[..17].fill(0);
    v
}

fn reveal_body(client: u8) -> Vec<u8> {
    let mut v = vec![0u8; L_REVEAL_UPLOAD];
    for t in 0..16usize {
        let off = L_SD + t * L_CT;
        v[off..off + L_CT].fill(client.wrapping_mul(16).wrapping_add(t as u8 + 1));
    }
    v
}

/// Pseudo-random contact `K_i` (the server does not look inside).
fn contact(seed: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(L_CONTACT);
    let mut h = sha(&[b"contact", &[seed]]);
    while out.len() < L_CONTACT {
        out.extend_from_slice(&h);
        h = sha(&[&h]);
    }
    out.truncate(L_CONTACT);
    out
}

async fn upload_roles(t: &TestApp, g: &Group, c: &FakeClient, round: u32, n: usize, i: u8) {
    let body = roles_body(n, i);
    let sig = c.sig(&g.gid, UploadKind::Roles, round, &body);
    let r = t
        .upload(
            &g.url(&format!("/rounds/{round}/roles")),
            &c.tok,
            Some(&sig),
            body,
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
}

async fn upload_reveal(t: &TestApp, g: &Group, c: &FakeClient, round: u32, i: u8) {
    let body = reveal_body(i);
    let sig = c.sig(&g.gid, UploadKind::Reveal, round, &body);
    let r = t
        .upload(
            &g.url(&format!("/rounds/{round}/reveal")),
            &c.tok,
            Some(&sig),
            body,
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
}

async fn run_to_done(t: &TestApp, g: &Group, cs: &[FakeClient], round: u32) {
    for (i, c) in cs.iter().enumerate() {
        upload_roles(t, g, c, round, cs.len(), i as u8).await;
    }
    for (i, c) in cs.iter().enumerate() {
        upload_reveal(t, g, c, round, i as u8).await;
    }
    assert_eq!(view(t, g).await["state"], "done");
}

async fn start(t: &TestApp, g: &Group) {
    let r = t.call(Method::POST, &g.url("/start"), Some(&g.admin)).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
}

/// A group of `n` in state `done` (round 1, draw 1).
async fn done_group(t: &TestApp, n: u8) -> (Group, Vec<FakeClient>) {
    let (g, cs) = group_with(t, n).await;
    start(t, &g).await;
    run_to_done(t, &g, &cs, 1).await;
    (g, cs)
}

/// `PUT …/participants/{pid}` with `c`'s current name/wish and an optional `notify_endpoint`.
async fn update(t: &TestApp, g: &Group, c: &FakeClient, notify: Option<&str>) -> Resp {
    let mut body = c.join_request(&g.gid);
    if let Some(ep) = notify {
        body["notify_endpoint"] = ep.into();
    }
    t.json(
        Method::PUT,
        &g.url(&format!("/participants/{}", b64(&c.pid))),
        Some(&c.tok),
        &body,
    )
    .await
}

fn wish_of(v: &serde_json::Value, c: &FakeClient) -> Vec<u8> {
    let p = v["participants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| unb64(p["pid"].as_str().unwrap()) == c.pid)
        .unwrap();
    unb64(p["enc_wish"].as_str().unwrap())
}

async fn put_contact(
    t: &TestApp,
    g: &Group,
    c: &FakeClient,
    draw_no: u32,
    round: u32,
    body: Vec<u8>,
) -> Resp {
    let sig = c.contact_sig(&g.gid, round, &body);
    t.upload(
        &g.url(&format!("/draws/{draw_no}/contact")),
        &c.tok,
        Some(&sig),
        body,
    )
    .await
}

async fn get_contacts(t: &TestApp, g: &Group, draw_no: u32) -> Resp {
    t.call(
        Method::GET,
        &g.url(&format!("/draws/{draw_no}/contacts")),
        None,
    )
    .await
}

async fn subscribe_group_push(t: &TestApp, g: &Group, c: &FakeClient) {
    let r = t
        .json(
            Method::PUT,
            &g.url(&format!("/participants/{}/push", b64(&c.pid))),
            Some(&c.tok),
            &json!({"endpoint": GROUP_SUB, "p256dh": b64(&[4; 65]), "auth": b64(&[5; 16])}),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
}

/// Let queued background pushes go out, then return how many were sent so far.
async fn settled_push_count(t: &TestApp) -> usize {
    tokio::time::sleep(Duration::from_millis(100)).await;
    t.push.count()
}

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

fn count_runs(path: &str, needle: &[u8]) -> usize {
    [path.to_owned(), format!("{path}-wal")]
        .iter()
        .filter_map(|f| std::fs::read(f).ok())
        .map(|bytes| bytes.windows(needle.len()).filter(|w| *w == needle).count())
        .sum()
}

// ---------------------------------------------------------------- 16.1 wish list

#[tokio::test]
async fn wish_list_can_change_in_every_state() {
    let t = TestApp::new().await;
    let (g, mut cs) = group_with(&t, 4).await;
    subscribe_group_push(&t, &g, &cs[3]).await;
    let (_, mut sub) = t.app.subscribe(&g.gid, None).await.unwrap();

    // open: name and wish may change.
    cs[0].enc_wish = vec![0x10; 70];
    cs[0].enc_name = vec![0x11; 30];
    assert_eq!(
        update(&t, &g, &cs[0], None).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(wish_of(&view(&t, &g).await, &cs[0]), vec![0x10; 70]);

    // drawing (roles): wish only; a running round is not affected.
    start(&t, &g).await;
    upload_roles(&t, &g, &cs[1], 1, 4, 1).await;
    cs[0].enc_wish = vec![0x20; 80];
    assert_eq!(
        update(&t, &g, &cs[0], None).await.status,
        StatusCode::NO_CONTENT
    );
    let v = view(&t, &g).await;
    assert_eq!(wish_of(&v, &cs[0]), vec![0x20; 80]);
    assert_eq!(v["state"], "drawing");
    assert_eq!(v["progress"]["submitted"], json!([b64(&cs[1].pid)]));
    let mut renamed = cs[0].clone();
    renamed.enc_name = vec![0x12; 30];
    let r = update(&t, &g, &renamed, None).await;
    assert_eq!(
        r.status,
        StatusCode::CONFLICT,
        "name change after the start"
    );
    // A wrong join signature is still rejected.
    let mut bad = cs[0].join_request(&g.gid);
    bad["enc_wish"] = b64(&[0x21; 80]).into();
    let r = t
        .json(
            Method::PUT,
            &g.url(&format!("/participants/{}", b64(&cs[0].pid))),
            Some(&cs[0].tok),
            &bad,
        )
        .await;
    assert_eq!(r.error_code(), "bad_request");

    // Finish the draw (round 1 continues normally).
    for (i, c) in cs.iter().enumerate() {
        if i != 1 {
            upload_roles(&t, &g, c, 1, 4, i as u8).await;
        }
    }
    for (i, c) in cs.iter().enumerate() {
        upload_reveal(&t, &g, c, 1, i as u8).await;
    }
    assert_eq!(view(&t, &g).await["state"], "done");

    // done: wish only, name change ⇒ 409.
    let base = settled_push_count(&t).await;
    while sub.rx.try_recv().is_ok() {}
    cs[0].enc_wish = vec![0x30; 90];
    assert_eq!(
        update(&t, &g, &cs[0], None).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(wish_of(&view(&t, &g).await, &cs[0]), vec![0x30; 90]);
    let ev = sub.rx.try_recv().expect("SSE event for open pages");
    assert_eq!(ev.participant_count, 4);
    let mut renamed = cs[0].clone();
    renamed.enc_name = vec![0x13; 30];
    assert_eq!(
        update(&t, &g, &renamed, None).await.status,
        StatusCode::CONFLICT
    );
    // Neither in drawing nor in done did a wish list change trigger a group push.
    assert_eq!(settled_push_count(&t).await, base, "no group push");
    assert_eq!(view(&t, &g).await["state"], "done");
}

// ---------------------------------------------------------------- 16.2 contacts

#[tokio::test]
async fn contact_upload_rules() {
    let t = TestApp::new().await;
    let (g, cs) = group_with(&t, 4).await;
    // Not before done.
    let r = put_contact(&t, &g, &cs[0], 0, 0, contact(1)).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    start(&t, &g).await;
    let r = put_contact(&t, &g, &cs[0], 1, 1, contact(1)).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(get_contacts(&t, &g, 1).await.status, StatusCode::CONFLICT);
    run_to_done(&t, &g, &cs, 1).await;

    let url = g.url("/draws/1/contact");
    let body = contact(1);
    let sig = cs[0].contact_sig(&g.gid, 1, &body);
    // Token, state/draw and length are checked before the body is read.
    for (req, status) in [
        (
            upload_req(
                &url,
                &[0x42; 32],
                Some(&sig),
                stalled_body(),
                Some(L_CONTACT),
            ),
            StatusCode::UNAUTHORIZED,
        ),
        (
            upload_req(
                &g.url("/draws/2/contact"),
                &cs[0].tok,
                Some(&sig),
                stalled_body(),
                Some(L_CONTACT),
            ),
            StatusCode::CONFLICT,
        ),
        (
            upload_req(
                &url,
                &cs[0].tok,
                Some(&sig),
                stalled_body(),
                Some(L_CONTACT + 1),
            ),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
        (
            upload_req(
                &url,
                &cs[0].tok,
                Some(&sig),
                stalled_body(),
                Some(L_CONTACT - 1),
            ),
            StatusCode::BAD_REQUEST,
        ),
        (
            upload_req(&url, &cs[0].tok, None, stalled_body(), Some(L_CONTACT)),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let r = tokio::time::timeout(IN_TIME, t.send(req))
            .await
            .expect("rejected without reading the body");
        assert_eq!(r.status, status);
    }
    // Too long / too short bodies without Content-Length.
    let r = t
        .send(upload_req(
            &url,
            &cs[0].tok,
            Some(&sig),
            Body::from(vec![0u8; L_CONTACT + 1]),
            None,
        ))
        .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    let short = vec![0u8; L_CONTACT - 1];
    let r = put_contact(&t, &g, &cs[0], 1, 1, short).await;
    assert_eq!(r.error_code(), "bad_request");
    // Signature: kind 3, round of Done, own key.
    let wrong_kind = cs[0].sig(&g.gid, UploadKind::Roles, 1, &body);
    let wrong_round = cs[0].contact_sig(&g.gid, 2, &body);
    let foreign = cs[1].contact_sig(&g.gid, 1, &body);
    for s in [wrong_kind, wrong_round, foreign] {
        let r = t.upload(&url, &cs[0].tok, Some(&s), body.clone()).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(get_contacts(&t, &g, 1).await.body.len(), 0);

    // Valid upload; a second one replaces the first.
    assert_eq!(
        put_contact(&t, &g, &cs[0], 1, 1, contact(1)).await.status,
        StatusCode::NO_CONTENT
    );
    assert!(t.app.vacuum_pending());
    assert_eq!(get_contacts(&t, &g, 1).await.body.to_vec(), contact(1));
    assert_eq!(
        put_contact(&t, &g, &cs[0], 1, 1, contact(2)).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(get_contacts(&t, &g, 1).await.body.to_vec(), contact(2));

    // Everybody uploads: GET returns all, sorted by hash, without pids.
    for (i, c) in cs.iter().enumerate().skip(1) {
        let r = put_contact(&t, &g, c, 1, 1, contact(10 + i as u8)).await;
        assert_eq!(r.status, StatusCode::NO_CONTENT);
    }
    let r = get_contacts(&t, &g, 1).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.headers["content-type"], "application/octet-stream");
    assert_eq!(r.headers["cache-control"], "no-store");
    assert_eq!(r.body.len(), 4 * L_CONTACT);
    let mut expected = [contact(2), contact(11), contact(12), contact(13)];
    expected.sort_by_key(|k| sha(&[k]));
    assert_eq!(r.body.to_vec(), expected.concat());
    for c in &cs {
        assert!(
            !r.body.windows(16).any(|w| w == c.pid),
            "response must not contain pids"
        );
    }
    // Other draw numbers: nothing.
    assert_eq!(get_contacts(&t, &g, 2).await.status, StatusCode::CONFLICT);
    assert_eq!(get_contacts(&t, &g, 0).await.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn contacts_are_rate_limited_like_large_downloads() {
    let t = TestApp::with(
        Config {
            download_limit_per_hour: 2,
            ..test_config()
        },
        Arc::new(FakeOps),
        &temp_db_path("contacts-rl"),
    )
    .await;
    let (g, _) = done_group(&t, 4).await;
    let get = |ip: &str| {
        let mut r = build(
            Method::GET,
            &g.url("/draws/1/contacts"),
            None,
            None,
            Body::empty(),
            None,
        );
        let addr: SocketAddr = format!("{ip}:1234").parse().unwrap();
        r.extensions_mut().insert(ConnectInfo(addr));
        r
    };
    assert_eq!(t.send(get("10.0.0.1")).await.status, StatusCode::OK);
    assert_eq!(t.send(get("10.0.0.1")).await.status, StatusCode::OK);
    assert_eq!(
        t.send(get("10.0.0.1")).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(t.send(get("10.0.0.2")).await.status, StatusCode::OK);
}

#[tokio::test]
async fn contacts_are_deleted_with_every_new_draw_and_the_group() {
    let path = temp_db_path("contacts-del");
    let t = TestApp::with(test_config(), Arc::new(FakeOps), &path).await;
    let (g, cs) = done_group(&t, 5).await;
    let marker = vec![0xD5u8; L_CONTACT];
    let r = put_contact(&t, &g, &cs[0], 1, 1, marker.clone()).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    put_contact(&t, &g, &cs[1], 1, 1, contact(1)).await;
    assert_eq!(t.app.store.count_contacts(&g.gid).await.unwrap(), 2);

    // Admin restart ⇒ draw 2, contacts gone (also from the file after VACUUM).
    t.app.maybe_vacuum(true).await;
    let r = t
        .call(Method::POST, &g.url("/restart"), Some(&g.admin))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(t.app.store.count_contacts(&g.gid).await.unwrap(), 0);
    assert_eq!(get_contacts(&t, &g, 1).await.status, StatusCode::CONFLICT);
    assert!(t.app.vacuum_pending());
    t.app.maybe_vacuum(true).await;
    assert_eq!(count_runs(&path, &[0xD5; 64]), 0, "deleted contact on disk");

    // Leave after the start ⇒ draw 3, contacts gone.
    run_to_done(&t, &g, &cs, 2).await;
    put_contact(&t, &g, &cs[0], 2, 2, contact(2)).await;
    assert_eq!(t.app.store.count_contacts(&g.gid).await.unwrap(), 1);
    let r = t
        .call(
            Method::DELETE,
            &g.url(&format!("/participants/{}", b64(&cs[4].pid))),
            Some(&cs[4].tok),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(view(&t, &g).await["draw_no"], 3);
    assert_eq!(t.app.store.count_contacts(&g.gid).await.unwrap(), 0);

    // Group deletion.
    run_to_done(&t, &g, &cs[..4], 3).await;
    put_contact(&t, &g, &cs[0], 3, 3, contact(3)).await;
    assert_eq!(t.app.store.count_contacts(&g.gid).await.unwrap(), 1);
    let r = t.call(Method::DELETE, &g.url(""), Some(&g.admin)).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(t.app.store.count_contacts(&g.gid).await.unwrap(), 0);
    assert!(t.app.vacuum_pending());
}

// ---------------------------------------------------------------- 16.3 notification

#[tokio::test]
async fn notify_endpoint_sends_exactly_one_push_to_the_giver() {
    let t = TestApp::new().await;
    let (g, mut cs) = done_group(&t, 4).await;
    subscribe_group_push(&t, &g, &cs[1]).await;
    let base = settled_push_count(&t).await;

    let ep = "https://push.example.org/wish/giver-of-0";
    cs[0].enc_wish = vec![0x40; 50];
    let r = update(&t, &g, &cs[0], Some(ep)).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
    let sent = t.push.wait_for(base + 1).await;
    assert_eq!(sent.len(), base + 1, "exactly one push");
    let msg = sent.last().unwrap();
    assert_eq!(msg.endpoint, ep);
    assert!(msg.authorization.starts_with("vapid t="));
    assert!(
        sent.iter().all(|m| m.endpoint != GROUP_SUB),
        "no group push"
    );

    // Within 10 minutes: wish list saved, notification dropped silently.
    cs[0].enc_wish = vec![0x41; 50];
    let r = update(&t, &g, &cs[0], Some(ep)).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(wish_of(&view(&t, &g).await, &cs[0]), vec![0x41; 50]);
    assert_eq!(settled_push_count(&t).await, base + 1, "rate limited");
    // The limit is per participant.
    let r = update(&t, &g, &cs[2], Some(ep)).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(t.push.wait_for(base + 2).await.len(), base + 2);
    // After 10 minutes again (also after the background job cleaned up).
    t.clock.advance(599);
    update(&t, &g, &cs[0], Some(ep)).await;
    assert_eq!(settled_push_count(&t).await, base + 2);
    t.clock.advance(1);
    t.app.run_jobs().await;
    update(&t, &g, &cs[0], Some(ep)).await;
    assert_eq!(t.push.wait_for(base + 3).await.len(), base + 3);

    // A gone endpoint (404/410) is ignored.
    let gone = "https://push.example.org/wish/gone";
    t.push.gone.lock().unwrap().insert(gone.to_owned());
    let r = update(&t, &g, &cs[3], Some(gone)).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(t.push.wait_for(base + 4).await.len(), base + 4);
    assert_eq!(t.app.store.list_push_subs(&g.gid).await.unwrap().len(), 1);
}

#[tokio::test]
async fn invalid_or_early_notify_endpoint_is_dropped_silently() {
    let t = TestApp::new().await;
    let (g, mut cs) = group_with(&t, 4).await;
    let ep = "https://push.example.org/wish/x";
    // open and drawing: saved, no push.
    cs[0].enc_wish = vec![0x50; 10];
    assert_eq!(
        update(&t, &g, &cs[0], Some(ep)).await.status,
        StatusCode::NO_CONTENT
    );
    start(&t, &g).await;
    cs[0].enc_wish = vec![0x51; 10];
    assert_eq!(
        update(&t, &g, &cs[0], Some(ep)).await.status,
        StatusCode::NO_CONTENT
    );
    run_to_done(&t, &g, &cs, 1).await;
    let base = settled_push_count(&t).await;
    assert_eq!(base, 0, "no subscriptions, no notification before done");

    let long = format!("https://push.example.org/{}", "a".repeat(700));
    for (i, bad) in [
        "",
        "http://push.example.org/wish/x",
        "https://evil.example/wish/x",
        "https://127.0.0.1/wish/x",
        "https://user:pw@push.example.org/x",
        "not a url",
        long.as_str(),
    ]
    .into_iter()
    .enumerate()
    {
        cs[1].enc_wish = vec![i as u8; 20];
        let r = update(&t, &g, &cs[1], Some(bad)).await;
        assert_eq!(r.status, StatusCode::NO_CONTENT, "{bad}");
        assert_eq!(wish_of(&view(&t, &g).await, &cs[1]), vec![i as u8; 20]);
    }
    assert_eq!(settled_push_count(&t).await, 0);
    // A rejected endpoint does not use up the rate limit.
    update(&t, &g, &cs[1], Some(ep)).await;
    assert_eq!(t.push.wait_for(1).await.len(), 1);
    // A failed name check still fails (and sends nothing).
    let mut renamed = cs[2].clone();
    renamed.enc_name = vec![0x77; 3];
    let r = update(&t, &g, &renamed, Some(ep)).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(settled_push_count(&t).await, 1);
}

#[tokio::test]
async fn notify_endpoint_never_reaches_the_database() {
    let path = temp_db_path("notify-db");
    let t = TestApp::with(test_config(), Arc::new(FakeOps), &path).await;
    let (g, cs) = done_group(&t, 4).await;
    let ep = "https://push.example.org/wish/UNIQUE-MARKER-7f3a9c";
    update(&t, &g, &cs[0], Some(ep)).await;
    update(&t, &g, &cs[0], Some(ep)).await; // rate limited
    assert_eq!(t.push.wait_for(1).await.len(), 1);
    assert_eq!(count_runs(&path, b"UNIQUE-MARKER-7f3a9c"), 0);
    t.app.maybe_vacuum(true).await;
    assert_eq!(count_runs(&path, b"UNIQUE-MARKER-7f3a9c"), 0);
}
