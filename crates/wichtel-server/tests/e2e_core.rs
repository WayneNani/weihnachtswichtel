//! End-to-end protocol tests: several clients with the real `wichtel-core` functions talk to
//! the server (real [`CoreOps`]) over HTTP. Ignored until `wichtel-core` is implemented (A1).

mod common;

use std::collections::HashSet;
use std::sync::Arc;

use axum::http::{Method, StatusCode};
use common::*;
use sha2::{Digest, Sha256};
use wichtel_api::{GroupView, JoinRequest, RevealRelease};
use wichtel_core::dcnet::{build_roles_vector, evaluate_roles, own_positions};
use wichtel_core::gk::{self, GkContext};
use wichtel_core::keys::{self, ParticipantKeys, UploadKind};
use wichtel_core::reveal::{build_reveal_upload, open_result};
use wichtel_core::roster::{Roster, RosterEntry, group_context};
use wichtel_core::{GroupId, Pid};
use wichtel_server::protocol::CoreOps;

struct Client {
    name: String,
    note: String,
    keys: ParticipantKeys,
}

impl Client {
    fn pid(&self) -> Pid {
        self.keys.public().pid
    }
}

fn roster_of(view: &GroupView) -> Roster {
    Roster::new(
        view.participants
            .iter()
            .map(|p| RosterEntry {
                pid: Pid(p.pid.0),
                ipk: p.ipk.0,
                idh: p.idh.0,
                enc_name_hash: Sha256::digest(&p.enc_name.0).into(),
            })
            .collect(),
    )
    .unwrap()
}

async fn get_view(t: &TestApp, gid_s: &str) -> GroupView {
    let r = t
        .call(Method::GET, &format!("/api/groups/{gid_s}"), None)
        .await;
    assert_eq!(r.status, StatusCode::OK);
    r.json()
}

async fn setup(t: &TestApp, names: &[&str]) -> (GroupId, String, [u8; 32], [u8; 32], Vec<Client>) {
    let gk_secret = keys::generate_secret().unwrap();
    let admin = keys::generate_secret().unwrap();
    // enc_meta is opaque to the server; any bytes work for this test.
    let req = serde_json::json!({
        "admin_hash": b64(&keys::admin_hash(&admin)),
        "enc_meta": b64(&[0u8; 64]),
        "delete_after": T0 + 20 * 86_400,
        "draw_at": null,
    });
    let r = t.json(Method::POST, "/api/groups", None, &req).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let gid_s = r.json::<serde_json::Value>()["gid"]
        .as_str()
        .unwrap()
        .to_owned();
    let gid = GroupId(unb64(&gid_s).try_into().unwrap());

    let mut clients = Vec::new();
    for name in names {
        let seed = keys::generate_secret().unwrap();
        let k = ParticipantKeys::derive(&seed, &gid).unwrap();
        let p = k.public();
        let enc_name = gk::seal(
            &gk_secret,
            GkContext::Name {
                gid: &gid,
                pid: &p.pid,
                ipk: &p.ipk,
                idh: &p.idh,
            },
            name.as_bytes(),
        )
        .unwrap();
        let enc_wish = gk::seal(
            &gk_secret,
            GkContext::Wish {
                gid: &gid,
                pid: &p.pid,
                ipk: &p.ipk,
                idh: &p.idh,
            },
            b"Socken",
        )
        .unwrap();
        let join = JoinRequest {
            ipk: wichtel_api::Fixed(p.ipk),
            idh: wichtel_api::Fixed(p.idh),
            auth_hash: wichtel_api::Fixed(keys::auth_hash(&k.auth_token())),
            join_sig: wichtel_api::Fixed(k.sign_join(&enc_name, &enc_wish)),
            enc_name: wichtel_api::Bin(enc_name),
            enc_wish: wichtel_api::Bin(enc_wish),
        };
        let r = t
            .json(
                Method::POST,
                &format!("/api/groups/{gid_s}/participants"),
                None,
                &join,
            )
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        let pid: serde_json::Value = r.json();
        assert_eq!(unb64(pid["pid"].as_str().unwrap()), p.pid.0.to_vec());
        clients.push(Client {
            name: (*name).to_owned(),
            note: format!("Größe M – von {name}"),
            keys: k,
        });
    }
    (gid, gid_s, *admin, *gk_secret, clients)
}

/// Drive the protocol until `done`; returns `giver pid → (recipient pid, note)`.
async fn run_protocol(
    t: &TestApp,
    gid: &GroupId,
    gid_s: &str,
    clients: &[Client],
) -> Vec<(Pid, Pid, String)> {
    for _step in 0..40 {
        let view = get_view(t, gid_s).await;
        let roster = roster_of(&view);
        let n = roster.len();
        match view.state {
            wichtel_api::GroupState::Drawing { round, phase } => {
                let submitted: HashSet<[u8; 16]> = view
                    .progress
                    .as_ref()
                    .unwrap()
                    .submitted
                    .iter()
                    .map(|p| p.0)
                    .collect();
                let base = format!("/api/groups/{gid_s}/rounds/{round}");
                match phase {
                    wichtel_api::Phase::Roles => {
                        for c in clients {
                            if submitted.contains(&c.pid().0) {
                                continue;
                            }
                            let v = build_roles_vector(&c.keys, gid, round, &roster).unwrap();
                            let sig = c.keys.sign_upload(UploadKind::Roles, round, &v);
                            let r = t
                                .upload(
                                    &format!("{base}/roles"),
                                    &c.keys.auth_token(),
                                    Some(&sig),
                                    v,
                                )
                                .await;
                            assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
                        }
                    }
                    wichtel_api::Phase::Reveal => {
                        let r_vec = t.call(Method::GET, &format!("{base}/roles"), None).await;
                        assert_eq!(r_vec.status, StatusCode::OK);
                        let g_r = group_context(gid, round, &roster);
                        let outcome = evaluate_roles(&g_r, n, &r_vec.body).unwrap();
                        for c in clients {
                            if submitted.contains(&c.pid().0) {
                                continue;
                            }
                            let own =
                                own_positions(&c.keys, gid, round, &roster, &r_vec.body, &outcome)
                                    .unwrap();
                            let body = build_reveal_upload(
                                &c.keys, gid, round, &roster, &outcome, &own, &c.note,
                            )
                            .unwrap();
                            let sig = c.keys.sign_upload(UploadKind::Reveal, round, &body);
                            let r = t
                                .upload(
                                    &format!("{base}/reveal"),
                                    &c.keys.auth_token(),
                                    Some(&sig),
                                    body,
                                )
                                .await;
                            assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
                        }
                    }
                }
            }
            wichtel_api::GroupState::Done { round, t_star } => {
                let base = format!("/api/groups/{gid_s}/rounds/{round}");
                let r_vec = t.call(Method::GET, &format!("{base}/roles"), None).await;
                let rel: RevealRelease = t
                    .call(Method::GET, &format!("{base}/reveal"), None)
                    .await
                    .json();
                assert_eq!(rel.t_star, t_star);
                assert_eq!(rel.reveals.len(), n);
                let g_r = group_context(gid, round, &roster);
                let outcome = evaluate_roles(&g_r, n, &r_vec.body).unwrap();
                assert_eq!(
                    wichtel_core::reveal::select_attempt(&outcome, &rel.selfdraw_aggregate.0),
                    Some(t_star),
                    "clients recompute t*"
                );
                let reveals: Vec<(Pid, Vec<u8>)> = rel
                    .reveals
                    .iter()
                    .map(|e| (Pid(e.pid.0), e.ciphertext.0.clone()))
                    .collect();
                let mut out = Vec::new();
                for c in clients {
                    let own =
                        own_positions(&c.keys, gid, round, &roster, &r_vec.body, &outcome).unwrap();
                    let res = open_result(
                        &c.keys, gid, round, &roster, &outcome, &own, t_star, &reveals,
                    )
                    .unwrap();
                    out.push((c.pid(), res.recipient, res.note.clone()));
                }
                return out;
            }
            wichtel_api::GroupState::Open => panic!("unexpected open state"),
        }
    }
    panic!("protocol did not finish");
}

fn check_derangement(clients: &[Client], results: &[(Pid, Pid, String)]) {
    let pids: HashSet<Pid> = clients.iter().map(|c| c.pid()).collect();
    let recipients: HashSet<Pid> = results.iter().map(|r| r.1).collect();
    assert_eq!(recipients, pids, "assignment is a permutation");
    for (giver, recipient, note) in results {
        assert_ne!(giver, recipient, "nobody draws themselves");
        let rc = clients.iter().find(|c| c.pid() == *recipient).unwrap();
        assert_eq!(note, &rc.note, "note of the recipient reaches the giver");
    }
}

fn db_contains(path: &str, needle: &[u8]) -> bool {
    [path.to_owned(), format!("{path}-wal")]
        .iter()
        .filter_map(|f| std::fs::read(f).ok())
        .any(|b| b.windows(needle.len()).any(|w| w == needle))
}

#[tokio::test]
async fn e2e_four_and_seven_participants() {
    for names in [
        &["Anna", "Ben", "Clara", "David"][..],
        &["Anna", "Ben", "Clara", "David", "Emil", "Frieda", "Gustav"][..],
    ] {
        let path = temp_db_path("e2e");
        let t = TestApp::with(test_config(), Arc::new(CoreOps), &path).await;
        let (gid, gid_s, admin, _gk, clients) = setup(&t, names).await;
        let r = t
            .call(
                Method::POST,
                &format!("/api/groups/{gid_s}/start"),
                Some(&admin),
            )
            .await;
        assert_eq!(r.status, StatusCode::NO_CONTENT);
        let results = run_protocol(&t, &gid, &gid_s, &clients).await;
        check_derangement(&clients, &results);

        // The server never sees names or notes in clear text.
        t.app.maybe_vacuum(true).await;
        for c in &clients {
            // Short names could occur by chance in megabytes of random-looking data.
            if c.name.len() >= 5 {
                assert!(!db_contains(&path, c.name.as_bytes()), "{}", c.name);
            }
            assert!(!db_contains(&path, c.note.as_bytes()));
        }
    }
}

#[tokio::test]
async fn e2e_leave_after_result_triggers_new_draw() {
    let t = TestApp::with(test_config(), Arc::new(CoreOps), &temp_db_path("e2e-leave")).await;
    let (gid, gid_s, admin, _gk, mut clients) =
        setup(&t, &["Anna", "Ben", "Clara", "David", "Emil"]).await;
    t.call(
        Method::POST,
        &format!("/api/groups/{gid_s}/start"),
        Some(&admin),
    )
    .await;
    let first = run_protocol(&t, &gid, &gid_s, &clients).await;
    check_derangement(&clients, &first);
    let v1 = get_view(&t, &gid_s).await;

    let gone = clients.pop().unwrap();
    let r = t
        .call(
            Method::DELETE,
            &format!("/api/groups/{gid_s}/participants/{}", b64(&gone.pid().0)),
            Some(&admin),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let v2 = get_view(&t, &gid_s).await;
    assert_eq!(v2.draw_no, v1.draw_no + 1);
    let second = run_protocol(&t, &gid, &gid_s, &clients).await;
    check_derangement(&clients, &second);
}

#[tokio::test]
async fn e2e_rejects_forged_uploads() {
    let t = TestApp::with(test_config(), Arc::new(CoreOps), &temp_db_path("e2e-forge")).await;
    let (gid, gid_s, admin, _gk, clients) = setup(&t, &["A", "B", "C", "D"]).await;
    t.call(
        Method::POST,
        &format!("/api/groups/{gid_s}/start"),
        Some(&admin),
    )
    .await;
    let view = get_view(&t, &gid_s).await;
    let roster = roster_of(&view);
    let v = build_roles_vector(&clients[0].keys, &gid, 1, &roster).unwrap();
    // Signed by somebody else.
    let sig = clients[1].keys.sign_upload(UploadKind::Roles, 1, &v);
    let url = format!("/api/groups/{gid_s}/rounds/1/roles");
    let r = t
        .upload(&url, &clients[0].keys.auth_token(), Some(&sig), v.clone())
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // Wrong kind.
    let sig = clients[0].keys.sign_upload(UploadKind::Reveal, 1, &v);
    let r = t
        .upload(&url, &clients[0].keys.auth_token(), Some(&sig), v.clone())
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // Correct.
    let sig = clients[0].keys.sign_upload(UploadKind::Roles, 1, &v);
    let r = t
        .upload(&url, &clients[0].keys.auth_token(), Some(&sig), v)
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);

    // Join with a forged signature (fresh open group).
    let (g2, g2_s, _, _, _) = setup(&t, &[]).await;
    let seed = keys::generate_secret().unwrap();
    let k = ParticipantKeys::derive(&seed, &g2).unwrap();
    let p = k.public();
    let join = JoinRequest {
        ipk: wichtel_api::Fixed(p.ipk),
        idh: wichtel_api::Fixed(p.idh),
        auth_hash: wichtel_api::Fixed(keys::auth_hash(&k.auth_token())),
        join_sig: wichtel_api::Fixed([7; 64]),
        enc_name: wichtel_api::Bin(vec![1; 40]),
        enc_wish: wichtel_api::Bin(vec![]),
    };
    let r = t
        .json(
            Method::POST,
            &format!("/api/groups/{g2_s}/participants"),
            None,
            &join,
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}
