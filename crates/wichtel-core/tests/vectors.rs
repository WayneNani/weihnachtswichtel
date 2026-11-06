//! Test vectors `tests/vectors/v1.json` (Spec §15), n = 4, fixed seeds/gid/GK.
//!
//! `check_vectors` recomputes everything and compares with the file.
//! Regenerate after an intentional protocol change with
//! `cargo test -p wichtel-core --test vectors -- --ignored regenerate_vectors`.
//!
//! Fields beyond Spec §15: `note` (the private note the participant sends to its giver) and
//! `p` uses `null` for invalid attempts. `sigma` lists `σ_t` for all 16 attempts.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wichtel_core::dcnet::{build_roles_vector, evaluate_roles, own_positions, xor_into};
use wichtel_core::gk::{GkContext, seal_with_nonce};
use wichtel_core::keys::{ParticipantKeys, auth_hash};
use wichtel_core::reveal::{build_reveal_upload, open_result, select_attempt, split_reveal_upload};
use wichtel_core::roster::{Roster, RosterEntry, fingerprint, group_context};
use wichtel_core::{GroupId, L_SD, Pid, draw, roles_vector_len};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/v1.json");
const NAMES: [&str; 4] = ["Anna", "Ben", "Clara", "David"];
const GK: [u8; 32] = [0x6b; 32];
const ROUND: u32 = 1;

/// Base64url without padding (RFC 4648 §5).
fn b64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let v = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for k in 0..=chunk.len() {
            out.push(A[((v >> (18 - 6 * k)) & 63) as usize] as char);
        }
    }
    out
}

fn sha(data: &[u8]) -> String {
    b64(&Sha256::digest(data))
}

fn seed(i: usize) -> [u8; 32] {
    core::array::from_fn(|k| (i * 32 + k) as u8)
}

fn gid(k: u8) -> GroupId {
    let mut g: [u8; 16] = core::array::from_fn(|i| 0xa0 + i as u8);
    g[15] = k;
    GroupId(g)
}

/// Full protocol run for `gid`; `None` if round 1 does not finish.
fn generate_for(gid: &GroupId) -> Option<Value> {
    let keys: Vec<ParticipantKeys> = (0..4)
        .map(|i| ParticipantKeys::derive(&seed(i), gid).unwrap())
        .collect();
    let nonces: Vec<[u8; 12]> = (0..4).map(|i| [0x30 + i as u8; 12]).collect();
    let enc_names: Vec<Vec<u8>> = keys
        .iter()
        .zip(NAMES)
        .zip(&nonces)
        .map(|((k, name), nonce)| {
            let p = k.public();
            let ctx = GkContext::Name {
                gid,
                pid: &p.pid,
                ipk: &p.ipk,
                idh: &p.idh,
            };
            seal_with_nonce(&GK, ctx, name.as_bytes(), nonce).unwrap()
        })
        .collect();
    let roster = Roster::new(
        keys.iter()
            .zip(&enc_names)
            .map(|(k, e)| {
                let p = k.public();
                RosterEntry::new(p.pid, p.ipk, p.idh, e)
            })
            .collect(),
    )
    .unwrap();
    // Participant order in the file = roster order.
    let order: Vec<usize> = roster
        .entries()
        .iter()
        .map(|e| keys.iter().position(|k| k.public().pid == e.pid).unwrap())
        .collect();
    let notes: Vec<String> = NAMES.iter().map(|n| format!("Notiz von {n}")).collect();

    let g_r = group_context(gid, ROUND, &roster);
    let mut r = vec![0u8; roles_vector_len(4)];
    let mut roles_vectors = vec![Vec::new(); 4];
    for &i in &order {
        let v = build_roles_vector(&keys[i], gid, ROUND, &roster).unwrap();
        xor_into(&mut r, &v).unwrap();
        roles_vectors[i] = v;
    }
    let outcome = evaluate_roles(&g_r, 4, &r).ok()?;
    let own: Vec<_> = keys
        .iter()
        .map(|k| own_positions(k, gid, ROUND, &roster, &r, &outcome).unwrap())
        .collect();
    let uploads: Vec<Vec<u8>> = (0..4)
        .map(|i| {
            build_reveal_upload(&keys[i], gid, ROUND, &roster, &outcome, &own[i], &notes[i])
                .unwrap()
        })
        .collect();
    let mut sd = vec![0u8; L_SD];
    for u in &uploads {
        xor_into(&mut sd, split_reveal_upload(u).unwrap().0).unwrap();
    }
    let t_star = select_attempt(&outcome, &sd)?;
    let released: Vec<(Pid, Vec<u8>)> = order
        .iter()
        .map(|&i| {
            let (_, cs) = split_reveal_upload(&uploads[i]).unwrap();
            (keys[i].public().pid, cs[usize::from(t_star - 1)].to_vec())
        })
        .collect();

    let participants: Vec<Value> = order
        .iter()
        .map(|&i| {
            let p = keys[i].public();
            let res = open_result(
                &keys[i], gid, ROUND, &roster, &outcome, &own[i], t_star, &released,
            )
            .unwrap();
            json!({
                "seed": b64(&seed(i)),
                "pid": b64(&p.pid.0),
                "ipk": b64(&p.ipk),
                "idh": b64(&p.idh),
                "auth_hash": b64(&auth_hash(&keys[i].auth_token())),
                "name": NAMES[i],
                "enc_name_nonce": b64(&nonces[i]),
                "enc_name": b64(&enc_names[i]),
                "note": notes[i],
                "roles_vector_sha256": sha(&roles_vectors[i]),
                "reveal_upload_sha256": sha(&uploads[i]),
                "e": own[i].e,
                "p": own[i].p.to_vec(),
                "recipient_pid": b64(&res.recipient.0),
            })
        })
        .collect();

    Some(json!({
        "version": "wichtel/v1",
        "gid": b64(&gid.0),
        "gk": b64(&GK),
        "round": ROUND,
        "participants": participants,
        "fingerprint": fingerprint(gid, &roster).to_vec(),
        "g_r": b64(&g_r),
        "r_sha256": sha(&r),
        "rho": b64(&outcome.rho),
        "attempt_valid": outcome.givers.iter().map(Option::is_some).collect::<Vec<_>>(),
        "sigma": (1..=16u8).map(|t| draw::sigma(&outcome.rho, t, 4)).collect::<Vec<_>>(),
        "selfdraw_aggregate": b64(&sd),
        "t_star": t_star,
    }))
}

/// First gid (by last byte) whose round 1 finishes with a valid `t*` > 1 if possible, so the
/// vectors also cover a self-draw attempt.
fn generate() -> Value {
    let mut fallback = None;
    for k in 0..=255u8 {
        if let Some(v) = generate_for(&gid(k)) {
            if v["t_star"].as_u64() > Some(1) {
                return v;
            }
            fallback.get_or_insert(v);
        }
    }
    fallback.expect("some gid finishes in round 1")
}

#[test]
fn b64_matches_rfc4648() {
    assert_eq!(b64(b""), "");
    assert_eq!(b64(b"f"), "Zg");
    assert_eq!(b64(b"fo"), "Zm8");
    assert_eq!(b64(b"foo"), "Zm9v");
    assert_eq!(b64(b"foob"), "Zm9vYg");
    assert_eq!(b64(&[0xfb, 0xff]), "-_8");
}

#[test]
fn check_vectors() {
    let file: Value = serde_json::from_str(include_str!("vectors/v1.json")).unwrap();
    let gid_k = {
        // Recompute only for the gid stored in the file (fast path).
        let stored = file["gid"].as_str().unwrap();
        (0..=255u8).find(|&k| b64(&gid(k).0) == stored).unwrap()
    };
    let fresh = generate_for(&gid(gid_k)).unwrap();
    assert_eq!(fresh, file, "test vectors changed – protocol change?");
}

#[test]
#[ignore]
fn regenerate_vectors() {
    let v = generate();
    std::fs::create_dir_all(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors")).unwrap();
    std::fs::write(PATH, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
}
