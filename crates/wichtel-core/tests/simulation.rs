//! Protocol simulation: in-process clients + in-memory mailbox playing the server.

mod common;

use common::*;
use wichtel_core::Error;
use wichtel_core::contact::{build_contact, open_contacts};
use wichtel_core::dcnet::{build_roles_vector, evaluate_roles, xor_into};
use wichtel_core::gk::{self, GkContext};
use wichtel_core::keys::{UploadKind, verify_upload};
use wichtel_core::roster::{Roster, group_context};
use wichtel_core::{GroupId, L_K, roles_vector_len};

fn normal(n: usize, run: u64) {
    let gid = gid_for(run);
    let clients = make_clients(&gid, run, n);
    let roster = roster_of(&gid, &clients);
    let refs: Vec<&Client> = clients.iter().collect();
    let (_, report, _) = run_until_done(&gid, 1, &roster, &refs, 20);
    check_done(&refs, &report);
}

#[test]
fn normal_small_groups() {
    for n in [4, 5, 7] {
        for run in 0..3 {
            normal(n, 1000 * n as u64 + run);
        }
    }
}

/// n = 20 takes about a minute in the debug profile (≈ 1 MB role vector per client).
#[test]
#[ignore]
fn normal_n20() {
    normal(20, 20_000);
}

/// n = 30 is slow in the debug profile (≈ 2.4 MB role vector per client).
#[test]
#[ignore]
fn normal_n30() {
    normal(30, 30_000);
}

/// Step 1 only: does round `round` collide in area E?
fn collides(gid: &GroupId, round: u32, roster: &Roster, clients: &[Client]) -> bool {
    let n = roster.len();
    let mut agg = vec![0u8; roles_vector_len(n)];
    for c in clients {
        let v = build_roles_vector(&c.keys, gid, round, roster).unwrap();
        xor_into(&mut agg, &v).unwrap();
    }
    let g = group_context(gid, round, roster);
    matches!(evaluate_roles(&g, n, &agg), Err(Error::Collision))
}

#[test]
fn collision_leads_to_next_round() {
    let gid = gid_for(77);
    let clients = make_clients(&gid, 77, 4);
    let roster = roster_of(&gid, &clients);
    let refs: Vec<&Client> = clients.iter().collect();
    // Search the (deterministic) first round with two clients in the same E-slot.
    let r_coll = (1..2000)
        .find(|&r| collides(&gid, r, &roster, &clients))
        .expect("a collision round exists");
    let views = vec![&roster; 4];
    assert!(matches!(
        run_round(&gid, r_coll, &roster, &views, &refs, &Faults::default()),
        RoundReport::Collision
    ));
    let (round, report, auto) = run_until_done(&gid, r_coll, &roster, &refs, 20);
    assert!(round > r_coll);
    assert!(auto >= 1);
    check_done(&refs, &report);
}

#[test]
fn leave_triggers_redraw_with_smaller_roster() {
    let gid = gid_for(55);
    let clients = make_clients(&gid, 55, 5);
    let roster = roster_of(&gid, &clients);
    let refs: Vec<&Client> = clients.iter().collect();
    let (round, report, _) = run_until_done(&gid, 1, &roster, &refs, 20);
    check_done(&refs, &report);

    // Participant 2 leaves after the result ⇒ new draw r+1 with 4 participants.
    let rest: Vec<&Client> = clients
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 2)
        .map(|(_, c)| c)
        .collect();
    let small = Roster::new(rest.iter().map(|c| c.join_entry(&gid)).collect()).unwrap();
    assert_ne!(fp(&gid, &small), fp(&gid, &roster));
    let (_, report, _) = run_until_done(&gid, round + 1, &small, &rest, 20);
    let assignment = check_done(&rest, &report);
    assert_eq!(assignment.len(), 4);

    // A client still holding the old roster cannot take part in the new round.
    assert_eq!(
        build_roles_vector(&clients[2].keys, &gid, round + 1, &small).err(),
        Some(Error::NotInRoster)
    );
}

#[test]
fn equivocation_aborts_without_panic() {
    let gid = gid_for(66);
    let clients = make_clients(&gid, 66, 5);
    let honest = roster_of(&gid, &clients);
    // The server shows client 0 a roster in which client 4 is replaced by a fake member
    // whose keys it controls.
    let fake = Client::new(&gid, seed(9999, 0), "Fake");
    let mut entries: Vec<_> = clients[..4].iter().map(|c| c.join_entry(&gid)).collect();
    entries.push(fake.join_entry(&gid));
    let forged = Roster::new(entries).unwrap();
    assert_ne!(
        fp(&gid, &forged),
        fp(&gid, &honest),
        "fingerprints reveal it"
    );

    let refs: Vec<&Client> = clients.iter().collect();
    let views: Vec<&Roster> = (0..5)
        .map(|i| if i == 0 { &forged } else { &honest })
        .collect();
    // Masks do not cancel ⇒ area E invalid in every round; clients give up after 3.
    for round in 1..=3 {
        assert!(matches!(
            run_round(&gid, round, &honest, &views, &refs, &Faults::default()),
            RoundReport::Collision
        ));
    }
}

#[test]
fn swapped_enc_name_is_rejected() {
    let gid = gid_for(44);
    let clients = make_clients(&gid, 44, 4);
    let a = clients[1].keys.public();
    let b = clients[2].keys.public();
    let ctx_a = GkContext::Name {
        gid: &gid,
        pid: &a.pid,
        ipk: &a.ipk,
        idh: &a.idh,
    };
    // Own name opens, a swapped one does not (AAD binds pid/IPK/IDH).
    assert_eq!(
        gk::open(&GK, ctx_a, &clients[1].enc_name).unwrap(),
        b"P1".to_vec()
    );
    assert_eq!(
        gk::open(&GK, ctx_a, &clients[2].enc_name),
        Err(Error::DecryptionFailed)
    );
    let ctx_b = GkContext::Name {
        gid: &gid,
        pid: &b.pid,
        ipk: &b.ipk,
        idh: &b.idh,
    };
    assert_eq!(
        gk::open(&GK, ctx_b, &clients[1].enc_name),
        Err(Error::DecryptionFailed)
    );
    // The swap also changes H(enc_name) in the roster, hence G_r and the fingerprint.
    let honest = roster_of(&gid, &clients);
    let mut entries = honest.entries().to_vec();
    let i1 = honest.index_of(&a.pid).unwrap();
    let i2 = honest.index_of(&b.pid).unwrap();
    let h = entries[i1].enc_name_hash;
    entries[i1].enc_name_hash = entries[i2].enc_name_hash;
    entries[i2].enc_name_hash = h;
    let swapped = Roster::new(entries).unwrap();
    assert_ne!(fp(&gid, &swapped), fp(&gid, &honest));
    assert_ne!(
        group_context(&gid, 1, &swapped),
        group_context(&gid, 1, &honest)
    );
}

#[allow(clippy::ptr_arg)] // signature must match `Mutator`
fn flip_e_area(v: &mut Vec<u8>) {
    v[100] ^= 0x55;
}

#[allow(clippy::ptr_arg)] // signature must match `Mutator`
fn randomize(v: &mut Vec<u8>) {
    for (i, b) in v.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(31).wrapping_add(7);
    }
}

fn truncate(v: &mut Vec<u8>) {
    v.pop();
}

#[allow(clippy::ptr_arg)] // signature must match `Mutator`
fn garble_reveals(v: &mut Vec<u8>) {
    for b in &mut v[wichtel_core::L_SD..] {
        *b ^= 0xa5;
    }
}

#[test]
fn broken_vector_fails_round_cleanly() {
    let gid = gid_for(33);
    let clients = make_clients(&gid, 33, 5);
    let roster = roster_of(&gid, &clients);
    let refs: Vec<&Client> = clients.iter().collect();
    let views = vec![&roster; 5];
    let (good_round, _, _) = run_until_done(&gid, 1, &roster, &refs, 20);

    for f in [flip_e_area as fn(&mut Vec<u8>), randomize] {
        let faults = Faults {
            corrupt_roles: Some((2, f)),
            ..Faults::default()
        };
        assert!(matches!(
            run_round(&gid, good_round, &roster, &views, &refs, &faults),
            RoundReport::Collision
        ));
    }
    let faults = Faults {
        corrupt_roles: Some((2, truncate)),
        ..Faults::default()
    };
    assert!(matches!(
        run_round(&gid, good_round, &roster, &views, &refs, &faults),
        RoundReport::UploadRejected(Error::InvalidLength)
    ));

    // Garbage reveals of client 2: exactly its giver sees a disturbance, nobody panics.
    let faults = Faults {
        corrupt_reveal: Some((2, garble_reveals)),
        ..Faults::default()
    };
    let RoundReport::Done { results, .. } =
        run_round(&gid, good_round, &roster, &views, &refs, &faults)
    else {
        panic!("expected released reveals");
    };
    let errs: Vec<_> = results.iter().filter(|r| r.is_err()).collect();
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0], &Err(Error::RevealCount));
    assert!(
        results
            .iter()
            .flatten()
            .all(|r| r.recipient != clients[2].pid())
    );
}

#[test]
fn wrong_t_star_is_detected() {
    let gid = gid_for(22);
    let clients = make_clients(&gid, 22, 4);
    let roster = roster_of(&gid, &clients);
    let refs: Vec<&Client> = clients.iter().collect();
    let views = vec![&roster; 4];
    let (round, report, _) = run_until_done(&gid, 1, &roster, &refs, 20);
    let RoundReport::Done { public, .. } = report else {
        unreachable!()
    };
    // Announce every other t: clients must abort (never open a wrong attempt).
    for t in 1..=16u8 {
        if t == public.t_star {
            continue;
        }
        let faults = Faults {
            wrong_t_star: Some(t),
            ..Faults::default()
        };
        let RoundReport::Done { results, .. } =
            run_round(&gid, round, &roster, &views, &refs, &faults)
        else {
            panic!("expected release");
        };
        assert!(results.iter().all(|r| *r == Err(Error::AttemptMismatch)));
    }
}

#[test]
fn deterministic_replay() {
    // Same seeds ⇒ identical uploads (reload after crash yields the same messages).
    let gid = gid_for(11);
    let a = make_clients(&gid, 11, 4);
    let b = make_clients(&gid, 11, 4);
    let roster = roster_of(&gid, &a);
    for (x, y) in a.iter().zip(&b) {
        assert_eq!(
            build_roles_vector(&x.keys, &gid, 1, &roster).unwrap(),
            build_roles_vector(&y.keys, &gid, 1, &roster).unwrap()
        );
    }
}

/// Spec §16.2 contacts of a finished round: endpoint per giver and the served bytes.
struct Contacts {
    endpoints: Vec<String>,
    served: Vec<u8>,
}

/// Every client of a finished round uploads its contact (endpoint `ep(i)`, signature kind 3);
/// the server serves them sorted (here: by bytes) and without pids.
fn upload_contacts(
    gid: &GroupId,
    round: u32,
    roster: &Roster,
    clients: &[&Client],
    report: &RoundReport,
    ep: fn(usize) -> String,
) -> Contacts {
    let RoundReport::Done {
        public,
        own,
        results,
    } = report
    else {
        panic!("round not done");
    };
    let mut blocks = Vec::new();
    let mut endpoints = Vec::new();
    for (i, c) in clients.iter().enumerate() {
        let recipient = results[i].as_ref().unwrap().recipient;
        let idh = roster.entries()[roster.index_of(&recipient).unwrap()].idh;
        let endpoint = ep(i);
        let k = build_contact(
            &c.keys,
            gid,
            round,
            roster,
            &public.outcome,
            own[i].as_ref().unwrap(),
            public.t_star,
            &idh,
            &endpoint,
        )
        .unwrap();
        assert_eq!(k.len(), L_K);
        let sig = c.keys.sign_upload(UploadKind::Contact, round, &k);
        let p = c.keys.public();
        verify_upload(gid, &p.pid, &p.ipk, UploadKind::Contact, round, &k, &sig).unwrap();
        blocks.push(k);
        endpoints.push(endpoint);
    }
    blocks.sort();
    Contacts {
        endpoints,
        served: blocks.concat(),
    }
}

/// Client `j` opens `contacts` with its state of `report` and attempt `t` (default `t*`).
#[allow(clippy::too_many_arguments)]
fn open_as(
    gid: &GroupId,
    round: u32,
    roster: &Roster,
    clients: &[&Client],
    report: &RoundReport,
    j: usize,
    t: Option<u8>,
    contacts: &[u8],
) -> Result<Option<String>, Error> {
    let RoundReport::Done { public, own, .. } = report else {
        panic!("round not done");
    };
    open_contacts(
        &clients[j].keys,
        gid,
        round,
        roster,
        &public.outcome,
        own[j].as_ref().unwrap(),
        t.unwrap_or(public.t_star),
        contacts,
    )
}

fn endpoint_even(i: usize) -> String {
    if i.is_multiple_of(2) {
        format!("https://push.example/send/{i}")
    } else {
        String::new()
    }
}

fn endpoint_all(i: usize) -> String {
    format!("https://push.example/next/{i}")
}

#[test]
fn contacts_reach_exactly_the_own_giver() {
    let gid = gid_for(88);
    let clients = make_clients(&gid, 88, 5);
    let roster = roster_of(&gid, &clients);
    let refs: Vec<&Client> = clients.iter().collect();
    let n = refs.len();
    let (round, report, _) = run_until_done(&gid, 1, &roster, &refs, 20);
    let assignment = check_done(&refs, &report);
    let giver_of = |j: usize| assignment.iter().position(|&r| r == j).unwrap();
    let open =
        |j: usize, t: Option<u8>, c: &[u8]| open_as(&gid, round, &roster, &refs, &report, j, t, c);

    // Every recipient finds exactly the endpoint of its giver; empty endpoint ⇒ None.
    let k = upload_contacts(&gid, round, &roster, &refs, &report, endpoint_even);
    for j in 0..n {
        let ep = &k.endpoints[giver_of(j)];
        let expected = (!ep.is_empty()).then(|| ep.clone());
        assert_eq!(open(j, None, &k.served), Ok(expected), "recipient {j}");
    }

    // Contacts of everybody else to j (wrong skS) do not open; among all of them j still finds
    // exactly the one of its giver.
    let RoundReport::Done { public, own, .. } = &report else {
        unreachable!()
    };
    const STRANGER: &str = "https://push.example/stranger";
    for (j, recipient) in clients.iter().enumerate() {
        let idh = recipient.keys.public().idh;
        let mut all = Vec::new();
        for i in (0..n).filter(|&i| i != j) {
            let c = build_contact(
                &refs[i].keys,
                &gid,
                round,
                &roster,
                &public.outcome,
                own[i].as_ref().unwrap(),
                public.t_star,
                &idh,
                STRANGER,
            )
            .unwrap();
            if i != giver_of(j) {
                assert_eq!(open(j, None, &c), Ok(None), "stranger {i} → {j}");
            }
            all.extend_from_slice(&c);
        }
        assert_eq!(open(j, None, &all), Ok(Some(STRANGER.to_owned())));
    }

    // Another t*: either unusable for the client or the contacts do not open.
    for t in (1..=16u8).filter(|&t| t != public.t_star) {
        for j in 0..n {
            match open(j, Some(t), &k.served) {
                Ok(None) | Err(Error::AttemptMismatch) => {}
                other => panic!("t = {t}, client {j}: {other:?}"),
            }
        }
    }

    // Broken lengths.
    for len in [1, L_K - 1, L_K + 1, k.served.len() - 1] {
        assert_eq!(
            open(0, None, &k.served[..len]).err(),
            Some(Error::InvalidLength),
            "{len}"
        );
    }
    let mut long = k.served.clone();
    long.push(0);
    assert_eq!(open(0, None, &long).err(), Some(Error::InvalidLength));
    assert_eq!(open(0, None, &[]), Ok(None));

    // A second upload with the same endpoint gives different bytes (fresh ephemeral).
    let again = upload_contacts(&gid, round, &roster, &refs, &report, endpoint_even);
    for a in again.served.chunks(L_K) {
        assert!(k.served.chunks(L_K).all(|b| a != b));
    }
    // Both versions of one giver at once (server did not replace) ⇒ error.
    let j = assignment[0];
    let both = [&k.served[..], &again.served[..]].concat();
    assert_eq!(open(j, None, &both), Err(Error::ContactCount));

    // New draw (r+1, same roster): old contacts do not open with the new state and vice versa.
    let (round2, report2, _) = run_until_done(&gid, round + 1, &roster, &refs, 20);
    let assignment2 = check_done(&refs, &report2);
    let k2 = upload_contacts(&gid, round2, &roster, &refs, &report2, endpoint_all);
    for j in 0..n {
        let giver2 = assignment2.iter().position(|&r| r == j).unwrap();
        let open2 = |c: &[u8]| open_as(&gid, round2, &roster, &refs, &report2, j, None, c);
        assert_eq!(open2(&k2.served), Ok(Some(endpoint_all(giver2))));
        assert_eq!(open2(&k.served), Ok(None));
        assert_eq!(open(j, None, &k2.served), Ok(None));
    }
}
