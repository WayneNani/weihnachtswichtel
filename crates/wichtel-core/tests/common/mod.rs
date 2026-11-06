//! Shared protocol driver for the integration tests: in-process clients plus an in-memory
//! "mailbox" that plays the server role (XOR aggregation, `evaluate_roles`, `select_attempt`,
//! release of the `t*` reveals only).

#![allow(dead_code)]

use wichtel_core::dcnet::{
    OwnPositions, RolesOutcome, build_roles_vector, evaluate_roles, own_positions, xor_into,
};
use wichtel_core::gk::{self, GkContext};
use wichtel_core::keys::{ParticipantKeys, UploadKind, auth_hash, verify_join, verify_upload};
use wichtel_core::reveal::{
    DrawResult, build_reveal_upload, open_result, select_attempt, split_reveal_upload,
};
use wichtel_core::roster::{Roster, RosterEntry, fingerprint, group_context};
use wichtel_core::{Error, GroupId, L_SD, Pid, roles_vector_len};

pub const GK: [u8; 32] = [0x47; 32];

/// One in-process participant.
pub struct Client {
    pub seed: [u8; 32],
    pub keys: ParticipantKeys,
    pub name: String,
    pub note: String,
    pub enc_name: Vec<u8>,
}

impl Client {
    pub fn new(gid: &GroupId, seed: [u8; 32], name: &str) -> Self {
        let keys = ParticipantKeys::derive(&seed, gid).unwrap();
        let p = keys.public();
        let enc_name = gk::seal(
            &GK,
            GkContext::Name {
                gid,
                pid: &p.pid,
                ipk: &p.ipk,
                idh: &p.idh,
            },
            name.as_bytes(),
        )
        .unwrap();
        Self {
            seed,
            keys,
            name: name.to_owned(),
            note: format!("Notiz von {name}"),
            enc_name,
        }
    }

    pub fn pid(&self) -> Pid {
        self.keys.public().pid
    }

    /// What the server stores after a successful join (join signature verified).
    pub fn join_entry(&self, gid: &GroupId) -> RosterEntry {
        let p = self.keys.public();
        let ah = auth_hash(&self.keys.auth_token());
        let sig = self.keys.sign_join(&self.enc_name, b"");
        let pid = verify_join(gid, &p.ipk, &p.idh, &ah, &self.enc_name, b"", &sig).unwrap();
        assert_eq!(pid, p.pid);
        RosterEntry::new(pid, p.ipk, p.idh, &self.enc_name)
    }
}

/// Deterministic seed for test participant `i` of run `run`.
pub fn seed(run: u64, i: usize) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&run.to_be_bytes());
    s[8] = i as u8;
    s[9] = 0xa1;
    s
}

pub fn gid_for(run: u64) -> GroupId {
    let mut g = [0x5au8; 16];
    g[..8].copy_from_slice(&run.to_be_bytes());
    GroupId(g)
}

pub fn make_clients(gid: &GroupId, run: u64, n: usize) -> Vec<Client> {
    (0..n)
        .map(|i| Client::new(gid, seed(run, i), &format!("P{i}")))
        .collect()
}

pub fn roster_of(gid: &GroupId, clients: &[Client]) -> Roster {
    Roster::new(clients.iter().map(|c| c.join_entry(gid)).collect()).unwrap()
}

/// Replace the upload of client `k` by `f(upload)`.
pub type Mutator = Option<(usize, fn(&mut Vec<u8>))>;

/// Test hooks to simulate faults.
#[derive(Default)]
pub struct Faults {
    /// Replace the role vector of client `k` by `f(vector)`.
    pub corrupt_roles: Mutator,
    /// Replace the step-2 upload of client `k` by `f(upload)`.
    pub corrupt_reveal: Mutator,
    /// The server announces this `t*` instead of the correct one.
    pub wrong_t_star: Option<u8>,
}

/// Public data of a finished round (as seen by the server / any observer).
pub struct PublicRound {
    pub g_r: [u8; 32],
    pub r: Vec<u8>,
    pub outcome: RolesOutcome,
    pub sd: Vec<u8>,
    pub t_star: u8,
}

/// Result of one protocol round.
#[allow(clippy::large_enum_variant)]
pub enum RoundReport {
    /// Server detected an invalid area E.
    Collision,
    /// The server rejected an upload (wrong length / signature).
    UploadRejected(Error),
    /// A client refused to build its role vector.
    ClientRefused(usize, Error),
    /// No valid attempt without self-draw.
    NoValidAttempt,
    /// Reveals released; per-client results.
    Done {
        public: PublicRound,
        own: Vec<Result<OwnPositions, Error>>,
        results: Vec<Result<DrawResult, Error>>,
    },
}

/// Run one round. `views[i]` is the roster client `i` is shown; `server_roster` the one the
/// server uses (its `n` and `G_r`).
pub fn run_round(
    gid: &GroupId,
    round: u32,
    server_roster: &Roster,
    views: &[&Roster],
    clients: &[&Client],
    faults: &Faults,
) -> RoundReport {
    let n = server_roster.len();
    assert_eq!(clients.len(), n);
    let server_g = group_context(gid, round, server_roster);

    // Step 1: role vectors, aggregated on arrival.
    let mut agg = vec![0u8; roles_vector_len(n)];
    for (i, c) in clients.iter().enumerate() {
        let mut v = match build_roles_vector(&c.keys, gid, round, views[i]) {
            Ok(v) => v,
            Err(e) => return RoundReport::ClientRefused(i, e),
        };
        if let Some((k, f)) = faults.corrupt_roles
            && k == i
        {
            f(&mut v);
        }
        let sig = c.keys.sign_upload(UploadKind::Roles, round, &v);
        let p = c.keys.public();
        if let Err(e) = verify_upload(gid, &p.pid, &p.ipk, UploadKind::Roles, round, &v, &sig) {
            return RoundReport::UploadRejected(e);
        }
        if let Err(e) = xor_into(&mut agg, &v) {
            return RoundReport::UploadRejected(e);
        }
    }
    let r = agg;
    let outcome = match evaluate_roles(&server_g, n, &r) {
        Ok(o) => o,
        Err(Error::Collision) => {
            // Every client must reach the same verdict with its own G_r.
            for (i, _) in clients.iter().enumerate() {
                let g = group_context(gid, round, views[i]);
                assert!(evaluate_roles(&g, views[i].len(), &r).is_err());
            }
            return RoundReport::Collision;
        }
        Err(e) => panic!("unexpected server error {e:?}"),
    };

    // Clients evaluate R themselves and check their own roles.
    let mut own = Vec::with_capacity(n);
    let mut client_outcomes = Vec::with_capacity(n);
    for (i, c) in clients.iter().enumerate() {
        let g = group_context(gid, round, views[i]);
        let o = evaluate_roles(&g, views[i].len(), &r);
        let pos = o
            .as_ref()
            .map_err(|e| *e)
            .and_then(|o| own_positions(&c.keys, gid, round, views[i], &r, o));
        own.push(pos);
        client_outcomes.push(o);
    }

    // Step 2: self-draw vector + reveals.
    let mut sd = vec![0u8; L_SD];
    let mut uploads: Vec<Option<Vec<u8>>> = Vec::with_capacity(n);
    for (i, c) in clients.iter().enumerate() {
        let (Ok(o), Ok(pos)) = (&client_outcomes[i], &own[i]) else {
            // Disturbed client: does not upload. The round cannot finish.
            uploads.push(None);
            continue;
        };
        let mut body = build_reveal_upload(&c.keys, gid, round, views[i], o, pos, &c.note).unwrap();
        if let Some((k, f)) = faults.corrupt_reveal
            && k == i
        {
            f(&mut body);
        }
        let sig = c.keys.sign_upload(UploadKind::Reveal, round, &body);
        let p = c.keys.public();
        verify_upload(gid, &p.pid, &p.ipk, UploadKind::Reveal, round, &body, &sig).unwrap();
        uploads.push(Some(body));
    }
    if uploads.iter().any(Option::is_none) {
        // Not all n uploads arrived; the admin would have to restart.
        return RoundReport::Done {
            public: PublicRound {
                g_r: server_g,
                r,
                outcome,
                sd,
                t_star: 0,
            },
            own,
            results: clients.iter().map(|_| Err(Error::OwnRoleMissing)).collect(),
        };
    }
    let mut cts: Vec<Vec<Vec<u8>>> = Vec::with_capacity(n);
    for body in uploads.iter().flatten() {
        let (sd_i, c) = match split_reveal_upload(body) {
            Ok(x) => x,
            Err(e) => return RoundReport::UploadRejected(e),
        };
        xor_into(&mut sd, sd_i).unwrap();
        cts.push(c.into_iter().map(<[u8]>::to_vec).collect());
    }
    let Some(t_server) = select_attempt(&outcome, &sd) else {
        return RoundReport::NoValidAttempt;
    };
    let t_star = faults.wrong_t_star.unwrap_or(t_server);
    // Release only the n reveals of t*; all other C_{j,t} are dropped.
    let released: Vec<(Pid, Vec<u8>)> = clients
        .iter()
        .zip(cts)
        .map(|(c, mut cs)| (c.pid(), cs.swap_remove(usize::from(t_star - 1))))
        .collect();

    let mut results = Vec::with_capacity(n);
    for (i, c) in clients.iter().enumerate() {
        let res = match (&client_outcomes[i], &own[i]) {
            (Ok(o), Ok(pos)) => {
                // Client computes t* itself and aborts on mismatch (Spec §9.1).
                if select_attempt(o, &sd) != Some(t_star) {
                    Err(Error::AttemptMismatch)
                } else {
                    open_result(&c.keys, gid, round, views[i], o, pos, t_star, &released)
                }
            }
            (Err(e), _) | (_, Err(e)) => Err(*e),
        };
        results.push(res);
    }
    RoundReport::Done {
        public: PublicRound {
            g_r: server_g,
            r,
            outcome,
            sd,
            t_star,
        },
        own,
        results,
    }
}

/// Run rounds starting at `round` until a round is done (collision / no-valid-attempt rounds
/// advance automatically). Returns the final round number and report.
pub fn run_until_done(
    gid: &GroupId,
    mut round: u32,
    roster: &Roster,
    clients: &[&Client],
    max_rounds: u32,
) -> (u32, RoundReport, u32) {
    let views: Vec<&Roster> = clients.iter().map(|_| roster).collect();
    let mut auto_rounds = 0;
    for _ in 0..max_rounds {
        match run_round(gid, round, roster, &views, clients, &Faults::default()) {
            RoundReport::Collision | RoundReport::NoValidAttempt => {
                round += 1;
                auto_rounds += 1;
            }
            rep => return (round, rep, auto_rounds),
        }
    }
    panic!("no successful round within {max_rounds} rounds");
}

/// Check the end-to-end properties of a successful round and return the assignment
/// `giver index → recipient index` (indices into `clients`).
pub fn check_done(clients: &[&Client], report: &RoundReport) -> Vec<usize> {
    let RoundReport::Done {
        public,
        own,
        results,
    } = report
    else {
        panic!("round not done");
    };
    let n = clients.len();
    let t = public.t_star;
    let ti = usize::from(t - 1);
    let sigma = wichtel_core::draw::sigma(&public.outcome.rho, t, n);
    let own: Vec<&OwnPositions> = own.iter().map(|o| o.as_ref().unwrap()).collect();

    let mut assignment = vec![usize::MAX; n];
    for (i, res) in results.iter().enumerate() {
        let res = res.as_ref().unwrap_or_else(|e| panic!("client {i}: {e:?}"));
        let j = clients
            .iter()
            .position(|c| c.pid() == res.recipient)
            .expect("recipient in roster");
        // The recipient is exactly the person at E-position σ_t*(p_i).
        let e = usize::from(sigma[own[i].p[ti].unwrap()]);
        assert_eq!(own[j].e, e, "client {i} learned a wrong recipient");
        assert_eq!(res.note, clients[j].note);
        assignment[i] = j;
    }
    // Derangement: permutation without fixed points.
    let mut seen = vec![false; n];
    for (i, &j) in assignment.iter().enumerate() {
        assert_ne!(i, j, "self-draw");
        assert!(!seen[j], "two givers for one recipient");
        seen[j] = true;
    }
    // E-positions are a permutation, too.
    let mut es: Vec<usize> = own.iter().map(|o| o.e).collect();
    es.sort_unstable();
    assert_eq!(es, (0..n).collect::<Vec<_>>());
    assignment
}

/// Fingerprint as shown to client `view`.
pub fn fp(gid: &GroupId, roster: &Roster) -> [&'static str; 8] {
    fingerprint(gid, roster)
}
