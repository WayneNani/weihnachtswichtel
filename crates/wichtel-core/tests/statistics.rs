//! Statistics test (`#[ignore]`, run manually):
//! `cargo test -p wichtel-core --test statistics -- --ignored --nocapture --test-threads=2`
//!
//! For n = 4 all 9 derangements must occur equally often (χ² test, 8 degrees of freedom).
//!
//! To keep the debug build fast, each run executes step 1 for real (role vectors, aggregation,
//! `evaluate_roles`, `own_positions`, `σ_t`) but determines the self-draw flags directly from the
//! clients' own positions instead of running the HPKE-heavy step 2. That is exactly the
//! information the self-draw DC-net aggregates (Spec §9.1); its correctness is covered by
//! `tests/simulation.rs`. Runs use the same group with increasing round numbers (fresh `G_r`).
//!
//! Environment: `WICHTEL_STATS_FULL=1` runs the complete protocol including the real step 2
//! (self-draw DC-net, HPKE reveals, `open_result`); `WICHTEL_STATS_RUNS=<k>` sets the number of
//! runs (default 1800; with the full protocol about 1.5 s per run in the debug profile).

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use common::*;
use wichtel_core::dcnet::{build_roles_vector, evaluate_roles, own_positions, xor_into};
use wichtel_core::draw::sigma;
use wichtel_core::roles_vector_len;
use wichtel_core::roster::{Roster, group_context};

const N: usize = 4;
const THREADS: u32 = 2;

fn runs() -> u32 {
    std::env::var("WICHTEL_STATS_RUNS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1800)
}

fn full() -> bool {
    std::env::var("WICHTEL_STATS_FULL").is_ok_and(|v| v == "1")
}

/// Like [`draw`], but with the real step 2 via the shared mailbox driver.
fn draw_full(
    gid: &wichtel_core::GroupId,
    clients: &[Client],
    roster: &Roster,
    round: u32,
) -> Option<Vec<usize>> {
    let refs: Vec<&Client> = clients.iter().collect();
    let views = vec![roster; clients.len()];
    let report = run_round(gid, round, roster, &views, &refs, &Faults::default());
    match report {
        RoundReport::Done { .. } => Some(check_done(&refs, &report)),
        _ => None,
    }
}

/// Assignment `giver → recipient` (client indices) of round `round`, or `None` if the round
/// does not finish (collision / no attempt without self-draw).
fn draw(
    gid: &wichtel_core::GroupId,
    clients: &[Client],
    roster: &Roster,
    round: u32,
) -> Option<Vec<usize>> {
    let mut agg = vec![0u8; roles_vector_len(N)];
    for c in clients {
        xor_into(
            &mut agg,
            &build_roles_vector(&c.keys, gid, round, roster).unwrap(),
        )
        .unwrap();
    }
    let g = group_context(gid, round, roster);
    let outcome = evaluate_roles(&g, N, &agg).ok()?;
    let own: Vec<_> = clients
        .iter()
        .map(|c| own_positions(&c.keys, gid, round, roster, &agg, &outcome).unwrap())
        .collect();
    for t in 1..=16u8 {
        let ti = usize::from(t - 1);
        if outcome.givers[ti].is_none() {
            continue;
        }
        let s = sigma(&outcome.rho, t, N);
        let selfdraw = own.iter().any(|o| usize::from(s[o.p[ti].unwrap()]) == o.e);
        if selfdraw {
            continue;
        }
        return Some(
            own.iter()
                .map(|o| {
                    let e = usize::from(s[o.p[ti].unwrap()]);
                    own.iter().position(|x| x.e == e).unwrap()
                })
                .collect(),
        );
    }
    None
}

#[test]
#[ignore]
fn derangements_are_uniform_n4() {
    let gid = gid_for(424_242);
    let (runs, full) = (runs(), full());
    let counts: HashMap<Vec<usize>, u32> = {
        let gid = Arc::new(gid);
        let handles: Vec<_> = (0..THREADS)
            .map(|th| {
                let gid = Arc::clone(&gid);
                std::thread::spawn(move || {
                    let clients = make_clients(&gid, 424_242, N);
                    let roster = roster_of(&gid, &clients);
                    let mut counts = HashMap::new();
                    let mut done = 0;
                    let mut round = 1 + th * 1_000_000;
                    let f = if full { draw_full } else { draw };
                    while done < runs / THREADS {
                        if let Some(a) = f(&gid, &clients, &roster, round) {
                            for (i, &j) in a.iter().enumerate() {
                                assert_ne!(i, j);
                            }
                            *counts.entry(a).or_insert(0u32) += 1;
                            done += 1;
                        }
                        round += 1;
                    }
                    counts
                })
            })
            .collect();
        let mut total = HashMap::new();
        for h in handles {
            for (k, v) in h.join().unwrap() {
                *total.entry(k).or_insert(0) += v;
            }
        }
        total
    };
    assert_eq!(counts.len(), 9, "{counts:?}");
    let total = runs / THREADS * THREADS;
    let expected = f64::from(total) / 9.0;
    let chi2: f64 = counts
        .values()
        .map(|&c| (f64::from(c) - expected).powi(2) / expected)
        .sum();
    let mut sorted: Vec<_> = counts.iter().collect();
    sorted.sort();
    for (k, v) in &sorted {
        eprintln!("{k:?}: {v}");
    }
    eprintln!(
        "chi2 = {chi2:.3} (df = 8, 5 %: 15.51, 0.1 %: 26.12), runs = {total}, full step 2: {full}"
    );
    assert!(chi2 < 26.12, "chi2 = {chi2}");
}
