//! Leak test (port of `docs/analysis/leak_check.py`, Review §G3).
//!
//! A curious participant A runs the real protocol (n = 4) and then computes, from all public
//! data (`σ_t`, valid attempts, the published self-draw aggregate `SD`, `t*`) plus its own
//! secrets (own E-position, own giver positions, own result), the posterior probability that
//! its recipient B also gives to A (mutual pair). It must equal the base rate 1/3 in every run.
//!
//! Hidden variables: E-positions of the two other persons C, D (2 possibilities) and, for every
//! valid attempt, the giver positions of B, C, D (3! possibilities each). Attempts are
//! independent given the E-positions, so the likelihood factorises.

#![allow(clippy::needless_range_loop)]

mod common;

use common::*;
use wichtel_core::SLOT_SD;
use wichtel_core::draw::sigma;

fn permutations(items: &[usize]) -> Vec<Vec<usize>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut out = Vec::new();
    for (k, &x) in items.iter().enumerate() {
        let mut rest = items.to_vec();
        rest.remove(k);
        for mut p in permutations(&rest) {
            p.insert(0, x);
            out.push(p);
        }
    }
    out
}

#[test]
fn mutual_pair_posterior_is_base_rate() {
    const N: usize = 4;
    const RUNS: u64 = 8;
    for run in 0..RUNS {
        let gid = gid_for(500_000 + run);
        let clients = make_clients(&gid, 500_000 + run, N);
        let roster = roster_of(&gid, &clients);
        let refs: Vec<&Client> = clients.iter().collect();
        let (_, report, _) = run_until_done(&gid, 1, &roster, &refs, 20);
        let assignment = check_done(&refs, &report);
        let RoundReport::Done { public, own, .. } = report else {
            unreachable!()
        };

        // A = person 0 (roster/client index), B = its recipient.
        let a = 0usize;
        let b = assignment[a];
        let own_a = own[a].as_ref().unwrap();
        let t_star = usize::from(public.t_star);
        let sig: Vec<Vec<usize>> = (1..=16u8)
            .map(|t| {
                sigma(&public.outcome.rho, t, N)
                    .into_iter()
                    .map(usize::from)
                    .collect()
            })
            .collect();
        let e_a = own_a.e;
        let g_a_star = own_a.p[t_star - 1].unwrap();
        let e_b = sig[t_star - 1][g_a_star];
        assert_ne!(e_a, e_b);

        let others: Vec<usize> = (0..N).filter(|&p| p != a && p != b).collect();
        let free_e: Vec<usize> = (0..N).filter(|&e| e != e_a && e != e_b).collect();
        let persons_but_a: Vec<usize> = (0..N).filter(|&p| p != a).collect();

        let mut num = 0f64;
        let mut den = 0f64;
        for perm_e in permutations(&free_e) {
            // r: person → E-position.
            let mut r = [usize::MAX; N];
            r[a] = e_a;
            r[b] = e_b;
            for (&p, &e) in others.iter().zip(&perm_e) {
                r[p] = e;
            }
            let mut lik = 1f64;
            let mut tot = 0f64;
            let mut mutual = 0f64;
            for ti in 0..16 {
                let Some(g_a) = own_a.p[ti] else {
                    continue; // invalid attempt: no information
                };
                let observed_selfdraw = public.sd[SLOT_SD * ti..SLOT_SD * (ti + 1)]
                    .iter()
                    .any(|&x| x != 0);
                let free_g: Vec<usize> = (0..N).filter(|&g| g != g_a).collect();
                let mut cnt = 0f64;
                let mut all = 0f64;
                for perm_g in permutations(&free_g) {
                    let mut g = [usize::MAX; N];
                    g[a] = g_a;
                    for (&p, &x) in persons_but_a.iter().zip(&perm_g) {
                        g[p] = x;
                    }
                    let fixed_point = (0..N).any(|i| sig[ti][g[i]] == r[i]);
                    all += 1.0;
                    if ti + 1 == t_star {
                        assert!(!observed_selfdraw);
                        if !fixed_point {
                            tot += 1.0;
                            if sig[ti][g[b]] == r[a] {
                                mutual += 1.0;
                            }
                        }
                    } else if fixed_point == observed_selfdraw {
                        cnt += 1.0;
                    }
                }
                if ti + 1 != t_star {
                    lik *= cnt / all;
                }
            }
            num += lik * mutual;
            den += lik * tot;
        }
        let posterior = num / den;
        assert!(
            (posterior - 1.0 / 3.0).abs() < 1e-12,
            "run {run}: posterior {posterior}"
        );
    }
}
