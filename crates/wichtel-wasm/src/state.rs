//! Opaque `evaluationState` between `evaluateRoles` and step 2 / the result.
//!
//! The UI stores it (IndexedDB) and passes it back unchanged. It contains the public evaluation
//! of `R` plus the own positions, so that `R` itself (up to 2.4 MB) need not be kept. The own
//! positions are not secret beyond what `seed` (also on the device) already implies.
//!
//! Format, version 1 (all integers big-endian):
//!
//! | Bytes | Field |
//! |---|---|
//! | 1 | version = `0x01` |
//! | 1 | `n` |
//! | 32 | `G_r` (binds the state to gid, round and roster) |
//! | 32 | `ρ` |
//! | 32·n | `RP[0…n−1]` |
//! | 2 | `u16` bit mask, bit `t−1` set ⇔ attempt `t` valid |
//! | 1 | own E-position `e` |
//! | per valid attempt t (ascending): 1 + 32·n | `p_{i,t}`, then `GP_t[0…n−1]` |

use wichtel_core::dcnet::{OwnPositions, RolesOutcome};
use wichtel_core::{N_MAX, N_MIN, T_ATTEMPTS};

use crate::error::{INVALID_STATE, Result, WasmError};

const VERSION: u8 = 1;

/// Decoded state.
pub struct EvalState {
    pub g_r: [u8; 32],
    pub outcome: RolesOutcome,
    pub own: OwnPositions,
}

const fn bad(msg: &'static str) -> WasmError {
    WasmError::new(INVALID_STATE, msg)
}

/// Encode. Fails only for inconsistent input (never for an outcome from `evaluate_roles`).
pub fn encode(g_r: &[u8; 32], outcome: &RolesOutcome, own: &OwnPositions) -> Result<Vec<u8>> {
    let n = outcome.n();
    if !(N_MIN..=N_MAX).contains(&n) || own.e >= n {
        return Err(bad("inconsistent evaluation"));
    }
    let mut mask = 0u16;
    let mut out = Vec::with_capacity(2 + 64 + 32 * n + 3 + T_ATTEMPTS * (1 + 32 * n));
    out.push(VERSION);
    out.push(n as u8); // n ≤ N_MAX < 256
    out.extend_from_slice(g_r);
    out.extend_from_slice(&outcome.rho);
    for rp in &outcome.recipients {
        out.extend_from_slice(rp);
    }
    let mask_at = out.len();
    out.extend_from_slice(&[0, 0]);
    out.push(own.e as u8);
    for t in 0..T_ATTEMPTS {
        match (&outcome.givers[t], own.p[t]) {
            (Some(givers), Some(p)) if givers.len() == n && p < n => {
                mask |= 1 << t;
                out.push(p as u8);
                for gp in givers {
                    out.extend_from_slice(gp);
                }
            }
            (None, None) => {}
            _ => return Err(bad("inconsistent evaluation")),
        }
    }
    out[mask_at..mask_at + 2].copy_from_slice(&mask.to_be_bytes());
    Ok(out)
}

/// Small cursor that never panics.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.0.len() < len {
            return Err(bad("truncated"));
        }
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn key(&mut self) -> Result<[u8; 32]> {
        let mut k = [0u8; 32];
        k.copy_from_slice(self.take(32)?);
        Ok(k)
    }

    fn keys(&mut self, n: usize) -> Result<Vec<[u8; 32]>> {
        (0..n).map(|_| self.key()).collect()
    }
}

/// Decode and validate (length, version, ranges).
pub fn decode(bytes: &[u8]) -> Result<EvalState> {
    let mut r = Reader(bytes);
    if r.u8()? != VERSION {
        return Err(bad("unknown version"));
    }
    let n = usize::from(r.u8()?);
    if !(N_MIN..=N_MAX).contains(&n) {
        return Err(bad("participant count out of range"));
    }
    let g_r = r.key()?;
    let rho = r.key()?;
    let recipients = r.keys(n)?;
    let mask = u16::from_be_bytes([r.u8()?, r.u8()?]);
    let e = usize::from(r.u8()?);
    if e >= n {
        return Err(bad("position out of range"));
    }
    let mut givers: [Option<Vec<[u8; 32]>>; T_ATTEMPTS] = Default::default();
    let mut p = [None; T_ATTEMPTS];
    for t in 0..T_ATTEMPTS {
        if mask & (1 << t) == 0 {
            continue;
        }
        let pos = usize::from(r.u8()?);
        if pos >= n {
            return Err(bad("position out of range"));
        }
        p[t] = Some(pos);
        givers[t] = Some(r.keys(n)?);
    }
    if !r.0.is_empty() {
        return Err(bad("trailing bytes"));
    }
    Ok(EvalState {
        g_r,
        outcome: RolesOutcome {
            recipients,
            givers,
            rho,
        },
        own: OwnPositions { e, p },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(n: usize) -> ([u8; 32], RolesOutcome, OwnPositions) {
        let key = |a: usize, b: usize| [(a * 31 + b) as u8; 32];
        let givers =
            core::array::from_fn(|t| (t % 3 != 1).then(|| (0..n).map(|i| key(t + 1, i)).collect()));
        let p = core::array::from_fn(|t| (t % 3 != 1).then_some((t + 1) % n));
        (
            [7u8; 32],
            RolesOutcome {
                recipients: (0..n).map(|i| key(0, i)).collect(),
                givers,
                rho: [9u8; 32],
            },
            OwnPositions { e: n - 1, p },
        )
    }

    #[test]
    fn roundtrip() {
        for n in [N_MIN, 7, N_MAX] {
            let (g_r, outcome, own) = sample(n);
            let bytes = encode(&g_r, &outcome, &own).unwrap();
            let valid = outcome.givers.iter().filter(|g| g.is_some()).count();
            assert_eq!(bytes.len(), 2 + 64 + 32 * n + 3 + valid * (1 + 32 * n));
            let s = decode(&bytes).unwrap();
            assert_eq!(s.g_r, g_r);
            assert_eq!(s.outcome, outcome);
            assert_eq!(s.own, own);
        }
    }

    #[test]
    fn rejects_garbage() {
        let (g_r, outcome, own) = sample(5);
        let bytes = encode(&g_r, &outcome, &own).unwrap();
        for len in 0..bytes.len() {
            assert_eq!(
                decode(&bytes[..len]).err().map(|e| e.code),
                Some(INVALID_STATE)
            );
        }
        let mut long = bytes.clone();
        long.push(0);
        assert!(decode(&long).is_err());
        let mut v = bytes.clone();
        v[0] = 2;
        assert!(decode(&v).is_err());
        let mut v = bytes.clone();
        v[1] = 3;
        assert!(decode(&v).is_err());
        // e ≥ n
        let mut v = bytes.clone();
        v[2 + 64 + 32 * 5 + 2] = 5;
        assert!(decode(&v).is_err());
        // inconsistent input to encode
        let mut bad_own = own.clone();
        bad_own.p[1] = Some(0);
        assert!(encode(&g_r, &outcome, &bad_own).is_err());
    }
}
