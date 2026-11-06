//! Step 1: role vector (DC-net) and evaluation of the aggregate `R` (Spec §7).

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::draw::UniformSampler;
use crate::keys::{ParticipantKeys, pid_from_ipk};
use crate::roster::{Roster, group_context};
use crate::util::{hkdf_expand, hkdf32, sha256, x25519_base, x25519_checked, xor_keystream};
use crate::{
    Error, GroupId, N_MAX, N_MIN, Result, SLOT_E, SLOT_S, SLOT_SD, T_ATTEMPTS, m_e, m_s,
    roles_vector_len,
};

/// Per-round secrets of the local participant (Spec §4, round-specific part).
/// Zeroized on drop (including the slot indices, which reveal the own roles).
pub struct RoundSecrets {
    /// `rp_r` (derived bytes, clamped on use).
    pub(crate) rp: Zeroizing<[u8; 32]>,
    /// `RP_r`.
    pub(crate) rp_pub: [u8; 32],
    /// `gp_{r,t}` at index `t−1`.
    pub(crate) gp: Zeroizing<[[u8; 32]; T_ATTEMPTS]>,
    /// `GP_{r,t}` at index `t−1`.
    pub(crate) gp_pub: [[u8; 32]; T_ATTEMPTS],
    /// Slot `s_E` in area E.
    pub(crate) s_e: usize,
    /// Slot `s_t` in area S_t (index `t−1`).
    pub(crate) s_t: [usize; T_ATTEMPTS],
    /// `sd_{r,t}` at index `t−1`.
    pub(crate) sd: Zeroizing<[[u8; SLOT_SD]; T_ATTEMPTS]>,
    /// `rngkey_r`.
    pub(crate) rng_key: Zeroizing<[u8; 32]>,
}

impl RoundSecrets {
    /// Derive from long-term keys and `G_r`; draws the slots via [`crate::draw::UniformSampler`].
    pub fn derive(keys: &ParticipantKeys, g_r: &[u8; 32], n: usize) -> Result<Self> {
        check_n(n)?;
        let prk = keys.prk();

        let mut rp = Zeroizing::new([0u8; 32]);
        hkdf_expand(prk, &[b"wichtel/v1/recv", g_r], rp.as_mut());
        let rp_pub = x25519_base(&rp);

        let mut gp = Zeroizing::new([[0u8; 32]; T_ATTEMPTS]);
        let mut gp_pub = [[0u8; 32]; T_ATTEMPTS];
        let mut sd = Zeroizing::new([[0u8; SLOT_SD]; T_ATTEMPTS]);
        for i in 0..T_ATTEMPTS {
            let t = [i as u8 + 1];
            hkdf_expand(prk, &[b"wichtel/v1/give", g_r, &t], &mut gp[i]);
            gp_pub[i] = x25519_base(&gp[i]);
            hkdf_expand(prk, &[b"wichtel/v1/selfdraw", g_r, &t], &mut sd[i]);
        }

        let mut slot_key = Zeroizing::new([0u8; 32]);
        hkdf_expand(prk, &[b"wichtel/v1/slot", g_r], slot_key.as_mut());
        let mut rng_key = Zeroizing::new([0u8; 32]);
        hkdf_expand(prk, &[b"wichtel/v1/reveal-rng", g_r], rng_key.as_mut());

        // n ≤ N_MAX ⇒ m_E, m_S < 2^32.
        let mut u = UniformSampler::new(&slot_key, &[0u8; 12]);
        let s_e = u.uniform(m_e(n) as u32) as usize;
        let mut s_t = [0usize; T_ATTEMPTS];
        for s in &mut s_t {
            *s = u.uniform(m_s(n) as u32) as usize;
        }

        Ok(Self {
            rp,
            rp_pub,
            gp,
            gp_pub,
            s_e,
            s_t,
            sd,
            rng_key,
        })
    }

    /// E-slot content `RP_r ‖ H("wichtel/v1/slot-check" ‖ G_r ‖ RP_r)[0..8]`.
    fn e_slot(&self, g_r: &[u8; 32]) -> [u8; SLOT_E] {
        let mut out = [0u8; SLOT_E];
        out[..32].copy_from_slice(&self.rp_pub);
        out[32..].copy_from_slice(&slot_check(g_r, &self.rp_pub));
        out
    }
}

impl Drop for RoundSecrets {
    fn drop(&mut self) {
        self.s_e.zeroize();
        self.s_t.zeroize();
        self.rp_pub.zeroize();
        self.gp_pub.zeroize();
    }
}

fn check_n(n: usize) -> Result<()> {
    if (N_MIN..=N_MAX).contains(&n) {
        Ok(())
    } else {
        Err(Error::InvalidParticipantCount)
    }
}

fn slot_check(g_r: &[u8; 32], rp: &[u8; 32]) -> [u8; 8] {
    let h = sha256(&[b"wichtel/v1/slot-check", g_r, rp]);
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
}

/// Everything a client needs for one round: `G_r`, own roster index and round secrets.
pub(crate) struct RoundCtx {
    pub(crate) g_r: [u8; 32],
    pub(crate) own_index: usize,
    pub(crate) secrets: RoundSecrets,
}

/// Validate the roster from the client's point of view and derive the round context.
///
/// Checks: `N_MIN ≤ n ≤ N_MAX`; `gid` matches the keys; every `pid` is derived from its `IPK`
/// (`InvalidKey` otherwise, the server cannot swap ids); the own entry is present with the own
/// keys (`NotInRoster` otherwise).
pub(crate) fn round_ctx(
    keys: &ParticipantKeys,
    gid: &GroupId,
    round: u32,
    roster: &Roster,
) -> Result<RoundCtx> {
    let n = roster.len();
    check_n(n)?;
    if gid != keys.gid() {
        return Err(Error::NotInRoster);
    }
    for e in roster.entries() {
        if e.pid != pid_from_ipk(gid, &e.ipk) {
            return Err(Error::InvalidKey);
        }
    }
    let me = keys.public();
    let own_index = roster.index_of(&me.pid).ok_or(Error::NotInRoster)?;
    let own = &roster.entries()[own_index];
    if own.ipk != me.ipk || own.idh != me.idh {
        return Err(Error::NotInRoster);
    }
    let g_r = group_context(gid, round, roster);
    let secrets = RoundSecrets::derive(keys, &g_r, n)?;
    Ok(RoundCtx {
        g_r,
        own_index,
        secrets,
    })
}

/// XOR all pair masks `ChaCha20(k_ij, Z(12))` with `label` into `buf` (Spec §7.1).
pub(crate) fn apply_pair_masks(
    keys: &ParticipantKeys,
    roster: &Roster,
    own_index: usize,
    g_r: &[u8; 32],
    label: &[&[u8]],
    buf: &mut [u8],
) -> Result<()> {
    let own_idh = keys.public().idh;
    for (j, other) in roster.entries().iter().enumerate() {
        if j == own_index {
            continue;
        }
        let dh = x25519_checked(keys.idh_secret(), &other.idh)?;
        let (lo, hi) = if own_idh <= other.idh {
            (&own_idh, &other.idh)
        } else {
            (&other.idh, &own_idh)
        };
        // info = label parts ‖ lo ‖ hi.
        let mut info: Vec<&[u8]> = label.to_vec();
        info.push(lo);
        info.push(hi);
        let k = hkdf32(g_r, dh.as_ref(), &info);
        xor_keystream(&k, &[0u8; 12], buf);
    }
    Ok(())
}

/// Build the masked role vector `V_i` (length `roles_vector_len(n)`).
pub fn build_roles_vector(
    keys: &ParticipantKeys,
    gid: &GroupId,
    round: u32,
    roster: &Roster,
) -> Result<Vec<u8>> {
    let ctx = round_ctx(keys, gid, round, roster)?;
    let n = roster.len();
    let s = &ctx.secrets;
    let mut v = vec![0u8; roles_vector_len(n)];

    let e_off = SLOT_E * s.s_e;
    v[e_off..e_off + SLOT_E].copy_from_slice(&s.e_slot(&ctx.g_r));
    for t in 0..T_ATTEMPTS {
        let off = s_area_offset(n, t) + SLOT_S * s.s_t[t];
        v[off..off + SLOT_S].copy_from_slice(&s.gp_pub[t]);
    }

    apply_pair_masks(
        keys,
        roster,
        ctx.own_index,
        &ctx.g_r,
        &[b"wichtel/v1/dc-roles"],
        &mut v,
    )?;
    Ok(v)
}

/// Byte offset of area S_t (index `t−1`) in the role vector.
fn s_area_offset(n: usize, t_index: usize) -> usize {
    SLOT_E * m_e(n) + t_index * SLOT_S * m_s(n)
}

/// XOR `src` into `acc` (server aggregation). Both must have equal length.
pub fn xor_into(acc: &mut [u8], src: &[u8]) -> Result<()> {
    if acc.len() != src.len() {
        return Err(Error::InvalidLength);
    }
    for (a, s) in acc.iter_mut().zip(src) {
        *a ^= s;
    }
    Ok(())
}

/// Public evaluation of `R` – identical on server and client (Spec §7.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RolesOutcome {
    /// `RP[e]` for E-positions `0…n−1`.
    pub recipients: Vec<[u8; 32]>,
    /// For each attempt t = 1…16 (index t−1): `Some(GP_t[p])` for p = 0…n−1 if valid.
    pub givers: [Option<Vec<[u8; 32]>>; T_ATTEMPTS],
    /// `ρ` (Spec §8).
    pub rho: [u8; 32],
}

impl RolesOutcome {
    /// Number of participants.
    pub fn n(&self) -> usize {
        self.recipients.len()
    }

    /// Whether attempt `t ∈ 1…16` is valid.
    pub fn attempt_valid(&self, t: u8) -> bool {
        matches!(
            usize::from(t)
                .checked_sub(1)
                .and_then(|i| self.givers.get(i)),
            Some(Some(_))
        )
    }
}

fn is_zero(b: &[u8]) -> bool {
    b.iter().all(|&x| x == 0)
}

/// Indices of the non-zero slots of `area` (slot size `size`), or `None` if there are not
/// exactly `n` of them.
fn occupied_slots(area: &[u8], size: usize, n: usize) -> Option<Vec<usize>> {
    let mut out = Vec::with_capacity(n);
    for (i, slot) in area.chunks_exact(size).enumerate() {
        if !is_zero(slot) {
            if out.len() == n {
                return None;
            }
            out.push(i);
        }
    }
    (out.len() == n).then_some(out)
}

fn key32(b: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(&b[..32]);
    k
}

/// Evaluate `R`. Returns `Err(Error::Collision)` if area E is invalid.
pub fn evaluate_roles(g_r: &[u8; 32], n: usize, r: &[u8]) -> Result<RolesOutcome> {
    check_n(n)?;
    if r.len() != roles_vector_len(n) {
        return Err(Error::InvalidLength);
    }
    let e_area = &r[..SLOT_E * m_e(n)];
    let e_slots = occupied_slots(e_area, SLOT_E, n).ok_or(Error::Collision)?;
    let mut recipients = Vec::with_capacity(n);
    for &i in &e_slots {
        let slot = &e_area[SLOT_E * i..SLOT_E * (i + 1)];
        let rp = key32(slot);
        if slot_check(g_r, &rp) != slot[32..] {
            return Err(Error::Collision);
        }
        recipients.push(rp);
    }

    let givers = core::array::from_fn(|t| {
        let off = s_area_offset(n, t);
        let area = &r[off..off + SLOT_S * m_s(n)];
        occupied_slots(area, SLOT_S, n)
            .map(|slots| slots.iter().map(|&i| key32(&area[SLOT_S * i..])).collect())
    });

    Ok(RolesOutcome {
        recipients,
        givers,
        rho: crate::draw::rho(g_r, r),
    })
}

/// Positions of the local participant in an outcome. Secret (they link the own roles):
/// zeroized on drop, `Debug` is redacted.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct OwnPositions {
    /// E-position `e_i`.
    pub e: usize,
    /// `p_{i,t}` for valid attempts (index t−1), `None` for invalid ones.
    pub p: [Option<usize>; T_ATTEMPTS],
}

impl core::fmt::Debug for OwnPositions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OwnPositions { <redacted> }")
    }
}

/// Position of `own_slot` among the occupied slots of `area` and whether that slot holds
/// exactly `expected`. Scans the whole area without early exit.
fn own_position(area: &[u8], size: usize, own_slot: usize, expected: &[u8]) -> (usize, bool) {
    let mut before = 0usize;
    let mut found = false;
    for (i, slot) in area.chunks_exact(size).enumerate() {
        if i == own_slot {
            found = bool::from(slot.ct_eq(expected));
        } else if i < own_slot && !is_zero(slot) {
            before += 1;
        }
    }
    (before, found)
}

/// Client check: own `RP`/`GP` present at own slots (else `Err(OwnRoleMissing)`).
pub fn own_positions(
    keys: &ParticipantKeys,
    gid: &GroupId,
    round: u32,
    roster: &Roster,
    r: &[u8],
    outcome: &RolesOutcome,
) -> Result<OwnPositions> {
    let ctx = round_ctx(keys, gid, round, roster)?;
    let n = roster.len();
    if r.len() != roles_vector_len(n) || outcome.n() != n {
        return Err(Error::InvalidLength);
    }
    let s = &ctx.secrets;

    let e_area = &r[..SLOT_E * m_e(n)];
    let (e, ok) = own_position(e_area, SLOT_E, s.s_e, &s.e_slot(&ctx.g_r));
    if !ok || e >= n || !bool::from(outcome.recipients[e].ct_eq(&s.rp_pub)) {
        return Err(Error::OwnRoleMissing);
    }

    let mut p = [None; T_ATTEMPTS];
    for (t, slot) in p.iter_mut().enumerate() {
        let Some(givers) = &outcome.givers[t] else {
            continue;
        };
        if givers.len() != n {
            return Err(Error::InvalidLength);
        }
        let off = s_area_offset(n, t);
        let area = &r[off..off + SLOT_S * m_s(n)];
        let (pos, ok) = own_position(area, SLOT_S, s.s_t[t], &s.gp_pub[t]);
        if !ok || pos >= n || !bool::from(givers[pos].ct_eq(&s.gp_pub[t])) {
            return Err(Error::OwnRoleMissing);
        }
        *slot = Some(pos);
    }
    Ok(OwnPositions { e, p })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roster::RosterEntry;

    pub(crate) fn setup(n: usize, gid: &GroupId) -> (Vec<ParticipantKeys>, Roster) {
        let keys: Vec<_> = (0..n)
            .map(|i| ParticipantKeys::derive(&[i as u8 + 1; 32], gid).unwrap())
            .collect();
        let entries = keys
            .iter()
            .map(|k| {
                let p = k.public();
                RosterEntry::new(p.pid, p.ipk, p.idh, b"name")
            })
            .collect();
        (keys, Roster::new(entries).unwrap())
    }

    #[test]
    fn xor_into_checks_length() {
        let mut a = [1u8, 2, 3];
        assert_eq!(xor_into(&mut a, &[1, 1, 1]), Ok(()));
        assert_eq!(a, [0, 3, 2]);
        assert_eq!(xor_into(&mut a, &[1, 1]), Err(Error::InvalidLength));
    }

    #[test]
    fn masks_cancel_and_roles_appear() {
        let gid = GroupId([3; 16]);
        let (keys, roster) = setup(4, &gid);
        // Find a round without collision (deterministic for the fixed seeds).
        for round in 1..20 {
            let g_r = group_context(&gid, round, &roster);
            let mut agg = vec![0u8; roles_vector_len(4)];
            for k in &keys {
                let v = build_roles_vector(k, &gid, round, &roster).unwrap();
                xor_into(&mut agg, &v).unwrap();
            }
            let Ok(out) = evaluate_roles(&g_r, 4, &agg) else {
                continue;
            };
            let mut es = Vec::new();
            for k in &keys {
                let own = own_positions(k, &gid, round, &roster, &agg, &out).unwrap();
                es.push(own.e);
            }
            es.sort();
            assert_eq!(es, vec![0, 1, 2, 3]);
            return;
        }
        panic!("no collision-free round");
    }

    #[test]
    fn evaluate_rejects_bad_input() {
        let g = [0u8; 32];
        assert_eq!(evaluate_roles(&g, 4, &[0u8; 10]), Err(Error::InvalidLength));
        assert_eq!(
            evaluate_roles(&g, 3, &[0u8; 10]),
            Err(Error::InvalidParticipantCount)
        );
        assert_eq!(
            evaluate_roles(&g, 4, &vec![0u8; roles_vector_len(4)]),
            Err(Error::Collision)
        );
        // n occupied slots with wrong check bytes ⇒ collision.
        let mut r = vec![0u8; roles_vector_len(4)];
        for i in 0..4 {
            r[SLOT_E * i * 3] = 1;
        }
        assert_eq!(evaluate_roles(&g, 4, &r), Err(Error::Collision));
    }

    #[test]
    fn roster_checks() {
        let gid = GroupId([3; 16]);
        let (keys, roster) = setup(4, &gid);
        let (other, _) = setup(5, &gid);
        assert_eq!(
            build_roles_vector(&other[4], &gid, 1, &roster).err(),
            Some(Error::NotInRoster)
        );
        assert_eq!(
            build_roles_vector(&keys[0], &GroupId([4; 16]), 1, &roster).err(),
            Some(Error::NotInRoster)
        );
        // Server swaps a pid ⇒ rejected.
        let mut entries = roster.entries().to_vec();
        entries[1].pid.0[0] ^= 1;
        let bad = Roster::new(entries).unwrap();
        assert_eq!(
            build_roles_vector(&keys[0], &gid, 1, &bad).err(),
            Some(Error::InvalidKey)
        );
        let (k3, r3) = setup(3, &gid);
        assert_eq!(
            build_roles_vector(&k3[0], &gid, 1, &r3).err(),
            Some(Error::InvalidParticipantCount)
        );
    }
}
