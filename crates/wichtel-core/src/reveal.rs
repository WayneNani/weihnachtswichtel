//! Step 2: self-draw vector, reveals, `t*`, result (Spec §9).

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use rand_core::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::dcnet::{OwnPositions, RolesOutcome, RoundCtx, apply_pair_masks, round_ctx};
use crate::draw::{invert, is_permutation, sigma};
use crate::keys::{ParticipantKeys, ct_eq};
use crate::roster::Roster;
use crate::util::{
    KeystreamRng, OnceRng, SecretVec, hkdf_expand, hkdf32, hmac, sha256, x25519_checked,
};
use crate::{
    Error, GroupId, L_CT, L_PT, L_REVEAL_UPLOAD, L_SD, NOTE_MAX, Pid, Result, SLOT_SD, T_ATTEMPTS,
};

pub(crate) type Kem = X25519HkdfSha256;
/// HPKE private key of [`Kem`].
pub(crate) type HpkeSk = <Kem as KemTrait>::PrivateKey;

/// Offsets in the reveal plaintext (Spec §9.2).
const PT_VERSION: u8 = 0x01;
const OFF_PID: usize = 1;
const OFF_MAC: usize = 17;
const OFF_LEN: usize = 49;
const OFF_NOTE: usize = 51;
/// HPKE `enc` length.
pub(crate) const L_ENC: usize = 32;

/// HPKE `info = label ‖ G_r ‖ ρ ‖ u8(t)` (label `"wichtel/v1/reveal"`, Spec §9.2, or
/// `"wichtel/v1/contact"`, Spec §16.2).
pub(crate) fn hpke_info(label: &[u8], g_r: &[u8; 32], rho: &[u8; 32], t: u8) -> Vec<u8> {
    let mut info = Vec::with_capacity(label.len() + 32 + 32 + 1);
    info.extend_from_slice(label);
    info.extend_from_slice(g_r);
    info.extend_from_slice(rho);
    info.push(t);
    info
}

/// HPKE label of the reveals (Spec §9.2).
const INFO_REVEAL: &[u8] = b"wichtel/v1/reveal";

/// HPKE single-shot seal in Mode Auth (suite of Spec §9.2) with the ephemeral key pair
/// `DeriveKeyPair(eph_ikm)`. Returns `enc ‖ ct`.
pub(crate) fn seal_auth(
    sk_s: &HpkeSk,
    pk_r: &[u8; 32],
    info: &[u8],
    pt: &[u8],
    eph_ikm: &[u8; 32],
) -> Result<Vec<u8>> {
    let pk_r_hpke =
        <Kem as KemTrait>::PublicKey::from_bytes(pk_r).map_err(|_| Error::InvalidKey)?;
    let mut eph_rng = OnceRng::new(eph_ikm);
    let (enc, ct) = hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeS::Auth((sk_s.clone(), Kem::sk_to_pk(sk_s))),
        &pk_r_hpke,
        info,
        pt,
        b"",
        &mut eph_rng,
    )
    .map_err(|_| Error::InvalidKey)?;
    if !eph_rng.consumed_exactly() {
        return Err(Error::Rng);
    }
    let mut out = Vec::with_capacity(L_ENC + ct.len());
    out.extend_from_slice(&enc.to_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// HPKE single-shot open in Mode Auth (suite of Spec §9.2) of `c = enc ‖ ct`; `None` on any
/// failure (wrong sender/recipient/info, tampering, malformed input).
pub(crate) fn open_auth(
    sk_r: &HpkeSk,
    pk_s: &[u8; 32],
    info: &[u8],
    c: &[u8],
) -> Option<SecretVec> {
    if c.len() < L_ENC {
        return None;
    }
    let pk_s = <Kem as KemTrait>::PublicKey::from_bytes(pk_s).ok()?;
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(&c[..L_ENC]).ok()?;
    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeR::Auth(pk_s),
        sk_r,
        &enc,
        info,
        &c[L_ENC..],
        b"",
    )
    .ok()
    .map(SecretVec)
}

/// X25519 private key for HPKE from the derived 32 bytes (clamped on use).
pub(crate) fn hpke_sk(sk: &[u8; 32]) -> Result<HpkeSk> {
    <Kem as KemTrait>::PrivateKey::from_bytes(sk).map_err(|_| Error::InvalidKey)
}

/// Claim MAC (Spec §9.2): `dh` is `X25519(rp_r, pkR)` (sender) or `X25519(gp, RP)` (receiver).
/// `mac = HMAC(mac_key, "wichtel/v1/claim" ‖ G_r ‖ ρ ‖ u8(t) ‖ pid ‖ RP ‖ pkR)`.
fn claim_mac(
    g_r: &[u8; 32],
    rho: &[u8; 32],
    t: u8,
    dh: &[u8; 32],
    pid: &Pid,
    rp: &[u8; 32],
    pk_r: &[u8; 32],
) -> [u8; 32] {
    let mac_key = hkdf32(g_r, dh, &[b"wichtel/v1/claim-mac", &[t]]);
    hmac(
        &mac_key,
        &[b"wichtel/v1/claim", g_r, rho, &[t], &pid.0, rp, pk_r],
    )
}

/// Reveal plaintext (Spec §9.2 table). Notes longer than `NOTE_MAX` are cut (callers check).
fn plaintext(version: u8, pid: &Pid, mac: &[u8; 32], note: &[u8]) -> Zeroizing<[u8; L_PT]> {
    let mut pt = Zeroizing::new([0u8; L_PT]);
    pt[0] = version;
    pt[OFF_PID..OFF_MAC].copy_from_slice(&pid.0);
    pt[OFF_MAC..OFF_LEN].copy_from_slice(mac);
    let len = note.len().min(NOTE_MAX);
    // len ≤ NOTE_MAX < 2^16.
    pt[OFF_LEN..OFF_NOTE].copy_from_slice(&(len as u16).to_be_bytes());
    pt[OFF_NOTE..OFF_NOTE + len].copy_from_slice(&note[..len]);
    pt
}

/// HPKE Auth seal of one reveal with the deterministic ephemeral (Spec §9.2):
/// `eph_ikm = Expand(rngkey_r, "wichtel/v1/reveal-eph" ‖ u8(t) ‖ ρ ‖ pkR ‖ H(pt), 32)`,
/// ephemeral key pair = `DeriveKeyPair(eph_ikm)` (RFC 9180 §7.1.3). Because the ephemeral
/// depends on the plaintext, different notes never reuse an AEAD key/nonce.
#[allow(clippy::too_many_arguments)]
fn seal_reveal(
    sk_s: &HpkeSk,
    rng_key: &[u8; 32],
    g_r: &[u8; 32],
    rho: &[u8; 32],
    t: u8,
    pk_r: &[u8; 32],
    pt: &[u8; L_PT],
) -> Result<[u8; L_CT]> {
    let mut eph_ikm = Zeroizing::new([0u8; 32]);
    hkdf_expand(
        rng_key,
        &[b"wichtel/v1/reveal-eph", &[t], rho, pk_r, &sha256(&[pt])],
        eph_ikm.as_mut(),
    );
    let c = seal_auth(
        sk_s,
        pk_r,
        &hpke_info(INFO_REVEAL, g_r, rho, t),
        pt,
        &eph_ikm,
    )?;
    c.try_into().map_err(|_| Error::InvalidLength)
}

/// Build the step-2 upload body `SD_i ‖ C_{i,1} ‖ … ‖ C_{i,16}` (length `L_REVEAL_UPLOAD`).
/// `note` is the optional private note for the giver (≤ `NOTE_MAX` bytes UTF-8).
///
/// Deterministic: the same inputs (including `note`) always give the same upload.
#[allow(clippy::too_many_arguments)]
pub fn build_reveal_upload(
    keys: &ParticipantKeys,
    gid: &GroupId,
    round: u32,
    roster: &Roster,
    outcome: &RolesOutcome,
    own: &OwnPositions,
    note: &str,
) -> Result<Vec<u8>> {
    let note = note.as_bytes();
    if note.len() > NOTE_MAX {
        return Err(Error::InvalidLength);
    }
    let ctx = round_ctx(keys, gid, round, roster)?;
    let n = roster.len();
    check_outcome(outcome, own, n)?;
    let s = &ctx.secrets;
    let rho = &outcome.rho;
    let pid = keys.public().pid;

    let mut body = Vec::with_capacity(L_REVEAL_UPLOAD);

    // §9.1 self-draw vector (masks bound to ρ).
    let mut d = Zeroizing::new([0u8; L_SD]);
    let sigmas: Vec<Option<Vec<u16>>> = (0..T_ATTEMPTS)
        .map(|i| {
            outcome.givers[i]
                .as_ref()
                .map(|_| sigma(rho, i as u8 + 1, n))
        })
        .collect();
    for (i, sig) in sigmas.iter().enumerate() {
        if let (Some(sig), Some(p)) = (sig, own.p[i])
            && usize::from(sig[p]) == own.e
        {
            d[SLOT_SD * i..SLOT_SD * (i + 1)].copy_from_slice(&s.sd[i]);
        }
    }
    apply_pair_masks(
        keys,
        roster,
        ctx.own_index,
        &ctx.g_r,
        &[b"wichtel/v1/dc-selfdraw", rho],
        d.as_mut(),
    )?;
    body.extend_from_slice(d.as_ref());

    // §9.2 reveals. Placeholders (invalid attempt or failed sealing) come from the stream
    // ChaCha20(padkey, Z(12)) with padkey = Expand(rngkey_r, "wichtel/v1/reveal-pad" ‖ ρ, 32),
    // 560 bytes per placeholder in the order t = 1…16; nothing else consumes this stream.
    let sk_s = hpke_sk(keys.idh_secret())?;
    let mut pad_key = Zeroizing::new([0u8; 32]);
    hkdf_expand(
        &s.rng_key,
        &[b"wichtel/v1/reveal-pad", rho],
        pad_key.as_mut(),
    );
    let mut pad = KeystreamRng::new(&pad_key);
    for (i, (sig, givers)) in sigmas.iter().zip(&outcome.givers).enumerate() {
        let t = i as u8 + 1;
        let sealed = match (sig, givers) {
            (Some(sig), Some(givers)) => {
                let pk_r = givers[usize::from(invert(sig)[own.e])];
                x25519_checked(&s.rp, &pk_r).and_then(|dh| {
                    let mac = claim_mac(&ctx.g_r, rho, t, &dh, &pid, &s.rp_pub, &pk_r);
                    let pt = plaintext(PT_VERSION, &pid, &mac, note);
                    seal_reveal(&sk_s, &s.rng_key, &ctx.g_r, rho, t, &pk_r, &pt)
                })
            }
            _ => Err(Error::NoValidAttempt),
        };
        match sealed {
            Ok(c) => body.extend_from_slice(&c),
            Err(_) => {
                let start = body.len();
                body.resize(start + L_CT, 0);
                pad.fill_bytes(&mut body[start..]);
            }
        }
    }
    debug_assert_eq!(body.len(), L_REVEAL_UPLOAD);
    Ok(body)
}

/// Consistency of an outcome with the own positions and `n` (no panics on foreign data).
fn check_outcome(outcome: &RolesOutcome, own: &OwnPositions, n: usize) -> Result<()> {
    if outcome.n() != n || own.e >= n {
        return Err(Error::InvalidLength);
    }
    for i in 0..T_ATTEMPTS {
        match (&outcome.givers[i], own.p[i]) {
            (Some(g), Some(p)) if g.len() == n && p < n => {}
            (None, None) => {}
            _ => return Err(Error::OwnRoleMissing),
        }
    }
    Ok(())
}

/// Server side: split an upload body into `(SD_i, [C_{i,t}; 16])`.
pub fn split_reveal_upload(body: &[u8]) -> Result<(&[u8], Vec<&[u8]>)> {
    if body.len() != L_REVEAL_UPLOAD {
        return Err(Error::InvalidLength);
    }
    let (sd, rest) = body.split_at(L_SD);
    Ok((sd, rest.chunks_exact(L_CT).collect()))
}

/// `t*`: smallest valid attempt whose self-draw slot is zero; `None` ⇒ next round (Spec §9.1).
/// A self-draw aggregate of the wrong length yields `None`.
pub fn select_attempt(outcome: &RolesOutcome, selfdraw_aggregate: &[u8]) -> Option<u8> {
    if selfdraw_aggregate.len() != L_SD {
        return None;
    }
    (0..T_ATTEMPTS)
        .find(|&i| {
            outcome.givers[i].is_some()
                && selfdraw_aggregate[SLOT_SD * i..SLOT_SD * (i + 1)]
                    .iter()
                    .all(|&b| b == 0)
        })
        .map(|i| i as u8 + 1)
}

/// Final result of the local participant. Zeroized on drop; `Debug` is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct DrawResult {
    pub recipient: Pid,
    pub note: String,
}

impl core::fmt::Debug for DrawResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DrawResult { <redacted> }")
    }
}

impl Zeroize for DrawResult {
    fn zeroize(&mut self) {
        self.recipient.0.zeroize();
        self.note.zeroize();
    }
}

impl Drop for DrawResult {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DrawResult {}

/// The own view of the chosen attempt `t*` (checks shared by Spec §9.3 and §16.2).
pub(crate) struct Attempt {
    pub(crate) ctx: RoundCtx,
    /// `t* − 1`.
    pub(crate) index: usize,
    /// `σ_{t*}` (checked to be a permutation of `0…n−1`).
    pub(crate) sigma: Vec<u16>,
    /// Own E-position `e` of the recipient, `σ_{t*}(p_{i,t*})` (never the own `e_i`).
    pub(crate) recipient: usize,
}

/// Validate `outcome`/`own` against the roster and resolve attempt `t*`.
///
/// `Err(AttemptMismatch)` if `t*` is not a valid attempt or if the own giver role would draw
/// itself in `t*` (impossible for an honest server, since that attempt has a non-zero self-draw
/// slot).
pub(crate) fn resolve_attempt(
    keys: &ParticipantKeys,
    gid: &GroupId,
    round: u32,
    roster: &Roster,
    outcome: &RolesOutcome,
    own: &OwnPositions,
    t_star: u8,
) -> Result<Attempt> {
    let ctx = round_ctx(keys, gid, round, roster)?;
    let n = roster.len();
    check_outcome(outcome, own, n)?;
    if !(1..=T_ATTEMPTS as u8).contains(&t_star) {
        return Err(Error::AttemptMismatch);
    }
    let index = usize::from(t_star - 1);
    let (Some(_), Some(p)) = (&outcome.givers[index], own.p[index]) else {
        return Err(Error::AttemptMismatch);
    };
    let sig = sigma(&outcome.rho, t_star, n);
    if !is_permutation(&sig) {
        return Err(Error::AttemptMismatch);
    }
    let recipient = usize::from(sig[p]);
    if recipient == own.e {
        return Err(Error::AttemptMismatch);
    }
    Ok(Attempt {
        ctx,
        index,
        sigma: sig,
        recipient,
    })
}

/// Open the released reveals of attempt `t*` (Spec §9.3). `reveals` = `(uploader pid, C_{j,t*})`.
/// Requires exactly one valid reveal (else `Err(RevealCount)`).
///
/// The caller MUST compare the server's `t*` with [`select_attempt`] on the published `SD`
/// beforehand (Spec §9.1). Additionally this function returns `Err(AttemptMismatch)` if `t*` is
/// not a valid attempt or if the own giver role would draw itself in `t*` (impossible for an
/// honest server, since that attempt has a non-zero self-draw slot).
#[allow(clippy::too_many_arguments)]
pub fn open_result(
    keys: &ParticipantKeys,
    gid: &GroupId,
    round: u32,
    roster: &Roster,
    outcome: &RolesOutcome,
    own: &OwnPositions,
    t_star: u8,
    reveals: &[(Pid, Vec<u8>)],
) -> Result<DrawResult> {
    let a = resolve_attempt(keys, gid, round, roster, outcome, own, t_star)?;
    let (ctx, i, e) = (&a.ctx, a.index, a.recipient);
    let s = &ctx.secrets;
    let rp_e = outcome.recipients[e];
    let gp_pub = s.gp_pub[i];
    let dh = x25519_checked(&s.gp[i], &rp_e)?;
    let sk_r = hpke_sk(&s.gp[i])?;
    let rho = &outcome.rho;
    let info = hpke_info(INFO_REVEAL, &ctx.g_r, rho, t_star);

    let mut found: Option<DrawResult> = None;
    let mut valid = 0usize;
    // Try every reveal (no early exit, uniform access pattern).
    for (pid_j, c) in reveals {
        let Some(res) = try_open(
            &ctx.g_r, rho, t_star, &dh, &rp_e, &gp_pub, &sk_r, &info, roster, pid_j, c,
        ) else {
            continue;
        };
        valid += 1;
        found = Some(res);
    }
    match (valid, found) {
        (1, Some(res)) => Ok(res),
        _ => Err(Error::RevealCount),
    }
}

/// Open and check one reveal; `None` if anything is wrong.
#[allow(clippy::too_many_arguments)]
fn try_open(
    g_r: &[u8; 32],
    rho: &[u8; 32],
    t: u8,
    dh: &[u8; 32],
    rp_e: &[u8; 32],
    gp_pub: &[u8; 32],
    sk_r: &HpkeSk,
    info: &[u8],
    roster: &Roster,
    pid_j: &Pid,
    c: &[u8],
) -> Option<DrawResult> {
    if c.len() != L_CT {
        return None;
    }
    let sender = &roster.entries()[roster.index_of(pid_j)?];
    let pt = open_auth(sk_r, &sender.idh, info, c)?;
    if pt.len() != L_PT || pt[0] != PT_VERSION || pt[OFF_PID..OFF_MAC] != pid_j.0 {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([pt[OFF_LEN], pt[OFF_LEN + 1]]));
    if len > NOTE_MAX || pt[OFF_NOTE + len..].iter().any(|&b| b != 0) {
        return None;
    }
    let mac = claim_mac(g_r, rho, t, dh, pid_j, rp_e, gp_pub);
    if !ct_eq(&mac, &pt[OFF_MAC..OFF_LEN]) {
        return None;
    }
    let note = core::str::from_utf8(&pt[OFF_NOTE..OFF_NOTE + len]).ok()?;
    Some(DrawResult {
        recipient: *pid_j,
        note: note.to_owned(),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::dcnet::{build_roles_vector, evaluate_roles, own_positions, xor_into};
    use crate::roles_vector_len;
    use crate::roster::{RosterEntry, group_context};

    /// A finished 4-person round (step 1 and step 2 uploads), searched deterministically.
    pub(crate) struct Fixture {
        pub(crate) gid: GroupId,
        pub(crate) round: u32,
        pub(crate) keys: Vec<ParticipantKeys>,
        pub(crate) roster: Roster,
        pub(crate) outcome: RolesOutcome,
        pub(crate) own: Vec<OwnPositions>,
        pub(crate) uploads: Vec<Vec<u8>>,
        pub(crate) t_star: u8,
    }

    const NOTE: &str = "Paket bitte an die Packstation";

    pub(crate) fn fixture() -> Fixture {
        let gid = GroupId([0x42; 16]);
        let keys: Vec<_> = (0..4)
            .map(|i| ParticipantKeys::derive(&[i as u8 + 0x10; 32], &gid).unwrap())
            .collect();
        let roster = Roster::new(
            keys.iter()
                .map(|k| {
                    let p = k.public();
                    RosterEntry::new(p.pid, p.ipk, p.idh, b"n")
                })
                .collect(),
        )
        .unwrap();
        for round in 1..50 {
            let mut r = vec![0u8; roles_vector_len(4)];
            for k in &keys {
                xor_into(
                    &mut r,
                    &build_roles_vector(k, &gid, round, &roster).unwrap(),
                )
                .unwrap();
            }
            let g = group_context(&gid, round, &roster);
            let Ok(outcome) = evaluate_roles(&g, 4, &r) else {
                continue;
            };
            let own: Vec<_> = keys
                .iter()
                .map(|k| own_positions(k, &gid, round, &roster, &r, &outcome).unwrap())
                .collect();
            let uploads: Vec<_> = keys
                .iter()
                .zip(&own)
                .map(|(k, o)| {
                    build_reveal_upload(k, &gid, round, &roster, &outcome, o, NOTE).unwrap()
                })
                .collect();
            let mut sd = vec![0u8; L_SD];
            for u in &uploads {
                xor_into(&mut sd, split_reveal_upload(u).unwrap().0).unwrap();
            }
            let Some(t_star) = select_attempt(&outcome, &sd) else {
                continue;
            };
            return Fixture {
                gid,
                round,
                keys,
                roster,
                outcome,
                own,
                uploads,
                t_star,
            };
        }
        panic!("no successful round");
    }

    impl Fixture {
        fn released(&self) -> Vec<(Pid, Vec<u8>)> {
            self.keys
                .iter()
                .zip(&self.uploads)
                .map(|(k, u)| {
                    let (_, cs) = split_reveal_upload(u).unwrap();
                    (k.public().pid, cs[usize::from(self.t_star - 1)].to_vec())
                })
                .collect()
        }

        fn open(&self, i: usize, t: u8, reveals: &[(Pid, Vec<u8>)]) -> Result<DrawResult> {
            open_result(
                &self.keys[i],
                &self.gid,
                self.round,
                &self.roster,
                &self.outcome,
                &self.own[i],
                t,
                reveals,
            )
        }

        /// Index of the participant that giver `i` gives to in attempt `t*`.
        pub(crate) fn recipient_of(&self, i: usize) -> usize {
            let ti = usize::from(self.t_star - 1);
            let s = sigma(&self.outcome.rho, self.t_star, 4);
            let e = usize::from(s[self.own[i].p[ti].unwrap()]);
            self.own.iter().position(|o| o.e == e).unwrap()
        }

        /// Reveal of sender `j` for `t*`, built like the real one but with the plaintext
        /// modified by `tamper` before sealing.
        fn craft(&self, j: usize, tamper: fn(&mut [u8; L_PT])) -> Vec<u8> {
            let ctx = round_ctx(&self.keys[j], &self.gid, self.round, &self.roster).unwrap();
            let s = &ctx.secrets;
            let t = self.t_star;
            let ti = usize::from(t - 1);
            let rho = &self.outcome.rho;
            let sig = sigma(rho, t, 4);
            let pk_r =
                self.outcome.givers[ti].as_ref().unwrap()[usize::from(invert(&sig)[self.own[j].e])];
            let pid = self.keys[j].public().pid;
            let dh = x25519_checked(&s.rp, &pk_r).unwrap();
            let mac = claim_mac(&ctx.g_r, rho, t, &dh, &pid, &s.rp_pub, &pk_r);
            let mut pt = plaintext(PT_VERSION, &pid, &mac, NOTE.as_bytes());
            tamper(&mut pt);
            let sk_s =
                <Kem as KemTrait>::PrivateKey::from_bytes(self.keys[j].idh_secret()).unwrap();
            seal_reveal(&sk_s, &s.rng_key, &ctx.g_r, rho, t, &pk_r, &pt)
                .unwrap()
                .to_vec()
        }
    }

    #[test]
    fn honest_round_and_crafted_reveal_match() {
        let f = fixture();
        let released = f.released();
        for i in 0..4 {
            let res = f.open(i, f.t_star, &released).unwrap();
            let j = f.recipient_of(i);
            assert_ne!(i, j);
            assert_eq!(res.recipient, f.keys[j].public().pid);
            assert_eq!(res.note, NOTE);
            // The test helper reproduces the real reveal byte for byte.
            assert_eq!(f.craft(j, |_| {}), released[j].1);
        }
    }

    #[test]
    fn tampered_plaintexts_are_rejected() {
        let f = fixture();
        let giver = 0;
        let j = f.recipient_of(giver);
        let tampers: [fn(&mut [u8; L_PT]); 6] = [
            |pt| pt[OFF_MAC] ^= 1,                                             // wrong MAC
            |pt| pt[OFF_PID] ^= 1,                                             // wrong pid
            |pt| pt[0] = 2,                                                    // wrong version
            |pt| pt[L_PT - 1] = 1,                                             // non-zero filler
            |pt| pt[OFF_LEN..OFF_NOTE].copy_from_slice(&462u16.to_be_bytes()), // too long
            |pt| pt[OFF_NOTE] = 0xff,                                          // invalid UTF-8
        ];
        for (k, tamper) in tampers.into_iter().enumerate() {
            let mut released = f.released();
            released[j].1 = f.craft(j, tamper);
            assert_eq!(
                f.open(giver, f.t_star, &released).err(),
                Some(Error::RevealCount),
                "tamper {k}"
            );
        }
        // A correctly sealed reveal under a pid other than the sender's is rejected, too.
        let mut released = f.released();
        let other = (0..4).find(|&x| x != j && x != giver).unwrap();
        released[j].0 = f.keys[other].public().pid;
        released[other].0 = f.keys[j].public().pid;
        assert_eq!(
            f.open(giver, f.t_star, &released).err(),
            Some(Error::RevealCount)
        );
        // Wrong length / unknown pid are skipped without panic.
        let mut released = f.released();
        released[j].1.pop();
        released.push((Pid([9; 16]), vec![0u8; L_CT]));
        assert_eq!(
            f.open(giver, f.t_star, &released).err(),
            Some(Error::RevealCount)
        );
    }

    #[test]
    fn two_valid_reveals_are_rejected() {
        let f = fixture();
        let giver = 1;
        let j = f.recipient_of(giver);
        let mut released = f.released();
        released.push(released[j].clone());
        assert_eq!(
            f.open(giver, f.t_star, &released).err(),
            Some(Error::RevealCount)
        );
    }

    #[test]
    fn open_result_rejects_wrong_attempt() {
        let f = fixture();
        let released = f.released();
        for t in [0u8, 17, 255] {
            assert_eq!(f.open(0, t, &released).err(), Some(Error::AttemptMismatch));
        }
        for t in 1..=16u8 {
            let ti = usize::from(t - 1);
            let self_draw = f.outcome.givers[ti].is_some()
                && usize::from(sigma(&f.outcome.rho, t, 4)[f.own[0].p[ti].unwrap()]) == f.own[0].e;
            if f.outcome.givers[ti].is_none() || self_draw {
                assert_eq!(
                    f.open(0, t, &released).err(),
                    Some(Error::AttemptMismatch),
                    "t = {t}"
                );
            }
        }
    }

    #[test]
    fn step2_is_deterministic_and_note_dependent() {
        let f = fixture();
        let build = |note: &str| {
            build_reveal_upload(
                &f.keys[2], &f.gid, f.round, &f.roster, &f.outcome, &f.own[2], note,
            )
            .unwrap()
        };
        assert_eq!(build(NOTE), f.uploads[2]);
        let other = build("andere Notiz");
        let (sd_a, ca) = split_reveal_upload(&f.uploads[2]).unwrap();
        let (sd_b, cb) = split_reveal_upload(&other).unwrap();
        assert_eq!(sd_a, sd_b);
        for ti in 0..T_ATTEMPTS {
            if f.outcome.givers[ti].is_some() {
                // Different plaintext ⇒ different ephemeral (no AEAD nonce reuse).
                assert_ne!(ca[ti][..L_ENC], cb[ti][..L_ENC], "attempt {}", ti + 1);
            } else {
                assert_eq!(ca[ti], cb[ti]);
            }
        }
        let too_long = "x".repeat(NOTE_MAX + 1);
        assert_eq!(
            build_reveal_upload(
                &f.keys[2], &f.gid, f.round, &f.roster, &f.outcome, &f.own[2], &too_long,
            )
            .err(),
            Some(Error::InvalidLength)
        );
    }

    #[test]
    fn redacted_debug() {
        let f = fixture();
        assert_eq!(format!("{:?}", f.own[0]), "OwnPositions { <redacted> }");
        let r = f.open(0, f.t_star, &f.released()).unwrap();
        assert_eq!(format!("{r:?}"), "DrawResult { <redacted> }");
    }

    fn outcome(valid: &[bool]) -> RolesOutcome {
        RolesOutcome {
            recipients: vec![[1; 32]; 4],
            givers: core::array::from_fn(|i| valid[i].then(|| vec![[2; 32]; 4])),
            rho: [0; 32],
        }
    }

    #[test]
    fn split_checks_length() {
        let body = vec![7u8; L_REVEAL_UPLOAD];
        let (sd, cs) = split_reveal_upload(&body).unwrap();
        assert_eq!(sd.len(), L_SD);
        assert_eq!(cs.len(), T_ATTEMPTS);
        assert!(cs.iter().all(|c| c.len() == L_CT));
        assert_eq!(
            split_reveal_upload(&body[1..]).err(),
            Some(Error::InvalidLength)
        );
    }

    #[test]
    fn select_attempt_rules() {
        let mut valid = [true; T_ATTEMPTS];
        valid[0] = false;
        let o = outcome(&valid);
        let mut sd = [0u8; L_SD];
        assert_eq!(select_attempt(&o, &sd), Some(2));
        sd[SLOT_SD] = 1; // t = 2 has a self-draw
        assert_eq!(select_attempt(&o, &sd), Some(3));
        let all_bad = [0xffu8; L_SD];
        assert_eq!(select_attempt(&o, &all_bad), None);
        assert_eq!(select_attempt(&o, &sd[1..]), None);
        let o = outcome(&[false; T_ATTEMPTS]);
        assert_eq!(select_attempt(&o, &[0u8; L_SD]), None);
    }
}
