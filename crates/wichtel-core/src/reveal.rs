//! Step 2: self-draw vector, reveals, `t*`, result (Spec §9).

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use rand_core::Rng;
use zeroize::Zeroizing;

use crate::dcnet::{OwnPositions, RolesOutcome, apply_pair_masks, round_ctx};
use crate::draw::{invert, is_permutation, sigma};
use crate::keys::{ParticipantKeys, ct_eq};
use crate::roster::Roster;
use crate::util::{KeystreamRng, SecretVec, hkdf32, hmac, x25519_checked};
use crate::{
    Error, GroupId, L_CT, L_PT, L_REVEAL_UPLOAD, L_SD, NOTE_MAX, Pid, Result, SLOT_SD, T_ATTEMPTS,
};

type Kem = X25519HkdfSha256;

/// Offsets in the reveal plaintext (Spec §9.2).
const PT_VERSION: u8 = 0x01;
const OFF_PID: usize = 1;
const OFF_MAC: usize = 17;
const OFF_LEN: usize = 49;
const OFF_NOTE: usize = 51;
/// HPKE `enc` length.
const L_ENC: usize = 32;

/// `info = "wichtel/v1/reveal" ‖ G_r ‖ u8(t)`.
fn hpke_info(g_r: &[u8; 32], t: u8) -> Vec<u8> {
    let mut info = Vec::with_capacity(17 + 32 + 1);
    info.extend_from_slice(b"wichtel/v1/reveal");
    info.extend_from_slice(g_r);
    info.push(t);
    info
}

/// Claim MAC (Spec §9.2): `dh` is `X25519(rp_r, pkR)` (sender) or `X25519(gp, RP)` (receiver).
fn claim_mac(
    g_r: &[u8; 32],
    t: u8,
    dh: &[u8; 32],
    pid: &Pid,
    rp: &[u8; 32],
    pk_r: &[u8; 32],
) -> [u8; 32] {
    let mac_key = hkdf32(g_r, dh, &[b"wichtel/v1/claim-mac", &[t]]);
    hmac(
        &mac_key,
        &[b"wichtel/v1/claim", g_r, &[t], &pid.0, rp, pk_r],
    )
}

/// Build the step-2 upload body `SD_i ‖ C_{i,1} ‖ … ‖ C_{i,16}` (length `L_REVEAL_UPLOAD`).
/// `note` is the optional private note for the giver (≤ `NOTE_MAX` bytes UTF-8).
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
    let pid = keys.public().pid;

    let mut body = Vec::with_capacity(L_REVEAL_UPLOAD);

    // §9.1 self-draw vector.
    let mut d = [0u8; L_SD];
    let sigmas: Vec<Option<Vec<u16>>> = (0..T_ATTEMPTS)
        .map(|i| {
            outcome.givers[i]
                .as_ref()
                .map(|_| sigma(&outcome.rho, i as u8 + 1, n))
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
        b"wichtel/v1/dc-selfdraw",
        &mut d,
    )?;
    body.extend_from_slice(&d);

    // §9.2 reveals.
    let sk_s = <Kem as KemTrait>::PrivateKey::from_bytes(keys.idh_secret())
        .map_err(|_| Error::InvalidKey)?;
    let pk_s = Kem::sk_to_pk(&sk_s);
    let mut rng = KeystreamRng::new(&s.rng_key);
    let mut pt = Zeroizing::new([0u8; L_PT]);
    for (i, (sig, givers)) in sigmas.iter().zip(&outcome.givers).enumerate() {
        let t = i as u8 + 1;
        let (Some(sig), Some(givers)) = (sig, givers) else {
            // Invalid attempt: placeholder from rng.
            let start = body.len();
            body.resize(start + L_CT, 0);
            rng.fill_bytes(&mut body[start..]);
            continue;
        };
        let g = usize::from(invert(sig)[own.e]);
        let pk_r = givers[g];

        // The HPKE ephemeral always consumes the first 32 bytes of rng for a valid attempt;
        // if anything fails, the placeholder (560 B) follows from rng (see report / spec §9.2).
        let sealed = x25519_checked(&s.rp, &pk_r).and_then(|dh| {
            let mac = claim_mac(&ctx.g_r, t, &dh, &pid, &s.rp_pub, &pk_r);
            pt.fill(0);
            pt[0] = PT_VERSION;
            pt[OFF_PID..OFF_MAC].copy_from_slice(&pid.0);
            pt[OFF_MAC..OFF_LEN].copy_from_slice(&mac);
            // note.len() ≤ NOTE_MAX < 2^16.
            pt[OFF_LEN..OFF_NOTE].copy_from_slice(&(note.len() as u16).to_be_bytes());
            pt[OFF_NOTE..OFF_NOTE + note.len()].copy_from_slice(note);
            let pk_r =
                <Kem as KemTrait>::PublicKey::from_bytes(&pk_r).map_err(|_| Error::InvalidKey)?;
            hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, Kem>(
                &OpModeS::Auth((sk_s.clone(), pk_s.clone())),
                &pk_r,
                &hpke_info(&ctx.g_r, t),
                pt.as_ref(),
                b"",
                &mut rng,
            )
            .map_err(|_| Error::InvalidKey)
        });
        match sealed {
            Ok((enc, ct)) if ct.len() + L_ENC == L_CT => {
                body.extend_from_slice(&enc.to_bytes());
                body.extend_from_slice(&ct);
            }
            Ok(_) => return Err(Error::InvalidLength),
            Err(_) => {
                if x25519_checked(&s.rp, &pk_r).is_err() {
                    // HPKE was not reached: consume the ephemeral's 32 bytes anyway.
                    let mut skip = Zeroizing::new([0u8; L_ENC]);
                    rng.fill_bytes(skip.as_mut());
                }
                let start = body.len();
                body.resize(start + L_CT, 0);
                rng.fill_bytes(&mut body[start..]);
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

/// Final result of the local participant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrawResult {
    pub recipient: Pid,
    pub note: String,
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
    let ctx = round_ctx(keys, gid, round, roster)?;
    let n = roster.len();
    check_outcome(outcome, own, n)?;
    if !(1..=T_ATTEMPTS as u8).contains(&t_star) {
        return Err(Error::AttemptMismatch);
    }
    let i = usize::from(t_star - 1);
    let (Some(_), Some(p)) = (&outcome.givers[i], own.p[i]) else {
        return Err(Error::AttemptMismatch);
    };
    let sig = sigma(&outcome.rho, t_star, n);
    if !is_permutation(&sig) {
        return Err(Error::AttemptMismatch);
    }
    let e = usize::from(sig[p]);
    if e == own.e {
        return Err(Error::AttemptMismatch);
    }
    let s = &ctx.secrets;
    let rp_e = outcome.recipients[e];
    let gp_pub = s.gp_pub[i];
    let dh = x25519_checked(&s.gp[i], &rp_e)?;
    let sk_r =
        <Kem as KemTrait>::PrivateKey::from_bytes(&s.gp[i]).map_err(|_| Error::InvalidKey)?;
    let info = hpke_info(&ctx.g_r, t_star);

    let mut found: Option<DrawResult> = None;
    let mut valid = 0usize;
    // Try every reveal (no early exit, uniform access pattern).
    for (pid_j, c) in reveals {
        let Some(res) = try_open(
            &ctx.g_r, t_star, &dh, &rp_e, &gp_pub, &sk_r, &info, roster, pid_j, c,
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
    t: u8,
    dh: &[u8; 32],
    rp_e: &[u8; 32],
    gp_pub: &[u8; 32],
    sk_r: &<Kem as KemTrait>::PrivateKey,
    info: &[u8],
    roster: &Roster,
    pid_j: &Pid,
    c: &[u8],
) -> Option<DrawResult> {
    if c.len() != L_CT {
        return None;
    }
    let sender = &roster.entries()[roster.index_of(pid_j)?];
    let pk_s = <Kem as KemTrait>::PublicKey::from_bytes(&sender.idh).ok()?;
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(&c[..L_ENC]).ok()?;
    let pt = SecretVec(
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeR::Auth(pk_s),
            sk_r,
            &enc,
            info,
            &c[L_ENC..],
            b"",
        )
        .ok()?,
    );
    if pt.len() != L_PT || pt[0] != PT_VERSION || pt[OFF_PID..OFF_MAC] != pid_j.0 {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([pt[OFF_LEN], pt[OFF_LEN + 1]]));
    if len > NOTE_MAX || pt[OFF_NOTE + len..].iter().any(|&b| b != 0) {
        return None;
    }
    let mac = claim_mac(g_r, t, dh, pid_j, rp_e, gp_pub);
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
mod tests {
    use super::*;

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
