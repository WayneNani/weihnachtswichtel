//! Contact from the giver to the recipient (Spec §16.2).
//!
//! After the result is known (`Done`), every participant uploads exactly one contact for its
//! recipient: an HPKE Auth ciphertext from the own giver role `gp_{r,t*}` to the recipient's
//! `IDH`, carrying an (anonymous) push endpoint or nothing. The recipient opens all contacts with
//! `pkS = GP_{r,t*}[σ_{t*}⁻¹(e_j)]` and thereby finds exactly the one of its own giver, without
//! learning who that is.

use zeroize::Zeroizing;

use crate::dcnet::{OwnPositions, RolesOutcome};
use crate::draw::invert;
use crate::keys::ParticipantKeys;
use crate::reveal::{HpkeSk, hpke_info, hpke_sk, open_auth, resolve_attempt, seal_auth};
use crate::roster::Roster;
use crate::{ENDPOINT_MAX, Error, GroupId, L_K, L_KP, Result};

/// HPKE label of the contacts.
const INFO_CONTACT: &[u8] = b"wichtel/v1/contact";
/// Offsets in the contact plaintext.
const KP_VERSION: u8 = 0x01;
const OFF_LEN: usize = 1;
const OFF_ENDPOINT: usize = 3;
/// Required prefix of a non-empty endpoint.
const HTTPS: &[u8] = b"https://";

/// Endpoint rules: empty, or `https://…` with at most `ENDPOINT_MAX` bytes.
fn check_endpoint(endpoint: &[u8]) -> Result<()> {
    if endpoint.len() > ENDPOINT_MAX {
        return Err(Error::InvalidLength);
    }
    if !endpoint.is_empty() && !endpoint.starts_with(HTTPS) {
        return Err(Error::InvalidEncoding);
    }
    Ok(())
}

/// Contact plaintext (Spec §16.2 table); the endpoint must have passed [`check_endpoint`].
fn plaintext(version: u8, endpoint: &[u8]) -> Zeroizing<[u8; L_KP]> {
    let mut pt = Zeroizing::new([0u8; L_KP]);
    pt[0] = version;
    let len = endpoint.len().min(ENDPOINT_MAX);
    // len ≤ ENDPOINT_MAX < 2^16.
    pt[OFF_LEN..OFF_ENDPOINT].copy_from_slice(&(len as u16).to_be_bytes());
    pt[OFF_ENDPOINT..OFF_ENDPOINT + len].copy_from_slice(&endpoint[..len]);
    pt
}

/// Seal a contact plaintext with a fresh random ephemeral.
fn seal(sk_s: &[u8; 32], pk_r: &[u8; 32], info: &[u8], pt: &[u8; L_KP]) -> Result<Vec<u8>> {
    let sk_s = hpke_sk(sk_s)?;
    // Fresh randomness from the platform CSPRNG (browser: crypto.getRandomValues), used as the
    // `GenerateKeyPair` input of the HPKE ephemeral (RFC 9180 §7.1.3).
    let mut eph_ikm = Zeroizing::new([0u8; 32]);
    getrandom::fill(eph_ikm.as_mut()).map_err(|_| Error::Rng)?;
    let c = seal_auth(&sk_s, pk_r, info, pt, &eph_ikm)?;
    if c.len() != L_K {
        return Err(Error::InvalidLength);
    }
    Ok(c)
}

/// Build the own contact `K_i` (`L_K` = 816 bytes) for the recipient with identity key
/// `recipient_idh` (Spec §16.2). `endpoint` is the anonymous push endpoint or `""` (no
/// notification).
///
/// Not deterministic: every call uses a fresh ephemeral (a new upload replaces the old one).
///
/// Errors: endpoint longer than `ENDPOINT_MAX` (`InvalidLength`) or non-empty without the
/// prefix `https://` (`InvalidEncoding`); `recipient_idh` not another member of the roster
/// (`NotInRoster`); `t*` not usable (`AttemptMismatch`, see [`crate::reveal::open_result`]);
/// no randomness (`Rng`).
#[allow(clippy::too_many_arguments)]
pub fn build_contact(
    keys: &ParticipantKeys,
    gid: &GroupId,
    round: u32,
    roster: &Roster,
    outcome: &RolesOutcome,
    own: &OwnPositions,
    t_star: u8,
    recipient_idh: &[u8; 32],
    endpoint: &str,
) -> Result<Vec<u8>> {
    let endpoint = endpoint.as_bytes();
    check_endpoint(endpoint)?;
    let a = resolve_attempt(keys, gid, round, roster, outcome, own, t_star)?;
    if *recipient_idh == keys.public().idh
        || !roster.entries().iter().any(|e| e.idh == *recipient_idh)
    {
        return Err(Error::NotInRoster);
    }
    let info = hpke_info(INFO_CONTACT, &a.ctx.g_r, &outcome.rho, t_star);
    seal(
        &a.ctx.secrets.gp[a.index],
        recipient_idh,
        &info,
        &plaintext(KP_VERSION, endpoint),
    )
}

/// Open the served contacts `K_a ‖ K_b ‖ …` (Spec §16.2) and return the endpoint of the own
/// giver: `Ok(None)` if no contact of the giver is present or its endpoint is empty.
///
/// Every block is tried (no early exit). A block that opens but fails the strict checks
/// (version, length ≤ `ENDPOINT_MAX`, zero padding, UTF-8, `https://` prefix) is discarded.
///
/// Errors: total length not a multiple of `L_K` (`InvalidLength`); more than one valid contact
/// (`ContactCount`, a server fault); `t*` not usable (`AttemptMismatch`).
#[allow(clippy::too_many_arguments)]
pub fn open_contacts(
    keys: &ParticipantKeys,
    gid: &GroupId,
    round: u32,
    roster: &Roster,
    outcome: &RolesOutcome,
    own: &OwnPositions,
    t_star: u8,
    contacts: &[u8],
) -> Result<Option<String>> {
    if !contacts.len().is_multiple_of(L_K) {
        return Err(Error::InvalidLength);
    }
    let a = resolve_attempt(keys, gid, round, roster, outcome, own, t_star)?;
    // Giver position of the own E-position; `resolve_attempt` checked σ and the givers list.
    let g = usize::from(invert(&a.sigma)[own.e]);
    let pk_s = outcome.givers[a.index]
        .as_ref()
        .and_then(|givers| givers.get(g))
        .ok_or(Error::AttemptMismatch)?;
    let sk_r = hpke_sk(keys.idh_secret())?;
    let info = hpke_info(INFO_CONTACT, &a.ctx.g_r, &outcome.rho, t_star);

    let mut found: Option<Zeroizing<String>> = None;
    let mut valid = 0usize;
    for c in contacts.chunks_exact(L_K) {
        if let Some(endpoint) = try_open(&sk_r, pk_s, &info, c) {
            valid += 1;
            found = Some(endpoint);
        }
    }
    match (valid, found) {
        (0, _) => Ok(None),
        (1, Some(endpoint)) if endpoint.is_empty() => Ok(None),
        (1, Some(endpoint)) => Ok(Some(endpoint.as_str().to_owned())),
        _ => Err(Error::ContactCount),
    }
}

/// Open and check one contact; `None` if anything is wrong.
fn try_open(sk_r: &HpkeSk, pk_s: &[u8; 32], info: &[u8], c: &[u8]) -> Option<Zeroizing<String>> {
    if c.len() != L_K {
        return None;
    }
    let pt = open_auth(sk_r, pk_s, info, c)?;
    if pt.len() != L_KP || pt[0] != KP_VERSION {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([pt[OFF_LEN], pt[OFF_LEN + 1]]));
    if len > ENDPOINT_MAX || pt[OFF_ENDPOINT + len..].iter().any(|&b| b != 0) {
        return None;
    }
    let endpoint = &pt[OFF_ENDPOINT..OFF_ENDPOINT + len];
    check_endpoint(endpoint).ok()?;
    let endpoint = core::str::from_utf8(endpoint).ok()?;
    Some(Zeroizing::new(endpoint.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::draw::sigma;
    use crate::reveal::L_ENC;
    use crate::reveal::tests::{Fixture, fixture};

    const EP: &str = "https://push.example/abc";

    impl Fixture {
        fn idh(&self, i: usize) -> [u8; 32] {
            self.keys[i].public().idh
        }

        fn build(&self, i: usize, recipient: usize, endpoint: &str) -> Result<Vec<u8>> {
            build_contact(
                &self.keys[i],
                &self.gid,
                self.round,
                &self.roster,
                &self.outcome,
                &self.own[i],
                self.t_star,
                &self.idh(recipient),
                endpoint,
            )
        }

        fn open_contacts(&self, j: usize, contacts: &[u8]) -> Result<Option<String>> {
            open_contacts(
                &self.keys[j],
                &self.gid,
                self.round,
                &self.roster,
                &self.outcome,
                &self.own[j],
                self.t_star,
                contacts,
            )
        }

        /// Contact of giver `i` (to its real recipient) with a crafted plaintext / `t`.
        fn craft_contact(&self, i: usize, t: u8, pt: &[u8; L_KP]) -> Vec<u8> {
            let a = resolve_attempt(
                &self.keys[i],
                &self.gid,
                self.round,
                &self.roster,
                &self.outcome,
                &self.own[i],
                self.t_star,
            )
            .unwrap();
            let info = hpke_info(INFO_CONTACT, &a.ctx.g_r, &self.outcome.rho, t);
            let j = self.recipient_of(i);
            seal(&a.ctx.secrets.gp[a.index], &self.idh(j), &info, pt).unwrap()
        }

        fn giver_of(&self, j: usize) -> usize {
            (0..self.keys.len())
                .find(|&i| self.recipient_of(i) == j)
                .unwrap()
        }
    }

    #[test]
    fn roundtrip_and_strict_checks() {
        let f = fixture();
        let n = f.keys.len();
        let all: Vec<u8> = (0..n)
            .flat_map(|i| f.build(i, f.recipient_of(i), &format!("{EP}/{i}")).unwrap())
            .collect();
        assert_eq!(all.len(), n * L_K);
        for j in 0..n {
            let giver = f.giver_of(j);
            assert_eq!(
                f.open_contacts(j, &all).unwrap().as_deref(),
                Some(format!("{EP}/{giver}").as_str())
            );
        }

        let j = f.recipient_of(0);
        let mut ok = plaintext(KP_VERSION, EP.as_bytes());
        assert_eq!(
            f.open_contacts(j, &f.craft_contact(0, f.t_star, &ok))
                .unwrap()
                .as_deref(),
            Some(EP)
        );
        // Each tampered plaintext is discarded (⇒ no contact found).
        let tampers: [fn(&mut [u8; L_KP]); 7] = [
            |pt| pt[0] = 2,                                                        // version
            |pt| pt[L_KP - 1] = 1,                                                 // padding
            |pt| pt[OFF_LEN..OFF_ENDPOINT].copy_from_slice(&701u16.to_be_bytes()), // too long
            |pt| pt[OFF_LEN..OFF_ENDPOINT].copy_from_slice(&800u16.to_be_bytes()), // beyond pt
            |pt| pt[OFF_ENDPOINT] = b'h' ^ 0x20,                                   // no https://
            |pt| pt[OFF_ENDPOINT + 10] = 0xff,                                     // invalid UTF-8
            |pt| pt[OFF_LEN + 1] -= 1, // length too short ⇒ non-zero padding
        ];
        for (k, tamper) in tampers.into_iter().enumerate() {
            let mut pt = plaintext(KP_VERSION, EP.as_bytes());
            tamper(&mut pt);
            assert_eq!(
                f.open_contacts(j, &f.craft_contact(0, f.t_star, &pt)),
                Ok(None),
                "tamper {k}"
            );
        }
        // A maximal endpoint is fine.
        let long = format!("https://{}", "a".repeat(ENDPOINT_MAX - 8));
        ok = plaintext(KP_VERSION, long.as_bytes());
        assert_eq!(
            f.open_contacts(j, &f.craft_contact(0, f.t_star, &ok))
                .unwrap(),
            Some(long)
        );
    }

    #[test]
    fn info_binds_t_star() {
        let f = fixture();
        let j = f.recipient_of(1);
        let pt = plaintext(KP_VERSION, EP.as_bytes());
        for t in 1..=16u8 {
            let c = f.craft_contact(1, t, &pt);
            let expect = (t == f.t_star).then(|| EP.to_owned());
            assert_eq!(f.open_contacts(j, &c), Ok(expect), "t = {t}");
        }
    }

    #[test]
    fn sender_and_recipient_are_checked() {
        let f = fixture();
        let n = f.keys.len();
        let j = f.recipient_of(2);
        // Everyone else addressing j (wrong skS) cannot be opened by j.
        for i in (0..n).filter(|&i| i != 2 && i != j) {
            let c = f.build(i, j, EP).unwrap();
            assert_eq!(f.open_contacts(j, &c), Ok(None), "sender {i}");
        }
        // The right contact cannot be opened by anybody but j.
        let c = f.build(2, j, EP).unwrap();
        for k in (0..n).filter(|&k| k != j) {
            assert_eq!(f.open_contacts(k, &c), Ok(None), "receiver {k}");
        }
        assert_eq!(f.open_contacts(j, &c), Ok(Some(EP.to_owned())));
        // Own IDH / foreign IDH are refused.
        assert_eq!(f.build(2, 2, EP).err(), Some(Error::NotInRoster));
        assert_eq!(
            build_contact(
                &f.keys[2], &f.gid, f.round, &f.roster, &f.outcome, &f.own[2], f.t_star, &[9; 32],
                EP,
            )
            .err(),
            Some(Error::NotInRoster)
        );
    }

    #[test]
    fn endpoint_rules_and_counts() {
        let f = fixture();
        let j = f.recipient_of(3);
        assert_eq!(
            f.build(3, j, "http://x").err(),
            Some(Error::InvalidEncoding)
        );
        let too_long = format!("https://{}", "a".repeat(ENDPOINT_MAX - 7));
        assert_eq!(f.build(3, j, &too_long).err(), Some(Error::InvalidLength));
        // Empty endpoint ⇒ None.
        let empty = f.build(3, j, "").unwrap();
        assert_eq!(f.open_contacts(j, &empty), Ok(None));
        assert_eq!(f.open_contacts(j, &[]), Ok(None));
        // Fresh randomness: two contacts with the same endpoint differ.
        let a = f.build(3, j, EP).unwrap();
        let b = f.build(3, j, EP).unwrap();
        assert_ne!(a, b);
        assert_ne!(a[..L_ENC], b[..L_ENC]);
        // Two valid contacts (also: one empty, one not) ⇒ error.
        assert_eq!(
            f.open_contacts(j, &[a.clone(), b].concat()),
            Err(Error::ContactCount)
        );
        assert_eq!(
            f.open_contacts(j, &[empty, a.clone()].concat()),
            Err(Error::ContactCount)
        );
        // Lengths.
        for len in [1, L_K - 1, L_K + 1, 2 * L_K - 1] {
            let mut c = a.clone();
            c.resize(len, 0);
            assert_eq!(f.open_contacts(j, &c), Err(Error::InvalidLength), "{len}");
        }
        // Garbage blocks are skipped without panic.
        let garbage = [vec![0u8; L_K], vec![0xffu8; L_K], a].concat();
        assert_eq!(f.open_contacts(j, &garbage), Ok(Some(EP.to_owned())));
    }

    #[test]
    fn unusable_t_star_is_rejected() {
        let f = fixture();
        let i = 0;
        let j = f.recipient_of(i);
        for t in [0u8, 17] {
            let r = build_contact(
                &f.keys[i],
                &f.gid,
                f.round,
                &f.roster,
                &f.outcome,
                &f.own[i],
                t,
                &f.idh(j),
                EP,
            );
            assert_eq!(r.err(), Some(Error::AttemptMismatch));
        }
        for t in 1..=16u8 {
            let ti = usize::from(t - 1);
            let unusable = f.outcome.givers[ti].is_none()
                || usize::from(sigma(&f.outcome.rho, t, 4)[f.own[i].p[ti].unwrap()]) == f.own[i].e;
            if unusable {
                let r = open_contacts(
                    &f.keys[i],
                    &f.gid,
                    f.round,
                    &f.roster,
                    &f.outcome,
                    &f.own[i],
                    t,
                    &[],
                );
                assert_eq!(r, Err(Error::AttemptMismatch), "t = {t}");
            }
        }
    }
}
