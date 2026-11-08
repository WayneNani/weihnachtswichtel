//! The protocol operations the server needs from `wichtel-core`, behind a small trait.
//!
//! Production uses [`CoreOps`] (thin wrappers around `wichtel-core`). Tests can substitute a
//! fake to exercise HTTP, state machine, store, push and jobs independently of the crypto.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use wichtel_core::dcnet::RolesOutcome;
use wichtel_core::keys::UploadKind;
use wichtel_core::roster::{Roster, RosterEntry};
use wichtel_core::{GroupId, Pid};

/// Server-side protocol operations (Spec §3–§12).
pub trait ProtocolOps: Send + Sync + 'static {
    /// `H("wichtel/v1/admin-hash" ‖ AS)`.
    fn admin_hash(&self, admin_secret: &[u8; 32]) -> [u8; 32];
    /// `H("wichtel/v1/auth-hash" ‖ tok)`.
    fn auth_hash(&self, token: &[u8; 32]) -> [u8; 32];
    /// Constant-time equality.
    fn ct_eq(&self, a: &[u8], b: &[u8]) -> bool;
    /// Verify a join request (signature, low-order `IDH`); returns the derived `pid`.
    #[allow(clippy::too_many_arguments)]
    fn verify_join(
        &self,
        gid: &[u8; 16],
        ipk: &[u8; 32],
        idh: &[u8; 32],
        auth_hash: &[u8; 32],
        enc_name: &[u8],
        enc_wish: &[u8],
        join_sig: &[u8; 64],
    ) -> Option<[u8; 16]>;
    /// Verify an upload signature (Spec §12).
    #[allow(clippy::too_many_arguments)]
    fn verify_upload(
        &self,
        gid: &[u8; 16],
        pid: &[u8; 16],
        ipk: &[u8; 32],
        kind: UploadKind,
        round: u32,
        body: &[u8],
        sig: &[u8; 64],
    ) -> bool;
    /// Verify a contact upload signature (Spec §12, kind 3; `round` = round of `Done`).
    fn verify_contact_upload(
        &self,
        gid: &[u8; 16],
        pid: &[u8; 16],
        ipk: &[u8; 32],
        round: u32,
        body: &[u8],
        sig: &[u8; 64],
    ) -> bool;
    /// `acc ^= src`; `false` on length mismatch.
    fn xor_into(&self, acc: &mut [u8], src: &[u8]) -> bool;
    /// `G_r` for the roster (any order; sorted by the implementation).
    fn group_context(
        &self,
        gid: &[u8; 16],
        round: u32,
        roster: Vec<RosterEntry>,
    ) -> Option<[u8; 32]>;
    /// Evaluate `R`; `None` if area E is invalid (collision) or `R` is malformed.
    fn evaluate_roles(&self, g_r: &[u8; 32], n: usize, r: &[u8]) -> Option<RolesOutcome>;
    /// Split a step-2 body into `SD_i` and `C_{i,1..=16}`.
    fn split_reveal_upload<'a>(&self, body: &'a [u8]) -> Option<(&'a [u8], Vec<&'a [u8]>)>;
    /// `t*` (Spec §9.1); `None` ⇒ failed-attempt round.
    fn select_attempt(&self, outcome: &RolesOutcome, selfdraw_aggregate: &[u8]) -> Option<u8>;
}

/// [`ProtocolOps`] backed by `wichtel-core`.
#[derive(Clone, Copy, Debug, Default)]
pub struct CoreOps;

impl ProtocolOps for CoreOps {
    fn admin_hash(&self, admin_secret: &[u8; 32]) -> [u8; 32] {
        wichtel_core::keys::admin_hash(admin_secret)
    }

    fn auth_hash(&self, token: &[u8; 32]) -> [u8; 32] {
        wichtel_core::keys::auth_hash(token)
    }

    fn ct_eq(&self, a: &[u8], b: &[u8]) -> bool {
        wichtel_core::keys::ct_eq(a, b)
    }

    fn verify_join(
        &self,
        gid: &[u8; 16],
        ipk: &[u8; 32],
        idh: &[u8; 32],
        auth_hash: &[u8; 32],
        enc_name: &[u8],
        enc_wish: &[u8],
        join_sig: &[u8; 64],
    ) -> Option<[u8; 16]> {
        wichtel_core::keys::verify_join(
            &GroupId(*gid),
            ipk,
            idh,
            auth_hash,
            enc_name,
            enc_wish,
            join_sig,
        )
        .ok()
        .map(|p| p.0)
    }

    fn verify_upload(
        &self,
        gid: &[u8; 16],
        pid: &[u8; 16],
        ipk: &[u8; 32],
        kind: UploadKind,
        round: u32,
        body: &[u8],
        sig: &[u8; 64],
    ) -> bool {
        wichtel_core::keys::verify_upload(&GroupId(*gid), &Pid(*pid), ipk, kind, round, body, sig)
            .is_ok()
    }

    fn verify_contact_upload(
        &self,
        gid: &[u8; 16],
        pid: &[u8; 16],
        ipk: &[u8; 32],
        round: u32,
        body: &[u8],
        sig: &[u8; 64],
    ) -> bool {
        verify_upload_kind(UPLOAD_KIND_CONTACT, gid, pid, ipk, round, body, sig)
    }

    fn xor_into(&self, acc: &mut [u8], src: &[u8]) -> bool {
        wichtel_core::dcnet::xor_into(acc, src).is_ok()
    }

    fn group_context(
        &self,
        gid: &[u8; 16],
        round: u32,
        roster: Vec<RosterEntry>,
    ) -> Option<[u8; 32]> {
        let roster = Roster::new(roster).ok()?;
        Some(wichtel_core::roster::group_context(
            &GroupId(*gid),
            round,
            &roster,
        ))
    }

    fn evaluate_roles(&self, g_r: &[u8; 32], n: usize, r: &[u8]) -> Option<RolesOutcome> {
        wichtel_core::dcnet::evaluate_roles(g_r, n, r).ok()
    }

    fn split_reveal_upload<'a>(&self, body: &'a [u8]) -> Option<(&'a [u8], Vec<&'a [u8]>)> {
        wichtel_core::reveal::split_reveal_upload(body).ok()
    }

    fn select_attempt(&self, outcome: &RolesOutcome, selfdraw_aggregate: &[u8]) -> Option<u8> {
        wichtel_core::reveal::select_attempt(outcome, selfdraw_aggregate)
    }
}

/// Upload kind byte of a contact (Spec §12, §16.2).
pub const UPLOAD_KIND_CONTACT: u8 = 3;

/// `upload_sig` check of Spec §12 for an arbitrary kind byte. Same message and checks as
/// `wichtel_core::keys::verify_upload` (strict verification, weak keys rejected); needed for
/// kind 3 as long as `wichtel_core::keys::UploadKind` has no contact variant. The test below
/// pins it to the core implementation for kinds 1 and 2.
// TODO(merge): use `wichtel_core::keys::verify_upload(…, UploadKind::Contact, …)` once
// wichtel-core provides it.
fn verify_upload_kind(
    kind: u8,
    gid: &[u8; 16],
    pid: &[u8; 16],
    ipk: &[u8; 32],
    round: u32,
    body: &[u8],
    sig: &[u8; 64],
) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(ipk) else {
        return false;
    };
    if vk.is_weak() {
        return false;
    }
    let msg: [u8; 32] = Sha256::new()
        .chain_update(b"wichtel/v1/upload")
        .chain_update([kind])
        .chain_update(gid)
        .chain_update(round.to_be_bytes())
        .chain_update(pid)
        .chain_update(Sha256::digest(body))
        .finalize()
        .into();
    vk.verify_strict(&msg, &Signature::from_bytes(sig)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wichtel_core::keys::ParticipantKeys;

    /// The local kind-3 verification uses exactly the message of wichtel-core (checked with
    /// kinds 1 and 2, which wichtel-core can sign).
    #[test]
    fn local_upload_verification_matches_core() {
        let gid = GroupId([3u8; 16]);
        let keys = ParticipantKeys::derive(&[8u8; 32], &gid).unwrap();
        let p = keys.public();
        let body = [0x5au8; 100];
        for (kind, byte) in [(UploadKind::Roles, 1u8), (UploadKind::Reveal, 2u8)] {
            let sig = keys.sign_upload(kind, 7, &body);
            assert!(verify_upload_kind(
                byte, &gid.0, &p.pid.0, &p.ipk, 7, &body, &sig
            ));
            assert!(!verify_upload_kind(
                UPLOAD_KIND_CONTACT,
                &gid.0,
                &p.pid.0,
                &p.ipk,
                7,
                &body,
                &sig
            ));
            assert!(!verify_upload_kind(
                byte, &gid.0, &p.pid.0, &p.ipk, 8, &body, &sig
            ));
            assert!(!verify_upload_kind(
                byte,
                &gid.0,
                &p.pid.0,
                &p.ipk,
                7,
                &body[1..],
                &sig
            ));
        }
    }
}
