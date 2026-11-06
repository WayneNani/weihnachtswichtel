//! The protocol operations the server needs from `wichtel-core`, behind a small trait.
//!
//! Production uses [`CoreOps`] (thin wrappers around `wichtel-core`). Tests can substitute a
//! fake to exercise HTTP, state machine, store, push and jobs independently of the crypto.

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
