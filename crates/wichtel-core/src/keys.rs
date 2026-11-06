//! Secrets, key derivation and signatures (Spec §3, §4, §5 join, §12).

use crate::{GroupId, Pid, Result};

/// Fresh 32-byte secret from the platform CSPRNG (used for `GK`, `AS`, `seed`).
pub fn generate_secret() -> Result<[u8; 32]> {
    todo!()
}

/// `admin_hash = H("wichtel/v1/admin-hash" ‖ AS)` (Spec §3).
pub fn admin_hash(admin_secret: &[u8; 32]) -> [u8; 32] {
    todo!()
}

/// `auth_hash = H("wichtel/v1/auth-hash" ‖ tok)` (Spec §4).
pub fn auth_hash(token: &[u8; 32]) -> [u8; 32] {
    todo!()
}

/// `pid = H("wichtel/v1/pid" ‖ gid ‖ IPK)[0..16]` (Spec §3).
pub fn pid_from_ipk(gid: &GroupId, ipk: &[u8; 32]) -> Pid {
    todo!()
}

/// Public identity of a participant as stored on the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicIdentity {
    pub pid: Pid,
    /// Ed25519 public key.
    pub ipk: [u8; 32],
    /// X25519 public key.
    pub idh: [u8; 32],
}

/// Long-term secrets of one participant in one group, derived from `seed` (Spec §4).
/// Zeroized on drop.
pub struct ParticipantKeys {
    // Implementation detail (A1): prk, isk, idh, tok, gid.
    _private: (),
}

impl ParticipantKeys {
    /// Derive all long-term keys from `seed` for group `gid`.
    pub fn derive(seed: &[u8; 32], gid: &GroupId) -> Result<Self> {
        todo!()
    }

    /// Public part (`pid`, `IPK`, `IDH`).
    pub fn public(&self) -> PublicIdentity {
        todo!()
    }

    /// Bearer token `tok`.
    pub fn auth_token(&self) -> [u8; 32] {
        todo!()
    }

    /// `join_sig` over `H("wichtel/v1/join" ‖ gid ‖ IPK ‖ IDH ‖ auth_hash ‖ lp(enc_name) ‖ lp(enc_wish))`.
    pub fn sign_join(&self, enc_name: &[u8], enc_wish: &[u8]) -> [u8; 64] {
        todo!()
    }

    /// `upload_sig` (Spec §12) for `kind` 1 (roles) or 2 (self-draw + reveals).
    pub fn sign_upload(&self, kind: UploadKind, round: u32, body: &[u8]) -> [u8; 64] {
        todo!()
    }
}

/// Upload kind for [`ParticipantKeys::sign_upload`] / [`verify_upload`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum UploadKind {
    Roles = 1,
    Reveal = 2,
}

/// Server side: verify a join request (signature, low-order check of `IDH`, `pid` derivation).
/// Returns the derived `pid`.
pub fn verify_join(
    gid: &GroupId,
    ipk: &[u8; 32],
    idh: &[u8; 32],
    auth_hash: &[u8; 32],
    enc_name: &[u8],
    enc_wish: &[u8],
    join_sig: &[u8; 64],
) -> Result<Pid> {
    todo!()
}

/// Server side: verify an upload signature (Spec §12).
pub fn verify_upload(
    gid: &GroupId,
    pid: &Pid,
    ipk: &[u8; 32],
    kind: UploadKind,
    round: u32,
    body: &[u8],
    sig: &[u8; 64],
) -> Result<()> {
    todo!()
}

/// Constant-time equality for hashes/tokens.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    todo!()
}
