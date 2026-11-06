//! AEAD for group data under the group key `GK` (Spec §6).

use crate::{GroupId, Pid, Result};

/// What is being encrypted; determines the AAD and size limit.
#[derive(Clone, Copy, Debug)]
pub enum GkContext<'a> {
    /// `"wichtel/v1/meta" ‖ gid`, limit `META_MAX`.
    Meta { gid: &'a GroupId },
    /// `"wichtel/v1/name" ‖ gid ‖ pid ‖ IPK ‖ IDH`, limit `NAME_MAX`.
    Name {
        gid: &'a GroupId,
        pid: &'a Pid,
        ipk: &'a [u8; 32],
        idh: &'a [u8; 32],
    },
    /// `"wichtel/v1/wish" ‖ gid ‖ pid ‖ IPK ‖ IDH`, limit `WISH_MAX`.
    Wish {
        gid: &'a GroupId,
        pid: &'a Pid,
        ipk: &'a [u8; 32],
        idh: &'a [u8; 32],
    },
}

/// Encrypt with a fresh random nonce. Output: `nonce ‖ ct ‖ tag`.
pub fn seal(gk: &[u8; 32], ctx: GkContext<'_>, data: &[u8]) -> Result<Vec<u8>> {
    todo!()
}

/// Like [`seal`] with an explicit nonce (test vectors only).
pub fn seal_with_nonce(
    gk: &[u8; 32],
    ctx: GkContext<'_>,
    data: &[u8],
    nonce: &[u8; 12],
) -> Result<Vec<u8>> {
    todo!()
}

/// Decrypt and check padding.
pub fn open(gk: &[u8; 32], ctx: GkContext<'_>, sealed: &[u8]) -> Result<Vec<u8>> {
    todo!()
}
