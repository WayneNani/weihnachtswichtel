//! AEAD for group data under the group key `GK` (Spec §6).

use crate::util::{SecretVec, hkdf32};
use crate::{Error, GroupId, META_MAX, NAME_MAX, Pid, Result, WISH_MAX};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

/// Nonce length.
const L_NONCE: usize = 12;
/// Tag length.
const L_TAG: usize = 16;
/// Padding block size.
const PAD_BLOCK: usize = 32;

/// The fixed group id `Z(16)` used in the AAD of `enc_meta` (Spec §6, the real `gid` is only
/// assigned by the server after `enc_meta` was sent).
pub const META_GID: GroupId = GroupId([0u8; 16]);

/// What is being encrypted; determines the AAD and size limit.
#[derive(Clone, Copy, Debug)]
pub enum GkContext<'a> {
    /// `"wichtel/v1/meta" ‖ gid`, limit `META_MAX`. Per Spec §6 the AAD uses the fixed
    /// null id `Z(16)`: pass [`META_GID`].
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

impl GkContext<'_> {
    fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(15 + 16 + 16 + 64);
        match self {
            GkContext::Meta { gid } => {
                aad.extend_from_slice(b"wichtel/v1/meta");
                aad.extend_from_slice(&gid.0);
            }
            GkContext::Name { gid, pid, ipk, idh } | GkContext::Wish { gid, pid, ipk, idh } => {
                aad.extend_from_slice(if matches!(self, GkContext::Name { .. }) {
                    b"wichtel/v1/name"
                } else {
                    b"wichtel/v1/wish"
                });
                aad.extend_from_slice(&gid.0);
                aad.extend_from_slice(&pid.0);
                aad.extend_from_slice(*ipk);
                aad.extend_from_slice(*idh);
            }
        }
        aad
    }

    fn limit(&self) -> usize {
        match self {
            GkContext::Meta { .. } => META_MAX,
            GkContext::Name { .. } => NAME_MAX,
            GkContext::Wish { .. } => WISH_MAX,
        }
    }
}

fn cipher(gk: &[u8; 32]) -> ChaCha20Poly1305 {
    let k = hkdf32(b"wichtel/v1/gk", gk, &[b"wichtel/v1/gk-aead"]);
    ChaCha20Poly1305::new((&*k).into())
}

/// Padded length of `data_len` bytes: `2 + data_len` rounded up to a multiple of 32.
fn padded_len(data_len: usize) -> usize {
    (2 + data_len).div_ceil(PAD_BLOCK) * PAD_BLOCK
}

/// Encrypt with a fresh random nonce. Output: `nonce ‖ ct ‖ tag`.
pub fn seal(gk: &[u8; 32], ctx: GkContext<'_>, data: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; L_NONCE];
    getrandom::fill(&mut nonce).map_err(|_| Error::Rng)?;
    seal_with_nonce(gk, ctx, data, &nonce)
}

/// Like [`seal`] with an explicit nonce (test vectors only).
pub fn seal_with_nonce(
    gk: &[u8; 32],
    ctx: GkContext<'_>,
    data: &[u8],
    nonce: &[u8; 12],
) -> Result<Vec<u8>> {
    if data.len() > ctx.limit() {
        return Err(Error::InvalidLength);
    }
    // limit ≤ META_MAX < 2^16.
    let mut padded = SecretVec(vec![0u8; padded_len(data.len())]);
    padded[..2].copy_from_slice(&(data.len() as u16).to_be_bytes());
    padded[2..2 + data.len()].copy_from_slice(data);
    let aad = ctx.aad();
    let ct = cipher(gk)
        .encrypt(
            nonce.into(),
            Payload {
                msg: &padded[..],
                aad: &aad,
            },
        )
        .map_err(|_| Error::InvalidLength)?;
    let mut out = Vec::with_capacity(L_NONCE + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt and check padding.
///
/// Errors: `InvalidLength` for impossible lengths, `DecryptionFailed` for a wrong key/AAD or a
/// tampered ciphertext, `InvalidEncoding` for non-canonical padding or a length above the limit.
pub fn open(gk: &[u8; 32], ctx: GkContext<'_>, sealed: &[u8]) -> Result<Vec<u8>> {
    let max = L_NONCE + padded_len(ctx.limit()) + L_TAG;
    if sealed.len() < L_NONCE + PAD_BLOCK + L_TAG || sealed.len() > max {
        return Err(Error::InvalidLength);
    }
    let (nonce, ct) = sealed.split_at(L_NONCE);
    let nonce: &[u8; L_NONCE] = nonce.try_into().map_err(|_| Error::InvalidLength)?;
    let aad = ctx.aad();
    let padded = SecretVec(
        cipher(gk)
            .decrypt(nonce.into(), Payload { msg: ct, aad: &aad })
            .map_err(|_| Error::DecryptionFailed)?,
    );
    if padded.len() < 2 || !padded.len().is_multiple_of(PAD_BLOCK) {
        return Err(Error::InvalidEncoding);
    }
    let len = usize::from(u16::from_be_bytes([padded[0], padded[1]]));
    if len > ctx.limit() || padded_len(len) != padded.len() {
        return Err(Error::InvalidEncoding);
    }
    if padded[2 + len..].iter().any(|&b| b != 0) {
        return Err(Error::InvalidEncoding);
    }
    Ok(padded[2..2 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GK: [u8; 32] = [4u8; 32];
    const GID: GroupId = GroupId([1u8; 16]);

    fn name_ctx<'a>(pid: &'a Pid, k: &'a [u8; 32]) -> GkContext<'a> {
        GkContext::Name {
            gid: &GID,
            pid,
            ipk: k,
            idh: k,
        }
    }

    #[test]
    fn roundtrip_and_padding() {
        let pid = Pid([2; 16]);
        let k = [3u8; 32];
        for len in [0usize, 1, 29, 30, 31, 62, 64] {
            let data = vec![b'a'; len];
            let s = seal(&GK, name_ctx(&pid, &k), &data).unwrap();
            assert_eq!(s.len(), 12 + padded_len(len) + 16);
            assert_eq!((s.len() - 28) % 32, 0);
            assert_eq!(open(&GK, name_ctx(&pid, &k), &s).unwrap(), data);
        }
        assert_eq!(padded_len(30), 32);
        assert_eq!(padded_len(31), 64);
        assert_eq!(
            seal(&GK, name_ctx(&pid, &k), &[0u8; NAME_MAX + 1]),
            Err(Error::InvalidLength)
        );
        let meta = GkContext::Meta { gid: &GID };
        let s = seal(&GK, meta, &[b'x'; META_MAX]).unwrap();
        assert_eq!(open(&GK, meta, &s).unwrap().len(), META_MAX);
    }

    #[test]
    fn aad_binds_context() {
        let pid = Pid([2; 16]);
        let other = Pid([3; 16]);
        let k = [3u8; 32];
        let s = seal(&GK, name_ctx(&pid, &k), b"Anna").unwrap();
        assert_eq!(
            open(&GK, name_ctx(&other, &k), &s),
            Err(Error::DecryptionFailed)
        );
        let wish = GkContext::Wish {
            gid: &GID,
            pid: &pid,
            ipk: &k,
            idh: &k,
        };
        assert_eq!(open(&GK, wish, &s), Err(Error::DecryptionFailed));
        assert_eq!(
            open(&[5u8; 32], name_ctx(&pid, &k), &s),
            Err(Error::DecryptionFailed)
        );
        let mut t = s.clone();
        t[20] ^= 1;
        assert_eq!(
            open(&GK, name_ctx(&pid, &k), &t),
            Err(Error::DecryptionFailed)
        );
        assert_eq!(
            open(&GK, name_ctx(&pid, &k), &s[..20]),
            Err(Error::InvalidLength)
        );
    }

    #[test]
    fn rejects_bad_padding() {
        let pid = Pid([2; 16]);
        let k = [3u8; 32];
        let ctx = name_ctx(&pid, &k);
        let nonce = [9u8; 12];
        let enc = |padded: &[u8]| {
            let mut out = nonce.to_vec();
            out.extend(
                cipher(&GK)
                    .encrypt(
                        (&nonce).into(),
                        Payload {
                            msg: padded,
                            aad: &ctx.aad(),
                        },
                    )
                    .unwrap(),
            );
            out
        };
        // Non-zero filler.
        let mut p = [0u8; 32];
        p[1] = 3;
        p[2..5].copy_from_slice(b"abc");
        p[31] = 1;
        assert_eq!(open(&GK, ctx, &enc(&p)), Err(Error::InvalidEncoding));
        // Length beyond the buffer.
        let mut p = [0u8; 32];
        p[1] = 40;
        assert_eq!(open(&GK, ctx, &enc(&p)), Err(Error::InvalidEncoding));
        // Non-minimal padding.
        let mut p = [0u8; 64];
        p[1] = 3;
        assert_eq!(open(&GK, ctx, &enc(&p)), Err(Error::InvalidEncoding));
        // Canonical one is fine.
        let mut p = [0u8; 32];
        p[1] = 3;
        p[2..5].copy_from_slice(b"abc");
        assert_eq!(open(&GK, ctx, &enc(&p)).unwrap(), b"abc");
    }
}
