//! Crate-internal primitives (Spec §1): hashing, HKDF, HMAC, ChaCha20 keystream, checked X25519.

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use rand_core::{Infallible, TryCryptoRng, TryRng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{Error, Result};

/// `H(p_0 ‖ p_1 ‖ …)` (SHA-256).
pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// `HKDF-Extract(salt, ikm)` → PRK.
pub(crate) fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&prk);
    out
}

/// `HKDF-Expand(prk, info_0 ‖ info_1 ‖ …, L)` into `out` (`L = out.len() ≤ 8160`).
pub(crate) fn hkdf_expand(prk: &[u8; 32], info: &[&[u8]], out: &mut [u8]) {
    // `from_prk` only fails for PRKs shorter than the hash length, `expand` only for
    // `L > 255·32`; both are excluded by the types/call sites, so a failure is a bug.
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("PRK has hash length");
    hk.expand_multi_info(info, out)
        .expect("HKDF output length within bounds");
}

/// `HKDF(salt, ikm, info, 32)` (Extract + Expand).
pub(crate) fn hkdf32(salt: &[u8], ikm: &[u8], info: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let prk = hkdf_extract(salt, ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf_expand(&prk, info, out.as_mut());
    out
}

/// `HMAC-SHA256(k, m_0 ‖ m_1 ‖ …)`.
pub(crate) fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

/// XOR the keystream `ChaCha20(key, nonce)` (counter from 0) into `buf`.
pub(crate) fn xor_keystream(key: &[u8; 32], nonce: &[u8; 12], buf: &mut [u8]) {
    let mut c = ChaCha20::new(key.into(), nonce.into());
    c.apply_keystream(buf);
}

/// `X25519(sk, pk)`, rejecting the all-zero (non-contributory) result (Spec §1).
pub(crate) fn x25519_checked(sk: &[u8; 32], pk: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let out = Zeroizing::new(x25519_dalek::x25519(*sk, *pk));
    if bool::from(out.ct_eq(&[0u8; 32])) {
        return Err(Error::InvalidKey);
    }
    Ok(out)
}

/// `X25519(sk, 9)`.
pub(crate) fn x25519_base(sk: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*sk, x25519_dalek::X25519_BASEPOINT_BYTES)
}

/// Heap buffer that is wiped on drop (`zeroize` is used without its `alloc` feature).
pub(crate) struct SecretVec(pub(crate) Vec<u8>);

impl Drop for SecretVec {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self.0.as_mut_slice());
    }
}

impl core::ops::Deref for SecretVec {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl core::ops::DerefMut for SecretVec {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// "RNG" that hands out one fixed 32-byte value exactly once (deterministic HPKE ephemeral,
/// Spec §9.2). Any other request yields zeros and is reported by [`OnceRng::consumed_exactly`].
pub(crate) struct OnceRng<'a> {
    value: &'a [u8; 32],
    reads: usize,
    exact: bool,
}

impl<'a> OnceRng<'a> {
    pub(crate) fn new(value: &'a [u8; 32]) -> Self {
        Self {
            value,
            reads: 0,
            exact: true,
        }
    }

    /// `true` iff exactly one 32-byte read happened.
    pub(crate) fn consumed_exactly(&self) -> bool {
        self.exact && self.reads == 1
    }
}

impl TryRng for OnceRng<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Infallible> {
        self.exact = false;
        Ok(0)
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Infallible> {
        self.exact = false;
        Ok(0)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Infallible> {
        if self.reads == 0 && dst.len() == 32 {
            dst.copy_from_slice(self.value);
        } else {
            self.exact = false;
            dst.fill(0);
        }
        self.reads += 1;
        Ok(())
    }
}

impl TryCryptoRng for OnceRng<'_> {}

/// Deterministic byte stream `ChaCha20(key, Z(12))` usable as a `CryptoRng` (Spec §9.2).
///
/// Bytes are handed out strictly in stream order without discarding anything, so the
/// consumption pattern is exactly what the spec describes.
pub(crate) struct KeystreamRng(ChaCha20);

impl KeystreamRng {
    pub(crate) fn new(key: &[u8; 32]) -> Self {
        Self(ChaCha20::new(key.into(), (&[0u8; 12]).into()))
    }
}

impl TryRng for KeystreamRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.0.apply_keystream(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.0.apply_keystream(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Infallible> {
        dst.fill(0);
        self.0.apply_keystream(dst);
        Ok(())
    }
}

impl TryCryptoRng for KeystreamRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha20_rfc8439_keystream() {
        // RFC 8439 §2.4.2 uses counter 1; check block 1 of the stream with counter start 0.
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let mut buf = [0u8; 128];
        xor_keystream(&key, &nonce, &mut buf);
        // First 16 bytes of the RFC 8439 §2.4.2 keystream (block counter 1).
        let expected = [
            0x22, 0x4f, 0x51, 0xf3, 0x40, 0x1b, 0xd9, 0xe1, 0x2f, 0xde, 0x27, 0x6f, 0xb8, 0x63,
            0x1d, 0xed,
        ];
        assert_eq!(&buf[64..80], &expected);
    }

    #[test]
    fn x25519_rejects_low_order() {
        let sk = [7u8; 32];
        assert_eq!(x25519_checked(&sk, &[0u8; 32]), Err(Error::InvalidKey));
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(x25519_checked(&sk, &one), Err(Error::InvalidKey));
        assert!(x25519_checked(&sk, &x25519_base(&[9u8; 32])).is_ok());
    }

    #[test]
    fn keystream_rng_is_plain_stream() {
        let key = [3u8; 32];
        let mut a = KeystreamRng::new(&key);
        let mut x = [0u8; 50];
        rand_core::Rng::fill_bytes(&mut a, &mut x[..17]);
        rand_core::Rng::fill_bytes(&mut a, &mut x[17..]);
        let mut y = [0u8; 50];
        xor_keystream(&key, &[0u8; 12], &mut y);
        assert_eq!(x, y);
    }
}
