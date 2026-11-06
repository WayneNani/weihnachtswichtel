//! `ρ`, `σ_t` and unbiased sampling (Spec §7.2, §8).

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};

use crate::util::sha256;

/// Unbiased integer in `0..m` from a ChaCha20 keystream read as big-endian `u32`s
/// (rejection sampling, Spec §7.2).
pub struct UniformSampler {
    /// Keystream state (zeroized on drop by `chacha20`).
    stream: ChaCha20,
}

impl UniformSampler {
    /// Stream `ChaCha20(key, nonce)`.
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        Self {
            stream: ChaCha20::new(key.into(), nonce.into()),
        }
    }

    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.stream.apply_keystream(&mut b);
        u32::from_be_bytes(b)
    }

    /// Next uniform value in `0..m` (`m ≥ 1`; `m = 0` returns 0 without consuming the stream).
    pub fn uniform(&mut self, m: u32) -> u32 {
        if m == 0 {
            return 0;
        }
        // limit = floor(2^32 / m) · m, computed in u64 (limit = 2^32 for m = 1).
        let m64 = u64::from(m);
        let limit = ((1u64 << 32) / m64) * m64;
        loop {
            let u = self.next_u32();
            if u64::from(u) < limit {
                return u % m;
            }
        }
    }
}

/// `ρ = H("wichtel/v1/rho" ‖ G_r ‖ R)`.
pub fn rho(g_r: &[u8; 32], r: &[u8]) -> [u8; 32] {
    sha256(&[b"wichtel/v1/rho", g_r, r])
}

/// `σ_t` as a vector: `sigma[p]` = E-position that giver position `p` gives to (Spec §8).
/// `t ∈ 1…16`.
pub fn sigma(rho: &[u8; 32], t: u8, n: usize) -> Vec<u16> {
    let key = sha256(&[b"wichtel/v1/sigma", rho]);
    let mut nonce = [0u8; 12];
    nonce[11] = t;
    let mut w = UniformSampler::new(&key, &nonce);
    // n ≤ N_MAX in the protocol; larger values are clamped to keep the u16 cast lossless.
    let n = n.min(usize::from(u16::MAX));
    let mut a: Vec<u16> = (0..n as u16).collect();
    for k in (1..n).rev() {
        let j = w.uniform(k as u32 + 1) as usize;
        a.swap(k, j);
    }
    a
}

/// Inverse permutation. Entries of a non-permutation that are out of range are ignored.
pub fn invert(perm: &[u16]) -> Vec<u16> {
    let mut inv = vec![0u16; perm.len()];
    for (i, &p) in perm.iter().enumerate() {
        if let Some(slot) = inv.get_mut(usize::from(p)) {
            *slot = i as u16;
        }
    }
    inv
}

/// `true` iff `perm` is a permutation of `0..perm.len()`.
pub(crate) fn is_permutation(perm: &[u16]) -> bool {
    let mut seen = vec![false; perm.len()];
    for &p in perm {
        match seen.get_mut(usize::from(p)) {
            Some(s) if !*s => *s = true,
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::xor_keystream;

    #[test]
    fn sampler_reads_big_endian_u32_stream() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let mut ks = [0u8; 64];
        xor_keystream(&key, &nonce, &mut ks);
        let mut s = UniformSampler::new(&key, &nonce);
        // m = 2^31: limit = 2^32, never rejects, value = u mod 2^31.
        for k in 0..16 {
            let u = u32::from_be_bytes(ks[4 * k..4 * k + 4].try_into().unwrap());
            assert_eq!(s.uniform(1 << 31), u % (1 << 31));
        }
    }

    #[test]
    fn sampler_rejects_above_limit() {
        // m = 2^31 + 1: limit = m, so about half of all u32 are rejected.
        let key = [4u8; 32];
        let nonce = [0u8; 12];
        let mut ks = [0u8; 4096];
        xor_keystream(&key, &nonce, &mut ks);
        let m: u32 = (1 << 31) + 1;
        let expected: Vec<u32> = ks
            .chunks(4)
            .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
            .filter(|&u| u < m)
            .map(|u| u % m)
            .take(50)
            .collect();
        let mut s = UniformSampler::new(&key, &nonce);
        let got: Vec<u32> = (0..50).map(|_| s.uniform(m)).collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn sampler_edge_cases() {
        let mut s = UniformSampler::new(&[0u8; 32], &[0u8; 12]);
        assert_eq!(s.uniform(0), 0);
        assert_eq!(s.uniform(1), 0);
        for _ in 0..100 {
            assert!(s.uniform(7) < 7);
        }
    }

    #[test]
    fn sigma_is_permutation_and_invertible() {
        let rho = [9u8; 32];
        for n in [1usize, 2, 4, 30] {
            for t in 1..=16u8 {
                let s = sigma(&rho, t, n);
                assert!(is_permutation(&s));
                let inv = invert(&s);
                for p in 0..n {
                    assert_eq!(usize::from(inv[usize::from(s[p])]), p);
                }
            }
        }
        assert_ne!(sigma(&rho, 1, 30), sigma(&rho, 2, 30));
        assert!(!is_permutation(&[0, 0]));
        assert!(!is_permutation(&[0, 2]));
        assert_eq!(invert(&[5, 0]), vec![1, 0]);
    }

    #[test]
    fn sigma_is_uniform_n3() {
        // All 6 permutations of 3 elements appear about equally often over many ρ.
        let mut counts = std::collections::HashMap::new();
        for i in 0..6000u32 {
            let mut rho = [0u8; 32];
            rho[..4].copy_from_slice(&i.to_be_bytes());
            *counts.entry(sigma(&rho, 1, 3)).or_insert(0u32) += 1;
        }
        assert_eq!(counts.len(), 6);
        for c in counts.values() {
            assert!((800..1200).contains(c), "{counts:?}");
        }
    }

    #[test]
    fn rho_matches_definition() {
        let g = [1u8; 32];
        assert_eq!(rho(&g, b"abc"), sha256(&[b"wichtel/v1/rho", &g, b"abc"]));
    }
}
