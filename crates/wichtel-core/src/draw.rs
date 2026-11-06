//! `ρ`, `σ_t` and unbiased sampling (Spec §7.2, §8).

/// Unbiased integer in `0..m` from a ChaCha20 keystream read as big-endian `u32`s
/// (rejection sampling, Spec §7.2).
pub struct UniformSampler {
    // Implementation detail (A1): keystream state.
    _private: (),
}

impl UniformSampler {
    /// Stream `ChaCha20(key, nonce)`.
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        todo!()
    }

    /// Next uniform value in `0..m` (`m ≥ 1`).
    pub fn uniform(&mut self, m: u32) -> u32 {
        todo!()
    }
}

/// `ρ = H("wichtel/v1/rho" ‖ G_r ‖ R)`.
pub fn rho(g_r: &[u8; 32], r: &[u8]) -> [u8; 32] {
    todo!()
}

/// `σ_t` as a vector: `sigma[p]` = E-position that giver position `p` gives to (Spec §8).
/// `t ∈ 1…16`.
pub fn sigma(rho: &[u8; 32], t: u8, n: usize) -> Vec<u16> {
    todo!()
}

/// Inverse permutation.
pub fn invert(perm: &[u16]) -> Vec<u16> {
    todo!()
}
