//! Step 1: role vector (DC-net) and evaluation of the aggregate `R` (Spec §7).

use crate::keys::ParticipantKeys;
use crate::roster::Roster;
use crate::{GroupId, Result, T_ATTEMPTS};

/// Per-round secrets of the local participant (Spec §4, round-specific part).
pub struct RoundSecrets {
    // Implementation detail (A1): rp, gp[16], slot indices, sd values, rng key.
    _private: (),
}

impl RoundSecrets {
    /// Derive from long-term keys and `G_r`; draws the slots via [`crate::draw::uniform`].
    pub fn derive(keys: &ParticipantKeys, g_r: &[u8; 32], n: usize) -> Result<Self> {
        todo!()
    }
}

/// Build the masked role vector `V_i` (length `roles_vector_len(n)`).
pub fn build_roles_vector(
    keys: &ParticipantKeys,
    gid: &GroupId,
    round: u32,
    roster: &Roster,
) -> Result<Vec<u8>> {
    todo!()
}

/// XOR `src` into `acc` (server aggregation). Both must have equal length.
pub fn xor_into(acc: &mut [u8], src: &[u8]) -> Result<()> {
    todo!()
}

/// Public evaluation of `R` – identical on server and client (Spec §7.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RolesOutcome {
    /// `RP[e]` for E-positions `0…n−1`.
    pub recipients: Vec<[u8; 32]>,
    /// For each attempt t = 1…16 (index t−1): `Some(GP_t[p])` for p = 0…n−1 if valid.
    pub givers: [Option<Vec<[u8; 32]>>; T_ATTEMPTS],
    /// `ρ` (Spec §8).
    pub rho: [u8; 32],
}

/// Evaluate `R`. Returns `Err(Error::Collision)` if area E is invalid.
pub fn evaluate_roles(g_r: &[u8; 32], n: usize, r: &[u8]) -> Result<RolesOutcome> {
    todo!()
}

/// Positions of the local participant in an outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnPositions {
    /// E-position `e_i`.
    pub e: usize,
    /// `p_{i,t}` for valid attempts (index t−1), `None` for invalid ones.
    pub p: [Option<usize>; T_ATTEMPTS],
}

/// Client check: own `RP`/`GP` present at own slots (else `Err(OwnRoleMissing)`).
pub fn own_positions(
    keys: &ParticipantKeys,
    gid: &GroupId,
    round: u32,
    roster: &Roster,
    r: &[u8],
    outcome: &RolesOutcome,
) -> Result<OwnPositions> {
    todo!()
}
