//! Protocol and cryptography for the Weihnachtswichtel draw.
//!
//! This crate has **no I/O**. It is compiled natively (server, tests) and to
//! `wasm32-unknown-unknown` (browser, via `wichtel-wasm`). Everything here is
//! normatively specified in `docs/04-protokoll-spec.md`; section numbers in the
//! doc comments (e.g. "Spec §7.2") refer to that file.
//!
//! Module overview:
//! - [`keys`]: secrets, key derivation from `seed`, hashes and signatures (Spec §3, §4, §12)
//! - [`roster`]: roster ordering, group context `G_r`, fingerprint (Spec §5)
//! - [`gk`]: AEAD for group data under the group key `GK` (Spec §6)
//! - [`dcnet`]: role vector (step 1) and its evaluation (Spec §7)
//! - [`draw`]: `ρ`, `σ_t` and unbiased sampling (Spec §7.2, §8)
//! - [`reveal`]: self-draw vector, reveals, choice of `t*`, result (Spec §9)

// Phase 0 skeleton: bodies are `todo!()`. Remove this allow once implemented (agent A1).
#![allow(unused_variables)]
#![forbid(unsafe_code)]

pub mod dcnet;
pub mod draw;
pub mod gk;
pub mod keys;
pub mod reveal;
pub mod roster;
pub mod wordlist;

/// Minimum number of participants to start a draw (Spec §2).
pub const N_MIN: usize = 4;
/// Maximum number of participants (Spec §2).
pub const N_MAX: usize = 30;
/// Number of draw attempts per protocol round (Spec §2).
pub const T_ATTEMPTS: usize = 16;
/// Bytes per slot in area E (recipient roles).
pub const SLOT_E: usize = 40;
/// Bytes per slot in each area S_t (giver roles).
pub const SLOT_S: usize = 32;
/// Bytes per self-draw slot.
pub const SLOT_SD: usize = 16;
/// Length of the self-draw vector.
pub const L_SD: usize = T_ATTEMPTS * SLOT_SD;
/// Plaintext length of one reveal.
pub const L_PT: usize = 512;
/// Ciphertext length of one reveal (`enc ‖ ct ‖ tag`).
pub const L_CT: usize = 32 + L_PT + 16;
/// Length of the step-2 upload body (`SD_i ‖ C_{i,1} ‖ … ‖ C_{i,16}`).
pub const L_REVEAL_UPLOAD: usize = L_SD + T_ATTEMPTS * L_CT;
/// Maximum UTF-8 bytes of a participant name.
pub const NAME_MAX: usize = 64;
/// Maximum UTF-8 bytes of a wish list.
pub const WISH_MAX: usize = 1000;
/// Maximum bytes of the group meta JSON.
pub const META_MAX: usize = 2000;
/// Maximum UTF-8 bytes of the private note in a reveal.
pub const NOTE_MAX: usize = L_PT - 1 - 16 - 32 - 2;

/// Slots in area E for `n` participants: `16·n²`.
pub const fn m_e(n: usize) -> usize {
    16 * n * n
}

/// Slots in each area S_t for `n` participants: `4·n²`.
pub const fn m_s(n: usize) -> usize {
    4 * n * n
}

/// Length of the role vector for `n` participants: `2688·n²`.
pub const fn roles_vector_len(n: usize) -> usize {
    SLOT_E * m_e(n) + T_ATTEMPTS * SLOT_S * m_s(n)
}

/// 16-byte group id (server generated).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GroupId(pub [u8; 16]);

/// 16-byte participant id, `H("wichtel/v1/pid" ‖ gid ‖ IPK)[0..16]` (Spec §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pid(pub [u8; 16]);

/// All errors of this crate. Variants must not carry secret data or positions.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid length")]
    InvalidLength,
    #[error("invalid key (low order / non-contributory)")]
    InvalidKey,
    #[error("signature verification failed")]
    BadSignature,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("invalid padding or encoding")]
    InvalidEncoding,
    #[error("participant count out of range")]
    InvalidParticipantCount,
    #[error("participant not in roster")]
    NotInRoster,
    #[error("own role missing from result (disturbance)")]
    OwnRoleMissing,
    #[error("area E invalid (collision)")]
    Collision,
    #[error("no valid attempt without self-draw")]
    NoValidAttempt,
    #[error("server reported a different t*")]
    AttemptMismatch,
    #[error("expected exactly one valid reveal")]
    RevealCount,
    #[error("randomness unavailable")]
    Rng,
}

pub type Result<T> = core::result::Result<T, Error>;
