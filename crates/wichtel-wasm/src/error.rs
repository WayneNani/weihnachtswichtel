//! Errors at the JS boundary.
//!
//! Every fallible export throws a JS `Error` with
//! - `name = "WichtelError"`,
//! - `code` = one of the stable codes below (string, part of the API contract),
//! - `message = "<code>: <English description>"`.
//!
//! Messages never contain secret data or positions (same rule as `wichtel_core::Error`).

use wasm_bindgen::prelude::*;

/// Error carried to JS. `code` is stable; `msg` is informational only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmError {
    pub code: &'static str,
    pub msg: &'static str,
}

impl WasmError {
    pub const fn new(code: &'static str, msg: &'static str) -> Self {
        Self { code, msg }
    }

    /// Argument has the wrong JS type or shape (not a `Uint8Array`, missing field, …).
    pub const fn arg(msg: &'static str) -> Self {
        Self::new(INVALID_ARGUMENT, msg)
    }
}

// Codes mapped 1:1 from `wichtel_core::Error`.
pub const INVALID_LENGTH: &str = "INVALID_LENGTH";
pub const INVALID_KEY: &str = "INVALID_KEY";
pub const BAD_SIGNATURE: &str = "BAD_SIGNATURE";
pub const DECRYPTION_FAILED: &str = "DECRYPTION_FAILED";
pub const INVALID_ENCODING: &str = "INVALID_ENCODING";
pub const INVALID_PARTICIPANT_COUNT: &str = "INVALID_PARTICIPANT_COUNT";
pub const NOT_IN_ROSTER: &str = "NOT_IN_ROSTER";
pub const OWN_ROLE_MISSING: &str = "OWN_ROLE_MISSING";
pub const COLLISION: &str = "COLLISION";
pub const NO_VALID_ATTEMPT: &str = "NO_VALID_ATTEMPT";
pub const ATTEMPT_MISMATCH: &str = "ATTEMPT_MISMATCH";
pub const REVEAL_COUNT: &str = "REVEAL_COUNT";
pub const RNG_UNAVAILABLE: &str = "RNG_UNAVAILABLE";
pub const CONTACT_COUNT: &str = "CONTACT_COUNT";
// Codes of this crate.
/// Wrong JS type/shape of an argument.
pub const INVALID_ARGUMENT: &str = "INVALID_ARGUMENT";
/// `evaluationState` cannot be decoded (corrupt, truncated, other version).
pub const INVALID_STATE: &str = "INVALID_STATE";
/// `evaluationState` belongs to a different gid/round/roster.
pub const STATE_MISMATCH: &str = "STATE_MISMATCH";

impl From<wichtel_core::Error> for WasmError {
    fn from(e: wichtel_core::Error) -> Self {
        use wichtel_core::Error as E;
        let code = match e {
            E::InvalidLength => INVALID_LENGTH,
            E::InvalidKey => INVALID_KEY,
            E::BadSignature => BAD_SIGNATURE,
            E::DecryptionFailed => DECRYPTION_FAILED,
            E::InvalidEncoding => INVALID_ENCODING,
            E::InvalidParticipantCount => INVALID_PARTICIPANT_COUNT,
            E::NotInRoster => NOT_IN_ROSTER,
            E::OwnRoleMissing => OWN_ROLE_MISSING,
            E::Collision => COLLISION,
            E::NoValidAttempt => NO_VALID_ATTEMPT,
            E::AttemptMismatch => ATTEMPT_MISMATCH,
            E::RevealCount => REVEAL_COUNT,
            E::Rng => RNG_UNAVAILABLE,
            E::ContactCount => CONTACT_COUNT,
        };
        Self {
            code,
            msg: core_message(e),
        }
    }
}

/// Static description of a core error (its `Display` text, without allocation per variant).
fn core_message(e: wichtel_core::Error) -> &'static str {
    use wichtel_core::Error as E;
    match e {
        E::InvalidLength => "invalid length",
        E::InvalidKey => "invalid key (low order / non-contributory)",
        E::BadSignature => "signature verification failed",
        E::DecryptionFailed => "decryption failed",
        E::InvalidEncoding => "invalid padding or encoding",
        E::InvalidParticipantCount => "participant count out of range",
        E::NotInRoster => "participant not in roster",
        E::OwnRoleMissing => "own role missing from result (disturbance)",
        E::Collision => "area E invalid (collision)",
        E::NoValidAttempt => "no valid attempt without self-draw",
        E::AttemptMismatch => "server reported a different t*",
        E::RevealCount => "expected exactly one valid reveal",
        E::Rng => "randomness unavailable",
        E::ContactCount => "more than one valid contact",
    }
}

impl From<WasmError> for JsValue {
    fn from(e: WasmError) -> Self {
        let err = js_sys::Error::new(&format!("{}: {}", e.code, e.msg));
        err.set_name("WichtelError");
        // Setting a property on a fresh Error object cannot fail; ignore the result anyway.
        let _ = js_sys::Reflect::set(&err, &JsValue::from_str("code"), &JsValue::from_str(e.code));
        err.into()
    }
}

pub type Result<T> = core::result::Result<T, WasmError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_core_error_has_a_distinct_code() {
        use wichtel_core::Error as E;
        let all = [
            E::InvalidLength,
            E::InvalidKey,
            E::BadSignature,
            E::DecryptionFailed,
            E::InvalidEncoding,
            E::InvalidParticipantCount,
            E::NotInRoster,
            E::OwnRoleMissing,
            E::Collision,
            E::NoValidAttempt,
            E::AttemptMismatch,
            E::RevealCount,
            E::Rng,
            E::ContactCount,
        ];
        let mut codes: Vec<&str> = all.iter().map(|&e| WasmError::from(e).code).collect();
        for e in all {
            assert_eq!(core_message(e), e.to_string());
        }
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
    }
}
