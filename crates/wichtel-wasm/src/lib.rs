//! wasm-bindgen bindings for `wichtel-core` (Phase-0 skeleton).
//!
//! The exported functions must match `web/src/wasm-api.ts`. Agent A4 fills this in.

#![forbid(unsafe_code)]

use wasm_bindgen::prelude::*;

/// Protocol version string, e.g. for display and compatibility checks.
#[wasm_bindgen(js_name = protocolVersion)]
pub fn protocol_version() -> String {
    "wichtel/v1".to_string()
}

/// Number of participants allowed (`[N_MIN, N_MAX]`).
#[wasm_bindgen(js_name = participantLimits)]
pub fn participant_limits() -> Vec<u32> {
    vec![wichtel_core::N_MIN as u32, wichtel_core::N_MAX as u32]
}
