//! wasm-bindgen bindings for `wichtel-core`.
//!
//! The exported functions implement the contract `web/src/wasm-api.ts` (`WichtelWasm`).
//! Byte values are `Uint8Array` in both directions (copies; no views into WASM memory).
//!
//! Errors are thrown as JS `Error` objects with `name = "WichtelError"` and a stable string
//! `code` (see [`error`] and the TypeScript type `WichtelErrorCode`). No export panics on
//! foreign input; there is no panic hook.

#![forbid(unsafe_code)]

mod convert;
mod error;
mod state;

use wasm_bindgen::prelude::*;
use wichtel_core::dcnet::{build_roles_vector, evaluate_roles, own_positions};
use wichtel_core::gk::{self, GkContext};
use wichtel_core::keys::{self, ParticipantKeys, UploadKind};
use wichtel_core::reveal::{build_reveal_upload, open_result, select_attempt};
use wichtel_core::roster::{self, Roster, group_context};
use wichtel_core::{GroupId, L_SD, N_MAX, N_MIN, T_ATTEMPTS};

use crate::convert::{bytes, fixed, fixed_ref, object, u32_arg};
use crate::error::{Result, STATE_MISMATCH, WasmError};

#[wasm_bindgen(typescript_custom_section)]
const TS_TYPES: &str = r#"
/** Stable error codes (`err.code` of a thrown `WichtelError`). */
export type WichtelErrorCode =
  | "INVALID_LENGTH" | "INVALID_KEY" | "BAD_SIGNATURE" | "DECRYPTION_FAILED"
  | "INVALID_ENCODING" | "INVALID_PARTICIPANT_COUNT" | "NOT_IN_ROSTER" | "OWN_ROLE_MISSING"
  | "COLLISION" | "NO_VALID_ATTEMPT" | "ATTEMPT_MISMATCH" | "REVEAL_COUNT" | "RNG_UNAVAILABLE"
  | "INVALID_ARGUMENT" | "INVALID_STATE" | "STATE_MISMATCH";

export interface RosterEntryInput {
  pid: Uint8Array;
  ipk: Uint8Array;
  idh: Uint8Array;
  encName: Uint8Array;
}

export interface RolesEvaluation {
  valid: boolean;
  attemptValid: boolean[];
  ownRoleMissing: boolean;
  state: Uint8Array;
}

export interface DrawResultJs {
  recipientPid: Uint8Array;
  note: string;
}

export interface RevealInput {
  pid: Uint8Array;
  ciphertext: Uint8Array;
}
"#;

// ---------------------------------------------------------------------------------------------
// Basics
// ---------------------------------------------------------------------------------------------

/// Protocol version string, e.g. for display and compatibility checks.
#[wasm_bindgen(js_name = protocolVersion)]
pub fn protocol_version() -> String {
    "wichtel/v1".to_string()
}

/// Number of participants allowed: `[N_MIN, N_MAX]`.
#[wasm_bindgen(js_name = participantLimits, unchecked_return_type = "[number, number]")]
pub fn participant_limits() -> js_sys::Array {
    js_sys::Array::of2(&(N_MIN as u32).into(), &(N_MAX as u32).into())
}

/// 32 random bytes from the browser CSPRNG (GK, AS, seed).
#[wasm_bindgen(js_name = generateSecret)]
pub fn generate_secret() -> Result<Vec<u8>> {
    Ok(keys::generate_secret()?.to_vec())
}

/// `H("wichtel/v1/admin-hash" ‖ AS)`.
#[wasm_bindgen(js_name = adminHash)]
pub fn admin_hash(admin_secret: &[u8]) -> Result<Vec<u8>> {
    let a = fixed_ref(admin_secret, "admin secret must be 32 bytes")?;
    Ok(keys::admin_hash(a).to_vec())
}

// ---------------------------------------------------------------------------------------------
// Participant keys
// ---------------------------------------------------------------------------------------------

/// Derived long-term keys of one participant in one group. Secrets stay in WASM memory and are
/// zeroized by `free()` (or by the finalizer).
#[wasm_bindgen(js_name = ParticipantKeysHandle)]
pub struct KeysHandle {
    keys: ParticipantKeys,
}

#[wasm_bindgen(js_class = ParticipantKeysHandle)]
impl KeysHandle {
    /// 16 B.
    #[wasm_bindgen(getter)]
    pub fn pid(&self) -> Vec<u8> {
        self.keys.public().pid.0.to_vec()
    }

    /// Ed25519 public key, 32 B.
    #[wasm_bindgen(getter)]
    pub fn ipk(&self) -> Vec<u8> {
        self.keys.public().ipk.to_vec()
    }

    /// X25519 public key, 32 B.
    #[wasm_bindgen(getter)]
    pub fn idh(&self) -> Vec<u8> {
        self.keys.public().idh.to_vec()
    }

    /// Bearer token `tok`, 32 B.
    #[wasm_bindgen(getter, js_name = authToken)]
    pub fn auth_token(&self) -> Vec<u8> {
        self.keys.auth_token().to_vec()
    }

    /// Spec §5 join signature (64 B).
    #[wasm_bindgen(js_name = signJoin)]
    pub fn sign_join(&self, enc_name: &[u8], enc_wish: &[u8]) -> Vec<u8> {
        self.keys.sign_join(enc_name, enc_wish).to_vec()
    }

    /// Spec §12 upload signature (64 B); `kind` 1 = roles, 2 = reveal.
    #[wasm_bindgen(js_name = signUpload)]
    pub fn sign_upload(
        &self,
        #[wasm_bindgen(unchecked_param_type = "1 | 2")] kind: f64,
        round: f64,
        body: &[u8],
    ) -> Result<Vec<u8>> {
        let kind = if kind == 1.0 {
            UploadKind::Roles
        } else if kind == 2.0 {
            UploadKind::Reveal
        } else {
            return Err(WasmError::arg("kind must be 1 or 2"));
        };
        let round = u32_arg(round, "round must be an integer ≥ 0")?;
        Ok(self.keys.sign_upload(kind, round, body).to_vec())
    }
}

/// Derive all long-term keys from `seed` for group `gid` (Spec §4).
#[wasm_bindgen(js_name = deriveKeys)]
pub fn derive_keys(seed: &[u8], gid: &[u8]) -> Result<KeysHandle> {
    let seed = fixed_ref(seed, "seed must be 32 bytes")?;
    let gid = convert::gid(gid)?;
    Ok(KeysHandle {
        keys: ParticipantKeys::derive(seed, &gid)?,
    })
}

// ---------------------------------------------------------------------------------------------
// Group data (Spec §6)
// ---------------------------------------------------------------------------------------------

/// Owned copies of the AAD parts of a [`GkContext`].
enum GkCtxOwned {
    Meta(GroupId),
    Name(GroupId, wichtel_core::Pid, [u8; 32], [u8; 32]),
    Wish(GroupId, wichtel_core::Pid, [u8; 32], [u8; 32]),
}

impl GkCtxOwned {
    fn parse(
        context: &str,
        gid: &[u8],
        pid: Option<Vec<u8>>,
        ipk: Option<Vec<u8>>,
        idh: Option<Vec<u8>>,
    ) -> Result<Self> {
        let gid = convert::gid(gid)?;
        let ids = || -> Result<_> {
            const MSG: &str = "pid, ipk and idh are required for context name/wish";
            let (Some(pid), Some(ipk), Some(idh)) = (pid, ipk, idh) else {
                return Err(WasmError::arg(MSG));
            };
            Ok((
                convert::pid(&pid)?,
                fixed(&ipk, "ipk must be 32 bytes")?,
                fixed(&idh, "idh must be 32 bytes")?,
            ))
        };
        match context {
            "meta" => Ok(Self::Meta(gid)),
            "name" => ids().map(|(p, i, d)| Self::Name(gid, p, i, d)),
            "wish" => ids().map(|(p, i, d)| Self::Wish(gid, p, i, d)),
            _ => Err(WasmError::arg(
                "context must be \"meta\", \"name\" or \"wish\"",
            )),
        }
    }

    fn ctx(&self) -> GkContext<'_> {
        match self {
            Self::Meta(gid) => GkContext::Meta { gid },
            Self::Name(gid, pid, ipk, idh) => GkContext::Name { gid, pid, ipk, idh },
            Self::Wish(gid, pid, ipk, idh) => GkContext::Wish { gid, pid, ipk, idh },
        }
    }
}

/// Encrypt group data under `GK` (Spec §6). Output `nonce ‖ ct ‖ tag`.
#[wasm_bindgen(js_name = gkSeal)]
#[allow(clippy::too_many_arguments)]
pub fn gk_seal(
    gk: &[u8],
    #[wasm_bindgen(unchecked_param_type = "\"meta\" | \"name\" | \"wish\"")] context: &str,
    gid: &[u8],
    data: &[u8],
    pid: Option<Vec<u8>>,
    ipk: Option<Vec<u8>>,
    idh: Option<Vec<u8>>,
) -> Result<Vec<u8>> {
    let gk = fixed_ref(gk, "GK must be 32 bytes")?;
    let ctx = GkCtxOwned::parse(context, gid, pid, ipk, idh)?;
    Ok(gk::seal(gk, ctx.ctx(), data)?)
}

/// Decrypt group data under `GK` (Spec §6).
#[wasm_bindgen(js_name = gkOpen)]
#[allow(clippy::too_many_arguments)]
pub fn gk_open(
    gk: &[u8],
    #[wasm_bindgen(unchecked_param_type = "\"meta\" | \"name\" | \"wish\"")] context: &str,
    gid: &[u8],
    sealed: &[u8],
    pid: Option<Vec<u8>>,
    ipk: Option<Vec<u8>>,
    idh: Option<Vec<u8>>,
) -> Result<Vec<u8>> {
    let gk = fixed_ref(gk, "GK must be 32 bytes")?;
    let ctx = GkCtxOwned::parse(context, gid, pid, ipk, idh)?;
    Ok(gk::open(gk, ctx.ctx(), sealed)?)
}

// ---------------------------------------------------------------------------------------------
// Roster (Spec §5)
// ---------------------------------------------------------------------------------------------

/// Fingerprint of the roster: 8 words (Spec §5).
#[wasm_bindgen]
pub fn fingerprint(
    gid: &[u8],
    #[wasm_bindgen(unchecked_param_type = "RosterEntryInput[]")] roster: JsValue,
) -> Result<Vec<String>> {
    let gid = convert::gid(gid)?;
    let roster = convert::roster(&roster)?;
    Ok(roster::fingerprint(&gid, &roster)
        .iter()
        .map(|w| (*w).to_owned())
        .collect())
}

/// Common arguments of the round functions.
struct RoundArgs {
    gid: GroupId,
    round: u32,
    roster: Roster,
}

impl RoundArgs {
    fn parse(gid: &[u8], round: f64, roster: &JsValue) -> Result<Self> {
        Ok(Self {
            gid: convert::gid(gid)?,
            round: u32_arg(round, "round must be an integer ≥ 0")?,
            roster: convert::roster(roster)?,
        })
    }

    fn g_r(&self) -> [u8; 32] {
        group_context(&self.gid, self.round, &self.roster)
    }

    /// Decode `evaluationState` and check that it belongs to this gid/round/roster.
    fn state(&self, bytes: &[u8]) -> Result<state::EvalState> {
        let s = state::decode(bytes)?;
        if s.g_r != self.g_r() || s.outcome.n() != self.roster.len() {
            return Err(WasmError::new(
                STATE_MISMATCH,
                "evaluation state belongs to another round or roster",
            ));
        }
        Ok(s)
    }
}

// ---------------------------------------------------------------------------------------------
// Step 1 (Spec §7)
// ---------------------------------------------------------------------------------------------

/// Masked role vector `V_i` (`2688·n²` bytes). Heavy – call from a Web Worker.
#[wasm_bindgen(js_name = buildRolesVector)]
pub fn build_roles_vector_js(
    keys: &KeysHandle,
    gid: &[u8],
    round: f64,
    #[wasm_bindgen(unchecked_param_type = "RosterEntryInput[]")] roster: JsValue,
) -> Result<Vec<u8>> {
    let a = RoundArgs::parse(gid, round, &roster)?;
    Ok(build_roles_vector(&keys.keys, &a.gid, a.round, &a.roster)?)
}

/// Evaluate `R` (Spec §7.4) and the own positions.
///
/// - Collision in E ⇒ `valid = false`, all attempts invalid, empty `state`.
/// - Own role missing ⇒ `valid = true`, `ownRoleMissing = true`, empty `state`.
/// - Otherwise `state` is the opaque input for `buildRevealUpload`, `selectAttempt`,
///   `openResult`.
///
/// Throws for malformed input (wrong length of `r`, keys not in roster, …).
#[wasm_bindgen(js_name = evaluateRoles, unchecked_return_type = "RolesEvaluation")]
pub fn evaluate_roles_js(
    keys: &KeysHandle,
    gid: &[u8],
    round: f64,
    #[wasm_bindgen(unchecked_param_type = "RosterEntryInput[]")] roster: JsValue,
    r: &[u8],
) -> Result<JsValue> {
    let a = RoundArgs::parse(gid, round, &roster)?;
    let g_r = a.g_r();
    let result = |valid: bool, attempts: &[bool], missing: bool, st: &[u8]| {
        let attempt_valid = js_sys::Array::new();
        for &v in attempts {
            attempt_valid.push(&JsValue::from_bool(v));
        }
        object(&[
            ("valid", JsValue::from_bool(valid)),
            ("attemptValid", attempt_valid.into()),
            ("ownRoleMissing", JsValue::from_bool(missing)),
            ("state", bytes(st)),
        ])
    };
    let outcome = match evaluate_roles(&g_r, a.roster.len(), r) {
        Ok(o) => o,
        Err(wichtel_core::Error::Collision) => {
            // Still reject a roster that does not contain us (same checks as below).
            own_membership(&keys.keys, &a)?;
            return Ok(result(false, &[false; T_ATTEMPTS], false, &[]));
        }
        Err(e) => return Err(e.into()),
    };
    let attempts: Vec<bool> = (1..=T_ATTEMPTS as u8)
        .map(|t| outcome.attempt_valid(t))
        .collect();
    match own_positions(&keys.keys, &a.gid, a.round, &a.roster, r, &outcome) {
        Ok(own) => Ok(result(
            true,
            &attempts,
            false,
            &state::encode(&g_r, &outcome, &own)?,
        )),
        Err(wichtel_core::Error::OwnRoleMissing) => Ok(result(true, &attempts, true, &[])),
        Err(e) => Err(e.into()),
    }
}

/// The own entry must be in the roster with the own keys (`NOT_IN_ROSTER` otherwise) and every
/// `pid` must derive from its `IPK` (`INVALID_KEY`), mirroring the core's client-side checks.
fn own_membership(keys: &ParticipantKeys, a: &RoundArgs) -> Result<()> {
    let me = keys.public();
    // A key set derived for another gid has a pid that does not derive from (gid, IPK).
    if me.pid != keys::pid_from_ipk(&a.gid, &me.ipk) {
        return Err(wichtel_core::Error::NotInRoster.into());
    }
    for e in a.roster.entries() {
        if e.pid != keys::pid_from_ipk(&a.gid, &e.ipk) {
            return Err(wichtel_core::Error::InvalidKey.into());
        }
    }
    let own = a
        .roster
        .index_of(&me.pid)
        .map(|i| &a.roster.entries()[i])
        .ok_or(wichtel_core::Error::NotInRoster)?;
    if own.ipk != me.ipk || own.idh != me.idh {
        return Err(wichtel_core::Error::NotInRoster.into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Step 2 and result (Spec §9)
// ---------------------------------------------------------------------------------------------

/// Step-2 upload body `SD_i ‖ C_{i,1…16}` (9216 B).
#[wasm_bindgen(js_name = buildRevealUpload)]
pub fn build_reveal_upload_js(
    keys: &KeysHandle,
    gid: &[u8],
    round: f64,
    #[wasm_bindgen(unchecked_param_type = "RosterEntryInput[]")] roster: JsValue,
    evaluation_state: &[u8],
    note: &str,
) -> Result<Vec<u8>> {
    let a = RoundArgs::parse(gid, round, &roster)?;
    let s = a.state(evaluation_state)?;
    Ok(build_reveal_upload(
        &keys.keys, &a.gid, a.round, &a.roster, &s.outcome, &s.own, note,
    )?)
}

/// `t*` from the released self-draw aggregate `SD` (256 B); `null` ⇒ no valid attempt (next
/// round). The caller MUST compare it with the server's `t*`.
#[wasm_bindgen(js_name = selectAttempt, unchecked_return_type = "number | null")]
pub fn select_attempt_js(evaluation_state: &[u8], selfdraw_aggregate: &[u8]) -> Result<JsValue> {
    let s = state::decode(evaluation_state)?;
    if selfdraw_aggregate.len() != L_SD {
        return Err(WasmError::new(
            error::INVALID_LENGTH,
            "self-draw aggregate must be 256 bytes",
        ));
    }
    Ok(match select_attempt(&s.outcome, selfdraw_aggregate) {
        Some(t) => JsValue::from(t),
        None => JsValue::NULL,
    })
}

/// Open the released reveals of `t*` (Spec §9.3). Throws on disturbance (`REVEAL_COUNT`,
/// `ATTEMPT_MISMATCH`, …).
#[wasm_bindgen(js_name = openResult, unchecked_return_type = "DrawResultJs")]
#[allow(clippy::too_many_arguments)]
pub fn open_result_js(
    keys: &KeysHandle,
    gid: &[u8],
    round: f64,
    #[wasm_bindgen(unchecked_param_type = "RosterEntryInput[]")] roster: JsValue,
    evaluation_state: &[u8],
    t_star: f64,
    #[wasm_bindgen(unchecked_param_type = "RevealInput[]")] reveals: JsValue,
) -> Result<JsValue> {
    let a = RoundArgs::parse(gid, round, &roster)?;
    let s = a.state(evaluation_state)?;
    let t_star = u32_arg(t_star, "tStar must be an integer")?;
    let t_star = u8::try_from(t_star).map_err(|_| wichtel_core::Error::AttemptMismatch)?;
    let reveals = convert::reveals(&reveals)?;
    let res = open_result(
        &keys.keys, &a.gid, a.round, &a.roster, &s.outcome, &s.own, t_star, &reveals,
    )?;
    Ok(object(&[
        ("recipientPid", bytes(&res.recipient.0)),
        ("note", JsValue::from_str(&res.note)),
    ]))
}
