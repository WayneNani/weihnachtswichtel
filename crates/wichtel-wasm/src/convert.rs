//! Conversions between JS values and core types. Never panics on foreign input.

use js_sys::{Array, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wichtel_core::roster::{Roster, RosterEntry};
use wichtel_core::{GroupId, N_MAX, Pid};

use crate::error::{INVALID_LENGTH, INVALID_PARTICIPANT_COUNT, Result, WasmError};

/// Fixed-size array from a slice (`INVALID_LENGTH` otherwise).
pub fn fixed<const N: usize>(b: &[u8], msg: &'static str) -> Result<[u8; N]> {
    b.try_into()
        .map_err(|_| WasmError::new(INVALID_LENGTH, msg))
}

/// Borrow a slice as a fixed-size array without copying (secrets: no stray stack copy).
pub fn fixed_ref<'a, const N: usize>(b: &'a [u8], msg: &'static str) -> Result<&'a [u8; N]> {
    b.try_into()
        .map_err(|_| WasmError::new(INVALID_LENGTH, msg))
}

pub fn gid(b: &[u8]) -> Result<GroupId> {
    fixed(b, "gid must be 16 bytes").map(GroupId)
}

pub fn pid(b: &[u8]) -> Result<Pid> {
    fixed(b, "pid must be 16 bytes").map(Pid)
}

/// A JS number that must be an integer in `0…=u32::MAX` (round numbers etc.).
pub fn u32_arg(x: f64, msg: &'static str) -> Result<u32> {
    if x.fract() == 0.0 && (0.0..=f64::from(u32::MAX)).contains(&x) {
        Ok(x as u32)
    } else {
        Err(WasmError::arg(msg))
    }
}

/// Elements of a JS array, at most `max` (else `too_many`).
fn array(v: &JsValue, max: usize, too_many: WasmError, msg: &'static str) -> Result<Vec<JsValue>> {
    if !Array::is_array(v) {
        return Err(WasmError::arg(msg));
    }
    let arr: &Array = v.unchecked_ref();
    let len = arr.length() as usize;
    if len > max {
        return Err(too_many);
    }
    Ok((0..len as u32).map(|i| arr.get(i)).collect())
}

/// `obj[key]` as bytes; the value must be a `Uint8Array`.
fn bytes_field(obj: &JsValue, key: &str, msg: &'static str) -> Result<Vec<u8>> {
    if !obj.is_object() {
        return Err(WasmError::arg(msg));
    }
    Reflect::get(obj, &JsValue::from_str(key))
        .ok()
        .and_then(|v| v.dyn_into::<Uint8Array>().ok())
        .map(|a| a.to_vec())
        .ok_or(WasmError::arg(msg))
}

/// `RosterEntryInput[]` → [`Roster`] (sorted, duplicates rejected; `n ≤ N_MAX`).
pub fn roster(v: &JsValue) -> Result<Roster> {
    let items = array(
        v,
        N_MAX,
        WasmError::new(INVALID_PARTICIPANT_COUNT, "participant count out of range"),
        "roster must be an array of RosterEntryInput",
    )?;
    let mut entries = Vec::with_capacity(items.len());
    for item in &items {
        const MSG: &str = "roster entry needs Uint8Array fields pid, ipk, idh, encName";
        let p = pid(&bytes_field(item, "pid", MSG)?)?;
        let ipk = fixed(&bytes_field(item, "ipk", MSG)?, "ipk must be 32 bytes")?;
        let idh = fixed(&bytes_field(item, "idh", MSG)?, "idh must be 32 bytes")?;
        let enc_name = bytes_field(item, "encName", MSG)?;
        entries.push(RosterEntry::new(p, ipk, idh, &enc_name));
    }
    Ok(Roster::new(entries)?)
}

/// `{ pid, ciphertext }[]` → `(pid, C)` pairs. More than `N_MAX` entries cannot come from an
/// honest server (`REVEAL_COUNT`).
pub fn reveals(v: &JsValue) -> Result<Vec<(Pid, Vec<u8>)>> {
    let items = array(
        v,
        N_MAX,
        WasmError::from(wichtel_core::Error::RevealCount),
        "reveals must be an array of { pid, ciphertext }",
    )?;
    items
        .iter()
        .map(|item| {
            const MSG: &str = "reveal needs Uint8Array fields pid, ciphertext";
            Ok((
                pid(&bytes_field(item, "pid", MSG)?)?,
                bytes_field(item, "ciphertext", MSG)?,
            ))
        })
        .collect()
}

/// Plain JS object from `(key, value)` pairs.
pub fn object(fields: &[(&str, JsValue)]) -> JsValue {
    let obj = js_sys::Object::new();
    for (k, v) in fields {
        // Defining a property on a fresh plain object cannot fail.
        let _ = Reflect::set(&obj, &JsValue::from_str(k), v);
    }
    obj.into()
}

pub fn bytes(b: &[u8]) -> JsValue {
    Uint8Array::new_from_slice(b).into()
}
