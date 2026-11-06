//! Base64url (no padding) wrappers for binary JSON fields.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Variable-length binary field.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Bin(pub Vec<u8>);

/// Fixed-length binary field; deserialization rejects other lengths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fixed<const N: usize>(pub [u8; N]);

impl Serialize for Bin {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Bin {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        URL_SAFE_NO_PAD.decode(s).map(Bin).map_err(D::Error::custom)
    }
}

impl<const N: usize> Serialize for Fixed<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl<'de, const N: usize> Deserialize<'de> for Fixed<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let v = URL_SAFE_NO_PAD.decode(s).map_err(D::Error::custom)?;
        let arr: [u8; N] = v
            .try_into()
            .map_err(|v: Vec<u8>| D::Error::invalid_length(v.len(), &"fixed-length bytes"))?;
        Ok(Fixed(arr))
    }
}

impl<const N: usize> Fixed<N> {
    /// Base64url (no padding) string, e.g. for URL path segments.
    pub fn to_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    /// Parse from Base64url (no padding).
    pub fn from_b64(s: &str) -> Option<Self> {
        let v = URL_SAFE_NO_PAD.decode(s).ok()?;
        Some(Fixed(v.try_into().ok()?))
    }
}
