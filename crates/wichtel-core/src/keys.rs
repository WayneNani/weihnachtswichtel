//! Secrets, key derivation and signatures (Spec §3, §4, §5 join, §12).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::util::{hkdf_expand, hkdf_extract, sha256, x25519_base, x25519_checked};
use crate::{Error, GroupId, Pid, Result};

/// Fixed scalar for the low-order check of a public X25519 key (Spec §5: "X25519 mit einem
/// festen Testschlüssel ist beitragend"). Any clamped scalar works: low-order points always map
/// to zero because clamping makes the scalar a multiple of the cofactor.
const LOW_ORDER_TEST_KEY: [u8; 32] = [0x5a; 32];

/// Fresh 32-byte secret from the platform CSPRNG (used for `GK`, `AS`, `seed`).
/// Wiped when dropped; deref to `[u8; 32]` with `*secret`.
pub fn generate_secret() -> Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    getrandom::fill(out.as_mut()).map_err(|_| Error::Rng)?;
    Ok(out)
}

/// `admin_hash = H("wichtel/v1/admin-hash" ‖ AS)` (Spec §3).
pub fn admin_hash(admin_secret: &[u8; 32]) -> [u8; 32] {
    sha256(&[b"wichtel/v1/admin-hash", admin_secret])
}

/// `auth_hash = H("wichtel/v1/auth-hash" ‖ tok)` (Spec §4).
pub fn auth_hash(token: &[u8; 32]) -> [u8; 32] {
    sha256(&[b"wichtel/v1/auth-hash", token])
}

/// `pid = H("wichtel/v1/pid" ‖ gid ‖ IPK)[0..16]` (Spec §3).
pub fn pid_from_ipk(gid: &GroupId, ipk: &[u8; 32]) -> Pid {
    let h = sha256(&[b"wichtel/v1/pid", &gid.0, ipk]);
    let mut pid = [0u8; 16];
    pid.copy_from_slice(&h[..16]);
    Pid(pid)
}

/// `true` iff `X25519(test, pk)` is non-zero, i.e. `pk` is not a point of small order.
pub(crate) fn is_contributory(pk: &[u8; 32]) -> bool {
    x25519_checked(&LOW_ORDER_TEST_KEY, pk).is_ok()
}

/// `true` iff `u` is the canonical encoding of a field element: bit 255 clear and
/// `u < p = 2^255 − 19` (little endian, RFC 7748).
fn is_canonical_u(u: &[u8; 32]) -> bool {
    if u[31] & 0x80 != 0 {
        return false;
    }
    // u ≥ p ⇔ u[31] = 0x7f, u[1..31] all 0xff and u[0] ≥ 0xed.
    let top_all_ones = u[31] == 0x7f && u[1..31].iter().all(|&b| b == 0xff);
    !(top_all_ones && u[0] >= 0xed)
}

/// Validate a public X25519 identity key `IDH` (Spec §5): canonical encoding (bit 255 clear,
/// `u < p`) and not of small order (non-contributory). Returns `Err(InvalidKey)` otherwise.
/// Uniqueness within a group is checked by [`crate::roster::Roster::new`] and the server.
pub fn validate_idh(idh: &[u8; 32]) -> Result<()> {
    if is_canonical_u(idh) && is_contributory(idh) {
        Ok(())
    } else {
        Err(Error::InvalidKey)
    }
}

/// Public identity of a participant as stored on the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicIdentity {
    pub pid: Pid,
    /// Ed25519 public key.
    pub ipk: [u8; 32],
    /// X25519 public key.
    pub idh: [u8; 32],
}

/// Long-term secrets of one participant in one group, derived from `seed` (Spec §4).
/// Zeroized on drop.
pub struct ParticipantKeys {
    /// `HKDF-Extract("wichtel/v1/seed", seed)`; needed for the round-specific keys.
    prk: Zeroizing<[u8; 32]>,
    gid: GroupId,
    /// Ed25519 signing key (zeroizes itself on drop).
    isk: SigningKey,
    /// X25519 identity secret (unclamped as derived; clamped on use).
    idh: Zeroizing<[u8; 32]>,
    tok: Zeroizing<[u8; 32]>,
    public: PublicIdentity,
}

impl ParticipantKeys {
    /// Derive all long-term keys from `seed` for group `gid`.
    pub fn derive(seed: &[u8; 32], gid: &GroupId) -> Result<Self> {
        let prk = hkdf_extract(b"wichtel/v1/seed", seed);

        let mut isk_bytes = Zeroizing::new([0u8; 32]);
        hkdf_expand(&prk, &[b"wichtel/v1/id-sig", &gid.0], isk_bytes.as_mut());
        let isk = SigningKey::from_bytes(&isk_bytes);

        let mut idh = Zeroizing::new([0u8; 32]);
        hkdf_expand(&prk, &[b"wichtel/v1/id-dh", &gid.0], idh.as_mut());
        let idh_pub = x25519_base(&idh);
        if validate_idh(&idh_pub).is_err() {
            // Cannot happen for a clamped scalar; checked anyway (Spec §11).
            return Err(Error::InvalidKey);
        }

        let mut tok = Zeroizing::new([0u8; 32]);
        hkdf_expand(&prk, &[b"wichtel/v1/auth", &gid.0], tok.as_mut());

        let ipk = isk.verifying_key().to_bytes();
        let public = PublicIdentity {
            pid: pid_from_ipk(gid, &ipk),
            ipk,
            idh: idh_pub,
        };
        Ok(Self {
            prk,
            gid: *gid,
            isk,
            idh,
            tok,
            public,
        })
    }

    /// Public part (`pid`, `IPK`, `IDH`).
    pub fn public(&self) -> PublicIdentity {
        self.public
    }

    /// Bearer token `tok` (wiped when the returned value is dropped).
    pub fn auth_token(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.tok)
    }

    /// `join_sig` over `H("wichtel/v1/join" ‖ gid ‖ IPK ‖ IDH ‖ auth_hash ‖ lp(enc_name) ‖ lp(enc_wish))`.
    pub fn sign_join(&self, enc_name: &[u8], enc_wish: &[u8]) -> [u8; 64] {
        let msg = join_message(
            &self.gid,
            &self.public.ipk,
            &self.public.idh,
            &auth_hash(&self.tok),
            enc_name,
            enc_wish,
        );
        self.isk.sign(&msg).to_bytes()
    }

    /// `upload_sig` (Spec §12) for `kind` 1 (roles) or 2 (self-draw + reveals).
    pub fn sign_upload(&self, kind: UploadKind, round: u32, body: &[u8]) -> [u8; 64] {
        let msg = upload_message(&self.gid, &self.public.pid, kind, round, body);
        self.isk.sign(&msg).to_bytes()
    }

    pub(crate) fn gid(&self) -> &GroupId {
        &self.gid
    }

    pub(crate) fn prk(&self) -> &[u8; 32] {
        &self.prk
    }

    pub(crate) fn idh_secret(&self) -> &[u8; 32] {
        &self.idh
    }
}

impl Drop for ParticipantKeys {
    fn drop(&mut self) {
        // `prk`, `idh`, `tok` are `Zeroizing`, `isk` is `ZeroizeOnDrop`; the public part is not
        // secret but cleared for good measure.
        self.public.ipk.zeroize();
        self.public.idh.zeroize();
    }
}

fn join_message(
    gid: &GroupId,
    ipk: &[u8; 32],
    idh: &[u8; 32],
    auth_hash: &[u8; 32],
    enc_name: &[u8],
    enc_wish: &[u8],
) -> [u8; 32] {
    sha256(&[
        b"wichtel/v1/join",
        &gid.0,
        ipk,
        idh,
        auth_hash,
        &lp_len(enc_name),
        enc_name,
        &lp_len(enc_wish),
        enc_wish,
    ])
}

fn upload_message(gid: &GroupId, pid: &Pid, kind: UploadKind, round: u32, body: &[u8]) -> [u8; 32] {
    let body_hash = sha256(&[body]);
    sha256(&[
        b"wichtel/v1/upload",
        &[kind as u8],
        &gid.0,
        &round.to_be_bytes(),
        &pid.0,
        &body_hash,
    ])
}

/// `u32(len(x))` of `lp(x)`. Inputs longer than `u32::MAX` saturate (they never pass the
/// server's size limits anyway).
fn lp_len(x: &[u8]) -> [u8; 4] {
    u32::try_from(x.len()).unwrap_or(u32::MAX).to_be_bytes()
}

/// Upload kind for [`ParticipantKeys::sign_upload`] / [`verify_upload`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum UploadKind {
    Roles = 1,
    Reveal = 2,
    /// Contact to the recipient (Spec §16.2); `round` = round of `Done`.
    Contact = 3,
}

fn verifying_key(ipk: &[u8; 32]) -> Result<VerifyingKey> {
    let vk = VerifyingKey::from_bytes(ipk).map_err(|_| Error::InvalidKey)?;
    if vk.is_weak() {
        return Err(Error::InvalidKey);
    }
    Ok(vk)
}

/// Server side: verify a join request (signature, [`validate_idh`] for `IDH`, `pid` derivation).
/// Returns the derived `pid`. The server must additionally reject an `IDH` (or `pid`) that is
/// already present in the group (Spec §5).
pub fn verify_join(
    gid: &GroupId,
    ipk: &[u8; 32],
    idh: &[u8; 32],
    auth_hash: &[u8; 32],
    enc_name: &[u8],
    enc_wish: &[u8],
    join_sig: &[u8; 64],
) -> Result<Pid> {
    let vk = verifying_key(ipk)?;
    validate_idh(idh)?;
    let msg = join_message(gid, ipk, idh, auth_hash, enc_name, enc_wish);
    vk.verify_strict(&msg, &Signature::from_bytes(join_sig))
        .map_err(|_| Error::BadSignature)?;
    Ok(pid_from_ipk(gid, ipk))
}

/// Server side: verify an upload signature (Spec §12).
pub fn verify_upload(
    gid: &GroupId,
    pid: &Pid,
    ipk: &[u8; 32],
    kind: UploadKind,
    round: u32,
    body: &[u8],
    sig: &[u8; 64],
) -> Result<()> {
    let vk = verifying_key(ipk)?;
    let msg = upload_message(gid, pid, kind, round, body);
    vk.verify_strict(&msg, &Signature::from_bytes(sig))
        .map_err(|_| Error::BadSignature)
}

/// Constant-time equality for hashes/tokens. Lengths are not secret: different lengths ⇒ `false`.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GID: GroupId = GroupId([1u8; 16]);

    #[test]
    fn derive_is_deterministic_and_group_bound() {
        let a = ParticipantKeys::derive(&[9u8; 32], &GID).unwrap();
        let b = ParticipantKeys::derive(&[9u8; 32], &GID).unwrap();
        assert_eq!(a.public(), b.public());
        assert_eq!(*a.auth_token(), *b.auth_token());
        let c = ParticipantKeys::derive(&[9u8; 32], &GroupId([2u8; 16])).unwrap();
        assert_ne!(a.public().ipk, c.public().ipk);
        assert_ne!(a.public().idh, c.public().idh);
        assert_eq!(a.public().pid, pid_from_ipk(&GID, &a.public().ipk));
    }

    #[test]
    fn idh_validation() {
        let good = ParticipantKeys::derive(&[1u8; 32], &GID)
            .unwrap()
            .public()
            .idh;
        assert_eq!(validate_idh(&good), Ok(()));
        // Bit 255 set: same point mod p for X25519, but non-canonical encoding.
        let mut high = good;
        high[31] |= 0x80;
        assert_eq!(validate_idh(&high), Err(Error::InvalidKey));
        // u = p (≡ 0) and u = p + 1 (≡ 1, low order) and u = p + 9 (≡ 9, non-canonical).
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        assert_eq!(validate_idh(&p), Err(Error::InvalidKey));
        let mut p9 = p;
        p9[0] = 0xed + 9;
        assert_eq!(validate_idh(&p9), Err(Error::InvalidKey));
        // p − 1 is canonical (but of small order: it is −1, a 2-torsion point).
        let mut pm1 = p;
        pm1[0] = 0xec;
        assert!(is_canonical_u(&pm1));
        assert_eq!(validate_idh(&pm1), Err(Error::InvalidKey));
        // Small-order points.
        assert_eq!(validate_idh(&[0u8; 32]), Err(Error::InvalidKey));
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(validate_idh(&one), Err(Error::InvalidKey));
        // Base point 9 is fine.
        let mut nine = [0u8; 32];
        nine[0] = 9;
        assert_eq!(validate_idh(&nine), Ok(()));
    }

    #[test]
    fn hashes_are_domain_separated() {
        let x = [5u8; 32];
        assert_ne!(admin_hash(&x), auth_hash(&x));
        assert_eq!(admin_hash(&x), sha256(&[b"wichtel/v1/admin-hash", &x]));
    }

    #[test]
    fn join_roundtrip_and_tamper() {
        let k = ParticipantKeys::derive(&[1u8; 32], &GID).unwrap();
        let p = k.public();
        let ah = auth_hash(&k.auth_token());
        let sig = k.sign_join(b"name", b"wish");
        assert_eq!(
            verify_join(&GID, &p.ipk, &p.idh, &ah, b"name", b"wish", &sig),
            Ok(p.pid)
        );
        // lp() makes the split between name and wish unambiguous.
        assert_eq!(
            verify_join(&GID, &p.ipk, &p.idh, &ah, b"namew", b"ish", &sig),
            Err(Error::BadSignature)
        );
        assert_eq!(
            verify_join(
                &GroupId([0; 16]),
                &p.ipk,
                &p.idh,
                &ah,
                b"name",
                b"wish",
                &sig
            ),
            Err(Error::BadSignature)
        );
        let mut bad = sig;
        bad[3] ^= 1;
        assert_eq!(
            verify_join(&GID, &p.ipk, &p.idh, &ah, b"name", b"wish", &bad),
            Err(Error::BadSignature)
        );
        // Low-order IDH is rejected.
        assert_eq!(
            verify_join(&GID, &p.ipk, &[0u8; 32], &ah, b"name", b"wish", &sig),
            Err(Error::InvalidKey)
        );
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(
            verify_join(&GID, &p.ipk, &one, &ah, b"name", b"wish", &sig),
            Err(Error::InvalidKey)
        );
        // Weak / invalid Ed25519 key.
        assert!(verify_join(&GID, &[0u8; 32], &p.idh, &ah, b"name", b"wish", &sig).is_err());
    }

    #[test]
    fn upload_roundtrip_and_tamper() {
        let k = ParticipantKeys::derive(&[2u8; 32], &GID).unwrap();
        let p = k.public();
        let sig = k.sign_upload(UploadKind::Roles, 3, b"body");
        assert_eq!(
            verify_upload(&GID, &p.pid, &p.ipk, UploadKind::Roles, 3, b"body", &sig),
            Ok(())
        );
        for (kind, round, body) in [
            (UploadKind::Reveal, 3, &b"body"[..]),
            (UploadKind::Roles, 4, &b"body"[..]),
            (UploadKind::Roles, 3, &b"bodx"[..]),
        ] {
            assert_eq!(
                verify_upload(&GID, &p.pid, &p.ipk, kind, round, body, &sig),
                Err(Error::BadSignature)
            );
        }
        assert_eq!(
            verify_upload(
                &GID,
                &Pid([0; 16]),
                &p.ipk,
                UploadKind::Roles,
                3,
                b"body",
                &sig
            ),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn generate_secret_is_random() {
        assert_ne!(generate_secret().unwrap(), generate_secret().unwrap());
    }
}
