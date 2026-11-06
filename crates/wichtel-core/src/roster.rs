//! Roster ordering, group context `G_r` and fingerprint (Spec §5).

use crate::util::sha256;
use crate::{Error, GroupId, N_MAX, Pid, Result};

/// One roster entry; serialized as `pid ‖ IPK ‖ IDH ‖ H(enc_name)` (112 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterEntry {
    pub pid: Pid,
    pub ipk: [u8; 32],
    pub idh: [u8; 32],
    /// `H(enc_name)`.
    pub enc_name_hash: [u8; 32],
}

impl RosterEntry {
    /// Build an entry from the stored join data (`enc_name` is hashed here).
    pub fn new(pid: Pid, ipk: [u8; 32], idh: [u8; 32], enc_name: &[u8]) -> Self {
        Self {
            pid,
            ipk,
            idh,
            enc_name_hash: sha256(&[enc_name]),
        }
    }

    /// `pid ‖ IPK ‖ IDH ‖ H(enc_name)`.
    pub fn to_bytes(&self) -> [u8; 112] {
        let mut out = [0u8; 112];
        out[..16].copy_from_slice(&self.pid.0);
        out[16..48].copy_from_slice(&self.ipk);
        out[48..80].copy_from_slice(&self.idh);
        out[80..].copy_from_slice(&self.enc_name_hash);
        out
    }
}

/// The frozen participant list, always sorted ascending by `pid`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Roster {
    entries: Vec<RosterEntry>,
}

impl Roster {
    /// Sort by `pid`, reject duplicates, invalid `IDH`s and `n > N_MAX`.
    ///
    /// Errors: `InvalidParticipantCount` for `n > N_MAX`; `InvalidKey` for an `IDH` that fails
    /// [`crate::keys::validate_idh`]; `InvalidEncoding` for a duplicate `pid` or a duplicate
    /// `IDH`. `n < N_MIN` is allowed here (an open group may be smaller); the draw functions
    /// check the lower bound.
    pub fn new(mut entries: Vec<RosterEntry>) -> Result<Self> {
        if entries.len() > N_MAX {
            return Err(Error::InvalidParticipantCount);
        }
        for e in &entries {
            crate::keys::validate_idh(&e.idh)?;
        }
        entries.sort_by_key(|e| e.pid);
        if entries.windows(2).any(|w| w[0].pid == w[1].pid) {
            return Err(Error::InvalidEncoding);
        }
        let mut idhs: Vec<&[u8; 32]> = entries.iter().map(|e| &e.idh).collect();
        idhs.sort_unstable();
        if idhs.windows(2).any(|w| w[0] == w[1]) {
            return Err(Error::InvalidEncoding);
        }
        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[RosterEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Index of `pid` in roster order.
    pub fn index_of(&self, pid: &Pid) -> Option<usize> {
        self.entries.binary_search_by(|e| e.pid.cmp(pid)).ok()
    }

    /// `u32(n) ‖ entry_0 ‖ … ‖ entry_{n−1}`.
    fn encode_entries(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 112 * self.entries.len());
        // n ≤ N_MAX, so the cast is lossless.
        out.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for e in &self.entries {
            out.extend_from_slice(&e.to_bytes());
        }
        out
    }
}

/// `G_r = H("wichtel/v1/G" ‖ gid ‖ u32(r) ‖ u32(n) ‖ entries…)`.
pub fn group_context(gid: &GroupId, round: u32, roster: &Roster) -> [u8; 32] {
    sha256(&[
        b"wichtel/v1/G",
        &gid.0,
        &round.to_be_bytes(),
        &roster.encode_entries(),
    ])
}

/// 8 words (64 bit) from `H("wichtel/v1/fp" ‖ gid ‖ u32(n) ‖ entries…)`.
pub fn fingerprint(gid: &GroupId, roster: &Roster) -> [&'static str; 8] {
    let fp = sha256(&[b"wichtel/v1/fp", &gid.0, &roster.encode_entries()]);
    core::array::from_fn(|k| crate::wordlist::word(fp[k]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(b: u8) -> RosterEntry {
        RosterEntry::new(Pid([b; 16]), [b; 32], [b.wrapping_add(100); 32], &[b])
    }

    #[test]
    fn sorted_and_validated() {
        let r = Roster::new(vec![entry(3), entry(1), entry(2)]).unwrap();
        let pids: Vec<u8> = r.entries().iter().map(|e| e.pid.0[0]).collect();
        assert_eq!(pids, vec![1, 2, 3]);
        assert_eq!(r.index_of(&Pid([2; 16])), Some(1));
        assert_eq!(r.index_of(&Pid([9; 16])), None);
        assert_eq!(
            Roster::new(vec![entry(1), entry(1)]),
            Err(Error::InvalidEncoding)
        );
        let mut dup_idh = entry(2);
        dup_idh.idh = entry(1).idh;
        assert_eq!(
            Roster::new(vec![entry(1), dup_idh]),
            Err(Error::InvalidEncoding)
        );
        let many: Vec<_> = (0..=N_MAX as u8).map(entry).collect();
        assert_eq!(Roster::new(many), Err(Error::InvalidParticipantCount));
        assert!(Roster::new(vec![]).unwrap().is_empty());
        let mut bad_idh = entry(4);
        bad_idh.idh = [0u8; 32];
        assert_eq!(
            Roster::new(vec![entry(1), bad_idh.clone()]),
            Err(Error::InvalidKey)
        );
        bad_idh.idh = entry(4).idh;
        bad_idh.idh[31] |= 0x80;
        assert_eq!(Roster::new(vec![bad_idh]), Err(Error::InvalidKey));
    }

    #[test]
    fn context_depends_on_everything() {
        let gid = GroupId([7; 16]);
        let a = Roster::new(vec![entry(1), entry(2)]).unwrap();
        let b = Roster::new(vec![entry(2), entry(1)]).unwrap();
        assert_eq!(group_context(&gid, 1, &a), group_context(&gid, 1, &b));
        assert_ne!(group_context(&gid, 1, &a), group_context(&gid, 2, &a));
        assert_ne!(
            group_context(&gid, 1, &a),
            group_context(&GroupId([8; 16]), 1, &a)
        );
        let mut e = entry(2);
        e.enc_name_hash[0] ^= 1;
        let c = Roster::new(vec![entry(1), e]).unwrap();
        assert_ne!(group_context(&gid, 1, &a), group_context(&gid, 1, &c));
        assert_ne!(fingerprint(&gid, &a), fingerprint(&gid, &c));

        let mut expected = Vec::new();
        expected.extend_from_slice(b"wichtel/v1/G");
        expected.extend_from_slice(&gid.0);
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.extend_from_slice(&2u32.to_be_bytes());
        expected.extend_from_slice(&entry(1).to_bytes());
        expected.extend_from_slice(&entry(2).to_bytes());
        assert_eq!(group_context(&gid, 1, &a), sha256(&[&expected]));
    }

    #[test]
    fn fingerprint_words() {
        let gid = GroupId([7; 16]);
        let a = Roster::new(vec![entry(1), entry(2)]).unwrap();
        let fp = fingerprint(&gid, &a);
        let h = sha256(&[b"wichtel/v1/fp", &gid.0, &a.encode_entries()]);
        for k in 0..8 {
            assert_eq!(fp[k], crate::wordlist::word(h[k]));
            assert_ne!(fp[k], "?");
        }
    }
}
