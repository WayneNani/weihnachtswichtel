//! Roster ordering, group context `G_r` and fingerprint (Spec §5).

use crate::{GroupId, Pid, Result};

/// One roster entry; serialized as `pid ‖ IPK ‖ IDH ‖ H(enc_name)` (112 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterEntry {
    pub pid: Pid,
    pub ipk: [u8; 32],
    pub idh: [u8; 32],
    /// `H(enc_name)`.
    pub enc_name_hash: [u8; 32],
}

/// The frozen participant list, always sorted ascending by `pid`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Roster {
    entries: Vec<RosterEntry>,
}

impl Roster {
    /// Sort by `pid`, reject duplicates and `n > N_MAX`.
    pub fn new(entries: Vec<RosterEntry>) -> Result<Self> {
        todo!()
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
        todo!()
    }
}

/// `G_r = H("wichtel/v1/G" ‖ gid ‖ u32(r) ‖ u32(n) ‖ entries…)`.
pub fn group_context(gid: &GroupId, round: u32, roster: &Roster) -> [u8; 32] {
    todo!()
}

/// 8 words (64 bit) from `H("wichtel/v1/fp" ‖ gid ‖ u32(n) ‖ entries…)`.
pub fn fingerprint(gid: &GroupId, roster: &Roster) -> [&'static str; 8] {
    todo!()
}
