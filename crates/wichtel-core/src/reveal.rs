//! Step 2: self-draw vector, reveals, `t*`, result (Spec §9).

use crate::dcnet::{OwnPositions, RolesOutcome};
use crate::keys::ParticipantKeys;
use crate::roster::Roster;
use crate::{GroupId, Pid, Result};

/// Build the step-2 upload body `SD_i ‖ C_{i,1} ‖ … ‖ C_{i,16}` (length `L_REVEAL_UPLOAD`).
/// `note` is the optional private note for the giver (≤ `NOTE_MAX` bytes UTF-8).
#[allow(clippy::too_many_arguments)]
pub fn build_reveal_upload(
    keys: &ParticipantKeys,
    gid: &GroupId,
    round: u32,
    roster: &Roster,
    outcome: &RolesOutcome,
    own: &OwnPositions,
    note: &str,
) -> Result<Vec<u8>> {
    todo!()
}

/// Server side: split an upload body into `(SD_i, [C_{i,t}; 16])`.
pub fn split_reveal_upload(body: &[u8]) -> Result<(&[u8], Vec<&[u8]>)> {
    todo!()
}

/// `t*`: smallest valid attempt whose self-draw slot is zero; `None` ⇒ next round (Spec §9.1).
pub fn select_attempt(outcome: &RolesOutcome, selfdraw_aggregate: &[u8]) -> Option<u8> {
    todo!()
}

/// Final result of the local participant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrawResult {
    pub recipient: Pid,
    pub note: String,
}

/// Open the released reveals of attempt `t*` (Spec §9.3). `reveals` = `(uploader pid, C_{j,t*})`.
/// Requires exactly one valid reveal (else `Err(RevealCount)`).
#[allow(clippy::too_many_arguments)]
pub fn open_result(
    keys: &ParticipantKeys,
    gid: &GroupId,
    round: u32,
    roster: &Roster,
    outcome: &RolesOutcome,
    own: &OwnPositions,
    t_star: u8,
    reveals: &[(Pid, Vec<u8>)],
) -> Result<DrawResult> {
    todo!()
}
