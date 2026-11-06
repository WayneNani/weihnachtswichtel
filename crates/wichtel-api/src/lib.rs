//! HTTP API contract (DTOs) shared by `wichtel-server` and clients.
//!
//! Human-readable description with JSON examples: `docs/api.md`.
//! Binary fields are Base64url without padding in JSON. Large protocol payloads
//! (role vectors, reveal uploads, `R`) are sent as raw `application/octet-stream`
//! bodies, not JSON – see [`HEADER_SIGNATURE`].

#![forbid(unsafe_code)]

mod bin;

pub use bin::{Bin, Fixed};
use serde::{Deserialize, Serialize};

/// Header carrying the Ed25519 upload signature (Base64url, 64 bytes) for binary uploads.
pub const HEADER_SIGNATURE: &str = "x-wichtel-signature";
/// Content type of binary protocol bodies.
pub const CONTENT_TYPE_BINARY: &str = "application/octet-stream";

pub type Gid = Fixed<16>;
pub type PidBytes = Fixed<16>;
pub type Key32 = Fixed<32>;
pub type Sig64 = Fixed<64>;
/// Unix seconds (UTC).
pub type UnixTime = i64;

// ---------------------------------------------------------------- groups

/// `POST /api/groups`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    /// `H("wichtel/v1/admin-hash" ‖ AS)`
    pub admin_hash: Key32,
    /// Group meta encrypted under `GK` (Spec §6).
    pub enc_meta: Bin,
    /// When all data is deleted (client computes event date + 14 days; server caps at +60 days).
    pub delete_after: UnixTime,
    /// Optional scheduled draw time.
    pub draw_at: Option<UnixTime>,
}

/// Response to `POST /api/groups`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateGroupResponse {
    pub gid: Gid,
}

/// Phase within a protocol round.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Step 1: role vectors (Spec §7).
    Roles,
    /// Step 2: self-draw vector + reveals (Spec §9).
    Reveal,
}

/// Group state machine (Spec §10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum GroupState {
    /// Accepting joins; draw not started.
    Open,
    /// Protocol running.
    Drawing { round: u32, phase: Phase },
    /// Reveals of attempt `t_star` released.
    Done { round: u32, t_star: u8 },
}

/// One roster entry as served to everybody.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantView {
    pub pid: PidBytes,
    pub ipk: Key32,
    pub idh: Key32,
    pub enc_name: Bin,
    pub enc_wish: Bin,
    pub joined_at: UnixTime,
}

/// Progress of the current phase (who has uploaded). Unproblematic: reveals nothing about the draw.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Progress {
    pub round: u32,
    pub phase: Phase,
    pub submitted: Vec<PidBytes>,
}

/// `GET /api/groups/{gid}`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupView {
    pub gid: Gid,
    #[serde(flatten)]
    pub state: GroupState,
    /// Number of draws started (start, admin restart, leave after start). Not incremented by
    /// collision or failed-attempt rounds.
    pub draw_no: u32,
    pub enc_meta: Bin,
    pub draw_at: Option<UnixTime>,
    /// Scheduled time passed with fewer than `N_MIN` participants.
    pub schedule_missed: bool,
    pub delete_after: UnixTime,
    pub created_at: UnixTime,
    /// Roster, sorted by `pid`.
    pub participants: Vec<ParticipantView>,
    /// Present while `state` is `drawing`.
    pub progress: Option<Progress>,
}

/// `PUT /api/groups/{gid}/schedule` (admin)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleRequest {
    /// `None` removes the schedule.
    pub draw_at: Option<UnixTime>,
}

// ---------------------------------------------------------------- participants

/// `POST /api/groups/{gid}/participants` and `PUT /api/groups/{gid}/participants/{pid}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequest {
    pub ipk: Key32,
    pub idh: Key32,
    pub auth_hash: Key32,
    pub enc_name: Bin,
    pub enc_wish: Bin,
    /// Spec §5.
    pub join_sig: Sig64,
}

/// Response to a join.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinResponse {
    pub pid: PidBytes,
}

// ---------------------------------------------------------------- protocol

/// `GET /api/groups/{gid}/rounds/{r}/reveal` once complete.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevealRelease {
    pub round: u32,
    /// Aggregated self-draw vector `SD` (256 B), so clients can verify `t_star`.
    pub selfdraw_aggregate: Bin,
    pub t_star: u8,
    /// `(pid_j, C_{j,t*})`, one per participant, roster order.
    pub reveals: Vec<RevealEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevealEntry {
    pub pid: PidBytes,
    /// 560 bytes.
    pub ciphertext: Bin,
}

// ---------------------------------------------------------------- push

/// `GET /api/push/vapid-key`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VapidKeyResponse {
    /// Uncompressed P-256 public key (65 bytes), as needed by `PushManager.subscribe`.
    pub public_key: Bin,
}

/// `PUT /api/groups/{gid}/participants/{pid}/push`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushSubscriptionRequest {
    /// Push service URL (HTTPS).
    pub endpoint: String,
    /// Browser's P-256 key (65 bytes). Stored but unused: pushes carry no payload.
    pub p256dh: Bin,
    /// Browser's auth secret (16 bytes). Stored but unused.
    pub auth: Bin,
}

// ---------------------------------------------------------------- events & errors

/// Server-sent event on `GET /api/groups/{gid}/events` (event name `update`).
/// Clients refetch the group view on every event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateEvent {
    #[serde(flatten)]
    pub state: GroupState,
    pub draw_no: u32,
    pub submitted_count: u32,
    pub participant_count: u32,
}

/// Machine-readable error codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    Unauthorized,
    NotFound,
    /// Wrong state/round/phase, or duplicate upload.
    Conflict,
    PayloadTooLarge,
    TooManyRequests,
    GroupFull,
    TooFewParticipants,
    Internal,
}

/// Body of every non-2xx response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: ErrorCode,
    /// Short English diagnostic, never contains secrets.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_state_json() {
        let s = GroupState::Drawing {
            round: 3,
            phase: Phase::Roles,
        };
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(j, r#"{"state":"drawing","round":3,"phase":"roles"}"#);
        assert_eq!(serde_json::from_str::<GroupState>(&j).unwrap(), s);
    }

    #[test]
    fn fixed_roundtrip() {
        let f = Fixed::<16>([7u8; 16]);
        let j = serde_json::to_string(&f).unwrap();
        assert_eq!(j, "\"BwcHBwcHBwcHBwcHBwcHBw\"");
        assert_eq!(serde_json::from_str::<Fixed<16>>(&j).unwrap(), f);
        assert!(serde_json::from_str::<Fixed<32>>(&j).is_err());
    }
}
