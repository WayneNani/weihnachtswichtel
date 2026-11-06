//! Persistence behind a small trait (Konzept §8: fallback to another SQLite backend possible).
//!
//! All mutations go through [`Store::commit`], which applies a list of [`WriteOp`]s in one
//! transaction. Reads are plain methods. The application serializes mutations per group
//! (see `app::GroupLocks`), so the store only has to guarantee atomicity of one commit.

mod turso_store;

pub use turso_store::TursoStore;

use std::future::Future;
use std::pin::Pin;

use wichtel_api::{GroupState, Phase};

/// 16-byte group id.
pub type Gid = [u8; 16];
/// 16-byte participant id.
pub type Pid = [u8; 16];

/// Boxed future returned by [`Store`] methods (object safe, `Send`).
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, StoreError>> + Send + 'a>>;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(#[from] turso::Error),
    #[error("corrupt row: {0}")]
    Corrupt(&'static str),
}

/// One group row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRecord {
    pub gid: Gid,
    pub admin_hash: [u8; 32],
    pub enc_meta: Vec<u8>,
    pub state: GroupState,
    /// Last protocol round used (0 = never started). Equals the current round while
    /// `drawing`/`done`.
    pub round: u32,
    pub draw_no: u32,
    pub draw_at: Option<i64>,
    pub reminder_sent: bool,
    pub schedule_missed: bool,
    pub delete_after: i64,
    pub created_at: i64,
    pub last_activity: i64,
}

/// One participant row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParticipantRecord {
    pub gid: Gid,
    pub pid: Pid,
    pub ipk: [u8; 32],
    pub idh: [u8; 32],
    pub auth_hash: [u8; 32],
    pub enc_name: Vec<u8>,
    pub enc_wish: Vec<u8>,
    pub joined_at: i64,
}

/// Running XOR of one `(round, phase)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateRecord {
    pub gid: Gid,
    pub round: u32,
    pub phase: Phase,
    pub aggregate: Vec<u8>,
    /// Participants that have uploaded, in upload order.
    pub submitted: Vec<Pid>,
}

/// One push subscription.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushSubRecord {
    pub gid: Gid,
    pub pid: Pid,
    pub endpoint: String,
    pub p256dh: Vec<u8>,
    pub auth: Vec<u8>,
    pub created_at: i64,
}

/// Group summary for the background job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduledGroup {
    pub gid: Gid,
    pub draw_at: i64,
    pub reminder_sent: bool,
}

/// A single write; [`Store::commit`] applies a list of them atomically.
#[derive(Clone, Debug)]
pub enum WriteOp {
    /// Insert or replace the group row.
    UpsertGroup(GroupRecord),
    /// Delete the group and every row belonging to it.
    DeleteGroup(Gid),
    InsertParticipant(ParticipantRecord),
    UpdateParticipantData {
        gid: Gid,
        pid: Pid,
        enc_name: Vec<u8>,
        enc_wish: Vec<u8>,
    },
    /// Delete the participant and their push subscription.
    DeleteParticipant {
        gid: Gid,
        pid: Pid,
    },
    /// Insert or replace a running aggregate.
    PutAggregate(AggregateRecord),
    /// Store `C_{pid,1..=16}` (index 0 = attempt 1).
    PutRevealCiphertexts {
        gid: Gid,
        round: u32,
        pid: Pid,
        ciphertexts: Vec<Vec<u8>>,
    },
    /// Delete every reveal ciphertext of `round` except those of `attempt`.
    KeepOnlyAttempt {
        gid: Gid,
        round: u32,
        attempt: u8,
    },
    /// Delete all aggregates and reveal ciphertexts of the group (all rounds).
    ClearRounds {
        gid: Gid,
    },
    PutPushSub(PushSubRecord),
    DeletePushSub {
        gid: Gid,
        pid: Pid,
    },
    /// Delete the subscription only if it still points to `endpoint`.
    DeletePushSubIfEndpoint {
        gid: Gid,
        pid: Pid,
        endpoint: String,
    },
    PutServerKey {
        name: String,
        value: Vec<u8>,
    },
}

/// Persistence interface.
pub trait Store: Send + Sync + 'static {
    /// Apply all operations in one transaction.
    fn commit(&self, ops: Vec<WriteOp>) -> StoreFuture<'_, ()>;

    fn get_group<'a>(&'a self, gid: &'a Gid) -> StoreFuture<'a, Option<GroupRecord>>;
    fn count_groups(&self) -> StoreFuture<'_, u64>;
    /// Participants sorted ascending by `pid`.
    fn list_participants<'a>(&'a self, gid: &'a Gid) -> StoreFuture<'a, Vec<ParticipantRecord>>;
    fn get_aggregate<'a>(
        &'a self,
        gid: &'a Gid,
        round: u32,
        phase: Phase,
    ) -> StoreFuture<'a, Option<AggregateRecord>>;
    /// Only the `submitted` list of an aggregate (cheap; no vector is read).
    fn get_submitted<'a>(
        &'a self,
        gid: &'a Gid,
        round: u32,
        phase: Phase,
    ) -> StoreFuture<'a, Vec<Pid>>;
    /// `(pid, C_{pid,attempt})`, sorted by `pid`.
    fn list_reveals<'a>(
        &'a self,
        gid: &'a Gid,
        round: u32,
        attempt: u8,
    ) -> StoreFuture<'a, Vec<(Pid, Vec<u8>)>>;
    /// Number of stored reveal ciphertexts of a round (all attempts).
    fn count_reveals<'a>(&'a self, gid: &'a Gid, round: u32) -> StoreFuture<'a, u64>;
    fn list_push_subs<'a>(&'a self, gid: &'a Gid) -> StoreFuture<'a, Vec<PushSubRecord>>;
    fn get_server_key<'a>(&'a self, name: &'a str) -> StoreFuture<'a, Option<Vec<u8>>>;

    /// Open groups with a `draw_at` at or before `until`.
    fn list_scheduled(&self, until: i64) -> StoreFuture<'_, Vec<ScheduledGroup>>;
    /// Groups whose `delete_after` is at or before `now`.
    fn list_expired(&self, now: i64) -> StoreFuture<'_, Vec<Gid>>;
    /// Open groups without `draw_at` whose last activity is at or before `cutoff`, with their
    /// participant count.
    fn list_idle_open(&self, cutoff: i64) -> StoreFuture<'_, Vec<(Gid, u64)>>;

    /// Compact the database so deleted data does not survive in free pages or the WAL
    /// (Spec §14: `VACUUM` + `wal_checkpoint(TRUNCATE)`).
    fn vacuum(&self) -> StoreFuture<'_, ()>;
}

pub(crate) fn state_columns(
    state: &GroupState,
) -> (&'static str, Option<&'static str>, Option<i64>) {
    match state {
        GroupState::Open => ("open", None, None),
        GroupState::Drawing { phase, .. } => ("drawing", Some(phase_str(*phase)), None),
        GroupState::Done { t_star, .. } => ("done", None, Some(i64::from(*t_star))),
    }
}

pub(crate) fn phase_str(p: Phase) -> &'static str {
    match p {
        Phase::Roles => "roles",
        Phase::Reveal => "reveal",
    }
}

pub(crate) fn parse_state(
    state: &str,
    round: u32,
    phase: Option<&str>,
    t_star: Option<i64>,
) -> Result<GroupState, StoreError> {
    Ok(match state {
        "open" => GroupState::Open,
        "drawing" => GroupState::Drawing {
            round,
            phase: match phase {
                Some("roles") => Phase::Roles,
                Some("reveal") => Phase::Reveal,
                _ => return Err(StoreError::Corrupt("phase")),
            },
        },
        "done" => GroupState::Done {
            round,
            t_star: t_star
                .and_then(|t| u8::try_from(t).ok())
                .ok_or(StoreError::Corrupt("t_star"))?,
        },
        _ => return Err(StoreError::Corrupt("state")),
    })
}
