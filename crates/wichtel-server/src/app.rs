//! Application core: group state machine (Spec §10), protocol aggregation (Spec §7.4, §9.3),
//! schedule/expiry jobs and change notifications. HTTP-independent.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use tokio::sync::{OwnedMutexGuard, broadcast};
use wichtel_api::{
    CreateGroupRequest, ErrorCode, GroupState, GroupView, JoinRequest, ParticipantView, Phase,
    Progress, PushSubscriptionRequest, RevealEntry, RevealRelease, UpdateEvent,
};
use wichtel_core::keys::UploadKind;
use wichtel_core::roster::RosterEntry;
use wichtel_core::{L_REVEAL_UPLOAD, L_SD, N_MAX, N_MIN, T_ATTEMPTS, roles_vector_len};

use crate::config::Config;
use crate::error::{ApiError, ApiResult};
use crate::events::Hub;
use crate::protocol::ProtocolOps;
use crate::push::{PushClient, PushDispatcher, Vapid, validate_endpoint};
use crate::ratelimit::{Bucket, RateLimiter};
use crate::store::{
    AggregateRecord, Gid, GroupRecord, ParticipantRecord, Pid, PushSubRecord, Store, StoreError,
    WriteOp,
};

/// Maximum size of `enc_meta` (docs/api.md, Limits).
pub const MAX_ENC_META: usize = 2048;
/// Maximum size of `enc_name`.
pub const MAX_ENC_NAME: usize = 128;
/// Maximum size of `enc_wish`.
pub const MAX_ENC_WISH: usize = 1100;
/// `delete_after` is capped at creation + 60 days (Spec §10).
pub const MAX_LIFETIME: i64 = 60 * 86_400;
/// Unused open groups are deleted after 7 days without activity (Review D2).
pub const IDLE_LIFETIME: i64 = 7 * 86_400;
/// Reminder push this many seconds before `draw_at` (Konzept §6.6).
pub const REMINDER_LEAD: i64 = 600;
const RATE_WINDOW: i64 = 3600;

/// Source of the current time (Unix seconds); replaceable in tests.
pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> i64;
}

/// Wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64)
    }
}

/// One async mutex per group: every read-check-write of a group runs under it.
#[derive(Default)]
pub struct GroupLocks {
    map: Mutex<HashMap<Gid, Arc<tokio::sync::Mutex<()>>>>,
}

impl GroupLocks {
    pub async fn lock(&self, gid: Gid) -> OwnedMutexGuard<()> {
        let m = self
            .map
            .lock()
            .expect("locks")
            .entry(gid)
            .or_default()
            .clone();
        m.lock_owned().await
    }

    fn cleanup(&self) {
        self.map
            .lock()
            .expect("locks")
            .retain(|_, m| Arc::strong_count(m) > 1);
    }
}

/// Bundled `VACUUM` after deletions of sensitive data (Spec §14).
#[derive(Default)]
struct VacuumState {
    pending: AtomicBool,
    last: Mutex<Option<i64>>,
}

/// Shared application state.
pub struct App {
    pub cfg: Config,
    pub store: Arc<dyn Store>,
    pub ops: Arc<dyn ProtocolOps>,
    pub clock: Arc<dyn Clock>,
    pub hub: Hub,
    pub vapid: Arc<Vapid>,
    push: PushDispatcher,
    locks: GroupLocks,
    rate: RateLimiter,
    vacuum: VacuumState,
}

impl App {
    /// Build the application; loads or creates the VAPID key and starts the push worker.
    pub async fn new(
        cfg: Config,
        store: Arc<dyn Store>,
        ops: Arc<dyn ProtocolOps>,
        clock: Arc<dyn Clock>,
        push_client: Arc<dyn PushClient>,
    ) -> Result<Arc<Self>, StoreError> {
        let vapid = Arc::new(Vapid::load_or_create(&*store, cfg.vapid_subject.clone()).await?);
        let push = PushDispatcher::spawn(store.clone(), vapid.clone(), push_client, clock.clone());
        Ok(Arc::new(Self {
            cfg,
            store,
            ops,
            clock,
            hub: Hub::default(),
            vapid,
            push,
            locks: GroupLocks::default(),
            rate: RateLimiter::default(),
            vacuum: VacuumState::default(),
        }))
    }

    pub fn now(&self) -> i64 {
        self.clock.now()
    }

    // ------------------------------------------------------------------ helpers

    async fn load_group(&self, gid: &Gid) -> ApiResult<GroupRecord> {
        self.store
            .get_group(gid)
            .await?
            .ok_or_else(ApiError::not_found)
    }

    fn is_admin(&self, g: &GroupRecord, token: &[u8; 32]) -> bool {
        self.ops.ct_eq(&self.ops.admin_hash(token), &g.admin_hash)
    }

    fn require_admin(&self, g: &GroupRecord, token: Option<&[u8; 32]>) -> ApiResult<()> {
        match token {
            Some(t) if self.is_admin(g, t) => Ok(()),
            _ => Err(ApiError::unauthorized()),
        }
    }

    /// Index of the participant whose `auth_hash` matches `token`. Compares against every
    /// entry without early exit.
    fn find_by_token(&self, parts: &[ParticipantRecord], token: &[u8; 32]) -> Option<usize> {
        let h = self.ops.auth_hash(token);
        let mut found = None;
        for (i, p) in parts.iter().enumerate() {
            let eq = self.ops.ct_eq(&h, &p.auth_hash);
            if eq && found.is_none() {
                found = Some(i);
            }
        }
        found
    }

    fn is_participant(&self, p: &ParticipantRecord, token: &[u8; 32]) -> bool {
        self.ops.ct_eq(&self.ops.auth_hash(token), &p.auth_hash)
    }

    fn rate_limit(&self, ip: Option<IpAddr>, bucket: Bucket, limit: u32) -> ApiResult<()> {
        if let Some(ip) = ip
            && !self.rate.check(ip, bucket, limit, RATE_WINDOW, self.now())
        {
            return Err(ApiError::new(
                ErrorCode::TooManyRequests,
                "rate limit exceeded",
            ));
        }
        Ok(())
    }

    fn roster_entries(parts: &[ParticipantRecord]) -> Vec<RosterEntry> {
        parts
            .iter()
            .map(|p| RosterEntry {
                pid: wichtel_core::Pid(p.pid),
                ipk: p.ipk,
                idh: p.idh,
                enc_name_hash: Sha256::digest(&p.enc_name).into(),
            })
            .collect()
    }

    fn group_context(
        &self,
        g: &GroupRecord,
        round: u32,
        parts: &[ParticipantRecord],
    ) -> ApiResult<[u8; 32]> {
        self.ops
            .group_context(&g.gid, round, Self::roster_entries(parts))
            .ok_or_else(|| {
                tracing::error!("cannot compute group context");
                ApiError::internal()
            })
    }

    /// Start a new draw (start, schedule, admin restart, leave after start): `r+1`, `draw_no+1`.
    fn begin_draw(g: &mut GroupRecord, now: i64) {
        g.round += 1;
        g.draw_no += 1;
        g.state = GroupState::Drawing {
            round: g.round,
            phase: Phase::Roles,
        };
        g.draw_at = None;
        g.reminder_sent = false;
        g.schedule_missed = false;
        g.last_activity = now;
    }

    /// Automatic follow-up round (collision / no valid attempt): `r+1`, same `draw_no`.
    fn next_round(g: &mut GroupRecord, now: i64) {
        g.round += 1;
        g.state = GroupState::Drawing {
            round: g.round,
            phase: Phase::Roles,
        };
        g.last_activity = now;
    }

    /// Notify SSE listeners (and push subscribers if `push`).
    fn emit(&self, g: &GroupRecord, participant_count: usize, submitted_count: usize, push: bool) {
        if self.hub.has_listeners(&g.gid) {
            self.hub.publish(
                &g.gid,
                UpdateEvent {
                    state: g.state,
                    draw_no: g.draw_no,
                    submitted_count: submitted_count as u32,
                    participant_count: participant_count as u32,
                },
            );
        }
        if push {
            self.push.notify(g.gid);
        }
    }

    fn mark_vacuum(&self) {
        self.vacuum.pending.store(true, Ordering::SeqCst);
    }

    async fn submitted(&self, g: &GroupRecord) -> Result<Vec<Pid>, StoreError> {
        match g.state {
            GroupState::Drawing { round, phase } => {
                self.store.get_submitted(&g.gid, round, phase).await
            }
            _ => Ok(Vec::new()),
        }
    }

    // ------------------------------------------------------------------ groups

    pub async fn create_group(
        &self,
        ip: Option<IpAddr>,
        req: CreateGroupRequest,
    ) -> ApiResult<Gid> {
        self.rate_limit(ip, Bucket::CreateGroup, self.cfg.create_limit_per_hour)?;
        if req.enc_meta.0.len() > MAX_ENC_META {
            return Err(ApiError::new(
                ErrorCode::PayloadTooLarge,
                "enc_meta too large",
            ));
        }
        let now = self.now();
        if req.delete_after <= now {
            return Err(ApiError::bad_request("delete_after must be in the future"));
        }
        let delete_after = req.delete_after.min(now + MAX_LIFETIME);
        if let Some(t) = req.draw_at
            && (t <= now || t >= delete_after)
        {
            return Err(ApiError::bad_request("draw_at out of range"));
        }
        if self.store.count_groups().await? >= self.cfg.max_groups {
            return Err(ApiError::new(ErrorCode::TooManyRequests, "server is full"));
        }
        let gid = loop {
            let mut gid = [0u8; 16];
            getrandom::fill(&mut gid).map_err(|_| ApiError::internal())?;
            if self.store.get_group(&gid).await?.is_none() {
                break gid;
            }
        };
        let g = GroupRecord {
            gid,
            admin_hash: req.admin_hash.0,
            enc_meta: req.enc_meta.0,
            state: GroupState::Open,
            round: 0,
            draw_no: 0,
            draw_at: req.draw_at,
            reminder_sent: false,
            schedule_missed: false,
            delete_after,
            created_at: now,
            last_activity: now,
        };
        self.store.commit(vec![WriteOp::UpsertGroup(g)]).await?;
        Ok(gid)
    }

    pub async fn view(&self, gid: &Gid) -> ApiResult<GroupView> {
        let g = self.load_group(gid).await?;
        let parts = self.store.list_participants(gid).await?;
        let progress = match g.state {
            GroupState::Drawing { round, phase } => {
                let mut submitted = self.store.get_submitted(gid, round, phase).await?;
                submitted.sort();
                Some(Progress {
                    round,
                    phase,
                    submitted: submitted.into_iter().map(wichtel_api::Fixed).collect(),
                })
            }
            _ => None,
        };
        Ok(GroupView {
            gid: wichtel_api::Fixed(g.gid),
            state: g.state,
            draw_no: g.draw_no,
            enc_meta: wichtel_api::Bin(g.enc_meta),
            draw_at: g.draw_at,
            schedule_missed: g.schedule_missed,
            delete_after: g.delete_after,
            created_at: g.created_at,
            participants: parts
                .into_iter()
                .map(|p| ParticipantView {
                    pid: wichtel_api::Fixed(p.pid),
                    ipk: wichtel_api::Fixed(p.ipk),
                    idh: wichtel_api::Fixed(p.idh),
                    enc_name: wichtel_api::Bin(p.enc_name),
                    enc_wish: wichtel_api::Bin(p.enc_wish),
                    joined_at: p.joined_at,
                })
                .collect(),
            progress,
        })
    }

    /// Current event for a new SSE listener.
    pub async fn current_event(&self, gid: &Gid) -> ApiResult<UpdateEvent> {
        let g = self.load_group(gid).await?;
        let n = self.store.list_participants(gid).await?.len();
        let submitted = self.submitted(&g).await?.len();
        Ok(UpdateEvent {
            state: g.state,
            draw_no: g.draw_no,
            submitted_count: submitted as u32,
            participant_count: n as u32,
        })
    }

    /// Subscribe to group updates (SSE).
    pub async fn subscribe(
        &self,
        gid: &Gid,
    ) -> ApiResult<(UpdateEvent, broadcast::Receiver<UpdateEvent>)> {
        let rx = self
            .hub
            .subscribe(*gid, self.cfg.sse_per_group)
            .ok_or(ApiError::new(
                ErrorCode::TooManyRequests,
                "too many listeners",
            ))?;
        let ev = self.current_event(gid).await?;
        Ok((ev, rx))
    }

    pub async fn delete_group(&self, gid: Gid, token: Option<[u8; 32]>) -> ApiResult<()> {
        let _guard = self.locks.lock(gid).await;
        let g = self.load_group(&gid).await?;
        self.require_admin(&g, token.as_ref())?;
        self.store.commit(vec![WriteOp::DeleteGroup(gid)]).await?;
        self.hub.close(&gid);
        self.mark_vacuum();
        Ok(())
    }

    pub async fn set_schedule(
        &self,
        gid: Gid,
        token: Option<[u8; 32]>,
        draw_at: Option<i64>,
    ) -> ApiResult<()> {
        let _guard = self.locks.lock(gid).await;
        let mut g = self.load_group(&gid).await?;
        self.require_admin(&g, token.as_ref())?;
        if g.state != GroupState::Open {
            return Err(ApiError::conflict(
                "schedule can only be changed before the draw",
            ));
        }
        let now = self.now();
        if let Some(t) = draw_at
            && (t <= now || t >= g.delete_after)
        {
            return Err(ApiError::bad_request("draw_at out of range"));
        }
        g.draw_at = draw_at;
        g.reminder_sent = false;
        g.schedule_missed = false;
        g.last_activity = now;
        let n = self.store.list_participants(&gid).await?.len();
        self.store
            .commit(vec![WriteOp::UpsertGroup(g.clone())])
            .await?;
        self.emit(&g, n, 0, false);
        Ok(())
    }

    pub async fn start(&self, gid: Gid, token: Option<[u8; 32]>) -> ApiResult<()> {
        let _guard = self.locks.lock(gid).await;
        let mut g = self.load_group(&gid).await?;
        self.require_admin(&g, token.as_ref())?;
        if g.state != GroupState::Open {
            return Err(ApiError::conflict("draw already started"));
        }
        let n = self.store.list_participants(&gid).await?.len();
        if !(N_MIN..=N_MAX).contains(&n) {
            return Err(ApiError::new(
                ErrorCode::TooFewParticipants,
                "need at least 4 participants",
            ));
        }
        Self::begin_draw(&mut g, self.now());
        self.store
            .commit(vec![
                WriteOp::ClearRounds { gid },
                WriteOp::UpsertGroup(g.clone()),
            ])
            .await?;
        self.emit(&g, n, 0, true);
        Ok(())
    }

    pub async fn restart(&self, gid: Gid, token: Option<[u8; 32]>) -> ApiResult<()> {
        let _guard = self.locks.lock(gid).await;
        let mut g = self.load_group(&gid).await?;
        self.require_admin(&g, token.as_ref())?;
        if g.state == GroupState::Open {
            return Err(ApiError::conflict("no draw to restart"));
        }
        let n = self.store.list_participants(&gid).await?.len();
        Self::begin_draw(&mut g, self.now());
        self.store
            .commit(vec![
                WriteOp::ClearRounds { gid },
                WriteOp::UpsertGroup(g.clone()),
            ])
            .await?;
        self.mark_vacuum();
        self.emit(&g, n, 0, true);
        Ok(())
    }

    // ------------------------------------------------------------------ participants

    fn check_join_sizes(req: &JoinRequest) -> ApiResult<()> {
        if req.enc_name.0.is_empty() {
            return Err(ApiError::bad_request("enc_name missing"));
        }
        if req.enc_name.0.len() > MAX_ENC_NAME || req.enc_wish.0.len() > MAX_ENC_WISH {
            return Err(ApiError::new(ErrorCode::PayloadTooLarge, "field too large"));
        }
        Ok(())
    }

    fn verify_join(&self, gid: &Gid, req: &JoinRequest) -> ApiResult<Pid> {
        self.ops
            .verify_join(
                gid,
                &req.ipk.0,
                &req.idh.0,
                &req.auth_hash.0,
                &req.enc_name.0,
                &req.enc_wish.0,
                &req.join_sig.0,
            )
            .ok_or(ApiError::bad_request("invalid join signature or key"))
    }

    pub async fn join(&self, gid: Gid, ip: Option<IpAddr>, req: JoinRequest) -> ApiResult<Pid> {
        Self::check_join_sizes(&req)?;
        let _guard = self.locks.lock(gid).await;
        let mut g = self.load_group(&gid).await?;
        if g.state != GroupState::Open {
            return Err(ApiError::conflict("draw already started"));
        }
        let parts = self.store.list_participants(&gid).await?;
        if parts.len() >= N_MAX {
            return Err(ApiError::new(ErrorCode::GroupFull, "group is full"));
        }
        self.rate_limit(ip, Bucket::Join, self.cfg.join_limit_per_hour)?;
        let pid = self.verify_join(&gid, &req)?;
        if parts.iter().any(|p| p.pid == pid) {
            return Err(ApiError::conflict("already joined"));
        }
        if parts
            .iter()
            .any(|p| self.ops.ct_eq(&p.auth_hash, &req.auth_hash.0))
        {
            return Err(ApiError::conflict("duplicate credentials"));
        }
        let now = self.now();
        g.last_activity = now;
        self.store
            .commit(vec![
                WriteOp::InsertParticipant(ParticipantRecord {
                    gid,
                    pid,
                    ipk: req.ipk.0,
                    idh: req.idh.0,
                    auth_hash: req.auth_hash.0,
                    enc_name: req.enc_name.0,
                    enc_wish: req.enc_wish.0,
                    joined_at: now,
                }),
                WriteOp::UpsertGroup(g.clone()),
            ])
            .await?;
        self.emit(&g, parts.len() + 1, 0, false);
        Ok(pid)
    }

    pub async fn update_participant(
        &self,
        gid: Gid,
        pid: Pid,
        token: Option<[u8; 32]>,
        req: JoinRequest,
    ) -> ApiResult<()> {
        Self::check_join_sizes(&req)?;
        let token = token.ok_or_else(ApiError::unauthorized)?;
        let _guard = self.locks.lock(gid).await;
        let mut g = self.load_group(&gid).await?;
        let parts = self.store.list_participants(&gid).await?;
        let me = parts
            .iter()
            .find(|p| p.pid == pid)
            .ok_or_else(ApiError::not_found)?;
        if !self.is_participant(me, &token) {
            return Err(ApiError::unauthorized());
        }
        if g.state != GroupState::Open {
            return Err(ApiError::conflict("draw already started"));
        }
        if req.ipk.0 != me.ipk || req.idh.0 != me.idh || req.auth_hash.0 != me.auth_hash {
            return Err(ApiError::bad_request("keys must not change"));
        }
        if self.verify_join(&gid, &req)? != pid {
            return Err(ApiError::bad_request("pid mismatch"));
        }
        g.last_activity = self.now();
        self.store
            .commit(vec![
                WriteOp::UpdateParticipantData {
                    gid,
                    pid,
                    enc_name: req.enc_name.0,
                    enc_wish: req.enc_wish.0,
                },
                WriteOp::UpsertGroup(g.clone()),
            ])
            .await?;
        self.emit(&g, parts.len(), 0, false);
        Ok(())
    }

    /// Leave (self) or remove (admin). After the start this triggers a new draw (Konzept §6.4).
    pub async fn leave(&self, gid: Gid, pid: Pid, token: Option<[u8; 32]>) -> ApiResult<()> {
        let token = token.ok_or_else(ApiError::unauthorized)?;
        let _guard = self.locks.lock(gid).await;
        let mut g = self.load_group(&gid).await?;
        let parts = self.store.list_participants(&gid).await?;
        let target = parts.iter().find(|p| p.pid == pid);
        let admin = self.is_admin(&g, &token);
        let own = target.is_some_and(|p| self.is_participant(p, &token));
        if !(admin || own) {
            return Err(ApiError::unauthorized());
        }
        if target.is_none() {
            return Err(ApiError::not_found());
        }
        let now = self.now();
        let n = parts.len() - 1;
        let mut ops = vec![WriteOp::DeleteParticipant { gid, pid }];
        let push = match g.state {
            GroupState::Open => {
                g.last_activity = now;
                false
            }
            GroupState::Drawing { .. } | GroupState::Done { .. } => {
                if n < N_MIN {
                    g.state = GroupState::Open;
                    g.last_activity = now;
                } else {
                    Self::begin_draw(&mut g, now);
                }
                ops.push(WriteOp::ClearRounds { gid });
                self.mark_vacuum();
                true
            }
        };
        ops.push(WriteOp::UpsertGroup(g.clone()));
        self.store.commit(ops).await?;
        self.emit(&g, n, 0, push);
        Ok(())
    }

    // ------------------------------------------------------------------ protocol

    /// Step 1 upload: XOR `V_i` into the running aggregate (Spec §7.4).
    pub async fn upload_roles(
        &self,
        gid: Gid,
        round: u32,
        token: Option<[u8; 32]>,
        sig: Option<[u8; 64]>,
        body: &[u8],
    ) -> ApiResult<()> {
        let token = token.ok_or_else(ApiError::unauthorized)?;
        let sig = sig.ok_or(ApiError::bad_request("missing upload signature"))?;
        let _guard = self.locks.lock(gid).await;
        let mut g = self.load_group(&gid).await?;
        let parts = self.store.list_participants(&gid).await?;
        let me = self
            .find_by_token(&parts, &token)
            .map(|i| parts[i].clone())
            .ok_or_else(ApiError::unauthorized)?;
        if g.state
            != (GroupState::Drawing {
                round,
                phase: Phase::Roles,
            })
        {
            return Err(ApiError::conflict(
                "not accepting role vectors for this round",
            ));
        }
        let n = parts.len();
        let len = roles_vector_len(n);
        if body.len() != len {
            return Err(ApiError::bad_request("wrong role vector length"));
        }
        let submitted = self.store.get_submitted(&gid, round, Phase::Roles).await?;
        if submitted.contains(&me.pid) {
            return Err(ApiError::conflict("already uploaded"));
        }
        if !self
            .ops
            .verify_upload(&gid, &me.pid, &me.ipk, UploadKind::Roles, round, body, &sig)
        {
            return Err(ApiError::new(
                ErrorCode::Unauthorized,
                "invalid upload signature",
            ));
        }
        let mut agg = match self.store.get_aggregate(&gid, round, Phase::Roles).await? {
            Some(a) => a,
            None => AggregateRecord {
                gid,
                round,
                phase: Phase::Roles,
                aggregate: vec![0u8; len],
                submitted: Vec::new(),
            },
        };
        if !self.ops.xor_into(&mut agg.aggregate, body) {
            return Err(ApiError::internal());
        }
        agg.submitted.push(me.pid);
        let count = agg.submitted.len();
        if count < n {
            self.store.commit(vec![WriteOp::PutAggregate(agg)]).await?;
            self.emit(&g, n, count, false);
            return Ok(());
        }
        // Complete: evaluate R publicly (Spec §7.4); collision ⇒ automatic follow-up round.
        let g_r = self.group_context(&g, round, &parts)?;
        let now = self.now();
        let ops = if self.ops.evaluate_roles(&g_r, n, &agg.aggregate).is_some() {
            g.state = GroupState::Drawing {
                round,
                phase: Phase::Reveal,
            };
            g.last_activity = now;
            vec![WriteOp::PutAggregate(agg), WriteOp::UpsertGroup(g.clone())]
        } else {
            tracing::info!(round, "collision in area E, next round");
            Self::next_round(&mut g, now);
            self.mark_vacuum();
            vec![
                WriteOp::ClearRounds { gid },
                WriteOp::UpsertGroup(g.clone()),
            ]
        };
        self.store.commit(ops).await?;
        self.emit(&g, n, 0, true);
        Ok(())
    }

    /// `R`, once all role vectors of `round` are in.
    pub async fn roles_result(&self, gid: Gid, round: u32) -> ApiResult<Vec<u8>> {
        let g = self.load_group(&gid).await?;
        let available = matches!(
            g.state,
            GroupState::Drawing { round: r, phase: Phase::Reveal } | GroupState::Done { round: r, .. }
                if r == round
        );
        if !available {
            return Err(ApiError::conflict("role vectors incomplete"));
        }
        self.store
            .get_aggregate(&gid, round, Phase::Roles)
            .await?
            .map(|a| a.aggregate)
            .ok_or_else(ApiError::internal)
    }

    /// Step 2 upload: XOR `SD_i`, store `C_{i,1..16}`; on completion choose `t*` and keep only
    /// its reveals (Spec §9.3).
    pub async fn upload_reveal(
        &self,
        gid: Gid,
        round: u32,
        token: Option<[u8; 32]>,
        sig: Option<[u8; 64]>,
        body: &[u8],
    ) -> ApiResult<()> {
        let token = token.ok_or_else(ApiError::unauthorized)?;
        let sig = sig.ok_or(ApiError::bad_request("missing upload signature"))?;
        let _guard = self.locks.lock(gid).await;
        let mut g = self.load_group(&gid).await?;
        let parts = self.store.list_participants(&gid).await?;
        let me = self
            .find_by_token(&parts, &token)
            .map(|i| parts[i].clone())
            .ok_or_else(ApiError::unauthorized)?;
        if g.state
            != (GroupState::Drawing {
                round,
                phase: Phase::Reveal,
            })
        {
            return Err(ApiError::conflict("not accepting reveals for this round"));
        }
        if body.len() != L_REVEAL_UPLOAD {
            return Err(ApiError::bad_request("wrong reveal upload length"));
        }
        let n = parts.len();
        let submitted = self.store.get_submitted(&gid, round, Phase::Reveal).await?;
        if submitted.contains(&me.pid) {
            return Err(ApiError::conflict("already uploaded"));
        }
        if !self.ops.verify_upload(
            &gid,
            &me.pid,
            &me.ipk,
            UploadKind::Reveal,
            round,
            body,
            &sig,
        ) {
            return Err(ApiError::new(
                ErrorCode::Unauthorized,
                "invalid upload signature",
            ));
        }
        let (sd, cts) = self
            .ops
            .split_reveal_upload(body)
            .filter(|(sd, cts)| sd.len() == L_SD && cts.len() == T_ATTEMPTS)
            .ok_or(ApiError::bad_request("malformed reveal upload"))?;
        let mut agg = match self.store.get_aggregate(&gid, round, Phase::Reveal).await? {
            Some(a) => a,
            None => AggregateRecord {
                gid,
                round,
                phase: Phase::Reveal,
                aggregate: vec![0u8; L_SD],
                submitted: Vec::new(),
            },
        };
        if !self.ops.xor_into(&mut agg.aggregate, sd) {
            return Err(ApiError::internal());
        }
        agg.submitted.push(me.pid);
        let count = agg.submitted.len();
        let cts_op = WriteOp::PutRevealCiphertexts {
            gid,
            round,
            pid: me.pid,
            ciphertexts: cts.iter().map(|c| c.to_vec()).collect(),
        };
        if count < n {
            self.store
                .commit(vec![cts_op, WriteOp::PutAggregate(agg)])
                .await?;
            self.emit(&g, n, count, false);
            return Ok(());
        }
        // Complete: SD ⇒ t* (Spec §9.1); keep only C_{·,t*}.
        let r_vec = self
            .store
            .get_aggregate(&gid, round, Phase::Roles)
            .await?
            .ok_or_else(ApiError::internal)?;
        let g_r = self.group_context(&g, round, &parts)?;
        let t_star = self
            .ops
            .evaluate_roles(&g_r, n, &r_vec.aggregate)
            .and_then(|outcome| self.ops.select_attempt(&outcome, &agg.aggregate))
            .filter(|t| (1..=T_ATTEMPTS as u8).contains(t));
        let now = self.now();
        let ops = match t_star {
            Some(t) => {
                g.state = GroupState::Done { round, t_star: t };
                g.last_activity = now;
                vec![
                    cts_op,
                    WriteOp::PutAggregate(agg),
                    WriteOp::KeepOnlyAttempt {
                        gid,
                        round,
                        attempt: t,
                    },
                    WriteOp::UpsertGroup(g.clone()),
                ]
            }
            None => {
                tracing::info!(round, "no valid attempt, next round");
                Self::next_round(&mut g, now);
                vec![
                    WriteOp::ClearRounds { gid },
                    WriteOp::UpsertGroup(g.clone()),
                ]
            }
        };
        self.mark_vacuum();
        self.store.commit(ops).await?;
        self.emit(&g, n, 0, true);
        Ok(())
    }

    /// `SD`, `t*` and the `n` reveals of attempt `t*`, once complete.
    pub async fn reveal_release(&self, gid: Gid, round: u32) -> ApiResult<RevealRelease> {
        let g = self.load_group(&gid).await?;
        let t_star = match g.state {
            GroupState::Done { round: r, t_star } if r == round => t_star,
            _ => return Err(ApiError::conflict("reveals incomplete")),
        };
        let sd = self
            .store
            .get_aggregate(&gid, round, Phase::Reveal)
            .await?
            .ok_or_else(ApiError::internal)?;
        let reveals = self.store.list_reveals(&gid, round, t_star).await?;
        Ok(RevealRelease {
            round,
            selfdraw_aggregate: wichtel_api::Bin(sd.aggregate),
            t_star,
            reveals: reveals
                .into_iter()
                .map(|(pid, ct)| RevealEntry {
                    pid: wichtel_api::Fixed(pid),
                    ciphertext: wichtel_api::Bin(ct),
                })
                .collect(),
        })
    }

    // ------------------------------------------------------------------ push

    pub async fn push_subscribe(
        &self,
        gid: Gid,
        pid: Pid,
        token: Option<[u8; 32]>,
        req: PushSubscriptionRequest,
    ) -> ApiResult<()> {
        let token = token.ok_or_else(ApiError::unauthorized)?;
        validate_endpoint(&req.endpoint, &self.cfg.push_hosts).map_err(ApiError::bad_request)?;
        if req.p256dh.0.len() != 65 || req.auth.0.len() != 16 {
            return Err(ApiError::bad_request("invalid subscription keys"));
        }
        let _guard = self.locks.lock(gid).await;
        let parts = self.store.list_participants(&gid).await?;
        let me = parts
            .iter()
            .find(|p| p.pid == pid)
            .ok_or_else(ApiError::not_found)?;
        if !self.is_participant(me, &token) {
            return Err(ApiError::unauthorized());
        }
        self.store
            .commit(vec![WriteOp::PutPushSub(PushSubRecord {
                gid,
                pid,
                endpoint: req.endpoint,
                p256dh: req.p256dh.0,
                auth: req.auth.0,
                created_at: self.now(),
            })])
            .await?;
        Ok(())
    }

    pub async fn push_unsubscribe(
        &self,
        gid: Gid,
        pid: Pid,
        token: Option<[u8; 32]>,
    ) -> ApiResult<()> {
        let token = token.ok_or_else(ApiError::unauthorized)?;
        let _guard = self.locks.lock(gid).await;
        let parts = self.store.list_participants(&gid).await?;
        let me = parts
            .iter()
            .find(|p| p.pid == pid)
            .ok_or_else(ApiError::not_found)?;
        if !self.is_participant(me, &token) {
            return Err(ApiError::unauthorized());
        }
        self.store
            .commit(vec![WriteOp::DeletePushSub { gid, pid }])
            .await?;
        Ok(())
    }

    // ------------------------------------------------------------------ background jobs

    /// Minutely job: scheduled draws and reminders, expiry, bundled `VACUUM`, housekeeping.
    pub async fn run_jobs(&self) {
        if let Err(e) = self.process_schedules().await {
            tracing::warn!(error = %e.message, "schedule job failed");
        }
        if let Err(e) = self.expire_groups().await {
            tracing::warn!(error = %e.message, "expiry job failed");
        }
        self.maybe_vacuum(false).await;
        self.hub.cleanup();
        self.locks.cleanup();
        self.rate.cleanup(self.now(), RATE_WINDOW);
    }

    /// Start due draws (`n < N_MIN` ⇒ `schedule_missed`) and send 10-minute reminders.
    pub async fn process_schedules(&self) -> ApiResult<()> {
        let now = self.now();
        for s in self.store.list_scheduled(now + REMINDER_LEAD).await? {
            let _guard = self.locks.lock(s.gid).await;
            let Some(mut g) = self.store.get_group(&s.gid).await? else {
                continue;
            };
            if g.state != GroupState::Open || g.draw_at != Some(s.draw_at) {
                continue;
            }
            let n = self.store.list_participants(&s.gid).await?.len();
            if s.draw_at <= now {
                let mut ops = Vec::new();
                if (N_MIN..=N_MAX).contains(&n) {
                    Self::begin_draw(&mut g, now);
                    ops.push(WriteOp::ClearRounds { gid: g.gid });
                    tracing::info!("scheduled draw started");
                } else {
                    g.schedule_missed = true;
                    g.draw_at = None;
                    g.reminder_sent = false;
                    tracing::info!("scheduled draw missed: too few participants");
                }
                ops.push(WriteOp::UpsertGroup(g.clone()));
                self.store.commit(ops).await?;
                self.emit(&g, n, 0, true);
            } else if !g.reminder_sent {
                g.reminder_sent = true;
                self.store
                    .commit(vec![WriteOp::UpsertGroup(g.clone())])
                    .await?;
                self.push.notify(g.gid);
            }
        }
        Ok(())
    }

    /// Delete expired groups and unused open groups (Spec §10, Review D2).
    pub async fn expire_groups(&self) -> ApiResult<()> {
        let now = self.now();
        let mut doomed = self.store.list_expired(now).await?;
        for (gid, n) in self.store.list_idle_open(now - IDLE_LIFETIME).await? {
            if (n as usize) < N_MIN && !doomed.contains(&gid) {
                doomed.push(gid);
            }
        }
        for gid in doomed {
            let _guard = self.locks.lock(gid).await;
            self.store.commit(vec![WriteOp::DeleteGroup(gid)]).await?;
            self.hub.close(&gid);
            self.mark_vacuum();
            tracing::info!("group expired and deleted");
        }
        Ok(())
    }

    /// Run `VACUUM` + checkpoint if deletions are pending and the last run is at least
    /// `vacuum_interval_secs` ago (or `force`).
    pub async fn maybe_vacuum(&self, force: bool) {
        if !self.vacuum.pending.load(Ordering::SeqCst) {
            return;
        }
        let now = self.now();
        {
            let last = self.vacuum.last.lock().expect("vacuum");
            if !force
                && let Some(t) = *last
                && now - t < self.cfg.vacuum_interval_secs as i64
            {
                return;
            }
        }
        self.vacuum.pending.store(false, Ordering::SeqCst);
        match self.store.vacuum().await {
            Ok(()) => *self.vacuum.last.lock().expect("vacuum") = Some(now),
            Err(e) => {
                self.vacuum.pending.store(true, Ordering::SeqCst);
                tracing::warn!(error = %e, "vacuum failed");
            }
        }
    }

    /// Whether a `VACUUM` is pending (for tests and diagnostics).
    pub fn vacuum_pending(&self) -> bool {
        self.vacuum.pending.load(Ordering::SeqCst)
    }
}
