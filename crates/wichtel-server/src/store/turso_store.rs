//! [`Store`] on an embedded, local Turso database file (Spec §14).

use tokio::sync::Mutex;
use turso::{Connection, Database, Value};
use wichtel_api::Phase;

use super::{
    AggregateRecord, Gid, GroupRecord, ParticipantRecord, Pid, PushSubRecord, ScheduledGroup,
    Store, StoreError, StoreFuture, WriteOp, parse_state, phase_str, state_columns,
};

/// SQL migrations, applied in order; the index + 1 is the schema version.
const MIGRATIONS: &[&str] = &[include_str!("../../migrations/0001_init.sql")];

/// Local Turso database. All statements run on one connection guarded by a mutex: the
/// workload is tiny, and this keeps `VACUUM`/checkpoint free of concurrently open statements.
pub struct TursoStore {
    _db: Database,
    conn: Mutex<Connection>,
}

impl TursoStore {
    /// Open (or create) the database file and apply pending migrations.
    pub async fn open(path: &str) -> Result<Self, StoreError> {
        let db = turso::Builder::new_local(path)
            .experimental_vacuum(true)
            .build()
            .await?;
        let conn = db.connect()?;
        let store = Self {
            _db: db,
            conn: Mutex::new(conn),
        };
        store.migrate().await?;
        Ok(store)
    }

    async fn migrate(&self) -> Result<(), StoreError> {
        let conn = self.conn.lock().await;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)",
            (),
        )
        .await?;
        let mut rows = conn
            .query(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                (),
            )
            .await?;
        let current = match rows.next().await? {
            Some(row) => int(&row.get_value(0)?)?,
            None => 0,
        };
        drop(rows);
        for (i, sql) in MIGRATIONS.iter().enumerate() {
            let version = i as i64 + 1;
            if version <= current {
                continue;
            }
            conn.execute("BEGIN", ()).await?;
            let res = async {
                conn.execute_batch(sql).await?;
                conn.execute(
                    "INSERT INTO schema_migrations (version) VALUES (?1)",
                    [Value::Integer(version)],
                )
                .await?;
                Ok::<_, turso::Error>(())
            }
            .await;
            match res {
                Ok(()) => {
                    conn.execute("COMMIT", ()).await?;
                }
                Err(e) => {
                    let _ = conn.execute("ROLLBACK", ()).await;
                    return Err(e.into());
                }
            }
        }
        Ok(())
    }

    async fn query_all(
        &self,
        sql: &str,
        params: Vec<Value>,
    ) -> Result<Vec<Vec<Value>>, StoreError> {
        let conn = self.conn.lock().await;
        let mut rows = conn.query(sql, params).await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            let mut vals = Vec::with_capacity(row.column_count());
            for i in 0..row.column_count() {
                vals.push(row.get_value(i)?);
            }
            out.push(vals);
        }
        Ok(out)
    }
}

async fn apply(conn: &Connection, op: WriteOp) -> Result<(), turso::Error> {
    match op {
        WriteOp::UpsertGroup(g) => {
            let (state, phase, t_star) = state_columns(&g.state);
            conn.execute(
                "INSERT OR REPLACE INTO groups (gid, admin_hash, enc_meta, state, round, phase, \
                 t_star, draw_no, draw_at, reminder_sent, schedule_missed, delete_after, \
                 created_at, last_activity) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                vec![
                    blob(&g.gid),
                    blob(&g.admin_hash),
                    Value::Blob(g.enc_meta),
                    Value::Text(state.into()),
                    Value::Integer(g.round.into()),
                    phase.map_or(Value::Null, |p| Value::Text(p.into())),
                    t_star.map_or(Value::Null, Value::Integer),
                    Value::Integer(g.draw_no.into()),
                    g.draw_at.map_or(Value::Null, Value::Integer),
                    Value::Integer(g.reminder_sent.into()),
                    Value::Integer(g.schedule_missed.into()),
                    Value::Integer(g.delete_after),
                    Value::Integer(g.created_at),
                    Value::Integer(g.last_activity),
                ],
            )
            .await?;
        }
        WriteOp::DeleteGroup(gid) => {
            for table in [
                "reveal_uploads",
                "round_aggregates",
                "push_subscriptions",
                "participants",
                "groups",
            ] {
                conn.execute(format!("DELETE FROM {table} WHERE gid = ?1"), [blob(&gid)])
                    .await?;
            }
        }
        WriteOp::InsertParticipant(p) => {
            conn.execute(
                "INSERT INTO participants (gid, pid, ipk, idh, auth_hash, enc_name, enc_wish, \
                 joined_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                vec![
                    blob(&p.gid),
                    blob(&p.pid),
                    blob(&p.ipk),
                    blob(&p.idh),
                    blob(&p.auth_hash),
                    Value::Blob(p.enc_name),
                    Value::Blob(p.enc_wish),
                    Value::Integer(p.joined_at),
                ],
            )
            .await?;
        }
        WriteOp::UpdateParticipantData {
            gid,
            pid,
            enc_name,
            enc_wish,
        } => {
            conn.execute(
                "UPDATE participants SET enc_name = ?3, enc_wish = ?4 WHERE gid = ?1 AND pid = ?2",
                vec![
                    blob(&gid),
                    blob(&pid),
                    Value::Blob(enc_name),
                    Value::Blob(enc_wish),
                ],
            )
            .await?;
        }
        WriteOp::DeleteParticipant { gid, pid } => {
            for table in ["push_subscriptions", "participants"] {
                conn.execute(
                    format!("DELETE FROM {table} WHERE gid = ?1 AND pid = ?2"),
                    [blob(&gid), blob(&pid)],
                )
                .await?;
            }
        }
        WriteOp::PutAggregate(a) => {
            conn.execute(
                "INSERT OR REPLACE INTO round_aggregates (gid, round, phase, aggregate, submitted) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                vec![
                    blob(&a.gid),
                    Value::Integer(a.round.into()),
                    Value::Text(phase_str(a.phase).into()),
                    Value::Blob(a.aggregate),
                    Value::Blob(a.submitted.concat()),
                ],
            )
            .await?;
        }
        WriteOp::PutRevealCiphertexts {
            gid,
            round,
            pid,
            ciphertexts,
        } => {
            for (i, ct) in ciphertexts.into_iter().enumerate() {
                conn.execute(
                    "INSERT INTO reveal_uploads (gid, round, pid, attempt, ciphertext) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    vec![
                        blob(&gid),
                        Value::Integer(round.into()),
                        blob(&pid),
                        Value::Integer(i as i64 + 1),
                        Value::Blob(ct),
                    ],
                )
                .await?;
            }
        }
        WriteOp::KeepOnlyAttempt {
            gid,
            round,
            attempt,
        } => {
            conn.execute(
                "DELETE FROM reveal_uploads WHERE gid = ?1 AND (round <> ?2 OR attempt <> ?3)",
                vec![
                    blob(&gid),
                    Value::Integer(round.into()),
                    Value::Integer(attempt.into()),
                ],
            )
            .await?;
        }
        WriteOp::ClearRounds { gid } => {
            for table in ["reveal_uploads", "round_aggregates"] {
                conn.execute(format!("DELETE FROM {table} WHERE gid = ?1"), [blob(&gid)])
                    .await?;
            }
        }
        WriteOp::PutPushSub(s) => {
            conn.execute(
                "INSERT OR REPLACE INTO push_subscriptions (gid, pid, endpoint, p256dh, auth, \
                 created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                vec![
                    blob(&s.gid),
                    blob(&s.pid),
                    Value::Text(s.endpoint),
                    Value::Blob(s.p256dh),
                    Value::Blob(s.auth),
                    Value::Integer(s.created_at),
                ],
            )
            .await?;
        }
        WriteOp::DeletePushSub { gid, pid } => {
            conn.execute(
                "DELETE FROM push_subscriptions WHERE gid = ?1 AND pid = ?2",
                [blob(&gid), blob(&pid)],
            )
            .await?;
        }
        WriteOp::DeletePushSubIfEndpoint { gid, pid, endpoint } => {
            conn.execute(
                "DELETE FROM push_subscriptions WHERE gid = ?1 AND pid = ?2 AND endpoint = ?3",
                vec![blob(&gid), blob(&pid), Value::Text(endpoint)],
            )
            .await?;
        }
        WriteOp::PutServerKey { name, value } => {
            conn.execute(
                "INSERT OR REPLACE INTO server_keys (name, value) VALUES (?1, ?2)",
                vec![Value::Text(name), Value::Blob(value)],
            )
            .await?;
        }
    }
    Ok(())
}

const GROUP_COLUMNS: &str = "gid, admin_hash, enc_meta, state, round, phase, t_star, draw_no, \
    draw_at, reminder_sent, schedule_missed, delete_after, created_at, last_activity";

fn group_from_row(v: &[Value]) -> Result<GroupRecord, StoreError> {
    let round = u32::try_from(int(&v[4])?).map_err(|_| StoreError::Corrupt("round"))?;
    let phase = match &v[5] {
        Value::Text(s) => Some(s.as_str()),
        _ => None,
    };
    let t_star = opt_int(&v[6])?;
    Ok(GroupRecord {
        gid: fixed(&v[0])?,
        admin_hash: fixed(&v[1])?,
        enc_meta: bytes(&v[2])?,
        state: parse_state(text(&v[3])?, round, phase, t_star)?,
        round,
        draw_no: u32::try_from(int(&v[7])?).map_err(|_| StoreError::Corrupt("draw_no"))?,
        draw_at: opt_int(&v[8])?,
        reminder_sent: int(&v[9])? != 0,
        schedule_missed: int(&v[10])? != 0,
        delete_after: int(&v[11])?,
        created_at: int(&v[12])?,
        last_activity: int(&v[13])?,
    })
}

impl Store for TursoStore {
    fn commit(&self, ops: Vec<WriteOp>) -> StoreFuture<'_, ()> {
        Box::pin(async move {
            if ops.is_empty() {
                return Ok(());
            }
            let conn = self.conn.lock().await;
            conn.execute("BEGIN IMMEDIATE", ()).await?;
            let mut result = Ok(());
            for op in ops {
                if let Err(e) = apply(&conn, op).await {
                    result = Err(e);
                    break;
                }
            }
            match result {
                Ok(()) => {
                    conn.execute("COMMIT", ()).await?;
                    Ok(())
                }
                Err(e) => {
                    let _ = conn.execute("ROLLBACK", ()).await;
                    Err(e.into())
                }
            }
        })
    }

    fn get_group<'a>(&'a self, gid: &'a Gid) -> StoreFuture<'a, Option<GroupRecord>> {
        Box::pin(async move {
            let rows = self
                .query_all(
                    &format!("SELECT {GROUP_COLUMNS} FROM groups WHERE gid = ?1"),
                    vec![blob(gid)],
                )
                .await?;
            rows.first().map(|r| group_from_row(r)).transpose()
        })
    }

    fn count_groups(&self) -> StoreFuture<'_, u64> {
        Box::pin(async move {
            let rows = self
                .query_all("SELECT count(*) FROM groups", vec![])
                .await?;
            let n = rows.first().map(|r| int(&r[0])).transpose()?.unwrap_or(0);
            Ok(n.max(0) as u64)
        })
    }

    fn list_participants<'a>(&'a self, gid: &'a Gid) -> StoreFuture<'a, Vec<ParticipantRecord>> {
        Box::pin(async move {
            let rows = self
                .query_all(
                    "SELECT gid, pid, ipk, idh, auth_hash, enc_name, enc_wish, joined_at \
                     FROM participants WHERE gid = ?1",
                    vec![blob(gid)],
                )
                .await?;
            let mut out = rows
                .iter()
                .map(|v| {
                    Ok(ParticipantRecord {
                        gid: fixed(&v[0])?,
                        pid: fixed(&v[1])?,
                        ipk: fixed(&v[2])?,
                        idh: fixed(&v[3])?,
                        auth_hash: fixed(&v[4])?,
                        enc_name: bytes(&v[5])?,
                        enc_wish: bytes(&v[6])?,
                        joined_at: int(&v[7])?,
                    })
                })
                .collect::<Result<Vec<_>, StoreError>>()?;
            out.sort_by_key(|a| a.pid);
            Ok(out)
        })
    }

    fn get_aggregate<'a>(
        &'a self,
        gid: &'a Gid,
        round: u32,
        phase: Phase,
    ) -> StoreFuture<'a, Option<AggregateRecord>> {
        Box::pin(async move {
            let rows = self
                .query_all(
                    "SELECT aggregate, submitted FROM round_aggregates \
                     WHERE gid = ?1 AND round = ?2 AND phase = ?3",
                    vec![
                        blob(gid),
                        Value::Integer(round.into()),
                        Value::Text(phase_str(phase).into()),
                    ],
                )
                .await?;
            let Some(mut v) = rows.into_iter().next() else {
                return Ok(None);
            };
            let submitted = pid_list(&v[1])?;
            let aggregate = match std::mem::replace(&mut v[0], Value::Null) {
                Value::Blob(b) => b,
                _ => return Err(StoreError::Corrupt("expected blob")),
            };
            Ok(Some(AggregateRecord {
                gid: *gid,
                round,
                phase,
                aggregate,
                submitted,
            }))
        })
    }

    fn get_submitted<'a>(
        &'a self,
        gid: &'a Gid,
        round: u32,
        phase: Phase,
    ) -> StoreFuture<'a, Vec<Pid>> {
        Box::pin(async move {
            let rows = self
                .query_all(
                    "SELECT submitted FROM round_aggregates \
                     WHERE gid = ?1 AND round = ?2 AND phase = ?3",
                    vec![
                        blob(gid),
                        Value::Integer(round.into()),
                        Value::Text(phase_str(phase).into()),
                    ],
                )
                .await?;
            match rows.first() {
                Some(v) => pid_list(&v[0]),
                None => Ok(Vec::new()),
            }
        })
    }

    fn list_reveals<'a>(
        &'a self,
        gid: &'a Gid,
        round: u32,
        attempt: u8,
    ) -> StoreFuture<'a, Vec<(Pid, Vec<u8>)>> {
        Box::pin(async move {
            let rows = self
                .query_all(
                    "SELECT pid, ciphertext FROM reveal_uploads \
                     WHERE gid = ?1 AND round = ?2 AND attempt = ?3",
                    vec![
                        blob(gid),
                        Value::Integer(round.into()),
                        Value::Integer(attempt.into()),
                    ],
                )
                .await?;
            let mut out = rows
                .iter()
                .map(|v| Ok((fixed(&v[0])?, bytes(&v[1])?)))
                .collect::<Result<Vec<_>, StoreError>>()?;
            out.sort_by_key(|a| a.0);
            Ok(out)
        })
    }

    fn count_reveals<'a>(&'a self, gid: &'a Gid, round: u32) -> StoreFuture<'a, u64> {
        Box::pin(async move {
            let rows = self
                .query_all(
                    "SELECT count(*) FROM reveal_uploads WHERE gid = ?1 AND round = ?2",
                    vec![blob(gid), Value::Integer(round.into())],
                )
                .await?;
            let n = rows.first().map(|r| int(&r[0])).transpose()?.unwrap_or(0);
            Ok(n.max(0) as u64)
        })
    }

    fn list_push_subs<'a>(&'a self, gid: &'a Gid) -> StoreFuture<'a, Vec<PushSubRecord>> {
        Box::pin(async move {
            let rows = self
                .query_all(
                    "SELECT gid, pid, endpoint, p256dh, auth, created_at \
                     FROM push_subscriptions WHERE gid = ?1",
                    vec![blob(gid)],
                )
                .await?;
            let mut out = rows
                .iter()
                .map(|v| {
                    Ok(PushSubRecord {
                        gid: fixed(&v[0])?,
                        pid: fixed(&v[1])?,
                        endpoint: text(&v[2])?.to_owned(),
                        p256dh: bytes(&v[3])?,
                        auth: bytes(&v[4])?,
                        created_at: int(&v[5])?,
                    })
                })
                .collect::<Result<Vec<_>, StoreError>>()?;
            out.sort_by_key(|a| a.pid);
            Ok(out)
        })
    }

    fn get_server_key<'a>(&'a self, name: &'a str) -> StoreFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            let rows = self
                .query_all(
                    "SELECT value FROM server_keys WHERE name = ?1",
                    vec![Value::Text(name.into())],
                )
                .await?;
            rows.first().map(|v| bytes(&v[0])).transpose()
        })
    }

    fn list_scheduled(&self, until: i64) -> StoreFuture<'_, Vec<ScheduledGroup>> {
        Box::pin(async move {
            let rows = self
                .query_all(
                    "SELECT gid, draw_at, reminder_sent FROM groups \
                     WHERE state = 'open' AND draw_at IS NOT NULL AND draw_at <= ?1",
                    vec![Value::Integer(until)],
                )
                .await?;
            rows.iter()
                .map(|v| {
                    Ok(ScheduledGroup {
                        gid: fixed(&v[0])?,
                        draw_at: int(&v[1])?,
                        reminder_sent: int(&v[2])? != 0,
                    })
                })
                .collect()
        })
    }

    fn list_expired(&self, now: i64) -> StoreFuture<'_, Vec<Gid>> {
        Box::pin(async move {
            let rows = self
                .query_all(
                    "SELECT gid FROM groups WHERE delete_after <= ?1",
                    vec![Value::Integer(now)],
                )
                .await?;
            rows.iter().map(|v| fixed(&v[0])).collect()
        })
    }

    fn list_idle_open(&self, cutoff: i64) -> StoreFuture<'_, Vec<(Gid, u64)>> {
        Box::pin(async move {
            let rows = self
                .query_all(
                    "SELECT gid FROM groups WHERE state = 'open' AND draw_at IS NULL \
                     AND last_activity <= ?1",
                    vec![Value::Integer(cutoff)],
                )
                .await?;
            let mut out = Vec::with_capacity(rows.len());
            for v in &rows {
                let gid: Gid = fixed(&v[0])?;
                let n = self
                    .query_all(
                        "SELECT count(*) FROM participants WHERE gid = ?1",
                        vec![blob(&gid)],
                    )
                    .await?;
                let n = n.first().map(|r| int(&r[0])).transpose()?.unwrap_or(0);
                out.push((gid, n.max(0) as u64));
            }
            Ok(out)
        })
    }

    fn vacuum(&self) -> StoreFuture<'_, ()> {
        Box::pin(async move {
            let conn = self.conn.lock().await;
            conn.execute("VACUUM", ()).await?;
            let mut rows = conn.query("PRAGMA wal_checkpoint(TRUNCATE)", ()).await?;
            while rows.next().await?.is_some() {}
            Ok(())
        })
    }
}

fn blob(b: &[u8]) -> Value {
    Value::Blob(b.to_vec())
}

fn int(v: &Value) -> Result<i64, StoreError> {
    match v {
        Value::Integer(i) => Ok(*i),
        _ => Err(StoreError::Corrupt("expected integer")),
    }
}

fn opt_int(v: &Value) -> Result<Option<i64>, StoreError> {
    match v {
        Value::Null => Ok(None),
        Value::Integer(i) => Ok(Some(*i)),
        _ => Err(StoreError::Corrupt("expected integer or null")),
    }
}

fn text(v: &Value) -> Result<&str, StoreError> {
    match v {
        Value::Text(s) => Ok(s),
        _ => Err(StoreError::Corrupt("expected text")),
    }
}

fn bytes(v: &Value) -> Result<Vec<u8>, StoreError> {
    match v {
        Value::Blob(b) => Ok(b.clone()),
        _ => Err(StoreError::Corrupt("expected blob")),
    }
}

fn pid_list(v: &Value) -> Result<Vec<Pid>, StoreError> {
    let raw = match v {
        Value::Blob(b) => b,
        _ => return Err(StoreError::Corrupt("expected blob")),
    };
    if raw.len() % 16 != 0 {
        return Err(StoreError::Corrupt("submitted"));
    }
    Ok(raw
        .chunks_exact(16)
        .map(|c| c.try_into().expect("16-byte chunk"))
        .collect())
}

fn fixed<const N: usize>(v: &Value) -> Result<[u8; N], StoreError> {
    match v {
        Value::Blob(b) => b
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupt("blob length")),
        _ => Err(StoreError::Corrupt("expected blob")),
    }
}
