//! [`Store`] on an embedded, local Turso database file (Spec §14).

use std::sync::Arc;

use tokio::sync::Mutex;
use turso::{Connection, Database, Value};
use wichtel_api::Phase;

use super::{
    AggregateRecord, Gid, GroupRecord, ParticipantRecord, Pid, PushSubRecord, ScheduledGroup,
    Store, StoreError, StoreFuture, WriteOp, parse_state, phase_str, state_columns,
};

/// SQL migrations, applied in order; the index + 1 is the schema version.
const MIGRATIONS: &[&str] = &[
    include_str!("../../migrations/0001_init.sql"),
    include_str!("../../migrations/0002_contacts.sql"),
];

/// `server_keys` row written together with every destructive commit and removed by
/// [`Store::vacuum`]: a pending `VACUUM` survives a crash or restart.
const VACUUM_MARKER: &str = "vacuum_pending";

/// Local Turso database. All statements run on one connection guarded by a mutex: the
/// workload is tiny, and this keeps `VACUUM`/checkpoint free of concurrently open statements.
///
/// Transactions are cancel-safe: [`Store::commit`] runs in a detached task that always ends
/// with `COMMIT` or `ROLLBACK`, and every user of the connection first rolls back a
/// transaction that was left open anyway (e.g. by a panic).
pub struct TursoStore {
    _db: Database,
    conn: Arc<Mutex<Connection>>,
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
            conn: Arc::new(Mutex::new(conn)),
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
            run_tx(&conn, async |c: &Connection| {
                c.execute_batch(sql).await?;
                c.execute(
                    "INSERT INTO schema_migrations (version) VALUES (?1)",
                    [Value::Integer(version)],
                )
                .await?;
                Ok(())
            })
            .await?;
        }
        Ok(())
    }

    async fn query_all(
        &self,
        sql: &str,
        params: Vec<Value>,
    ) -> Result<Vec<Vec<Value>>, StoreError> {
        let conn = self.conn.lock().await;
        reset_open_tx(&conn).await?;
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
                "contacts",
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
            for table in ["reveal_uploads", "round_aggregates", "contacts"] {
                conn.execute(format!("DELETE FROM {table} WHERE gid = ?1"), [blob(&gid)])
                    .await?;
            }
        }
        WriteOp::PutContact {
            gid,
            pid,
            draw_no,
            contact,
        } => {
            conn.execute(
                "INSERT OR REPLACE INTO contacts (gid, pid, draw_no, contact) \
                 VALUES (?1, ?2, ?3, ?4)",
                vec![
                    blob(&gid),
                    blob(&pid),
                    Value::Integer(draw_no.into()),
                    Value::Blob(contact),
                ],
            )
            .await?;
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
        let conn = self.conn.clone();
        Box::pin(async move {
            if ops.is_empty() {
                return Ok(());
            }
            // Detached from the request: if the caller's future is dropped (client gone,
            // request timeout), the transaction still runs to COMMIT or ROLLBACK.
            tokio::spawn(async move {
                let conn = conn.lock_owned().await;
                let destroys = ops.iter().any(WriteOp::destroys_data);
                run_tx(&conn, async |c: &Connection| {
                    for op in ops {
                        apply(c, op).await?;
                    }
                    if destroys {
                        c.execute(
                            "INSERT OR REPLACE INTO server_keys (name, value) VALUES (?1, x'01')",
                            [Value::Text(VACUUM_MARKER.into())],
                        )
                        .await?;
                    }
                    Ok(())
                })
                .await
            })
            .await
            .map_err(|_| StoreError::Aborted)?
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

    fn list_contacts<'a>(&'a self, gid: &'a Gid, draw_no: u32) -> StoreFuture<'a, Vec<Vec<u8>>> {
        Box::pin(async move {
            let rows = self
                .query_all(
                    "SELECT contact FROM contacts WHERE gid = ?1 AND draw_no = ?2",
                    vec![blob(gid), Value::Integer(draw_no.into())],
                )
                .await?;
            rows.iter().map(|v| bytes(&v[0])).collect()
        })
    }

    fn count_contacts<'a>(&'a self, gid: &'a Gid) -> StoreFuture<'a, u64> {
        Box::pin(async move {
            let rows = self
                .query_all(
                    "SELECT count(*) FROM contacts WHERE gid = ?1",
                    vec![blob(gid)],
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

    fn list_empty_open(&self, cutoff: i64) -> StoreFuture<'_, Vec<Gid>> {
        Box::pin(async move {
            let rows = self
                .query_all(
                    "SELECT gid FROM groups WHERE state = 'open' AND last_activity <= ?1 \
                     AND NOT EXISTS (SELECT 1 FROM participants p WHERE p.gid = groups.gid)",
                    vec![Value::Integer(cutoff)],
                )
                .await?;
            rows.iter().map(|v| fixed(&v[0])).collect()
        })
    }

    fn needs_vacuum(&self) -> StoreFuture<'_, bool> {
        Box::pin(async move {
            if self.get_server_key(VACUUM_MARKER).await?.is_some() {
                return Ok(true);
            }
            let rows = self.query_all("PRAGMA freelist_count", vec![]).await?;
            let n = rows.first().map(|r| int(&r[0])).transpose()?.unwrap_or(0);
            Ok(n > 0)
        })
    }

    fn vacuum(&self) -> StoreFuture<'_, ()> {
        Box::pin(async move {
            let conn = self.conn.lock().await;
            reset_open_tx(&conn).await?;
            conn.execute("VACUUM", ()).await?;
            // Only after a successful VACUUM (a crash in between just repeats it at the next
            // start); the residue of this delete is the marker itself, nothing personal.
            conn.execute(
                "DELETE FROM server_keys WHERE name = ?1",
                [Value::Text(VACUUM_MARKER.into())],
            )
            .await?;
            let mut rows = conn.query("PRAGMA wal_checkpoint(TRUNCATE)", ()).await?;
            while rows.next().await?.is_some() {}
            Ok(())
        })
    }
}

/// Roll back a transaction that is still open on `conn` (left behind by a panic or an
/// earlier failure), so it cannot block every later write.
async fn reset_open_tx(conn: &Connection) -> Result<(), turso::Error> {
    if !conn.is_autocommit()? {
        tracing::warn!("rolling back a transaction that was left open");
        conn.execute("ROLLBACK", ()).await?;
    }
    Ok(())
}

/// `ROLLBACK` if a transaction is open; errors are only logged.
async fn rollback_quietly(conn: &Connection) {
    if conn.is_autocommit().unwrap_or(false) {
        return;
    }
    if let Err(e) = conn.execute("ROLLBACK", ()).await {
        tracing::error!(error = %e, "rollback failed");
    }
}

/// `BEGIN IMMEDIATE`, `body`, `COMMIT`. On any error – including a failed `BEGIN` or
/// `COMMIT` – the transaction is rolled back, so the connection stays usable.
async fn run_tx<F>(conn: &Connection, body: F) -> Result<(), StoreError>
where
    F: AsyncFnOnce(&Connection) -> Result<(), turso::Error>,
{
    reset_open_tx(conn).await?;
    let res = async {
        conn.execute("BEGIN IMMEDIATE", ()).await?;
        body(conn).await?;
        conn.execute("COMMIT", ()).await?;
        Ok::<_, turso::Error>(())
    }
    .await;
    if let Err(e) = res {
        rollback_quietly(conn).await;
        return Err(e.into());
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("wichtel-unit-{name}-{}.db", std::process::id()));
        let s = p.to_string_lossy().into_owned();
        remove(&s);
        s
    }

    fn remove(path: &str) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{path}{suffix}"));
        }
    }

    fn key(name: &str, v: u8) -> WriteOp {
        WriteOp::PutServerKey {
            name: name.into(),
            value: vec![v; 8],
        }
    }

    /// A transaction left open on the connection (e.g. by a panicking task) is rolled back
    /// before the next commit instead of blocking every write until a restart.
    #[tokio::test]
    async fn leftover_transaction_is_rolled_back() {
        let path = temp_path("leftover");
        let store = TursoStore::open(&path).await.unwrap();
        {
            let conn = store.conn.lock().await;
            conn.execute("BEGIN IMMEDIATE", ()).await.unwrap();
            conn.execute(
                "INSERT INTO server_keys (name, value) VALUES ('ghost', x'00')",
                (),
            )
            .await
            .unwrap();
            assert!(!conn.is_autocommit().unwrap());
        }
        store.commit(vec![key("a", 1)]).await.unwrap();
        assert_eq!(store.get_server_key("a").await.unwrap(), Some(vec![1; 8]));
        assert_eq!(store.get_server_key("ghost").await.unwrap(), None);
        drop(store);
        remove(&path);
    }

    /// Destructive commits leave a persistent marker until the next VACUUM.
    #[tokio::test]
    async fn vacuum_marker_is_persistent() {
        let path = temp_path("marker");
        let store = TursoStore::open(&path).await.unwrap();
        store.commit(vec![key("a", 1)]).await.unwrap();
        assert!(!store.needs_vacuum().await.unwrap());
        store
            .commit(vec![WriteOp::DeletePushSub {
                gid: [1; 16],
                pid: [2; 16],
            }])
            .await
            .unwrap();
        assert!(store.needs_vacuum().await.unwrap());
        drop(store);
        let store = TursoStore::open(&path).await.unwrap();
        assert!(store.needs_vacuum().await.unwrap(), "survives a restart");
        store.vacuum().await.unwrap();
        assert!(!store.needs_vacuum().await.unwrap());
        drop(store);
        remove(&path);
    }

    /// A failing statement or a failing `COMMIT` rolls back; the next commit works.
    #[tokio::test]
    async fn failed_statement_or_commit_rolls_back() {
        let path = temp_path("failcommit");
        let store = TursoStore::open(&path).await.unwrap();
        let conn = store.conn.lock().await;
        let res = run_tx(&conn, async |c: &Connection| {
            c.execute(
                "INSERT INTO server_keys (name, value) VALUES ('x', x'01')",
                (),
            )
            .await?;
            c.execute("INSERT INTO no_such_table VALUES (1)", ())
                .await?;
            Ok(())
        })
        .await;
        assert!(res.is_err());
        assert!(conn.is_autocommit().unwrap(), "transaction closed");

        // Deferred foreign key violation: only the COMMIT statement fails.
        conn.execute("PRAGMA foreign_keys = ON", ()).await.unwrap();
        conn.execute_batch(
            "CREATE TABLE fk_parent (id INTEGER PRIMARY KEY); \
             CREATE TABLE fk_child (p INTEGER REFERENCES fk_parent(id) \
             DEFERRABLE INITIALLY DEFERRED);",
        )
        .await
        .unwrap();
        let res = run_tx(&conn, async |c: &Connection| {
            c.execute(
                "INSERT INTO server_keys (name, value) VALUES ('y', x'01')",
                (),
            )
            .await?;
            c.execute("INSERT INTO fk_child (p) VALUES (42)", ())
                .await?;
            Ok(())
        })
        .await;
        assert!(res.is_err(), "COMMIT must fail");
        assert!(conn.is_autocommit().unwrap(), "transaction closed");
        drop(conn);

        store.commit(vec![key("z", 3)]).await.unwrap();
        assert_eq!(store.get_server_key("x").await.unwrap(), None);
        assert_eq!(store.get_server_key("y").await.unwrap(), None);
        assert_eq!(store.get_server_key("z").await.unwrap(), Some(vec![3; 8]));
        drop(store);
        remove(&path);
    }
}
