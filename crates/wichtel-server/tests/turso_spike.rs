//! Phase-0 spike: checks the Turso features the server relies on.
//! Results are documented in docs/04-protokoll-spec.md §14. Run with `--nocapture` to see the report.

use std::sync::Arc;

fn temp_db(name: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!("wichtel-spike-{}-{}.db", name, std::process::id()));
    let _ = std::fs::remove_file(&p);
    p.to_string_lossy().into_owned()
}

async fn pragma(conn: &turso::Connection, sql: &str) -> String {
    match conn.query(sql, ()).await {
        Ok(mut rows) => match rows.next().await {
            Ok(Some(row)) => format!("{:?}", row.get_value(0)),
            Ok(None) => "<no row>".into(),
            Err(e) => format!("ERR {e}"),
        },
        Err(e) => format!("ERR {e}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn turso_spike() {
    let path = temp_db("main");
    let db = turso::Builder::new_local(&path)
        .build()
        .await
        .expect("open db");
    let conn = db.connect().expect("connect");

    println!(
        "journal_mode       = {}",
        pragma(&conn, "PRAGMA journal_mode").await
    );
    println!(
        "journal_mode=wal   = {}",
        pragma(&conn, "PRAGMA journal_mode=wal").await
    );
    println!(
        "secure_delete=ON   = {}",
        pragma(&conn, "PRAGMA secure_delete=ON").await
    );
    println!(
        "secure_delete      = {}",
        pragma(&conn, "PRAGMA secure_delete").await
    );

    conn.execute(
        "CREATE TABLE blobs (id INTEGER PRIMARY KEY, data BLOB NOT NULL)",
        (),
    )
    .await
    .expect("create");

    // Transactions: commit and rollback.
    conn.execute("BEGIN", ()).await.expect("begin");
    let big = vec![0xA5u8; 2_500_000];
    conn.execute("INSERT INTO blobs (id, data) VALUES (1, ?1)", [big.clone()])
        .await
        .expect("insert 2.5 MB blob");
    conn.execute("COMMIT", ()).await.expect("commit");
    conn.execute("BEGIN", ()).await.expect("begin2");
    conn.execute("INSERT INTO blobs (id, data) VALUES (2, x'00')", ())
        .await
        .expect("insert2");
    conn.execute("ROLLBACK", ()).await.expect("rollback");
    let mut rows = conn.query("SELECT count(*) FROM blobs", ()).await.unwrap();
    let count: i64 = rows.next().await.unwrap().unwrap().get(0).unwrap();
    println!("rollback works     = {}", count == 1);
    assert_eq!(count, 1);

    // Blob round trip.
    let mut rows = conn
        .query("SELECT data FROM blobs WHERE id = 1", ())
        .await
        .unwrap();
    let v = rows.next().await.unwrap().unwrap().get_value(0).unwrap();
    drop(rows);
    let ok = matches!(&v, turso::Value::Blob(b) if *b == big);
    println!("2.5 MB blob roundtrip = {ok}");
    assert!(ok);

    // Parallel readers under tokio.
    let db = Arc::new(db);
    let mut handles = Vec::new();
    for _ in 0..4 {
        let db = db.clone();
        handles.push(tokio::spawn(async move {
            let c = db.connect().unwrap();
            let mut rows = c.query("SELECT length(data) FROM blobs", ()).await.unwrap();
            let len: i64 = rows.next().await.unwrap().unwrap().get(0).unwrap();
            len
        }));
    }
    for h in handles {
        assert_eq!(h.await.unwrap(), 2_500_000);
    }
    println!("parallel readers   = ok");

    // Delete + VACUUM.
    conn.execute("DELETE FROM blobs WHERE id = 1", ())
        .await
        .expect("delete");
    match conn.execute("VACUUM", ()).await {
        Ok(_) => println!("VACUUM             = ok"),
        Err(e) => println!("VACUUM             = ERR {e}"),
    }
    println!(
        "wal_checkpoint     = {}",
        pragma(&conn, "PRAGMA wal_checkpoint(TRUNCATE)").await
    );
    drop(conn);
    drop(db);

    // Are deleted bytes still on disk?
    let mut residue = 0usize;
    for f in [path.clone(), format!("{path}-wal")] {
        if let Ok(bytes) = std::fs::read(&f) {
            let n = bytes
                .windows(64)
                .filter(|w| w.iter().all(|&b| b == 0xA5))
                .count();
            println!(
                "residue in {f}: {} bytes total, 0xA5-runs: {n}",
                bytes.len()
            );
            residue += n;
        }
    }
    println!("deleted data residue = {}", residue > 0);

    // VACUUM with the experimental flag.
    let path2 = temp_db("vac");
    let db2 = turso::Builder::new_local(&path2)
        .experimental_vacuum(true)
        .build()
        .await
        .unwrap();
    let c2 = db2.connect().unwrap();
    c2.execute("CREATE TABLE b (data BLOB)", ()).await.unwrap();
    c2.execute("INSERT INTO b VALUES (?1)", [vec![0xA5u8; 500_000]])
        .await
        .unwrap();
    c2.execute("DELETE FROM b", ()).await.unwrap();
    match c2.execute("VACUUM", ()).await {
        Ok(_) => println!("VACUUM (experimental flag) = ok"),
        Err(e) => println!("VACUUM (experimental flag) = ERR {e}"),
    }
    let _ = pragma(&c2, "PRAGMA wal_checkpoint(TRUNCATE)").await;
    drop(c2);
    drop(db2);
    let mut residue2 = 0;
    for f in [path2.clone(), format!("{path2}-wal")] {
        if let Ok(bytes) = std::fs::read(&f) {
            residue2 += bytes
                .windows(64)
                .filter(|w| w.iter().all(|&b| b == 0xA5))
                .count();
        }
    }
    println!("residue after experimental VACUUM = {}", residue2 > 0);
    // The server relies on this property (Spec §14).
    assert_eq!(residue2, 0, "VACUUM must remove deleted data");

    // Overwrite-before-delete workaround.
    let path3 = temp_db("zero");
    let db3 = turso::Builder::new_local(&path3).build().await.unwrap();
    let c3 = db3.connect().unwrap();
    c3.execute("CREATE TABLE b (id INTEGER PRIMARY KEY, data BLOB)", ())
        .await
        .unwrap();
    c3.execute("INSERT INTO b VALUES (1, ?1)", [vec![0xA5u8; 500_000]])
        .await
        .unwrap();
    c3.execute(
        "UPDATE b SET data = zeroblob(length(data)) WHERE id = 1",
        (),
    )
    .await
    .unwrap();
    c3.execute("DELETE FROM b WHERE id = 1", ()).await.unwrap();
    println!(
        "checkpoint (zero case) = {}",
        pragma(&c3, "PRAGMA wal_checkpoint(TRUNCATE)").await
    );
    drop(c3);
    drop(db3);
    let mut residue3 = 0;
    for f in [path3.clone(), format!("{path3}-wal")] {
        if let Ok(bytes) = std::fs::read(&f) {
            let n = bytes
                .windows(64)
                .filter(|w| w.iter().all(|&b| b == 0xA5))
                .count();
            println!("  zero case {f}: {} bytes, runs {n}", bytes.len());
            residue3 += n;
        }
    }
    println!(
        "residue after zeroblob-overwrite + checkpoint = {}",
        residue3 > 0
    );

    for p in [&path, &path2, &path3] {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{p}{suffix}"));
        }
    }
}
