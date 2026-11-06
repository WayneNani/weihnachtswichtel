-- Weihnachtswichtel schema v1 (Konzept §7.3, Spec §10, §14).
-- All ids and keys are raw BLOBs; times are Unix seconds (UTC).

CREATE TABLE groups (
    gid             BLOB PRIMARY KEY,
    admin_hash      BLOB NOT NULL,
    enc_meta        BLOB NOT NULL,
    -- 'open' | 'drawing' | 'done'
    state           TEXT NOT NULL,
    -- last protocol round used (0 = never started); current round while drawing/done
    round           INTEGER NOT NULL,
    -- 'roles' | 'reveal' while drawing, NULL otherwise
    phase           TEXT,
    -- chosen attempt while done, NULL otherwise
    t_star          INTEGER,
    draw_no         INTEGER NOT NULL,
    draw_at         INTEGER,
    -- 10-minute reminder for the current draw_at already pushed
    reminder_sent   INTEGER NOT NULL,
    schedule_missed INTEGER NOT NULL,
    delete_after    INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    last_activity   INTEGER NOT NULL
);

CREATE TABLE participants (
    gid       BLOB NOT NULL,
    pid       BLOB NOT NULL,
    ipk       BLOB NOT NULL,
    idh       BLOB NOT NULL,
    auth_hash BLOB NOT NULL,
    enc_name  BLOB NOT NULL,
    enc_wish  BLOB NOT NULL,
    joined_at INTEGER NOT NULL,
    PRIMARY KEY (gid, pid)
);

-- Only after explicit opt-in; deleted together with the participant/group.
CREATE TABLE push_subscriptions (
    gid        BLOB NOT NULL,
    pid        BLOB NOT NULL,
    endpoint   TEXT NOT NULL,
    p256dh     BLOB NOT NULL,
    auth       BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (gid, pid)
);

-- Running XOR per (round, phase): 'roles' = R, 'reveal' = SD. Individual vectors are never stored.
-- submitted = concatenation of 16-byte pids that have uploaded.
CREATE TABLE round_aggregates (
    gid       BLOB NOT NULL,
    round     INTEGER NOT NULL,
    phase     TEXT NOT NULL,
    aggregate BLOB NOT NULL,
    submitted BLOB NOT NULL,
    PRIMARY KEY (gid, round, phase)
);

-- Reveal ciphertexts C_{pid,attempt}; after t* is chosen only attempt t* is kept.
CREATE TABLE reveal_uploads (
    gid        BLOB NOT NULL,
    round      INTEGER NOT NULL,
    pid        BLOB NOT NULL,
    attempt    INTEGER NOT NULL,
    ciphertext BLOB NOT NULL,
    PRIMARY KEY (gid, round, pid, attempt)
);

-- Server key material (VAPID key pair).
CREATE TABLE server_keys (
    name  TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
