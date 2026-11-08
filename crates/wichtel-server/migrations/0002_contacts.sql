-- Spec §16.2: one encrypted contact K_i (816 B) per participant and draw. The pid is only
-- kept to replace a participant's previous contact; it is never served (GET …/contacts returns
-- the contacts sorted by hash, without pids). Deleted with every new draw and with the group.
CREATE TABLE contacts (
    gid     BLOB NOT NULL,
    pid     BLOB NOT NULL,
    draw_no INTEGER NOT NULL,
    contact BLOB NOT NULL,
    PRIMARY KEY (gid, pid)
);
