//! The database: one SQLite file, and the few tables a mailbox needs.
//!
//! Every statement here runs on one connection behind a mutex. That is not a
//! bottleneck worth removing: a request writes at most one batch of records,
//! and SQLite in WAL mode does that in well under a millisecond. Work that is
//! genuinely slow — a backup, a purge — runs on a thread of its own.

pub mod accounts;
pub mod devices;
pub mod invites;
pub mod records;
pub mod teams;

use parking_lot::{Mutex, MutexGuard};
use rusqlite::{params, Connection, OpenFlags};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct Db {
    conn: Mutex<Connection>,
    /// Where the file is, for work that wants a connection of its own. None
    /// for a database in memory.
    path: Option<PathBuf>,
}

impl Db {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = Connection::open(path)?;
        conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get::<_, String>(0))?;
        Self::init(conn, Some(path.to_path_buf()))
    }

    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::init(Connection::open_in_memory()?, None)
    }

    fn init(mut conn: Connection, path: Option<PathBuf>) -> rusqlite::Result<Self> {
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // A record that is deleted is deleted: its ciphertext must not stay
        // readable in a free page of the file.
        conn.pragma_update(None, "secure_delete", "ON")?;
        conn.busy_timeout(Duration::from_secs(5))?;
        migrate(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            path,
        })
    }

    pub fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock()
    }

    /// A consistent copy of a running database, which copying the file is not:
    /// the write-ahead log would be missing.
    ///
    /// It reads through a connection of its own. In WAL mode a reader sees one
    /// consistent state and holds nobody up, so the server goes on answering
    /// while a large database is copied — through the shared connection, every
    /// request would wait for the whole copy.
    pub fn backup_to(&self, path: &Path) -> rusqlite::Result<()> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let target = path.to_string_lossy();
        match &self.path {
            Some(source) => {
                let conn = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
                conn.busy_timeout(Duration::from_secs(5))?;
                conn.execute("VACUUM INTO ?1", [target.as_ref()])?;
            }
            None => {
                self.lock().execute("VACUUM INTO ?1", [target.as_ref()])?;
            }
        }
        Ok(())
    }
}

/// How far past a backup's sequence numbers a restore moves an account when
/// the database it replaces cannot say how far it had got. A personal server
/// does not hand out a million numbers between two backups.
const RESTORE_GAP: i64 = 1_000_000;

/// Put a backup in place of the database at `database`, keeping what was
/// there at `aside`.
///
/// The backup is checked first: an intact SQLite file, with this server's
/// tables, at a schema this build can read. And the database must not be in
/// use — a server still writing to it would lose everything after the
/// backup, or worse, write its log into the file that replaced it. Leaving
/// WAL mode needs the only connection there is, which makes it the test, and
/// it folds the log into the file on the way, so nothing of it is left lying
/// next to the backup either.
pub fn restore(backup: &Path, database: &Path, aside: &Path) -> Result<(), String> {
    let found = |error: rusqlite::Error| format!("{}: {error}", backup.display());
    {
        let conn =
            Connection::open_with_flags(backup, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(found)?;
        let check: String = conn
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|_| format!("{} is not a database", backup.display()))?;
        if check != "ok" {
            return Err(format!("{} is damaged: {check}", backup.display()));
        }
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(found)?;
        let tables: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' \
                 AND name IN ('accounts', 'devices', 'records')",
                [],
                |row| row.get(0),
            )
            .map_err(found)?;
        if version < 1 || tables != 3 {
            return Err(format!(
                "{} is not a UwUSync Server database",
                backup.display()
            ));
        }
        if version > SCHEMA_VERSION {
            return Err(format!(
                "{} comes from a newer UwUSync Server (schema {version}); restore it with that one",
                backup.display()
            ));
        }
    }

    if let (Ok(backup), Ok(database)) = (backup.canonicalize(), database.canonicalize()) {
        if backup == database {
            return Err("that is the database itself, not a backup of it".into());
        }
    }

    let failed = |error: rusqlite::Error| error.to_string();
    let replaced = database.exists();
    if replaced {
        let conn = Connection::open(database).map_err(failed)?;
        conn.busy_timeout(Duration::ZERO).map_err(failed)?;
        let mode: Option<String> = conn
            .pragma_update_and_check(None, "journal_mode", "DELETE", |row| row.get(0))
            .ok();
        if mode.as_deref() != Some("delete") {
            return Err(
                "the database is in use. Stop the server first: docker compose stop".into(),
            );
        }
    }

    // The backup is made ready beside the database — copied through SQLite,
    // so it is one consistent file, and numbered on — and only then swapped
    // in. Until the last step the database is where it was; a copy that fails
    // halfway, on a full disk say, leaves it alone.
    let incoming = with_suffix(database, "-restoring");
    let _ = std::fs::remove_file(&incoming);
    let prepared = Connection::open_with_flags(backup, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .and_then(|conn| {
            conn.execute("VACUUM INTO ?1", [incoming.to_string_lossy().as_ref()])
                .map(drop)
        })
        .and_then(|()| carry_numbers_forward(&incoming, replaced.then_some(database)));
    if let Err(error) = prepared {
        let _ = std::fs::remove_file(&incoming);
        return Err(format!("the backup could not be made ready: {error}"));
    }

    if replaced {
        std::fs::rename(database, aside).map_err(|error| error.to_string())?;
    }
    if let Err(error) = std::fs::rename(&incoming, database) {
        if replaced {
            let _ = std::fs::rename(aside, database);
        }
        return Err(format!("the backup could not be put in place: {error}"));
    }
    // A log beside the database belongs to the one that was there; the backup
    // must never have it played over it.
    for leftover in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(with_suffix(database, leftover));
    }
    Ok(())
}

/// The database's name with something after it, the way SQLite names its own
/// files next to it — whichever name the database has: `uwusync.db` and
/// `-wal` make `uwusync.db-wal`.
pub fn with_suffix(database: &Path, suffix: &str) -> PathBuf {
    let mut name = database.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Devices remember how far they have read, and never step back — a server
/// that answers with a lower number than they know is one they do not
/// believe. After a restore the numbers would start again from the backup's,
/// and everything written from then on would be numbered below what the
/// devices already read past: they would never pull it. So every account
/// continues from the highest number it ever handed out, as far as the
/// replaced database says, and from well past the backup's where it cannot.
/// The same for every team, which numbers its records on its own.
fn carry_numbers_forward(database: &Path, replaced: Option<&Path>) -> rusqlite::Result<()> {
    let conn = Connection::open(database)?;
    for table in ["accounts", "teams"] {
        // A backup from before there were teams has no such table yet; the
        // server makes it, empty, when it next opens the file.
        let there: bool = conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| Ok(row.get::<_, i64>(0)? > 0),
        )?;
        if !there {
            continue;
        }
        let mut reached: HashMap<String, i64> = HashMap::new();
        if let Some(replaced) = replaced {
            if let Ok(old) = Connection::open_with_flags(replaced, OpenFlags::SQLITE_OPEN_READ_ONLY)
            {
                if let Ok(mut stmt) = old.prepare(&format!("SELECT id, seq FROM {table}")) {
                    if let Ok(rows) = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?))) {
                        reached.extend(rows.flatten());
                    }
                }
            }
        }
        let numbered: Vec<(String, i64)> = conn
            .prepare(&format!("SELECT id, seq FROM {table}"))?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (id, seq) in numbered {
            let next = match reached.get(&id) {
                Some(before) => seq.max(*before),
                None => seq + RESTORE_GAP,
            };
            conn.execute(
                &format!("UPDATE {table} SET seq = ?2 WHERE id = ?1"),
                params![id, next],
            )?;
        }
    }
    Ok(())
}

pub const SCHEMA_VERSION: i64 = 4;

const V1: &str = r#"
CREATE TABLE accounts (
    id              TEXT    PRIMARY KEY,
    created_ms      INTEGER NOT NULL,
    -- The vault every record of this account belongs to. A record claiming
    -- another one is refused: that is a bug on a device, not a new vault.
    vault_id        TEXT    NOT NULL,
    -- The vault header, which is not secret and useless without the master
    -- password: salt, key derivation costs, and the wrapped vault key.
    kdf_memory_kib  INTEGER NOT NULL,
    kdf_time_cost   INTEGER NOT NULL,
    kdf_parallelism INTEGER NOT NULL,
    salt            BLOB    NOT NULL,
    wrapped_nonce   BLOB    NOT NULL,
    wrapped_blob    BLOB    NOT NULL,
    -- SHA-256 of the login key, not the key itself. The key is derived from
    -- the master password *and* the account key, so this hash is no shortcut.
    auth_verifier   BLOB    NOT NULL,
    -- The last sequence number handed out, per account. Monotonic, never
    -- reused, and the version of every record it numbered.
    seq             INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE devices (
    id              TEXT    PRIMARY KEY,
    account_id      TEXT    NOT NULL REFERENCES accounts (id),
    name            TEXT    NOT NULL,
    -- Ed25519. The device signs a challenge with it instead of sending
    -- anything that could be replayed.
    public_key      BLOB    NOT NULL,
    created_ms      INTEGER NOT NULL,
    last_seen_ms    INTEGER,
    -- How far this device has read, so the server knows what nobody needs any
    -- more and can say when a device was last here.
    cursor          INTEGER NOT NULL DEFAULT 0,
    revoked_ms      INTEGER
);

CREATE INDEX devices_by_account ON devices (account_id);

CREATE TABLE records (
    account_id      TEXT    NOT NULL REFERENCES accounts (id),
    id              TEXT    NOT NULL,
    kind            TEXT    NOT NULL,
    seq             INTEGER NOT NULL,
    hlc_wall_ms     INTEGER NOT NULL,
    hlc_counter     INTEGER NOT NULL,
    hlc_device      INTEGER NOT NULL,
    deleted         INTEGER NOT NULL DEFAULT 0,
    nonce           BLOB    NOT NULL,
    blob            BLOB    NOT NULL,
    -- Which device wrote this version. For the log, and for a future pull that
    -- skips what the asking device wrote itself.
    device_id       TEXT,
    updated_ms      INTEGER NOT NULL,
    PRIMARY KEY (account_id, id)
);

CREATE INDEX records_by_seq ON records (account_id, seq);

CREATE TABLE invites (
    code_hash       BLOB    PRIMARY KEY,
    created_ms      INTEGER NOT NULL,
    expires_ms      INTEGER NOT NULL,
    used_ms         INTEGER
);

-- A one-time token an enrolled device hands to a joining one, through a
-- channel this server cannot read.
CREATE TABLE enrolments (
    token_hash      BLOB    PRIMARY KEY,
    account_id      TEXT    NOT NULL REFERENCES accounts (id),
    created_ms      INTEGER NOT NULL,
    expires_ms      INTEGER NOT NULL,
    used_ms         INTEGER
);
"#;

/// Whether a vault needs its account key as well as the password. The server
/// cannot tell — it never sees either — so the client says, and the server
/// hands the answer to the next device that joins.
const V2: &str = r#"
ALTER TABLE accounts ADD COLUMN needs_account_key INTEGER NOT NULL DEFAULT 0;
"#;

/// What an account holds, counted as it changes, so a push can be refused
/// once an account is full without adding up every record it has. And for an
/// enrolment token: which device made it, so revoking that device takes its
/// tokens along, and how often a wrong password was tried with it.
const V3: &str = r#"
ALTER TABLE accounts ADD COLUMN record_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN record_bytes INTEGER NOT NULL DEFAULT 0;
UPDATE accounts SET
    record_count = (SELECT count(*) FROM records WHERE records.account_id = accounts.id),
    record_bytes = (SELECT coalesce(sum(length(blob)), 0) FROM records
                     WHERE records.account_id = accounts.id);
ALTER TABLE enrolments ADD COLUMN device_id TEXT;
ALTER TABLE enrolments ADD COLUMN failures INTEGER NOT NULL DEFAULT 0;
"#;

/// Teams: a vault several accounts share. The server holds what it holds of an
/// account's own vault — sealed records it cannot read — and beside them who
/// belongs to the team, as what, and the team key wrapped once for each member
/// by a client. See `docs/teams.md`.
const V4: &str = r#"
-- The key pair a team key is wrapped to: one per account. The private half
-- is sealed by the client with a key of the account's own vault.
CREATE TABLE team_identities (
    account_id      TEXT    PRIMARY KEY REFERENCES accounts (id),
    public_key      BLOB    NOT NULL,
    sealed_private  BLOB    NOT NULL,
    updated_ms      INTEGER NOT NULL
);

CREATE TABLE teams (
    id              TEXT    PRIMARY KEY,
    -- Not sealed: the operator's list of teams shows it.
    name            TEXT    NOT NULL,
    created_ms      INTEGER NOT NULL,
    -- Which team key is the current one. Every record held was pushed under
    -- it: a rotation takes the records of the epoch before along.
    epoch           INTEGER NOT NULL DEFAULT 1,
    -- Somebody who knew the current key is not a member any more.
    needs_rotation  INTEGER NOT NULL DEFAULT 0,
    -- As for an account: the last number handed out, never reused, and never
    -- set back — not by a rotation either.
    seq             INTEGER NOT NULL DEFAULT 0,
    record_count    INTEGER NOT NULL DEFAULT 0,
    record_bytes    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE team_members (
    team_id         TEXT    NOT NULL REFERENCES teams (id),
    account_id      TEXT    NOT NULL REFERENCES accounts (id),
    display_name    TEXT    NOT NULL,
    -- owner, admin, editor, reader
    role            TEXT    NOT NULL,
    -- pending until a member who manages the team has wrapped the team key
    -- for this one; active from then on.
    state           TEXT    NOT NULL,
    -- The team key of the current epoch, wrapped to this member's public
    -- key. Never there while pending.
    wrapped_key     BLOB,
    -- Whether this member was ever handed the key of the current epoch.
    -- Taking such a member out is what calls for a rotation.
    had_key         INTEGER NOT NULL DEFAULT 0,
    joined_ms       INTEGER NOT NULL,
    PRIMARY KEY (team_id, account_id)
);

CREATE INDEX team_members_by_account ON team_members (account_id);

CREATE TABLE team_invites (
    id              TEXT    PRIMARY KEY,
    team_id         TEXT    NOT NULL REFERENCES teams (id),
    -- SHA-256 of the code. The code itself is shown once and kept nowhere.
    code_hash       BLOB    NOT NULL UNIQUE,
    role            TEXT    NOT NULL,
    created_by      TEXT    NOT NULL,
    created_ms      INTEGER NOT NULL,
    expires_ms      INTEGER NOT NULL,
    used_ms         INTEGER
);

CREATE INDEX team_invites_by_team ON team_invites (team_id);

-- The records table once more, for what belongs to a team instead of an
-- account. Two tables rather than one with two kinds of owner, so that no
-- query for one can ever answer with the other's.
CREATE TABLE team_records (
    team_id         TEXT    NOT NULL REFERENCES teams (id),
    id              TEXT    NOT NULL,
    kind            TEXT    NOT NULL,
    seq             INTEGER NOT NULL,
    hlc_wall_ms     INTEGER NOT NULL,
    hlc_counter     INTEGER NOT NULL,
    hlc_device      INTEGER NOT NULL,
    deleted         INTEGER NOT NULL DEFAULT 0,
    nonce           BLOB    NOT NULL,
    blob            BLOB    NOT NULL,
    device_id       TEXT,
    updated_ms      INTEGER NOT NULL,
    PRIMARY KEY (team_id, id)
);

CREATE INDEX team_records_by_seq ON team_records (team_id, seq);
"#;

fn migrate(conn: &mut Connection) -> rusqlite::Result<()> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        // An older server on a newer database would not keep up what the
        // newer one added — the counts of what an account holds, say — and
        // nothing would ever put them right again. It stops instead; the
        // backup from before the update is the way back.
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN),
            Some(format!(
                "this database comes from a newer UwUSync Server (schema {version}, this one knows \
                 {SCHEMA_VERSION}). Run the newer version, or restore the backup from before it"
            )),
        ));
    }
    if version == SCHEMA_VERSION {
        return Ok(());
    }
    if version < 1 {
        let tx = conn.transaction()?;
        tx.execute_batch(V1)?;
        tx.pragma_update(None, "user_version", 1)?;
        tx.commit()?;
        tracing::info!("database created at schema 1");
    }
    if version < 2 {
        let tx = conn.transaction()?;
        tx.execute_batch(V2)?;
        tx.pragma_update(None, "user_version", 2)?;
        tx.commit()?;
        tracing::info!("database migrated to schema 2");
    }
    if version < 3 {
        let tx = conn.transaction()?;
        tx.execute_batch(V3)?;
        tx.pragma_update(None, "user_version", 3)?;
        tx.commit()?;
        tracing::info!("database migrated to schema 3");
    }
    if version < 4 {
        let tx = conn.transaction()?;
        tx.execute_batch(V4)?;
        tx.pragma_update(None, "user_version", 4)?;
        tx.commit()?;
        tracing::info!("database migrated to schema 4");
    }
    Ok(())
}

/// Compare two secrets without letting how long it takes say how much of them
/// matched.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrating_twice_is_harmless() {
        let db = Db::open_in_memory().unwrap();
        let conn = db.lock();
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let tables: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 10);
    }

    /// A database as 0.2 left it — schema 3, with an account and a record —
    /// is taken as it is: what was there stays, and the tables for teams come
    /// beside it.
    #[test]
    fn a_database_from_before_teams_is_upgraded_where_it_lies() {
        let dir = scratch();
        let path = dir.join("uwusync.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(V1).unwrap();
            conn.execute_batch(V2).unwrap();
            conn.execute_batch(V3).unwrap();
            conn.pragma_update(None, "user_version", 3).unwrap();
            conn.execute(
                "INSERT INTO accounts
                    (id, created_ms, vault_id, kdf_memory_kib, kdf_time_cost, kdf_parallelism,
                     salt, wrapped_nonce, wrapped_blob, auth_verifier, seq,
                     record_count, record_bytes)
                 VALUES ('a', 1, 'v', 1, 1, 1, x'00', x'00', x'00', x'00', 7, 1, 3)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO records
                    (account_id, id, kind, seq, hlc_wall_ms, hlc_counter, hlc_device,
                     nonce, blob, updated_ms)
                 VALUES ('a', 'r', 'host', 7, 1, 0, 1, x'00', x'010203', 1)",
                [],
            )
            .unwrap();
        }

        let db = Db::open(&path).unwrap();
        let conn = db.lock();
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let (seq, bytes): (i64, i64) = conn
            .query_row(
                "SELECT seq, record_bytes FROM accounts WHERE id = 'a'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((seq, bytes), (7, 3), "the account is as it was");
        let records: i64 = conn
            .query_row("SELECT count(*) FROM records", [], |row| row.get(0))
            .unwrap();
        assert_eq!(records, 1);
        for table in [
            "team_identities",
            "teams",
            "team_members",
            "team_invites",
            "team_records",
        ] {
            let rows: i64 = conn
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(rows, 0, "{table}");
        }
        drop(conn);
        drop(db);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn scratch() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("uwusync-restore-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn invites(path: &Path) -> i64 {
        let db = Db::open(path).unwrap();
        let conn = db.lock();
        conn.query_row("SELECT count(*) FROM invites", [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn a_backup_goes_back_and_what_was_there_is_kept() {
        let dir = scratch();
        let live = dir.join("uwusync.db");
        let backup = dir.join("backup.db");
        let aside = dir.join("uwusync.db.before-restore");
        {
            let db = Db::open(&live).unwrap();
            invites::create_invite(&db.lock(), 60_000).unwrap();
            db.backup_to(&backup).unwrap();
            // Written after the backup, so it is what the restore takes away.
            invites::create_invite(&db.lock(), 60_000).unwrap();
        }
        assert_eq!(invites(&live), 2);

        restore(&backup, &live, &aside).unwrap();
        assert_eq!(invites(&live), 1, "the backup's state");
        assert_eq!(invites(&aside), 2, "and the one before, kept");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn seq_of(path: &Path, account: uuid::Uuid) -> u64 {
        let db = Db::open(path).unwrap();
        let conn = db.lock();
        accounts::get(&conn, account).unwrap().unwrap().seq
    }

    #[test]
    fn after_a_restore_the_numbers_go_on_from_where_the_devices_are() {
        let dir = scratch();
        let live = dir.join("uwusync.db");
        let backup = dir.join("backup.db");
        let account = {
            let db = Db::open(&live).unwrap();
            let mut conn = db.lock();
            let account = accounts::create(&conn, &accounts::tests::header(), b"key").unwrap();
            let push = |conn: &mut Connection| {
                let account = accounts::get(conn, account.id).unwrap().unwrap();
                records::tests::push_one(conn, &account);
            };
            push(&mut conn);
            drop(conn);
            db.backup_to(&backup).unwrap();
            // Written after the backup: a device has read up to 3 now.
            let mut conn = db.lock();
            push(&mut conn);
            push(&mut conn);
            account.id
        };
        assert_eq!(seq_of(&live, account), 3);

        restore(&backup, &live, &dir.join("aside")).unwrap();
        assert_eq!(
            seq_of(&live, account),
            3,
            "the next record is numbered past what a device already read"
        );

        // Without the database it replaces, well past the backup's.
        let fresh = dir.join("fresh.db");
        restore(&backup, &fresh, &dir.join("no-aside")).unwrap();
        assert!(seq_of(&fresh, account) > 1_000);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_backup_of_a_database_on_disk_is_taken_beside_the_server_not_through_it() {
        let dir = scratch();
        let db = Db::open(&dir.join("uwusync.db")).unwrap();
        invites::create_invite(&db.lock(), 60_000).unwrap();
        // Holding the shared connection, as a request in flight would: the
        // backup does not wait for it.
        let held = db.lock();
        db.backup_to(&dir.join("backup.db")).unwrap();
        drop(held);
        drop(db);
        assert_eq!(invites(&dir.join("backup.db")), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_database_in_use_is_not_replaced() {
        let dir = scratch();
        let live = dir.join("uwusync.db");
        let backup = dir.join("backup.db");
        let running = Db::open(&live).unwrap();
        running.backup_to(&backup).unwrap();

        let error = restore(&backup, &live, &dir.join("aside")).unwrap_err();
        assert!(error.contains("in use"), "{error}");
        assert!(!dir.join("aside").exists());
        // The running server still has its database, in WAL mode.
        invites::create_invite(&running.lock(), 60_000).unwrap();
        drop(running);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_database_from_a_newer_server_is_not_opened() {
        let dir = scratch();
        let path = dir.join("uwusync.db");
        drop(Db::open(&path).unwrap());
        Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        let error = Db::open(&path).err().expect("refused").to_string();
        assert!(error.contains("newer UwUSync Server"), "{error}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_database_is_not_its_own_backup() {
        let dir = scratch();
        let live = dir.join("uwusync.db");
        drop(Db::open(&live).unwrap());
        let error = restore(&live, &live, &dir.join("aside")).unwrap_err();
        assert!(error.contains("itself"), "{error}");
        assert_eq!(invites(&live), 0, "and it is still there");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_restore_leaves_no_log_of_the_old_database_behind() {
        let dir = scratch();
        let live = dir.join("uwusync.db");
        let backup = dir.join("backup.db");
        {
            let db = Db::open(&live).unwrap();
            db.backup_to(&backup).unwrap();
        }
        // A log left from a server that was killed.
        std::fs::write(with_suffix(&live, "-wal"), b"not this database's").unwrap();
        restore(&backup, &live, &dir.join("aside")).unwrap();
        assert!(!with_suffix(&live, "-wal").exists());
        assert!(!with_suffix(&live, "-restoring").exists());
        assert_eq!(invites(&live), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_a_sound_backup_of_this_server_is_taken() {
        let dir = scratch();
        let live = dir.join("uwusync.db");
        Db::open(&live).unwrap();

        let junk = dir.join("junk.db");
        std::fs::write(&junk, b"not a database at all, not even close to one").unwrap();
        assert!(restore(&junk, &live, &dir.join("aside")).is_err());

        let other = dir.join("other.db");
        Connection::open(&other)
            .unwrap()
            .execute_batch("CREATE TABLE notes (text TEXT); PRAGMA user_version = 1;")
            .unwrap();
        let error = restore(&other, &live, &dir.join("aside")).unwrap_err();
        assert!(error.contains("not a UwUSync Server database"), "{error}");

        let newer = dir.join("newer.db");
        Db::open(&live).unwrap().backup_to(&newer).unwrap();
        Connection::open(&newer)
            .unwrap()
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        let error = restore(&newer, &live, &dir.join("aside")).unwrap_err();
        assert!(error.contains("newer"), "{error}");

        assert!(!dir.join("aside").exists(), "nothing was moved");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn comparing_secrets_does_not_stop_at_the_first_difference() {
        assert!(constant_time_eq(b"abcd", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abce"));
        assert!(!constant_time_eq(b"abcd", b"abc"));
    }
}
