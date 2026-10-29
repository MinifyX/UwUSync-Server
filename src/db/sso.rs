//! The pairing with UwUAuth, and the people it sent. See `docs/sso.md`.
//!
//! A person here is who UwUAuth says they are — its issuer and their `sub` —
//! never an address: an address changes, and a new person may get an old
//! one. Their account is linked once they make it, and stays linked.

use crate::db::{constant_time_eq, invites};
use crate::now_ms;
use rusqlite::{params, Connection, OptionalExtension, Row};
use uuid::Uuid;

/// What pairing with UwUAuth left this server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pairing {
    pub url: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub scim_token_hash: Option<Vec<u8>>,
    pub app_id: Option<String>,
    pub manage_url: Option<String>,
    pub paired_ms: u64,
}

impl Pairing {
    /// Which pairing this is: a new pairing, even with the same client, is
    /// another one. Logins and tickets are bound to it, so whatever the
    /// command line does to the pairing, a running server notices on the
    /// next request.
    pub fn generation(&self) -> String {
        format!("{}\n{}", self.client_id, self.paired_ms)
    }
}

pub fn pairing(conn: &Connection) -> rusqlite::Result<Option<Pairing>> {
    conn.query_row(
        "SELECT url, issuer, client_id, client_secret, scim_token_hash, app_id, manage_url,
                paired_ms
           FROM uwuauth WHERE id = 1",
        [],
        |row| {
            Ok(Pairing {
                url: row.get(0)?,
                issuer: row.get(1)?,
                client_id: row.get(2)?,
                client_secret: row.get(3)?,
                scim_token_hash: row.get(4)?,
                app_id: row.get(5)?,
                manage_url: row.get(6)?,
                paired_ms: row.get::<_, i64>(7)? as u64,
            })
        },
    )
    .optional()
}

/// Keep a pairing, in place of the one there was.
pub fn set_pairing(conn: &Connection, pairing: &Pairing) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO uwuauth
            (id, url, issuer, client_id, client_secret, scim_token_hash, app_id, manage_url,
             paired_ms)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            pairing.url,
            pairing.issuer,
            pairing.client_id,
            pairing.client_secret,
            pairing.scim_token_hash,
            pairing.app_id,
            pairing.manage_url,
            pairing.paired_ms as i64,
        ],
    )?;
    Ok(())
}

/// Forget the pairing. The people stay, with their accounts: pairing with
/// the same UwUAuth again finds them where they were.
pub fn unpair(conn: &Connection) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM uwuauth WHERE id = 1", [])? > 0)
}

/// Whether `token` is the SCIM token of the pairing, compared in constant
/// time. No pairing, or one without SCIM, takes no token at all.
pub fn scim_token_matches(conn: &Connection, token: &str) -> rusqlite::Result<bool> {
    let stored = pairing(conn)?.and_then(|pairing| pairing.scim_token_hash);
    Ok(match stored {
        Some(stored) if !token.is_empty() => {
            constant_time_eq(&stored, &crate::sha256(token.as_bytes()))
        }
        _ => false,
    })
}

/// A person UwUAuth told this server about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsoUser {
    pub id: Uuid,
    pub issuer: String,
    pub subject: String,
    pub user_name: String,
    pub display_name: Option<String>,
    pub active: bool,
    pub account_id: Option<Uuid>,
    pub created_ms: u64,
    pub updated_ms: u64,
}

const COLUMNS: &str = "id, issuer, subject, user_name, display_name, active, account_id, \
                       created_ms, updated_ms";

fn from_row(row: &Row<'_>) -> rusqlite::Result<SsoUser> {
    let uuid = |index: usize, text: String| {
        Uuid::parse_str(&text).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                index,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })
    };
    Ok(SsoUser {
        id: uuid(0, row.get(0)?)?,
        issuer: row.get(1)?,
        subject: row.get(2)?,
        user_name: row.get(3)?,
        display_name: row.get(4)?,
        active: row.get(5)?,
        account_id: row
            .get::<_, Option<String>>(6)?
            .map(|text| uuid(6, text))
            .transpose()?,
        created_ms: row.get::<_, i64>(7)? as u64,
        updated_ms: row.get::<_, i64>(8)? as u64,
    })
}

fn one(
    conn: &Connection,
    condition: &str,
    values: impl rusqlite::Params,
) -> rusqlite::Result<Option<SsoUser>> {
    conn.query_row(
        &format!("SELECT {COLUMNS} FROM sso_users WHERE {condition}"),
        values,
        from_row,
    )
    .optional()
}

pub fn by_id(conn: &Connection, id: Uuid) -> rusqlite::Result<Option<SsoUser>> {
    one(conn, "id = ?1", [id.to_string()])
}

pub fn by_subject(
    conn: &Connection,
    issuer: &str,
    subject: &str,
) -> rusqlite::Result<Option<SsoUser>> {
    one(conn, "issuer = ?1 AND subject = ?2", [issuer, subject])
}

pub fn by_user_name(
    conn: &Connection,
    issuer: &str,
    user_name: &str,
) -> rusqlite::Result<Option<SsoUser>> {
    one(
        conn,
        "issuer = ?1 AND user_name = ?2 COLLATE NOCASE ORDER BY created_ms LIMIT 1",
        [issuer, user_name],
    )
}

pub fn by_account(conn: &Connection, account: Uuid) -> rusqlite::Result<Option<SsoUser>> {
    one(conn, "account_id = ?1", [account.to_string()])
}

/// The people of `issuer`, a page of them, in the order they came; and how
/// many there are in all.
pub fn list(
    conn: &Connection,
    issuer: &str,
    skip: usize,
    take: usize,
) -> rusqlite::Result<(Vec<SsoUser>, usize)> {
    let total: i64 = conn.query_row(
        "SELECT count(*) FROM sso_users WHERE issuer = ?1",
        [issuer],
        |row| row.get(0),
    )?;
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLUMNS} FROM sso_users WHERE issuer = ?1
          ORDER BY created_ms, id LIMIT ?2 OFFSET ?3"
    ))?;
    let rows = stmt
        .query_map(params![issuer, take as i64, skip as i64], from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok((rows, total as usize))
}

/// A person, new.
pub fn insert(
    conn: &Connection,
    issuer: &str,
    subject: &str,
    user_name: &str,
    display_name: Option<&str>,
    active: bool,
) -> rusqlite::Result<SsoUser> {
    let id = Uuid::now_v7();
    let now = now_ms();
    conn.execute(
        "INSERT INTO sso_users
            (id, issuer, subject, user_name, display_name, active, created_ms, updated_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
        params![
            id.to_string(),
            issuer,
            subject,
            user_name,
            display_name,
            active,
            now as i64
        ],
    )?;
    Ok(SsoUser {
        id,
        issuer: issuer.to_string(),
        subject: subject.to_string(),
        user_name: user_name.to_string(),
        display_name: display_name.map(str::to_string),
        active,
        account_id: None,
        created_ms: now,
        updated_ms: now,
    })
}

/// What may change about a person: never their account, which [`link`] sets
/// once.
pub fn update(conn: &Connection, user: &SsoUser) -> rusqlite::Result<bool> {
    let changed = conn.execute(
        "UPDATE sso_users
            SET subject = ?2, user_name = ?3, display_name = ?4, active = ?5, updated_ms = ?6
          WHERE id = ?1",
        params![
            user.id.to_string(),
            user.subject,
            user.user_name,
            user.display_name,
            user.active,
            now_ms() as i64,
        ],
    )?;
    Ok(changed > 0)
}

/// Link a person to the account they just made. Only once: a person who has
/// an account already is not handed a second one.
pub fn link(conn: &Connection, id: Uuid, account: Uuid) -> rusqlite::Result<bool> {
    let changed = conn.execute(
        "UPDATE sso_users SET account_id = ?2, updated_ms = ?3
          WHERE id = ?1 AND account_id IS NULL",
        params![id.to_string(), account.to_string(), now_ms() as i64],
    )?;
    Ok(changed > 0)
}

pub fn delete(conn: &Connection, id: Uuid) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM sso_users WHERE id = ?1", [id.to_string()])? > 0)
}

/// Shut every device of an account out, the way revoking each would: what
/// they hold they keep, but they sync no more, and the enrolment tokens they
/// made go with them. The records stay. Hands back the devices.
pub fn revoke_all_devices(conn: &Connection, account: Uuid) -> rusqlite::Result<Vec<Uuid>> {
    let ids: Vec<String> = {
        let mut stmt =
            conn.prepare("SELECT id FROM devices WHERE account_id = ?1 AND revoked_ms IS NULL")?;
        let rows = stmt.query_map([account.to_string()], |row| row.get(0))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    let mut devices = Vec::with_capacity(ids.len());
    for id in ids {
        let Ok(id) = Uuid::parse_str(&id) else {
            continue;
        };
        crate::db::devices::revoke(conn, account, id)?;
        invites::drop_enrolments_of(conn, id)?;
        devices.push(id);
    }
    // Tokens made by devices revoked earlier, or by none, cannot join anybody
    // either.
    conn.execute(
        "DELETE FROM enrolments WHERE account_id = ?1 AND used_ms IS NULL",
        [account.to_string()],
    )?;
    Ok(devices)
}

/// Teams that deleting `account` would leave without an owner: it is their
/// only owner, others are still in them, and none of those is an active
/// admin who would become owner in its place (see
/// [`crate::db::teams::forget_account`]).
pub fn teams_only_owned_by(conn: &Connection, account: Uuid) -> rusqlite::Result<Vec<Uuid>> {
    let mut stmt = conn.prepare(
        "SELECT m.team_id FROM team_members m
          WHERE m.account_id = ?1 AND m.role = 'owner'
            AND NOT EXISTS (SELECT 1 FROM team_members o
                             WHERE o.team_id = m.team_id AND o.account_id <> ?1
                               AND o.role = 'owner')
            AND EXISTS (SELECT 1 FROM team_members o
                         WHERE o.team_id = m.team_id AND o.account_id <> ?1)
            AND NOT EXISTS (SELECT 1 FROM team_members o
                             WHERE o.team_id = m.team_id AND o.account_id <> ?1
                               AND o.role = 'admin' AND o.state = 'active')",
    )?;
    let rows = stmt.query_map([account.to_string()], |row| row.get::<_, String>(0))?;
    Ok(rows
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .filter_map(|id| Uuid::parse_str(&id).ok())
        .collect())
}

/// Delete a person together with their account and everything it holds: its
/// records, its devices, its place in every team. All of it in one
/// transaction, so nothing is left half gone. The caller has checked
/// [`teams_only_owned_by`] first. Hands back the devices it had, and what
/// became of its teams.
pub fn delete_account(
    conn: &mut Connection,
    person: Uuid,
    account: Uuid,
) -> crate::Result<(Vec<Uuid>, crate::db::teams::Left)> {
    let tx = conn.transaction()?;
    // Memberships, invites made, team cursors of its devices, the identity —
    // and a team it was the last member of.
    let left = crate::db::teams::forget_account_in(&tx, account)?;
    let id = account.to_string();
    let devices: Vec<Uuid> = {
        let mut stmt = tx.prepare("SELECT id FROM devices WHERE account_id = ?1")?;
        let rows = stmt.query_map([&id], |row| row.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .filter_map(|id| Uuid::parse_str(&id).ok())
            .collect()
    };
    tx.execute(
        "UPDATE sso_users SET account_id = NULL WHERE account_id = ?1",
        [&id],
    )?;
    tx.execute("DELETE FROM records WHERE account_id = ?1", [&id])?;
    tx.execute("DELETE FROM enrolments WHERE account_id = ?1", [&id])?;
    tx.execute(
        "DELETE FROM team_cursors WHERE device_id IN
            (SELECT id FROM devices WHERE account_id = ?1)",
        [&id],
    )?;
    tx.execute("DELETE FROM devices WHERE account_id = ?1", [&id])?;
    tx.execute("DELETE FROM accounts WHERE id = ?1", [&id])?;
    tx.execute("DELETE FROM sso_users WHERE id = ?1", [person.to_string()])?;
    tx.commit()?;
    Ok((devices, left))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    #[test]
    fn a_person_is_who_the_issuer_says_not_their_address() {
        let db = Db::open_in_memory().unwrap();
        let conn = db.lock();
        let mia = insert(
            &conn,
            "https://auth.example.com",
            "p-1",
            "mia@example.com",
            Some("Mia"),
            true,
        )
        .unwrap();
        assert_eq!(
            by_user_name(&conn, "https://auth.example.com", "MIA@example.com")
                .unwrap()
                .unwrap()
                .id,
            mia.id
        );
        assert!(by_subject(&conn, "https://other.example.com", "p-1")
            .unwrap()
            .is_none());
        // The same subject twice from one issuer is one person.
        assert!(insert(
            &conn,
            "https://auth.example.com",
            "p-1",
            "x@example.com",
            None,
            true
        )
        .is_err());

        let account = Uuid::now_v7();
        assert!(
            link(&conn, mia.id, account).is_err(),
            "only an account that is there"
        );
    }

    #[test]
    fn the_scim_token_is_kept_as_a_hash_and_needs_a_pairing() {
        let db = Db::open_in_memory().unwrap();
        let conn = db.lock();
        assert!(!scim_token_matches(&conn, "secret").unwrap());
        let mut pairing = Pairing {
            url: "https://auth.example.com".into(),
            issuer: "https://auth.example.com".into(),
            client_id: "sync".into(),
            client_secret: "s".into(),
            scim_token_hash: Some(crate::sha256(b"secret").to_vec()),
            app_id: None,
            manage_url: None,
            paired_ms: 1,
        };
        set_pairing(&conn, &pairing).unwrap();
        assert!(scim_token_matches(&conn, "secret").unwrap());
        assert!(!scim_token_matches(&conn, "secreT").unwrap());
        assert!(!scim_token_matches(&conn, "").unwrap());
        pairing.scim_token_hash = None;
        set_pairing(&conn, &pairing).unwrap();
        assert!(!scim_token_matches(&conn, "secret").unwrap());
        assert!(unpair(&conn).unwrap());
        assert!(pairing_is_gone(&conn));
    }

    fn pairing_is_gone(conn: &Connection) -> bool {
        pairing(conn).unwrap().is_none()
    }
}
