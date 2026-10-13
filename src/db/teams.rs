//! Teams: a vault several accounts share.
//!
//! The server knows who is in a team and as what, and holds the team key
//! wrapped once for every member — by a client, to that member's public key.
//! It cannot unwrap one. What it enforces needs no key: who may read, who may
//! write, who may let others in, and that somebody who was taken out is out
//! from that moment on.
//!
//! Every rule is checked in the transaction that acts on it, and by the
//! account, not the device: a team is the account's, on all its devices.
//!
//! An account that is no member of a team is told `not-found` — the same as
//! for a team that does not exist, so nobody learns which ids are teams.

use crate::config::Teams;
use crate::db::invites::{code, hash};
use crate::db::records::{self, Mailbox, Quota};
use crate::wire::{Envelope, PushResponse};
use crate::{ApiError, Result, TeamError};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashSet;
use uuid::Uuid;

/// How long a team invite can be redeemed.
pub const INVITE_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Invites one team may have open at once.
pub const MAX_OPEN_INVITES: i64 = 20;

/// A member's public key: X25519.
pub const PUBLIC_KEY_BYTES: usize = 32;

/// The longest sealed private key taken. It is 32 bytes, a nonce and a tag,
/// with room for however a client frames them.
pub const MAX_SEALED_PRIVATE_BYTES: usize = 1024;

/// The longest wrapped team key taken: a 32-byte key in a sealed box is 80
/// bytes.
pub const MAX_WRAPPED_KEY_BYTES: usize = 512;

/// The longest team name, in characters.
pub const MAX_NAME_CHARS: usize = 80;

/// The longest name a member goes by in a team, in characters.
pub const MAX_DISPLAY_NAME_CHARS: usize = 60;

/// What a member may do. Each role may do what the ones after it may.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Everything, and alone: deleting the team, making and unmaking owners.
    Owner,
    /// Members, invites, roles below owner, rotation, the name.
    Admin,
    /// Reads and writes records.
    Editor,
    /// Reads records.
    Reader,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Editor => "editor",
            Self::Reader => "reader",
        }
    }

    fn stored(name: &str) -> Self {
        match name {
            "owner" => Self::Owner,
            "admin" => Self::Admin,
            "editor" => Self::Editor,
            // Nothing else is ever written; whatever it is may do the least.
            _ => Self::Reader,
        }
    }

    pub fn manages(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    pub fn writes(self) -> bool {
        !matches!(self, Self::Reader)
    }
}

/// Whether a member has been handed the team key yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemberState {
    /// Redeemed an invite, or changed their key pair: waits for a member who
    /// manages the team to wrap the team key for them. Reads nothing.
    Pending,
    Active,
}

impl MemberState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
        }
    }

    fn stored(name: &str) -> Self {
        match name {
            "active" => Self::Active,
            _ => Self::Pending,
        }
    }
}

/// An account's key pair for teams, as the server holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub public_key: Vec<u8>,
    pub sealed_private: Vec<u8>,
    pub updated_ms: u64,
}

/// A team as one of its members sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Team {
    pub id: Uuid,
    pub name: String,
    pub role: Role,
    pub state: MemberState,
    pub epoch: u64,
    /// None while pending.
    pub wrapped_key: Option<Vec<u8>>,
    pub needs_rotation: bool,
    /// How many members, counting those who wait.
    pub members: u64,
    pub created_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub account_id: Uuid,
    pub display_name: String,
    pub role: Role,
    pub state: MemberState,
    pub public_key: Vec<u8>,
    pub joined_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub id: Uuid,
    pub role: Role,
    pub created_by: Uuid,
    pub created_ms: u64,
    pub expires_ms: u64,
}

/// An invite as it is made: the one time its code is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewInvite {
    pub id: Uuid,
    pub code: String,
    pub role: Role,
    pub expires_ms: u64,
}

/// Where an account stands in a team, and where the team is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Standing {
    pub role: Role,
    pub state: MemberState,
    pub epoch: u64,
    pub needs_rotation: bool,
    /// The last sequence number the team handed out.
    pub seq: u64,
}

fn uuid_at(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Uuid> {
    let text: String = row.get(index)?;
    Uuid::parse_str(&text).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

/// Where `account` stands in `team` — or `not-found`, for a team it is not
/// in and for one there is not.
pub fn standing(conn: &Connection, team: Uuid, account: Uuid) -> Result<Standing> {
    conn.query_row(
        "SELECT m.role, m.state, t.epoch, t.needs_rotation, t.seq
           FROM team_members m JOIN teams t ON t.id = m.team_id
          WHERE m.team_id = ?1 AND m.account_id = ?2",
        params![team.to_string(), account.to_string()],
        |row| {
            Ok(Standing {
                role: Role::stored(&row.get::<_, String>(0)?),
                state: MemberState::stored(&row.get::<_, String>(1)?),
                epoch: row.get::<_, i64>(2)? as u64,
                needs_rotation: row.get(3)?,
                seq: row.get::<_, i64>(4)? as u64,
            })
        },
    )
    .optional()?
    .ok_or(ApiError::NotFound)
}

/// A member who has the key. One who waits is told so.
pub fn active(conn: &Connection, team: Uuid, account: Uuid) -> Result<Standing> {
    let standing = standing(conn, team, account)?;
    if standing.state != MemberState::Active {
        return Err(TeamError::Pending.into());
    }
    Ok(standing)
}

/// A member who has the key and manages the team: an owner or an admin.
fn manager(conn: &Connection, team: Uuid, account: Uuid) -> Result<Standing> {
    let standing = active(conn, team, account)?;
    if !standing.role.manages() {
        return Err(TeamError::Forbidden.into());
    }
    Ok(standing)
}

/// Every account in a team, for telling their devices that it changed.
pub fn accounts_of(conn: &Connection, team: Uuid) -> Result<Vec<Uuid>> {
    let mut stmt = conn.prepare("SELECT account_id FROM team_members WHERE team_id = ?1")?;
    let rows = stmt.query_map([team.to_string()], |row| uuid_at(row, 0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

// ── Identity ────────────────────────────────────────────────────────────────

pub fn identity(conn: &Connection, account: Uuid) -> Result<Option<Identity>> {
    Ok(conn
        .query_row(
            "SELECT public_key, sealed_private, updated_ms FROM team_identities
              WHERE account_id = ?1",
            [account.to_string()],
            |row| {
                Ok(Identity {
                    public_key: row.get(0)?,
                    sealed_private: row.get(1)?,
                    updated_ms: row.get::<_, i64>(2)? as u64,
                })
            },
        )
        .optional()?)
}

/// What storing an identity did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub identity: Identity,
    /// The teams in which this made the account wait again, because the key
    /// its team keys were wrapped to is not its key any more.
    pub waiting_in: Vec<Uuid>,
}

/// Store the account's key pair. The first one stays: two devices setting up
/// at once must end with one pair, not each with their own — the second is
/// refused and takes the first's. Sending the very same pair again is fine.
///
/// With `replace`, a new sealed private key for the same public key is just
/// taken (the vault's password changed, say). A new *public* key is another
/// identity: every team key wrapped to the old one is dropped, and the
/// account waits in each of its teams until somebody who manages the team
/// has checked the new key and wrapped the team key to it.
pub fn put_identity(
    conn: &mut Connection,
    account: Uuid,
    public_key: &[u8],
    sealed_private: &[u8],
    replace: bool,
    now: u64,
) -> Result<Stored> {
    let tx = conn.transaction()?;
    let held = identity(&tx, account)?;
    let mut waiting_in = Vec::new();
    match held {
        Some(held) if held.public_key == public_key && held.sealed_private == sealed_private => {
            return Ok(Stored {
                identity: held,
                waiting_in,
            });
        }
        Some(_) if !replace => return Err(TeamError::IdentityExists.into()),
        Some(held) => {
            if held.public_key != public_key {
                {
                    let mut stmt =
                        tx.prepare("SELECT team_id FROM team_members WHERE account_id = ?1")?;
                    let rows = stmt.query_map([account.to_string()], |row| uuid_at(row, 0))?;
                    waiting_in = rows.collect::<rusqlite::Result<_>>()?;
                }
                tx.execute(
                    "UPDATE team_members SET state = 'pending', wrapped_key = NULL
                      WHERE account_id = ?1",
                    [account.to_string()],
                )?;
            }
            tx.execute(
                "UPDATE team_identities SET public_key = ?2, sealed_private = ?3, updated_ms = ?4
                  WHERE account_id = ?1",
                params![account.to_string(), public_key, sealed_private, now as i64],
            )?;
        }
        None => {
            tx.execute(
                "INSERT INTO team_identities (account_id, public_key, sealed_private, updated_ms)
                 VALUES (?1, ?2, ?3, ?4)",
                params![account.to_string(), public_key, sealed_private, now as i64],
            )?;
        }
    }
    tx.commit()?;
    Ok(Stored {
        identity: Identity {
            public_key: public_key.to_vec(),
            sealed_private: sealed_private.to_vec(),
            updated_ms: now,
        },
        waiting_in,
    })
}

// ── Teams ───────────────────────────────────────────────────────────────────

fn memberships(conn: &Connection, account: Uuid) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT count(*) FROM team_members WHERE account_id = ?1",
        [account.to_string()],
        |row| row.get(0),
    )
}

fn member_count(conn: &Connection, team: Uuid) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT count(*) FROM team_members WHERE team_id = ?1",
        [team.to_string()],
        |row| row.get(0),
    )
}

/// Start a team. Whoever does is its owner and its first member, and brings
/// the team key wrapped to their own public key — so they need one.
pub fn create(
    conn: &mut Connection,
    account: Uuid,
    name: &str,
    display_name: &str,
    wrapped_key: &[u8],
    policy: &Teams,
    now: u64,
) -> Result<Team> {
    let tx = conn.transaction()?;
    if identity(&tx, account)?.is_none() {
        return Err(TeamError::NoIdentity.into());
    }
    if memberships(&tx, account)? as u64 >= policy.max_per_account {
        return Err(TeamError::TeamLimit.into());
    }
    let id = Uuid::now_v7();
    tx.execute(
        "INSERT INTO teams (id, name, created_ms) VALUES (?1, ?2, ?3)",
        params![id.to_string(), name, now as i64],
    )?;
    tx.execute(
        "INSERT INTO team_members
            (team_id, account_id, display_name, role, state, wrapped_key, had_key, joined_ms)
         VALUES (?1, ?2, ?3, 'owner', 'active', ?4, 1, ?5)",
        params![
            id.to_string(),
            account.to_string(),
            display_name,
            wrapped_key,
            now as i64
        ],
    )?;
    tx.commit()?;
    Ok(Team {
        id,
        name: name.to_string(),
        role: Role::Owner,
        state: MemberState::Active,
        epoch: 1,
        wrapped_key: Some(wrapped_key.to_vec()),
        needs_rotation: false,
        members: 1,
        created_ms: now,
    })
}

const TEAM_COLUMNS: &str = "t.id, t.name, m.role, m.state, t.epoch, m.wrapped_key,
        t.needs_rotation, t.created_ms,
        (SELECT count(*) FROM team_members c WHERE c.team_id = t.id)";

fn row_to_team(row: &rusqlite::Row<'_>) -> rusqlite::Result<Team> {
    let state = MemberState::stored(&row.get::<_, String>(3)?);
    let wrapped_key: Option<Vec<u8>> = row.get(5)?;
    Ok(Team {
        id: uuid_at(row, 0)?,
        name: row.get(1)?,
        role: Role::stored(&row.get::<_, String>(2)?),
        state,
        epoch: row.get::<_, i64>(4)? as u64,
        // Belt and braces: the key is taken out of the row when a member is
        // made to wait, and never handed out for one who waits either way.
        wrapped_key: wrapped_key.filter(|_| state == MemberState::Active),
        needs_rotation: row.get(6)?,
        created_ms: row.get::<_, i64>(7)? as u64,
        members: row.get::<_, i64>(8)? as u64,
    })
}

/// The teams an account is in, oldest first, with those it waits to be let
/// into.
pub fn list(conn: &Connection, account: Uuid) -> Result<Vec<Team>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {TEAM_COLUMNS}
           FROM team_members m JOIN teams t ON t.id = m.team_id
          WHERE m.account_id = ?1
          ORDER BY t.created_ms, t.id"
    ))?;
    let rows = stmt.query_map([account.to_string()], row_to_team)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// One team, as `account` sees it.
pub fn get(conn: &Connection, team: Uuid, account: Uuid) -> Result<Team> {
    conn.query_row(
        &format!(
            "SELECT {TEAM_COLUMNS}
               FROM team_members m JOIN teams t ON t.id = m.team_id
              WHERE m.team_id = ?1 AND m.account_id = ?2"
        ),
        params![team.to_string(), account.to_string()],
        row_to_team,
    )
    .optional()?
    .ok_or(ApiError::NotFound)
}

pub fn rename(conn: &Connection, team: Uuid, by: Uuid, name: &str) -> Result<()> {
    manager(conn, team, by)?;
    conn.execute(
        "UPDATE teams SET name = ?2 WHERE id = ?1",
        params![team.to_string(), name],
    )?;
    Ok(())
}

/// Take a team away with everything it holds, whoever asks. Returns whether
/// there was one.
pub fn delete_any(conn: &Connection, team: Uuid) -> rusqlite::Result<bool> {
    let id = team.to_string();
    conn.execute("DELETE FROM team_records WHERE team_id = ?1", [&id])?;
    conn.execute("DELETE FROM team_invites WHERE team_id = ?1", [&id])?;
    conn.execute("DELETE FROM team_members WHERE team_id = ?1", [&id])?;
    Ok(conn.execute("DELETE FROM teams WHERE id = ?1", [&id])? > 0)
}

/// Delete a team: its records, its invites, its memberships. An owner's to
/// do, and nobody else's — also an owner who waits, having changed their key
/// pair: that the team's data is theirs to delete does not hang on a key.
/// Returns who was in it.
pub fn delete(conn: &mut Connection, team: Uuid, by: Uuid) -> Result<Vec<Uuid>> {
    let tx = conn.transaction()?;
    if standing(&tx, team, by)?.role != Role::Owner {
        return Err(TeamError::Forbidden.into());
    }
    let members = accounts_of(&tx, team)?;
    delete_any(&tx, team)?;
    tx.commit()?;
    Ok(members)
}

// ── Invites ─────────────────────────────────────────────────────────────────

/// Make an invite for a role. The code is returned once and never stored.
/// Nobody is invited as an owner: an owner is made from a member.
pub fn create_invite(
    conn: &mut Connection,
    team: Uuid,
    by: Uuid,
    role: Role,
    now: u64,
) -> Result<NewInvite> {
    if role == Role::Owner {
        return Err(ApiError::Invalid(
            "an invite is for an admin, an editor or a reader".into(),
        ));
    }
    let tx = conn.transaction()?;
    manager(&tx, team, by)?;
    // What nobody can redeem any more makes room.
    tx.execute(
        "DELETE FROM team_invites
          WHERE team_id = ?1 AND (used_ms IS NOT NULL OR expires_ms <= ?2)",
        params![team.to_string(), now as i64],
    )?;
    let open: i64 = tx.query_row(
        "SELECT count(*) FROM team_invites WHERE team_id = ?1",
        [team.to_string()],
        |row| row.get(0),
    )?;
    if open >= MAX_OPEN_INVITES {
        return Err(TeamError::TooManyInvites.into());
    }
    let invite = NewInvite {
        id: Uuid::now_v7(),
        code: code(),
        role,
        expires_ms: now + INVITE_TTL_MS,
    };
    tx.execute(
        "INSERT INTO team_invites (id, team_id, code_hash, role, created_by, created_ms, expires_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            invite.id.to_string(),
            team.to_string(),
            hash(&invite.code),
            role.as_str(),
            by.to_string(),
            now as i64,
            invite.expires_ms as i64,
        ],
    )?;
    tx.commit()?;
    Ok(invite)
}

/// The invites that can still be redeemed. Never their codes: nobody has
/// those but whoever was shown them.
pub fn invites(conn: &Connection, team: Uuid, by: Uuid, now: u64) -> Result<Vec<Invite>> {
    manager(conn, team, by)?;
    let mut stmt = conn.prepare(
        "SELECT id, role, created_by, created_ms, expires_ms FROM team_invites
          WHERE team_id = ?1 AND used_ms IS NULL AND expires_ms > ?2
          ORDER BY created_ms, id",
    )?;
    let rows = stmt.query_map(params![team.to_string(), now as i64], |row| {
        Ok(Invite {
            id: uuid_at(row, 0)?,
            role: Role::stored(&row.get::<_, String>(1)?),
            created_by: uuid_at(row, 2)?,
            created_ms: row.get::<_, i64>(3)? as u64,
            expires_ms: row.get::<_, i64>(4)? as u64,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Take an invite back. One of another team is not found, like one that is
/// not there.
pub fn revoke_invite(conn: &Connection, team: Uuid, by: Uuid, invite: Uuid) -> Result<()> {
    manager(conn, team, by)?;
    let gone = conn.execute(
        "DELETE FROM team_invites WHERE id = ?1 AND team_id = ?2",
        params![invite.to_string(), team.to_string()],
    )?;
    if gone == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(())
}

/// Redeem an invite: the account becomes a member who waits. A code that was
/// never one, was used, has run out or was taken back is refused the same
/// way, and only a code that lets somebody in is used up.
pub fn join(
    conn: &mut Connection,
    account: Uuid,
    code: &str,
    display_name: &str,
    policy: &Teams,
    now: u64,
) -> Result<Team> {
    let tx = conn.transaction()?;
    if identity(&tx, account)?.is_none() {
        return Err(TeamError::NoIdentity.into());
    }
    // Found by the hash of what was typed. The code itself is never compared:
    // there is nothing here that holds one.
    let invite: Option<(String, Uuid, String)> = tx
        .query_row(
            "SELECT id, team_id, role FROM team_invites
              WHERE code_hash = ?1 AND used_ms IS NULL AND expires_ms > ?2",
            params![hash(code), now as i64],
            |row| Ok((row.get(0)?, uuid_at(row, 1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((invite, team, role)) = invite else {
        return Err(TeamError::InvalidInvite.into());
    };
    let already: i64 = tx.query_row(
        "SELECT count(*) FROM team_members WHERE team_id = ?1 AND account_id = ?2",
        params![team.to_string(), account.to_string()],
        |row| row.get(0),
    )?;
    if already > 0 {
        return Err(TeamError::AlreadyMember.into());
    }
    if memberships(&tx, account)? as u64 >= policy.max_per_account {
        return Err(TeamError::TeamLimit.into());
    }
    if member_count(&tx, team)? as u64 >= policy.max_members {
        return Err(TeamError::TeamFull.into());
    }
    tx.execute(
        "UPDATE team_invites SET used_ms = ?2 WHERE id = ?1",
        params![invite, now as i64],
    )?;
    tx.execute(
        "INSERT INTO team_members
            (team_id, account_id, display_name, role, state, wrapped_key, had_key, joined_ms)
         VALUES (?1, ?2, ?3, ?4, 'pending', NULL, 0, ?5)",
        params![
            team.to_string(),
            account.to_string(),
            display_name,
            role,
            now as i64
        ],
    )?;
    let joined = get(&tx, team, account)?;
    tx.commit()?;
    Ok(joined)
}

/// Forget invites nobody can redeem any more.
pub fn purge(conn: &Connection, now: u64) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM team_invites WHERE used_ms IS NOT NULL OR expires_ms <= ?1",
        [now as i64],
    )
}

// ── Members ─────────────────────────────────────────────────────────────────

/// Who is in the team, oldest first, with those who wait — and their public
/// keys, which is what a member who manages the team checks before letting
/// one of them in. For members who have the key; one who waits sees nobody.
pub fn members(conn: &Connection, team: Uuid, by: Uuid) -> Result<Vec<Member>> {
    active(conn, team, by)?;
    let mut stmt = conn.prepare(
        "SELECT m.account_id, m.display_name, m.role, m.state, i.public_key, m.joined_ms
           FROM team_members m LEFT JOIN team_identities i ON i.account_id = m.account_id
          WHERE m.team_id = ?1
          ORDER BY m.joined_ms, m.account_id",
    )?;
    let rows = stmt.query_map([team.to_string()], |row| {
        Ok(Member {
            account_id: uuid_at(row, 0)?,
            display_name: row.get(1)?,
            role: Role::stored(&row.get::<_, String>(2)?),
            state: MemberState::stored(&row.get::<_, String>(3)?),
            public_key: row.get::<_, Option<Vec<u8>>>(4)?.unwrap_or_default(),
            joined_ms: row.get::<_, i64>(5)? as u64,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// `(role, state, had_key)` of a member, or `not-found`.
fn member(conn: &Connection, team: Uuid, account: Uuid) -> Result<(Role, MemberState, bool)> {
    conn.query_row(
        "SELECT role, state, had_key FROM team_members WHERE team_id = ?1 AND account_id = ?2",
        params![team.to_string(), account.to_string()],
        |row| {
            Ok((
                Role::stored(&row.get::<_, String>(0)?),
                MemberState::stored(&row.get::<_, String>(1)?),
                row.get(2)?,
            ))
        },
    )
    .optional()?
    .ok_or(ApiError::NotFound)
}

/// Let a waiting member in: hand them the team key of the current epoch,
/// wrapped to their public key by whoever confirms them.
///
/// The request names the epoch the key belongs to and the public key it was
/// wrapped to. Either may have changed since the confirming client looked —
/// the team was rotated, the member replaced their key pair — and a key
/// stored then would be one the member cannot use, or one for a key nobody
/// checked. Both are refused by name.
pub fn confirm(
    conn: &mut Connection,
    team: Uuid,
    by: Uuid,
    target: Uuid,
    epoch: u64,
    public_key: &[u8],
    wrapped_key: &[u8],
) -> Result<()> {
    let tx = conn.transaction()?;
    let standing = manager(&tx, team, by)?;
    let (_, state, _) = member(&tx, team, target)?;
    if standing.epoch != epoch {
        return Err(TeamError::StaleEpoch {
            current: standing.epoch,
        }
        .into());
    }
    if state != MemberState::Pending {
        return Err(TeamError::NotPending.into());
    }
    let held = identity(&tx, target)?.map(|identity| identity.public_key);
    if !held.is_some_and(|held| crate::db::constant_time_eq(&held, public_key)) {
        return Err(TeamError::IdentityChanged.into());
    }
    tx.execute(
        "UPDATE team_members SET state = 'active', wrapped_key = ?3, had_key = 1
          WHERE team_id = ?1 AND account_id = ?2",
        params![team.to_string(), target.to_string(), wrapped_key],
    )?;
    tx.commit()?;
    Ok(())
}

/// Whether the team would still have an owner without `target` as one: an
/// owner who has the key if `target` has it, any owner if `target` waits.
fn another_owner(conn: &Connection, team: Uuid, target: Uuid, state: MemberState) -> Result<bool> {
    let others: i64 = conn.query_row(
        "SELECT count(*) FROM team_members
          WHERE team_id = ?1 AND account_id != ?2 AND role = 'owner'
            AND (state = 'active' OR ?3)",
        params![
            team.to_string(),
            target.to_string(),
            state == MemberState::Pending
        ],
        |row| row.get(0),
    )?;
    Ok(others > 0)
}

/// Change what a member may do.
///
/// Whoever manages the team may; making an owner, or making an owner
/// something else, is an owner's alone. An owner is made from a member who
/// has the key, and the team keeps one.
pub fn set_role(
    conn: &mut Connection,
    team: Uuid,
    by: Uuid,
    target: Uuid,
    role: Role,
) -> Result<()> {
    let tx = conn.transaction()?;
    let standing = manager(&tx, team, by)?;
    let (current, state, _) = member(&tx, team, target)?;
    if (current == Role::Owner || role == Role::Owner) && standing.role != Role::Owner {
        return Err(TeamError::Forbidden.into());
    }
    if current == role {
        return Ok(());
    }
    if role == Role::Owner && state != MemberState::Active {
        return Err(TeamError::NotActive.into());
    }
    if current == Role::Owner && !another_owner(&tx, team, target, state)? {
        return Err(TeamError::LastOwner.into());
    }
    tx.execute(
        "UPDATE team_members SET role = ?3 WHERE team_id = ?1 AND account_id = ?2",
        params![team.to_string(), target.to_string(), role.as_str()],
    )?;
    tx.commit()?;
    Ok(())
}

/// Take a member out — or leave, when it is oneself, which anybody may,
/// waiting or not. From here on they get nothing: every team request looks
/// the membership up again.
///
/// If they ever held the key of this epoch, the team is marked as needing a
/// rotation: what they could read they may have kept, but nothing written
/// from the next epoch on is theirs to read. Returns whether it is.
pub fn remove(conn: &mut Connection, team: Uuid, by: Uuid, target: Uuid) -> Result<bool> {
    let tx = conn.transaction()?;
    let (role, state, had_key) = if by == target {
        member(&tx, team, target)?
    } else {
        let standing = manager(&tx, team, by)?;
        let found = member(&tx, team, target)?;
        if found.0 == Role::Owner && standing.role != Role::Owner {
            return Err(TeamError::Forbidden.into());
        }
        found
    };
    if role == Role::Owner && !another_owner(&tx, team, target, state)? {
        return Err(TeamError::LastOwner.into());
    }
    tx.execute(
        "DELETE FROM team_members WHERE team_id = ?1 AND account_id = ?2",
        params![team.to_string(), target.to_string()],
    )?;
    if had_key {
        tx.execute(
            "UPDATE teams SET needs_rotation = 1 WHERE id = ?1",
            [team.to_string()],
        )?;
    }
    tx.commit()?;
    Ok(had_key)
}

/// Move the team to a new key.
///
/// The request names the next epoch and the new key wrapped for every member
/// who has the current one — exactly those, each once: a member left out
/// would be locked out by accident, and anybody else named would be let in
/// without having been confirmed. A member confirmed or removed while the
/// rotating client was at work makes the lists differ, and the client starts
/// again from the members there are.
///
/// In one transaction: the epoch moves, the keys are replaced, the records of
/// the old epoch go — the rotating client pushes them again under the new
/// key — and the team no longer needs a rotation. Members who wait keep
/// waiting. Sequence numbers go on from where they were, so every member's
/// cursor still means what it meant.
///
/// With `cursor`, the rotation only happens if that is the team's last
/// sequence number: the rotating client has seen every record it is about to
/// have deleted.
pub fn rotate(
    conn: &mut Connection,
    team: Uuid,
    by: Uuid,
    epoch: u64,
    keys: &[(Uuid, Vec<u8>)],
    cursor: Option<u64>,
) -> Result<()> {
    let tx = conn.transaction()?;
    let standing = manager(&tx, team, by)?;
    if standing.epoch.checked_add(1) != Some(epoch) {
        return Err(TeamError::StaleEpoch {
            current: standing.epoch,
        }
        .into());
    }
    if cursor.is_some_and(|cursor| cursor != standing.seq) {
        return Err(TeamError::StaleCursor.into());
    }
    let have_it: HashSet<Uuid> = {
        let mut stmt = tx.prepare(
            "SELECT account_id FROM team_members WHERE team_id = ?1 AND state = 'active'",
        )?;
        let rows = stmt.query_map([team.to_string()], |row| uuid_at(row, 0))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    let named: HashSet<Uuid> = keys.iter().map(|(account, _)| *account).collect();
    if named.len() != keys.len() || named != have_it {
        return Err(TeamError::MembersMismatch.into());
    }
    let id = team.to_string();
    // Those who wait were never handed this epoch's key: taking one of them
    // out later calls for no rotation.
    tx.execute(
        "UPDATE team_members SET had_key = 0, wrapped_key = NULL
          WHERE team_id = ?1 AND state != 'active'",
        [&id],
    )?;
    for (account, wrapped) in keys {
        tx.execute(
            "UPDATE team_members SET wrapped_key = ?3, had_key = 1
              WHERE team_id = ?1 AND account_id = ?2",
            params![id, account.to_string(), wrapped],
        )?;
    }
    tx.execute("DELETE FROM team_records WHERE team_id = ?1", [&id])?;
    tx.execute(
        "UPDATE teams SET epoch = ?2, needs_rotation = 0, record_count = 0, record_bytes = 0
          WHERE id = ?1",
        params![id, epoch as i64],
    )?;
    tx.commit()?;
    Ok(())
}

// ── Records ─────────────────────────────────────────────────────────────────

/// Offer records to a team: from a member who has the key and may write, for
/// the epoch the team is at. Decided in the transaction that stores them, so
/// a member taken out, or a rotation, a moment earlier is a refusal and not
/// a record under the wrong key.
pub fn push(
    conn: &mut Connection,
    team: Uuid,
    account: Uuid,
    device: Uuid,
    epoch: u64,
    envelopes: &[Envelope],
    quota: Quota,
) -> Result<PushResponse> {
    let tx = conn.transaction()?;
    let standing = active(&tx, team, account)?;
    if !standing.role.writes() {
        return Err(TeamError::Forbidden.into());
    }
    if standing.epoch != epoch {
        return Err(TeamError::StaleEpoch {
            current: standing.epoch,
        }
        .into());
    }
    let response = records::push_in(&tx, Mailbox::team(team), device, envelopes, quota)?;
    tx.commit()?;
    Ok(response)
}

// ── For the operator, and for an account that goes ──────────────────────────

/// A team as the operator's list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub id: Uuid,
    pub name: String,
    pub members: u64,
    pub owners: u64,
    pub records: u64,
    pub created_ms: u64,
}

/// Every team on the server, oldest first.
pub fn all(conn: &Connection) -> rusqlite::Result<Vec<Listed>> {
    let mut stmt = conn.prepare(
        "SELECT t.id, t.name, t.record_count, t.created_ms,
                (SELECT count(*) FROM team_members m WHERE m.team_id = t.id),
                (SELECT count(*) FROM team_members m
                  WHERE m.team_id = t.id AND m.role = 'owner')
           FROM teams t ORDER BY t.created_ms, t.id",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(Listed {
            id: uuid_at(row, 0)?,
            name: row.get(1)?,
            records: row.get::<_, i64>(2)? as u64,
            created_ms: row.get::<_, i64>(3)? as u64,
            members: row.get::<_, i64>(4)? as u64,
            owners: row.get::<_, i64>(5)? as u64,
        })
    })?;
    rows.collect()
}

/// Make a member an owner, on the operator's word: for a team that was left
/// without one. Returns whether that account is in that team and has its
/// key — an owner who waits to be let in could let nobody in, itself least.
pub fn make_owner(conn: &Connection, team: Uuid, account: Uuid) -> rusqlite::Result<bool> {
    let changed = conn.execute(
        "UPDATE team_members SET role = 'owner'
          WHERE team_id = ?1 AND account_id = ?2 AND state = 'active'",
        params![team.to_string(), account.to_string()],
    )?;
    Ok(changed > 0)
}

/// What became of the teams of an account that went.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Left {
    /// Teams it was in that still have members.
    pub teams: Vec<Uuid>,
    /// Of those, the ones now without an owner and without an admin who
    /// could become one: the operator's to settle (`team-owner`).
    pub ownerless: Vec<Uuid>,
    /// Teams it was the only member of, deleted with it.
    pub deleted: Vec<Uuid>,
}

/// Take an account out of everything to do with teams, as part of deleting
/// it: its memberships and its identity. No membership is left pointing at
/// an account that is not there.
///
/// A team it was the last member of goes with it. A team it was the last
/// owner of gets the admin who has been in it longest as its owner; with no
/// admin either, it is reported back. And every team it held the key of
/// needs a rotation, as after any other removal.
pub fn forget_account(conn: &mut Connection, account: Uuid) -> Result<Left> {
    let tx = conn.transaction()?;
    let mut left = Left::default();
    let teams: Vec<(Uuid, bool)> = {
        let mut stmt =
            tx.prepare("SELECT team_id, had_key FROM team_members WHERE account_id = ?1")?;
        let rows = stmt.query_map([account.to_string()], |row| {
            Ok((uuid_at(row, 0)?, row.get(1)?))
        })?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    tx.execute(
        "DELETE FROM team_members WHERE account_id = ?1",
        [account.to_string()],
    )?;
    tx.execute(
        "DELETE FROM team_identities WHERE account_id = ?1",
        [account.to_string()],
    )?;
    for (team, had_key) in teams {
        let id = team.to_string();
        if member_count(&tx, team)? == 0 {
            delete_any(&tx, team)?;
            left.deleted.push(team);
            continue;
        }
        left.teams.push(team);
        if had_key {
            tx.execute("UPDATE teams SET needs_rotation = 1 WHERE id = ?1", [&id])?;
        }
        let owners: i64 = tx.query_row(
            "SELECT count(*) FROM team_members WHERE team_id = ?1 AND role = 'owner'",
            [&id],
            |row| row.get(0),
        )?;
        if owners > 0 {
            continue;
        }
        let promoted = tx.execute(
            "UPDATE team_members SET role = 'owner'
              WHERE team_id = ?1 AND account_id = (
                    SELECT account_id FROM team_members
                     WHERE team_id = ?1 AND role = 'admin' AND state = 'active'
                     ORDER BY joined_ms, account_id LIMIT 1)",
            [&id],
        )?;
        if promoted == 0 {
            left.ownerless.push(team);
        }
    }
    tx.commit()?;
    Ok(left)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{accounts, Db};

    fn account(conn: &Connection) -> Uuid {
        let account = accounts::create(conn, &accounts::tests::header(), b"key").unwrap();
        put_identity_for(conn, account.id);
        account.id
    }

    fn put_identity_for(conn: &Connection, account: Uuid) {
        conn.execute(
            "INSERT INTO team_identities (account_id, public_key, sealed_private, updated_ms)
             VALUES (?1, ?2, x'01', 1)",
            params![account.to_string(), account.as_bytes().repeat(2)],
        )
        .unwrap();
    }

    /// A team of `owner`, with `others` let in as what they are named.
    fn team_with(conn: &mut Connection, owner: Uuid, others: &[(Uuid, Role)]) -> Uuid {
        let policy = Teams::default();
        let team = create(conn, owner, "ops", "Owner", b"wrapped", &policy, 1)
            .unwrap()
            .id;
        for (index, (other, role)) in others.iter().enumerate() {
            let now = 10 + index as u64;
            let invite = create_invite(conn, team, owner, *role, now).unwrap();
            join(conn, *other, &invite.code, "Other", &policy, now).unwrap();
            let key = other.as_bytes().repeat(2);
            confirm(conn, team, owner, *other, 1, &key, b"theirs").unwrap();
        }
        team
    }

    fn team_error<T: std::fmt::Debug>(result: Result<T>) -> TeamError {
        match result {
            Err(ApiError::Team(error)) => error,
            other => panic!("expected a team refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_account_that_goes_leaves_nothing_behind_and_its_teams_stay_manageable() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let (owner, admin, later_admin, reader) = (
            account(&conn),
            account(&conn),
            account(&conn),
            account(&conn),
        );
        // One team with admins, one with only a reader, one all its own.
        let with_admins = team_with(
            &mut conn,
            owner,
            &[(admin, Role::Admin), (later_admin, Role::Admin)],
        );
        let with_reader = team_with(&mut conn, owner, &[(reader, Role::Reader)]);
        let alone = team_with(&mut conn, owner, &[]);

        let left = forget_account(&mut conn, owner).unwrap();
        assert_eq!(left.deleted, vec![alone]);
        assert_eq!(left.ownerless, vec![with_reader]);
        assert_eq!(left.teams.len(), 2);

        let dangling: i64 = conn
            .query_row(
                "SELECT (SELECT count(*) FROM team_members WHERE account_id = ?1)
                      + (SELECT count(*) FROM team_identities WHERE account_id = ?1)
                      + (SELECT count(*) FROM teams WHERE id = ?2)",
                params![owner.to_string(), alone.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(dangling, 0);

        // The admin who has been there longest is the owner now, and the
        // team wants a new key: the account that went knew the old one.
        let promoted = standing(&conn, with_admins, admin).unwrap();
        assert_eq!(promoted.role, Role::Owner);
        assert!(promoted.needs_rotation);
        assert_eq!(
            standing(&conn, with_admins, later_admin).unwrap().role,
            Role::Admin
        );

        // The one without an admin is the operator's to settle.
        assert_eq!(
            standing(&conn, with_reader, reader).unwrap().role,
            Role::Reader
        );
        assert!(make_owner(&conn, with_reader, reader).unwrap());
        assert_eq!(
            standing(&conn, with_reader, reader).unwrap().role,
            Role::Owner
        );
        assert!(!make_owner(&conn, with_reader, owner).unwrap());
    }

    #[test]
    fn a_new_sealed_private_key_changes_nothing_and_a_new_public_key_everything() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let owner = accounts::create(&conn, &accounts::tests::header(), b"key")
            .unwrap()
            .id;
        let first = put_identity(&mut conn, owner, &[1; 32], b"sealed", false, 1).unwrap();
        assert!(first.waiting_in.is_empty());
        let team = create(&mut conn, owner, "ops", "Owner", b"w", &Teams::default(), 1)
            .unwrap()
            .id;

        // Somebody else's pair, without saying replace: the first one stays.
        assert_eq!(
            team_error(put_identity(&mut conn, owner, &[2; 32], b"other", false, 2)),
            TeamError::IdentityExists
        );
        // The same pair again is not an error.
        put_identity(&mut conn, owner, &[1; 32], b"sealed", false, 2).unwrap();

        // Sealed again under a new password: still the same identity.
        let resealed = put_identity(&mut conn, owner, &[1; 32], b"resealed", true, 3).unwrap();
        assert!(resealed.waiting_in.is_empty());
        assert_eq!(
            standing(&conn, team, owner).unwrap().state,
            MemberState::Active
        );

        // Another key: the team key wrapped to the old one is gone.
        let replaced = put_identity(&mut conn, owner, &[2; 32], b"new", true, 4).unwrap();
        assert_eq!(replaced.waiting_in, vec![team]);
        let mine = get(&conn, team, owner).unwrap();
        assert_eq!(mine.state, MemberState::Pending);
        assert_eq!(mine.wrapped_key, None);
        // Waiting, it still owns the team — and may delete what is in it.
        assert_eq!(team_error(members(&conn, team, owner)), TeamError::Pending);
        assert_eq!(delete(&mut conn, team, owner).unwrap(), vec![owner]);
    }

    #[test]
    fn a_member_who_never_had_the_key_calls_for_no_rotation() {
        let db = Db::open_in_memory().unwrap();
        let mut conn = db.lock();
        let (owner, waiting, reader) = (account(&conn), account(&conn), account(&conn));
        let team = team_with(&mut conn, owner, &[(reader, Role::Reader)]);
        let policy = Teams::default();
        let invite = create_invite(&mut conn, team, owner, Role::Editor, 50).unwrap();
        join(&mut conn, waiting, &invite.code, "Waiting", &policy, 50).unwrap();

        assert!(!remove(&mut conn, team, owner, waiting).unwrap());
        assert!(!standing(&conn, team, owner).unwrap().needs_rotation);
        assert!(remove(&mut conn, team, owner, reader).unwrap());
        assert!(standing(&conn, team, owner).unwrap().needs_rotation);
    }
}
