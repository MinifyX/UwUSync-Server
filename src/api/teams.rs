//! Teams over HTTP. The rules are in [`crate::db::teams`]; here is what a
//! request looks like, what it is bounded by, and who is told afterwards.
//!
//! Every endpoint takes the device's bearer token and acts for its account.
//! Nothing here is open to somebody the server does not know. The protocol,
//! field by field, is in `docs/teams.md`.

use crate::auth::Authenticated;
use crate::config::{TeamCreation, TEAM_MEMBERS_CEILING};
use crate::connections::Holding;
use crate::db::records::{self, Mailbox};
use crate::db::teams::{self, MemberState, Role};
use crate::limits;
use crate::state::AppState;
use crate::wire::{Envelope, PullResponse, PushResponse, Reader};
use crate::{b64, ApiError, Result, TeamError};
use axum::body::Body;
use axum::extract::{Path, Query, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use uwussh_proto::{MAX_BATCH, SCHEMA_VERSION};

/// The largest rotation: a wrapped key for every member of the largest team
/// there can be.
pub const ROTATE_BODY_BYTES: usize = 1024 * 1024;

// ── What every handler starts with ──────────────────────────────────────────

/// Count the request, and refuse it if teams are switched off.
fn begin(state: &AppState, auth: &Authenticated) -> Result<()> {
    state
        .limits
        .check_account(auth.account.id, &limits::TEAMS)?;
    switched_on(state)
}

fn switched_on(state: &AppState) -> Result<()> {
    if !state.config.teams.enabled {
        return Err(TeamError::Disabled.into());
    }
    Ok(())
}

/// An id out of a path. One that is not shaped like an id names nothing.
fn id(text: &str) -> Result<Uuid> {
    Uuid::parse_str(text).map_err(|_| ApiError::NotFound)
}

/// A name a person typed: trimmed, not empty, not long, and nothing in it
/// that is not meant to be seen.
fn label(text: &str, max_chars: usize, what: &str) -> Result<String> {
    let text = text.trim();
    if text.is_empty() {
        return Err(ApiError::Invalid(format!("{what} must not be empty")));
    }
    if text.chars().count() > max_chars {
        return Err(ApiError::Invalid(format!(
            "{what} may be {max_chars} characters at most"
        )));
    }
    if text.chars().any(char::is_control) {
        return Err(ApiError::Invalid(format!(
            "{what} must not contain control characters"
        )));
    }
    Ok(text.to_string())
}

/// Bytes that travel as base64 (URL-safe, no padding): not none, not more
/// than `max`.
fn bytes(text: &str, max: usize, what: &str) -> Result<Vec<u8>> {
    // Longer than `max` bytes could ever be written: not worth decoding.
    if text.len() > max * 4 / 3 + 4 {
        return Err(ApiError::Invalid(format!(
            "{what} may be {max} bytes at most"
        )));
    }
    let bytes = b64::decode(text).ok_or_else(|| {
        ApiError::Invalid(format!("{what} must be base64 (URL-safe, no padding)"))
    })?;
    if bytes.is_empty() || bytes.len() > max {
        return Err(ApiError::Invalid(format!(
            "{what} must be between 1 and {max} bytes"
        )));
    }
    Ok(bytes)
}

fn public_key(text: &str) -> Result<Vec<u8>> {
    let key = bytes(text, teams::PUBLIC_KEY_BYTES, "a public key")?;
    if key.len() != teams::PUBLIC_KEY_BYTES {
        return Err(ApiError::Invalid("a public key must be 32 bytes".into()));
    }
    Ok(key)
}

fn wrapped_key(text: &str) -> Result<Vec<u8>> {
    bytes(text, teams::MAX_WRAPPED_KEY_BYTES, "a wrapped key")
}

/// Tell every device of every member to look at the team again.
fn announce(state: &AppState, team: Uuid, also: &[Uuid]) {
    let mut accounts = teams::accounts_of(&state.db.lock(), team).unwrap_or_default();
    accounts.extend_from_slice(also);
    state.events.announce_team(&accounts, team);
}

// ── Policy ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct Policy {
    pub enabled: bool,
    pub may_create: bool,
    pub max_teams_per_account: u64,
    pub max_members_per_team: u64,
}

/// What this server allows about teams. Also how a client finds out whether
/// a server knows teams at all: one from before answers 404.
pub async fn policy(auth: Authenticated, State(state): State<AppState>) -> Result<Json<Policy>> {
    state
        .limits
        .check_account(auth.account.id, &limits::TEAMS)?;
    let teams = state.config.teams;
    Ok(Json(Policy {
        enabled: teams.enabled,
        may_create: teams.enabled && teams.creation == TeamCreation::All,
        max_teams_per_account: teams.max_per_account,
        max_members_per_team: teams.max_members,
    }))
}

// ── Identity ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct Identity {
    pub public_key: String,
    pub sealed_private: String,
    pub updated_ms: u64,
}

impl From<teams::Identity> for Identity {
    fn from(identity: teams::Identity) -> Self {
        Self {
            public_key: b64::encode(identity.public_key),
            sealed_private: b64::encode(identity.sealed_private),
            updated_ms: identity.updated_ms,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct PutIdentity {
    pub public_key: String,
    pub sealed_private: String,
    #[serde(default)]
    pub replace: bool,
}

pub async fn identity(
    auth: Authenticated,
    State(state): State<AppState>,
) -> Result<Json<Identity>> {
    begin(&state, &auth)?;
    let identity = teams::identity(&state.db.lock(), auth.account.id)?.ok_or(ApiError::NotFound)?;
    Ok(Json(identity.into()))
}

pub async fn put_identity(
    auth: Authenticated,
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<Identity>> {
    begin(&state, &auth)?;
    let request: PutIdentity = super::body(&state, request).await?;
    let public = public_key(&request.public_key)?;
    let sealed = bytes(
        &request.sealed_private,
        teams::MAX_SEALED_PRIVATE_BYTES,
        "a sealed private key",
    )?;
    let stored = teams::put_identity(
        &mut state.db.lock(),
        auth.account.id,
        &public,
        &sealed,
        request.replace,
        state.clock.now_ms(),
    )?;
    if !stored.waiting_in.is_empty() {
        tracing::info!(
            account = %auth.account.id, teams = stored.waiting_in.len(),
            "a team identity was replaced; its memberships wait to be confirmed again"
        );
    }
    for team in &stored.waiting_in {
        announce(&state, *team, &[]);
    }
    Ok(Json(stored.identity.into()))
}

// ── Teams ───────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct Team {
    pub id: Uuid,
    pub name: String,
    pub role: Role,
    pub state: MemberState,
    pub epoch: u64,
    pub wrapped_key: Option<String>,
    pub needs_rotation: bool,
    pub members: u64,
    pub created_ms: u64,
}

impl From<teams::Team> for Team {
    fn from(team: teams::Team) -> Self {
        Self {
            id: team.id,
            name: team.name,
            role: team.role,
            state: team.state,
            epoch: team.epoch,
            wrapped_key: team.wrapped_key.map(b64::encode),
            needs_rotation: team.needs_rotation,
            members: team.members,
            created_ms: team.created_ms,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct NewTeam {
    pub name: String,
    pub display_name: String,
    pub wrapped_key: String,
}

pub async fn create(
    auth: Authenticated,
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<Team>> {
    begin(&state, &auth)?;
    if state.config.teams.creation != TeamCreation::All {
        return Err(TeamError::CreationClosed.into());
    }
    let request: NewTeam = super::body(&state, request).await?;
    let name = label(&request.name, teams::MAX_NAME_CHARS, "a team name")?;
    let display_name = label(
        &request.display_name,
        teams::MAX_DISPLAY_NAME_CHARS,
        "a display name",
    )?;
    let wrapped = wrapped_key(&request.wrapped_key)?;
    let team = teams::create(
        &mut state.db.lock(),
        auth.account.id,
        &name,
        &display_name,
        &wrapped,
        &state.config.teams,
        state.clock.now_ms(),
    )?;
    tracing::info!(team = %team.id, account = %auth.account.id, "team created");
    // The account's other devices learn of it the way they learn of anything.
    state.events.announce_team(&[auth.account.id], team.id);
    Ok(Json(team.into()))
}

pub async fn list(auth: Authenticated, State(state): State<AppState>) -> Result<Json<Vec<Team>>> {
    begin(&state, &auth)?;
    let teams = teams::list(&state.db.lock(), auth.account.id)?;
    Ok(Json(teams.into_iter().map(Team::from).collect()))
}

#[derive(Debug, Deserialize)]
pub struct Rename {
    pub name: String,
}

pub async fn rename(
    auth: Authenticated,
    State(state): State<AppState>,
    Path(team): Path<String>,
    request: Request,
) -> Result<Json<Team>> {
    begin(&state, &auth)?;
    let team = id(&team)?;
    let request: Rename = super::body(&state, request).await?;
    let name = label(&request.name, teams::MAX_NAME_CHARS, "a team name")?;
    let renamed = {
        let conn = state.db.lock();
        teams::rename(&conn, team, auth.account.id, &name)?;
        teams::get(&conn, team, auth.account.id)?
    };
    announce(&state, team, &[]);
    Ok(Json(renamed.into()))
}

pub async fn delete(
    auth: Authenticated,
    State(state): State<AppState>,
    Path(team): Path<String>,
) -> Result<StatusCode> {
    begin(&state, &auth)?;
    let team = id(&team)?;
    let members = teams::delete(&mut state.db.lock(), team, auth.account.id)?;
    tracing::info!(%team, account = %auth.account.id, "team deleted");
    state.events.announce_team(&members, team);
    Ok(StatusCode::NO_CONTENT)
}

// ── Invites ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct NewInvite {
    pub role: Role,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreatedInvite {
    pub id: Uuid,
    pub code: String,
    pub role: Role,
    pub expires_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Invite {
    pub id: Uuid,
    pub role: Role,
    pub created_by: Uuid,
    pub created_ms: u64,
    pub expires_ms: u64,
}

pub async fn create_invite(
    auth: Authenticated,
    State(state): State<AppState>,
    Path(team): Path<String>,
    request: Request,
) -> Result<Json<CreatedInvite>> {
    begin(&state, &auth)?;
    let team = id(&team)?;
    let request: NewInvite = super::body(&state, request).await?;
    let invite = teams::create_invite(
        &mut state.db.lock(),
        team,
        auth.account.id,
        request.role,
        state.clock.now_ms(),
    )?;
    Ok(Json(CreatedInvite {
        id: invite.id,
        code: invite.code,
        role: invite.role,
        expires_ms: invite.expires_ms,
    }))
}

pub async fn invites(
    auth: Authenticated,
    State(state): State<AppState>,
    Path(team): Path<String>,
) -> Result<Json<Vec<Invite>>> {
    begin(&state, &auth)?;
    let team = id(&team)?;
    let invites = teams::invites(
        &state.db.lock(),
        team,
        auth.account.id,
        state.clock.now_ms(),
    )?;
    Ok(Json(
        invites
            .into_iter()
            .map(|invite| Invite {
                id: invite.id,
                role: invite.role,
                created_by: invite.created_by,
                created_ms: invite.created_ms,
                expires_ms: invite.expires_ms,
            })
            .collect(),
    ))
}

pub async fn revoke_invite(
    auth: Authenticated,
    State(state): State<AppState>,
    Path((team, invite)): Path<(String, String)>,
) -> Result<StatusCode> {
    begin(&state, &auth)?;
    let (team, invite) = (id(&team)?, id(&invite)?);
    teams::revoke_invite(&state.db.lock(), team, auth.account.id, invite)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct Join {
    pub code: String,
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Joined {
    pub team_id: Uuid,
    pub name: String,
    pub role: Role,
    pub state: MemberState,
}

/// The longest thing taken for a code. One is 17 characters as shown.
const MAX_CODE_CHARS: usize = 64;

/// Redeem an invite. Tries are counted per account, before anything is
/// looked up, and a try that worked is taken off the count again.
pub async fn join(
    auth: Authenticated,
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<Joined>> {
    begin(&state, &auth)?;
    state
        .limits
        .check_account(auth.account.id, &limits::TEAM_JOIN)?;
    let request: Join = super::body(&state, request).await?;
    if request.code.len() > MAX_CODE_CHARS {
        return Err(TeamError::InvalidInvite.into());
    }
    let display_name = label(
        &request.display_name,
        teams::MAX_DISPLAY_NAME_CHARS,
        "a display name",
    )?;
    let joined = teams::join(
        &mut state.db.lock(),
        auth.account.id,
        &request.code,
        &display_name,
        &state.config.teams,
        state.clock.now_ms(),
    );
    let team = match joined {
        Ok(team) => team,
        Err(error) => {
            if matches!(error, ApiError::Team(TeamError::InvalidInvite)) {
                tracing::warn!(account = %auth.account.id, "a team invite that is not one");
            }
            return Err(error);
        }
    };
    state
        .limits
        .forgive_account(auth.account.id, &limits::TEAM_JOIN);
    tracing::info!(team = %team.id, account = %auth.account.id, "a team invite was redeemed");
    announce(&state, team.id, &[]);
    Ok(Json(Joined {
        team_id: team.id,
        name: team.name,
        role: team.role,
        state: team.state,
    }))
}

// ── Members ─────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct Member {
    pub account_id: Uuid,
    pub display_name: String,
    pub role: Role,
    pub state: MemberState,
    pub public_key: String,
    pub joined_ms: u64,
}

pub async fn members(
    auth: Authenticated,
    State(state): State<AppState>,
    Path(team): Path<String>,
) -> Result<Json<Vec<Member>>> {
    begin(&state, &auth)?;
    let team = id(&team)?;
    let members = teams::members(&state.db.lock(), team, auth.account.id)?;
    Ok(Json(
        members
            .into_iter()
            .map(|member| Member {
                account_id: member.account_id,
                display_name: member.display_name,
                role: member.role,
                state: member.state,
                public_key: b64::encode(member.public_key),
                joined_ms: member.joined_ms,
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct Confirm {
    pub epoch: u64,
    /// The member's public key as the confirming client saw it, and wrapped
    /// the team key to.
    pub public_key: String,
    pub wrapped_key: String,
}

pub async fn confirm(
    auth: Authenticated,
    State(state): State<AppState>,
    Path((team, member)): Path<(String, String)>,
    request: Request,
) -> Result<StatusCode> {
    begin(&state, &auth)?;
    let (team, member) = (id(&team)?, id(&member)?);
    let request: Confirm = super::body(&state, request).await?;
    let public = public_key(&request.public_key)?;
    let wrapped = wrapped_key(&request.wrapped_key)?;
    teams::confirm(
        &mut state.db.lock(),
        team,
        auth.account.id,
        member,
        request.epoch,
        &public,
        &wrapped,
    )?;
    tracing::info!(%team, by = %auth.account.id, %member, "a team member was confirmed");
    announce(&state, team, &[]);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct SetRole {
    pub role: Role,
}

pub async fn set_role(
    auth: Authenticated,
    State(state): State<AppState>,
    Path((team, member)): Path<(String, String)>,
    request: Request,
) -> Result<StatusCode> {
    begin(&state, &auth)?;
    let (team, member) = (id(&team)?, id(&member)?);
    let request: SetRole = super::body(&state, request).await?;
    teams::set_role(
        &mut state.db.lock(),
        team,
        auth.account.id,
        member,
        request.role,
    )?;
    tracing::info!(
        %team, by = %auth.account.id, %member, role = request.role.as_str(),
        "a team member's role was changed"
    );
    announce(&state, team, &[]);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn remove(
    auth: Authenticated,
    State(state): State<AppState>,
    Path((team, member)): Path<(String, String)>,
) -> Result<StatusCode> {
    begin(&state, &auth)?;
    let (team, member) = (id(&team)?, id(&member)?);
    let needs_rotation = teams::remove(&mut state.db.lock(), team, auth.account.id, member)?;
    tracing::info!(
        %team, by = %auth.account.id, %member, needs_rotation,
        "a team member was removed"
    );
    // Whoever was taken out hears it too: their devices drop the team.
    announce(&state, team, &[member]);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct RotatedKey {
    pub account_id: Uuid,
    pub wrapped_key: String,
}

#[derive(Debug, Deserialize)]
pub struct Rotate {
    pub epoch: u64,
    pub keys: Vec<RotatedKey>,
    /// The team's cursor as the rotating client last saw it. Optional; with
    /// it, a record somebody pushed in the meantime stops the rotation
    /// instead of being deleted unseen.
    #[serde(default)]
    pub cursor: Option<u64>,
}

pub async fn rotate(
    auth: Authenticated,
    State(state): State<AppState>,
    Path(team): Path<String>,
    request: Request,
) -> Result<Json<Team>> {
    begin(&state, &auth)?;
    let team = id(&team)?;
    // Whether this account may rotate at all, before a megabyte is read for
    // it. Decided again, for good, in the transaction that rotates.
    {
        let standing = teams::active(&state.db.lock(), team, auth.account.id)?;
        if !standing.role.manages() {
            return Err(TeamError::Forbidden.into());
        }
    }
    let request: Rotate = super::body(&state, request).await?;
    if request.keys.len() as u64 > TEAM_MEMBERS_CEILING {
        return Err(TeamError::MembersMismatch.into());
    }
    let keys = request
        .keys
        .iter()
        .map(|key| Ok((key.account_id, wrapped_key(&key.wrapped_key)?)))
        .collect::<Result<Vec<_>>>()?;
    let rotated = {
        let mut conn = state.db.lock();
        teams::rotate(
            &mut conn,
            team,
            auth.account.id,
            request.epoch,
            &keys,
            request.cursor,
        )?;
        teams::get(&conn, team, auth.account.id)?
    };
    tracing::info!(%team, by = %auth.account.id, epoch = rotated.epoch, "a team key was rotated");
    announce(&state, team, &[]);
    Ok(Json(rotated.into()))
}

// ── Records ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PullQuery {
    /// Where to go on from. `since`, as `/v1/records` calls it, is taken too.
    #[serde(default, alias = "since")]
    pub cursor: u64,
    pub limit: Option<usize>,
}

/// A page of a team's records, and where the team is: a member reads the
/// epoch and its own role off every pull, so it notices a rotation or a
/// changed role without asking for either.
#[derive(Debug, Serialize, Deserialize)]
pub struct TeamPull {
    #[serde(flatten)]
    pub page: PullResponse,
    pub epoch: u64,
    pub role: Role,
    pub needs_rotation: bool,
}

/// Everything in a team after a cursor, for a member who has the key. The
/// same pages as `/v1/records`, counted against the same limits: it is the
/// same account pulling. Every kind is handed out — a client that knows
/// teams skips a kind it does not know.
pub async fn pull(
    auth: Authenticated,
    State(state): State<AppState>,
    Path(team): Path<String>,
    Query(query): Query<PullQuery>,
) -> Result<Response> {
    state.limits.check_account(auth.account.id, &limits::PULL)?;
    switched_on(&state)?;
    let team = id(&team)?;
    let going = state.limits.start(auth.account.id, &limits::PULLS)?;
    let limit = query.limit.unwrap_or(MAX_BATCH).min(MAX_BATCH);
    let pull = {
        let conn = state.db.lock();
        let standing = teams::active(&conn, team, auth.account.id)?;
        let page =
            records::pull_from(&conn, Mailbox::team(team), query.cursor, limit, Reader::ALL)?;
        TeamPull {
            page,
            epoch: standing.epoch,
            role: standing.role,
            needs_rotation: standing.needs_rotation,
        }
    };
    Ok(Json(pull)
        .into_response()
        .map(|body| Body::new(Holding::new(body, going))))
}

#[derive(Debug, Deserialize)]
pub struct TeamPush {
    pub schema: u32,
    /// The epoch whose key sealed these records.
    pub epoch: u64,
    pub envelopes: Vec<Envelope>,
}

/// Offer records to a team. Counted, and the membership looked at, before
/// the body is read: it may be 16 MiB, and a reader's is never wanted.
pub async fn push(
    auth: Authenticated,
    State(state): State<AppState>,
    Path(team): Path<String>,
    request: Request,
) -> Result<Json<PushResponse>> {
    state.limits.check_account(auth.account.id, &limits::PUSH)?;
    switched_on(&state)?;
    let team = id(&team)?;
    let _going = state.limits.start(auth.account.id, &limits::PUSHES)?;
    {
        let standing = teams::active(&state.db.lock(), team, auth.account.id)?;
        if !standing.role.writes() {
            return Err(TeamError::Forbidden.into());
        }
    }
    let request: TeamPush = super::body(&state, request).await?;
    if request.schema != SCHEMA_VERSION {
        return Err(ApiError::Schema {
            found: request.schema,
            known: SCHEMA_VERSION,
        });
    }
    let response = teams::push(
        &mut state.db.lock(),
        team,
        auth.account.id,
        auth.device.id,
        request.epoch,
        &request.envelopes,
        state.config.quota,
    )?;
    if !response.accepted.is_empty() {
        announce(&state, team, &[]);
    }
    Ok(Json(response))
}
