//! SCIM 2.0 (RFC 7643/7644), for UwUAuth to say who may use this server. See
//! `docs/sso.md`.
//!
//! Only as much as UwUAuth speaks: Users with `userName`, `externalId` (the
//! person's `sub` there), `displayName` and `active`; filters on `userName`
//! and `externalId` with `eq`; PATCH with `add`, `replace` and `remove`.
//! Groups are taken and forgotten: this server has no use for them.
//!
//! - A person UwUAuth pushes before they ever signed in is kept **pending**:
//!   signing in later finds them by their `sub`.
//! - `active: false` shuts every device of their account out and ends its
//!   sessions, and no new one can join. The vault stays: `active: true`
//!   lets them sign in and join again with their master password.
//! - DELETE deletes their account with it — unless that would leave a team
//!   with members and nobody to own it, which is refused with 409.
//!
//! What identifies a person is their `externalId`, never their `userName`:
//! an address can be handed to somebody else later, and must not hand them
//! the account that came with it.

use super::{who, Peer};
use crate::db::sso::{self as people, SsoUser};
use crate::state::AppState;
use crate::{limits, ApiError};
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use uuid::Uuid;

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

/// A page, at most.
const MAX_PAGE: usize = 200;
/// A name, an address or an id, at most.
const MAX_TEXT: usize = 256;
/// Operations in one PATCH, at most.
const MAX_OPERATIONS: usize = 64;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(service_provider_config),
        )
        .route("/scim/v2/ResourceTypes", get(resource_types))
        .route("/scim/v2/Users", get(list_users).post(create_user))
        .route(
            "/scim/v2/Users/{id}",
            get(get_user)
                .put(replace_user)
                .patch(patch_user)
                .delete(delete_user),
        )
        .route("/scim/v2/Groups", get(list_groups).post(create_group))
        .route(
            "/scim/v2/Groups/{id}",
            get(get_group)
                .put(replace_group)
                .patch(patch_group)
                .delete(delete_group),
        )
}

/// What SCIM is told when something is wrong.
#[derive(Debug)]
pub struct ScimError {
    status: StatusCode,
    scim_type: Option<&'static str>,
    detail: String,
}

impl ScimError {
    fn new(status: StatusCode, detail: impl Into<String>) -> Self {
        Self {
            status,
            scim_type: None,
            detail: detail.into(),
        }
    }

    fn bad(scim_type: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            scim_type: Some(scim_type),
            detail: detail.into(),
        }
    }

    fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "no such resource")
    }

    fn conflict(scim_type: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            scim_type: Some(scim_type),
            detail: detail.into(),
        }
    }
}

impl From<rusqlite::Error> for ScimError {
    fn from(error: rusqlite::Error) -> Self {
        tracing::error!(%error, "database error in SCIM");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "something went wrong")
    }
}

impl From<ApiError> for ScimError {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::RateLimited => Self::new(StatusCode::TOO_MANY_REQUESTS, error.to_string()),
            ApiError::Database(inner) => inner.into(),
            ApiError::Body(rejection) => Self::bad("invalidSyntax", rejection.body_text()),
            ApiError::Team(_) | ApiError::Conflict(_) => {
                Self::conflict("uniqueness", error.to_string())
            }
            other => {
                tracing::error!(error = %other, "error in SCIM");
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, "something went wrong")
            }
        }
    }
}

impl IntoResponse for ScimError {
    fn into_response(self) -> Response {
        let mut body = json!({
            "schemas": [ERROR_SCHEMA],
            "status": self.status.as_str(),
            "detail": self.detail,
        });
        if let Some(scim_type) = self.scim_type {
            body["scimType"] = json!(scim_type);
        }
        respond(self.status, body)
    }
}

type ScimResult<T> = std::result::Result<T, ScimError>;

fn respond(status: StatusCode, body: Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/scim+json")],
        body.to_string(),
    )
        .into_response()
}

/// Only UwUAuth, with the token it was given when pairing; and somebody
/// trying tokens is slowed down without UwUAuth ever being.
pub struct Scim {
    issuer: String,
}

fn authenticate(state: &AppState, headers: &HeaderMap, peer: Peer) -> ScimResult<Scim> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|token| !token.is_empty() && token.len() <= 512);
    let conn = state.db.lock();
    if let Some(token) = token {
        if people::scim_token_matches(&conn, token)? {
            if let Some(pairing) = people::pairing(&conn)? {
                return Ok(Scim {
                    issuer: pairing.issuer,
                });
            }
        }
    }
    drop(conn);
    // Only refusals count, and only they are refused once too many came:
    // the right token is let in however many wrong ones were tried before.
    let who = who(state, headers, peer);
    if state.limits.exhausted(&who, &limits::SCIM_REFUSED) {
        return Err(ApiError::RateLimited.into());
    }
    state.limits.check(&who, &limits::SCIM_REFUSED)?;
    Err(ScimError::new(StatusCode::UNAUTHORIZED, "not allowed"))
}

/// The body, as JSON, after the caller was let in.
async fn body(request: Request) -> ScimResult<Value> {
    // SCIM sends `application/scim+json`, which the `Json` extractor does not
    // take; the body is read with the same limit all the same.
    let bytes = axum::body::to_bytes(request.into_body(), super::SMALL_BODY_BYTES)
        .await
        .map_err(|_| ScimError::new(StatusCode::PAYLOAD_TOO_LARGE, "too large"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| ScimError::bad("invalidSyntax", "the body is not JSON"))
}

fn user_json(state: &AppState, user: &SsoUser) -> Value {
    let mut value = json!({
        "schemas": [USER_SCHEMA],
        "id": user.id.to_string(),
        "externalId": user.subject,
        "userName": user.user_name,
        "active": user.active,
        "meta": {
            "resourceType": "User",
            "created": crate::rfc3339(user.created_ms),
            "lastModified": crate::rfc3339(user.updated_ms),
            "location": format!("{}/scim/v2/Users/{}", state.config.base_url(), user.id),
        },
    });
    if let Some(name) = &user.display_name {
        value["displayName"] = json!(name);
        value["name"] = json!({ "formatted": name });
    }
    value
}

/// A name, an address or an id from UwUAuth: present, not too long, and no
/// control characters that would end up in a log line.
fn text(value: &Value, what: &str) -> ScimResult<String> {
    let text = value
        .as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| ScimError::bad("invalidValue", format!("{what} is missing")))?;
    if text.len() > MAX_TEXT || text.chars().any(char::is_control) {
        return Err(ScimError::bad("invalidValue", format!("{what} is not one")));
    }
    Ok(text.to_string())
}

fn optional_text(value: Option<&Value>, what: &str) -> ScimResult<Option<String>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(empty)) if empty.trim().is_empty() => Ok(None),
        Some(value) => text(value, what).map(Some),
    }
}

/// `true`, `false`, or the strings some clients send instead.
fn boolean(value: &Value) -> ScimResult<bool> {
    match value {
        Value::Bool(flag) => Ok(*flag),
        Value::String(text) if text.eq_ignore_ascii_case("true") => Ok(true),
        Value::String(text) if text.eq_ignore_ascii_case("false") => Ok(false),
        _ => Err(ScimError::bad("invalidValue", "active is true or false")),
    }
}

/// The display name of a user resource: `displayName`, else `name.formatted`.
fn display_name_of(user: &Map<String, Value>) -> ScimResult<Option<String>> {
    match optional_text(user.get("displayName"), "displayName")? {
        Some(name) => Ok(Some(name)),
        None => optional_text(
            user.get("name").and_then(|name| name.get("formatted")),
            "name.formatted",
        ),
    }
}

fn find(conn: &rusqlite::Connection, scim: &Scim, id: &str) -> ScimResult<SsoUser> {
    let id = Uuid::parse_str(id).map_err(|_| ScimError::not_found())?;
    people::by_id(conn, id)?
        .filter(|user| user.issuer == scim.issuer)
        .ok_or_else(ScimError::not_found)
}

// ── Discovery ───────────────────────────────────────────────────────────────

async fn service_provider_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
) -> ScimResult<Response> {
    authenticate(&state, &headers, peer)?;
    Ok(respond(
        StatusCode::OK,
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": { "supported": true },
            "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
            "filter": { "supported": true, "maxResults": MAX_PAGE },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": false },
            "authenticationSchemes": [{
                "type": "oauthbearertoken",
                "name": "Bearer token",
                "description": "The token UwUAuth was given when this server paired with it.",
            }],
        }),
    ))
}

async fn resource_types(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
) -> ScimResult<Response> {
    authenticate(&state, &headers, peer)?;
    let types = [
        ("User", "/Users", USER_SCHEMA),
        ("Group", "/Groups", GROUP_SCHEMA),
    ]
    .map(|(id, endpoint, schema)| {
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": id, "name": id, "endpoint": endpoint, "schema": schema,
        })
    });
    Ok(respond(StatusCode::OK, list(types.to_vec(), 2, 1)))
}

fn list(resources: Vec<Value>, total: usize, start: usize) -> Value {
    json!({
        "schemas": [LIST_SCHEMA],
        "totalResults": total,
        "startIndex": start,
        "itemsPerPage": resources.len(),
        "Resources": resources,
    })
}

// ── Users ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListQuery {
    filter: Option<String>,
    start_index: Option<usize>,
    count: Option<usize>,
}

/// `userName eq "…"` or `externalId eq "…"`: what UwUAuth looks people up by.
fn parse_filter(filter: &str) -> ScimResult<(&'static str, String)> {
    let invalid = || ScimError::bad("invalidFilter", "only userName or externalId eq \"…\"");
    let filter = filter.trim();
    let (attribute, rest) = filter.split_once(char::is_whitespace).ok_or_else(invalid)?;
    let (op, value) = rest
        .trim_start()
        .split_once(char::is_whitespace)
        .ok_or_else(invalid)?;
    if !op.eq_ignore_ascii_case("eq") {
        return Err(invalid());
    }
    let attribute = if attribute.eq_ignore_ascii_case("userName") {
        "userName"
    } else if attribute.eq_ignore_ascii_case("externalId") {
        "externalId"
    } else {
        return Err(invalid());
    };
    let value: String = serde_json::from_str(value.trim()).map_err(|_| invalid())?;
    if value.len() > MAX_TEXT {
        return Err(invalid());
    }
    Ok((attribute, value))
}

async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    Query(query): Query<ListQuery>,
) -> ScimResult<Response> {
    let scim = authenticate(&state, &headers, peer)?;
    let start = query.start_index.unwrap_or(1).max(1);
    let count = query.count.unwrap_or(100).min(MAX_PAGE);
    let conn = state.db.lock();
    let (users, total) = match query.filter.as_deref() {
        Some(filter) => {
            let (attribute, value) = parse_filter(filter)?;
            let found = match attribute {
                "userName" => people::by_user_name(&conn, &scim.issuer, &value)?,
                _ => people::by_subject(&conn, &scim.issuer, &value)?,
            };
            let found: Vec<SsoUser> = found.into_iter().collect();
            let total = found.len();
            (
                found.into_iter().skip(start - 1).take(count).collect(),
                total,
            )
        }
        None => people::list(&conn, &scim.issuer, start - 1, count)?,
    };
    let resources = users.iter().map(|user| user_json(&state, user)).collect();
    Ok(respond(StatusCode::OK, list(resources, total, start)))
}

async fn get_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    Path(id): Path<String>,
) -> ScimResult<Response> {
    let scim = authenticate(&state, &headers, peer)?;
    let user = find(&state.db.lock(), &scim, &id)?;
    Ok(scim_ok(&state, &user))
}

fn scim_ok(state: &AppState, user: &SsoUser) -> Response {
    respond(StatusCode::OK, user_json(state, user))
}

async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    request: Request,
) -> ScimResult<Response> {
    let scim = authenticate(&state, &headers, peer)?;
    let body = body(request).await?;
    let user = body
        .as_object()
        .ok_or_else(|| ScimError::bad("invalidSyntax", "a user is an object"))?;
    let user_name = text(user.get("userName").unwrap_or(&Value::Null), "userName")?;
    // The person's `sub` at UwUAuth: what signing in finds them by.
    let subject = text(user.get("externalId").unwrap_or(&Value::Null), "externalId")?;
    let display_name = display_name_of(user)?;
    let active = user.get("active").map(boolean).transpose()?.unwrap_or(true);

    let conn = state.db.lock();
    if let Some(known) = people::by_subject(&conn, &scim.issuer, &subject)? {
        // Already here: they signed in before UwUAuth pushed them, or the
        // push is repeated. Either way it is the same person, so the push
        // updates them and answers with the id they already have.
        drop(conn);
        tracing::info!(person = %known.id, "UwUAuth pushed a person already known here");
        let change = Change {
            user_name: Some(user_name),
            subject: None,
            display_name: Some(display_name),
            active: Some(active),
        };
        return apply(&state, &scim, &known.id.to_string(), change);
    }
    let created = people::insert(
        &conn,
        &scim.issuer,
        &subject,
        &user_name,
        display_name.as_deref(),
        active,
    )?;
    tracing::info!(person = %created.id, "UwUAuth added a person");
    Ok(respond(StatusCode::CREATED, user_json(&state, &created)))
}

/// What a PUT or PATCH would make of a person.
struct Change {
    user_name: Option<String>,
    subject: Option<String>,
    display_name: Option<Option<String>>,
    active: Option<bool>,
}

async fn replace_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    Path(id): Path<String>,
    request: Request,
) -> ScimResult<Response> {
    let scim = authenticate(&state, &headers, peer)?;
    let body = body(request).await?;
    let user = body
        .as_object()
        .ok_or_else(|| ScimError::bad("invalidSyntax", "a user is an object"))?;
    let change = Change {
        user_name: Some(text(
            user.get("userName").unwrap_or(&Value::Null),
            "userName",
        )?),
        subject: optional_text(user.get("externalId"), "externalId")?,
        display_name: Some(display_name_of(user)?),
        active: Some(user.get("active").map(boolean).transpose()?.unwrap_or(true)),
    };
    apply(&state, &scim, &id, change)
}

#[derive(Deserialize)]
struct PatchOp {
    #[serde(default)]
    schemas: Vec<String>,
    #[serde(rename = "Operations")]
    operations: Vec<Operation>,
}

#[derive(Deserialize)]
struct Operation {
    op: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    value: Option<Value>,
}

async fn patch_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    Path(id): Path<String>,
    request: Request,
) -> ScimResult<Response> {
    let scim = authenticate(&state, &headers, peer)?;
    let body = body(request).await?;
    let patch: PatchOp = serde_json::from_value(body)
        .map_err(|_| ScimError::bad("invalidSyntax", "a PatchOp with Operations"))?;
    if !patch.schemas.is_empty() && !patch.schemas.iter().any(|schema| schema == PATCH_SCHEMA) {
        return Err(ScimError::bad("invalidSyntax", "a PatchOp"));
    }
    if patch.operations.len() > MAX_OPERATIONS {
        return Err(ScimError::bad("tooMany", "too many operations"));
    }
    let mut change = Change {
        user_name: None,
        subject: None,
        display_name: None,
        active: None,
    };
    for operation in &patch.operations {
        let op = operation.op.to_ascii_lowercase();
        if !matches!(op.as_str(), "add" | "replace" | "remove") {
            return Err(ScimError::bad(
                "invalidSyntax",
                "op is add, replace or remove",
            ));
        }
        let remove = op == "remove";
        // With a path, one attribute; without, an object of them.
        let pairs: Vec<(String, Option<&Value>)> = match &operation.path {
            Some(path) => vec![(path.clone(), operation.value.as_ref())],
            None => match &operation.value {
                Some(Value::Object(values)) => values
                    .iter()
                    .map(|(key, value)| (key.clone(), Some(value)))
                    .collect(),
                _ => return Err(ScimError::bad("noTarget", "an operation without a path")),
            },
        };
        for (path, value) in pairs {
            let value = if remove { None } else { value };
            match path.to_ascii_lowercase().as_str() {
                "active" => {
                    change.active = Some(match value {
                        Some(value) => boolean(value)?,
                        None => return Err(ScimError::bad("mutability", "active stays")),
                    })
                }
                "displayname" | "name.formatted" => {
                    change.display_name = Some(optional_text(value, "displayName")?)
                }
                "name" => {
                    change.display_name = Some(optional_text(
                        value.and_then(|name| name.get("formatted")),
                        "name.formatted",
                    )?)
                }
                "username" => {
                    change.user_name = Some(text(value.unwrap_or(&Value::Null), "userName")?)
                }
                "externalid" => {
                    change.subject = Some(text(value.unwrap_or(&Value::Null), "externalId")?)
                }
                // Nothing else is kept here, so nothing else changes.
                _ => {}
            }
        }
    }
    apply(&state, &scim, &id, change)
}

/// Make the change, and whatever it means for the person's devices.
fn apply(state: &AppState, scim: &Scim, id: &str, change: Change) -> ScimResult<Response> {
    let conn = state.db.lock();
    let mut user = find(&conn, scim, id)?;
    if let Some(subject) = change.subject {
        if subject != user.subject {
            // Who the account belongs to is not UwUAuth's to move: an
            // account that was made by one person stays theirs.
            if user.account_id.is_some() {
                return Err(ScimError::bad(
                    "mutability",
                    "externalId of a person with an account here cannot change",
                ));
            }
            if people::by_subject(&conn, &scim.issuer, &subject)?.is_some() {
                return Err(ScimError::conflict(
                    "uniqueness",
                    "a user with this externalId exists",
                ));
            }
            user.subject = subject;
        }
    }
    if let Some(user_name) = change.user_name {
        user.user_name = user_name;
    }
    if let Some(display_name) = change.display_name {
        user.display_name = display_name;
    }
    let deactivated = change.active == Some(false) && user.active;
    if let Some(active) = change.active {
        user.active = active;
    }
    people::update(&conn, &user)?;
    let devices = match (deactivated, user.account_id) {
        (true, Some(account)) => people::revoke_all_devices(&conn, account)?,
        _ => Vec::new(),
    };
    drop(conn);
    if deactivated {
        shut_out(state, &user, &devices);
    }
    Ok(scim_ok(state, &user))
}

/// What goes with a person UwUAuth turned away: their tickets, their
/// sessions, the pairing sessions their devices opened.
fn shut_out(state: &AppState, user: &SsoUser, devices: &[Uuid]) {
    state.sso.forget_person(user.id);
    for device in devices {
        state.sessions.drop_device(*device);
        state.pairings.close_opened_by(*device);
    }
    tracing::info!(
        person = %user.id, account = ?user.account_id, devices = devices.len(),
        "UwUAuth deactivated a person; their devices are shut out"
    );
}

async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    Path(id): Path<String>,
) -> ScimResult<Response> {
    let scim = authenticate(&state, &headers, peer)?;
    let mut conn = state.db.lock();
    let user = find(&conn, &scim, &id)?;
    let Some(account) = user.account_id else {
        people::delete(&conn, user.id)?;
        tracing::info!(person = %user.id, "UwUAuth removed a person without an account");
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    let stranded = people::teams_only_owned_by(&conn, account)?;
    if !stranded.is_empty() {
        tracing::warn!(
            person = %user.id, %account, teams = stranded.len(),
            "UwUAuth would delete the only owner of a team; refused"
        );
        return Err(ScimError::conflict(
            "mutability",
            "this person is the only owner of a team that has other members; \
             make someone else owner first",
        ));
    }
    let (devices, left) = people::delete_account(&mut conn, user.id, account)?;
    let mut told = Vec::new();
    for team in &left.teams {
        told.push((
            *team,
            crate::db::teams::accounts_of(&conn, *team).unwrap_or_default(),
        ));
    }
    drop(conn);
    state.sso.forget_person(user.id);
    for device in &devices {
        state.sessions.drop_device(*device);
        state.pairings.close_opened_by(*device);
    }
    for (team, members) in told {
        state.events.announce_team(&members, team);
    }
    tracing::info!(
        person = %user.id, %account, devices = devices.len(),
        "UwUAuth removed a person; their account is deleted"
    );
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ── Groups: taken, and forgotten ────────────────────────────────────────────

fn group_json(id: &str, display_name: &str) -> Value {
    json!({
        "schemas": [GROUP_SCHEMA],
        "id": id,
        "displayName": display_name,
        "members": [],
        "meta": { "resourceType": "Group" },
    })
}

async fn list_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
) -> ScimResult<Response> {
    authenticate(&state, &headers, peer)?;
    Ok(respond(StatusCode::OK, list(Vec::new(), 0, 1)))
}

async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    request: Request,
) -> ScimResult<Response> {
    authenticate(&state, &headers, peer)?;
    let body = body(request).await?;
    let name = text(
        body.get("displayName").unwrap_or(&Value::Null),
        "displayName",
    )?;
    Ok(respond(
        StatusCode::CREATED,
        group_json(&Uuid::now_v7().to_string(), &name),
    ))
}

async fn get_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
) -> ScimResult<Response> {
    authenticate(&state, &headers, peer)?;
    Err(ScimError::not_found())
}

async fn replace_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    Path(id): Path<String>,
    request: Request,
) -> ScimResult<Response> {
    authenticate(&state, &headers, peer)?;
    let body = body(request).await?;
    let name = text(
        body.get("displayName").unwrap_or(&Value::Null),
        "displayName",
    )?;
    if id.len() > MAX_TEXT {
        return Err(ScimError::not_found());
    }
    Ok(respond(StatusCode::OK, group_json(&id, &name)))
}

async fn patch_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    request: Request,
) -> ScimResult<Response> {
    authenticate(&state, &headers, peer)?;
    body(request).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn delete_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
) -> ScimResult<Response> {
    authenticate(&state, &headers, peer)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_are_the_two_uwuauth_uses() {
        assert_eq!(
            parse_filter(r#"userName eq "mia@example.com""#).unwrap(),
            ("userName", "mia@example.com".to_string())
        );
        assert_eq!(
            parse_filter(r#"externalid EQ "p-1""#).unwrap(),
            ("externalId", "p-1".to_string())
        );
        for wrong in [
            r#"userName co "mia""#,
            r#"emails eq "mia@example.com""#,
            "userName eq mia",
            "userName",
            "",
            r#"userName eq "a" or userName eq "b""#,
        ] {
            assert!(parse_filter(wrong).is_err(), "{wrong}");
        }
    }

    #[test]
    fn names_from_uwuauth_are_bounded_and_printable() {
        assert!(text(&json!("Mia"), "x").is_ok());
        assert!(text(&json!(""), "x").is_err());
        assert!(text(&json!("a\nb"), "x").is_err());
        assert!(text(&json!("a".repeat(MAX_TEXT + 1)), "x").is_err());
        assert!(text(&json!(5), "x").is_err());
        assert!(boolean(&json!("False")).is_ok_and(|flag| !flag));
        assert!(boolean(&json!(1)).is_err());
    }
}
