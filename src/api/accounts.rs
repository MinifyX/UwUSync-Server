//! Creating an account, and the vault header that belongs to it.
//!
//! The header — salt, key derivation costs, wrapped vault key — is what a
//! second device needs before it can turn a master password into keys. It is
//! not secret, but the wrapped key is only handed to a device that has proved
//! it knows the password, and the parameters alone are handed to a device that
//! is in the middle of joining. Those are two different endpoints on purpose.

use super::{auth_key, device_key, sso, who, Admitted, Peer};
use crate::auth::Authenticated;
use crate::config::Registration;
use crate::db::accounts::{plausible, VaultHeader, VaultParams};
use crate::db::{accounts, devices, invites};
use crate::limits;
use crate::state::AppState;
use crate::{ApiError, Result};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;

pub use uwussh_proto::api::{CreateAccount, VaultParamsRequest};

/// The first device of a new account.
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    request: Request,
) -> Result<Json<Admitted>> {
    // A closed server has nothing to count: every attempt gets the same no,
    // and none of them takes room in the limiter.
    if state.config.registration == Registration::Closed {
        return Err(ApiError::RegistrationClosed);
    }
    // Counted whether it works or not: with open registration every attempt
    // works, and a limit that forgives success would be no limit there.
    let who = who(&state, &headers, peer);
    state.limits.check(&who, &limits::ACCOUNTS)?;
    let request: CreateAccount = super::body(&state, request).await?;

    if !plausible(&request.vault) {
        return Err(ApiError::Invalid(
            "a vault header no device could open".into(),
        ));
    }
    state
        .config
        .kdf_floor
        .check(&request.vault)
        .map_err(ApiError::Invalid)?;
    let key = auth_key(&request.auth_key)?;
    let device_key = device_key(&request.device)?;

    let conn = state.db.lock();
    // Before the invite is spent, so a full server does not eat one.
    if accounts::count(&conn)? as u64 >= state.config.max_accounts {
        return Err(ApiError::ServerFull);
    }
    // Signed in with UwUAuth: the ticket stands in for the invite, whatever
    // the registration mode says — UwUAuth decided who may.
    let person = match &request.sso_ticket {
        Some(ticket) => {
            let now = state.clock.now_ms();
            let person = sso::ticket_person(&state, &conn, ticket, now)?;
            if person.account_id.is_some() {
                return Err(ApiError::Conflict(
                    "this person has an account here already: join it instead".into(),
                ));
            }
            if state.sso.spend(ticket, now) != Some(person.id) {
                return Err(ApiError::Unauthorized);
            }
            Some(person)
        }
        None => None,
    };
    match state.config.registration {
        _ if person.is_some() => {}
        Registration::Closed => return Err(ApiError::RegistrationClosed),
        Registration::Invite => {
            if !invites::redeem_invite(&conn, &request.invite)? {
                // An invite that is used, expired or made up: all the same
                // answer, so the code cannot be probed for.
                return Err(ApiError::Unauthorized);
            }
        }
        Registration::Open => {}
    }

    let account = accounts::create(&conn, &request.vault, &key)?;
    let device = devices::add(&conn, account.id, &request.device.name, &device_key)?;
    if let Some(person) = &person {
        crate::db::sso::link(&conn, person.id, account.id)?;
    }
    drop(conn);

    let (token, expires_ms) =
        state
            .sessions
            .issue(account.id, device.id, state.config.session_secs * 1000);
    // No device name: that is whatever somebody typed, and the log is read by
    // people and by install.sh.
    tracing::info!(
        account = %account.id, device = %device.id, sso = person.is_some(),
        "account created"
    );
    Ok(Json(Admitted {
        account_id: account.id,
        device_id: device.id,
        token,
        expires_ms,
    }))
}

/// The whole header, for a device that is in.
pub async fn vault(
    auth: Authenticated,
    State(state): State<AppState>,
) -> Result<Json<VaultHeader>> {
    let conn = state.db.lock();
    let header = accounts::header(&conn, auth.account.id)?.ok_or(ApiError::NotFound)?;
    Ok(Json(header))
}

/// What a joining device needs *before* it can prove anything: the salt and
/// the costs, so it can turn the master password into the key it will prove
/// with. The wrapped vault key is not in here — that one is the reward for
/// proving it.
///
/// The enrolment token comes in the body. In the address it would sit in the
/// access log of every proxy in between.
pub async fn vault_params(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    request: Request,
) -> Result<Json<VaultParams>> {
    let who = who(&state, &headers, peer);
    state.limits.check(&who, &limits::ENROL)?;
    let request: VaultParamsRequest = super::body(&state, request).await?;

    let conn = state.db.lock();
    let account = match &request.sso_ticket {
        // Signed in with UwUAuth: the ticket of a person with an account
        // here, instead of an enrolment token.
        Some(ticket) => sso::ticket_person(&state, &conn, ticket, state.clock.now_ms())?
            .account_id
            .ok_or(ApiError::Unauthorized)?,
        None => {
            invites::peek_enrolment(&conn, &request.enrolment)?.ok_or(ApiError::Unauthorized)?
        }
    };
    let header = accounts::header(&conn, account)?.ok_or(ApiError::Unauthorized)?;
    Ok(Json(header.params()))
}

pub use uwussh_proto::api::ChangePassword;

/// A new master password: the vault key is wrapped again, the verifier
/// replaced, and not one record is touched.
pub async fn change_password(
    auth: Authenticated,
    State(state): State<AppState>,
    Json(request): Json<ChangePassword>,
) -> Result<StatusCode> {
    let current = auth_key(&request.current_auth_key)?;
    let next = auth_key(&request.auth_key)?;
    if !plausible(&request.vault) {
        return Err(ApiError::Invalid(
            "a vault header no device could open".into(),
        ));
    }
    state
        .config
        .kdf_floor
        .check(&request.vault)
        .map_err(ApiError::Invalid)?;
    if request.vault.vault_id != auth.account.vault_id {
        // Changing the password does not change which vault this is. A header
        // for another vault would orphan every record in the account.
        return Err(ApiError::Invalid(
            "that header belongs to another vault".into(),
        ));
    }
    super::prove_password(&state, &auth, &current)?;
    let conn = state.db.lock();
    accounts::set_header(&conn, auth.account.id, &request.vault, &next)?;
    tracing::info!(account = %auth.account.id, "master password changed");
    Ok(StatusCode::NO_CONTENT)
}
