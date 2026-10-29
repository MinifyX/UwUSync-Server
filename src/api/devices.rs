//! Devices: list them, let one in, shut one out.
//!
//! Joining is two secrets, not one. The **enrolment token** comes from a device
//! that is already in, through a channel this server cannot read — so the
//! server knows the join was approved. The **login key** comes from the master
//! password — so the server knows the person approving it is the owner. Either
//! one alone gets nowhere, which is what makes an intercepted pairing code
//! worthless.

use super::{auth_key, device_key, sso, who, Admitted, Peer};
use crate::auth::Authenticated;
use crate::db::{accounts, devices, invites};
use crate::limits;
use crate::state::AppState;
use crate::{ApiError, Result};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use uuid::Uuid;
use uwussh_proto::api::{DeviceSummary, RevokeDevice};

pub async fn list(
    auth: Authenticated,
    State(state): State<AppState>,
) -> Result<Json<Vec<DeviceSummary>>> {
    let conn = state.db.lock();
    Ok(Json(devices::list(&conn, auth.account.id)?))
}

pub use uwussh_proto::api::{EnrolDevice as EnrolRequest, EnrolmentToken as Enrolment};

/// A one-time token for a device about to join, made by a device that is
/// already in. It travels to the new device through the pairing channel, never
/// through this server in the clear.
pub async fn invite(auth: Authenticated, State(state): State<AppState>) -> Result<Json<Enrolment>> {
    state
        .limits
        .check_account(auth.account.id, &limits::JOINS)?;
    let conn = state.db.lock();
    let token = invites::create_enrolment(&conn, auth.account.id, auth.device.id)?;
    tracing::info!(account = %auth.account.id, device = %auth.device.id, "an enrolment token was made");
    Ok(Json(Enrolment {
        token,
        expires_ms: crate::now_ms() + invites::ENROLMENT_TTL_MS,
    }))
}

pub async fn enrol(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    request: Request,
) -> Result<Json<Admitted>> {
    let who = who(&state, &headers, peer);
    state.limits.check(&who, &limits::ENROL)?;
    let request: EnrolRequest = super::body(&state, request).await?;

    let key = auth_key(&request.auth_key)?;
    let device_key = device_key(&request.device)?;

    let conn = state.db.lock();
    let mut sso_join = None;
    // Look first, spend later: a mistyped password must not use up the token
    // the other device just showed on its screen. But only a few times — a
    // token is not a licence to guess the password with.
    let account = match &request.sso_ticket {
        // Signed in with UwUAuth: the ticket says who, the master password
        // still has to open the account — UwUAuth never knows it.
        Some(ticket) => {
            let now = state.clock.now_ms();
            let person = sso::ticket_person(&state, &conn, ticket, now)?;
            let account = person.account_id.ok_or(ApiError::Unauthorized)?;
            if let Err(error) = state.limits.check_account(account, &limits::SSO_JOINS) {
                tracing::warn!(%account, person = %person.id, "too many joins with UwUAuth; refused");
                return Err(error);
            }
            if !accounts::verify(&conn, account, &key)? {
                let spent = state.sso.failed(ticket);
                tracing::warn!(%account, spent, "a join with UwUAuth and the wrong master password");
                return Err(ApiError::Unauthorized);
            }
            if state.sso.spend(ticket, now) != Some(person.id) {
                return Err(ApiError::Unauthorized);
            }
            sso_join = Some(person.id);
            account
        }
        None => {
            let account = invites::peek_enrolment(&conn, &request.enrolment)?
                .ok_or(ApiError::Unauthorized)?;
            if !accounts::verify(&conn, account, &key)? {
                let spent = invites::enrolment_failed(&conn, &request.enrolment)?;
                tracing::warn!(%account, spent, "a join with the wrong master password");
                return Err(ApiError::Unauthorized);
            }
            if invites::redeem_enrolment(&conn, &request.enrolment)?.is_none() {
                return Err(ApiError::Unauthorized);
            }
            account
        }
    };
    let device = devices::add(&conn, account, &request.device.name, &device_key)?;
    drop(conn);

    state.limits.forgive(&who, &limits::ENROL);
    let (token, expires_ms) =
        state
            .sessions
            .issue(account, device.id, state.config.session_secs * 1000);
    match sso_join {
        // Audit trail: a device that came in with a UwUAuth sign-in rather
        // than one shown by a device already in.
        Some(person) => tracing::info!(
            %account, device = %device.id, %person,
            "a device joined with a UwUAuth sign-in"
        ),
        None => tracing::info!(%account, device = %device.id, "a device joined"),
    }
    Ok(Json(Admitted {
        account_id: account,
        device_id: device.id,
        token,
        expires_ms,
    }))
}

/// Shut a device out. It stops syncing at once — its tokens, its event
/// streams, the enrolment tokens and pairing sessions it made go with it — but
/// what it already holds, it holds: the client says so when you do this.
///
/// A device may take itself out with its token alone. Any other one takes the
/// master password as well, proved the way a password change proves it:
/// whoever holds a stolen laptop has its token, and must not be able to lock
/// the owner's other devices out one by one.
pub async fn revoke(
    auth: Authenticated,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<RevokeDevice>,
) -> Result<StatusCode> {
    if id != auth.device.id {
        let key = request
            .current_auth_key
            .as_deref()
            .ok_or(ApiError::WrongPassword)?;
        super::prove_password(&state, &auth, &auth_key(key)?)?;
    }

    let conn = state.db.lock();
    if devices::live_count(&conn, auth.account.id)? <= 1 {
        // An account with no device left is an account nobody can reach, and
        // the records in it would be unreachable rather than gone.
        return Err(ApiError::Invalid(
            "this is the only device left; add another one first".into(),
        ));
    }
    if !devices::revoke(&conn, auth.account.id, id)? {
        return Err(ApiError::NotFound);
    }
    let tokens = invites::drop_enrolments_of(&conn, id)?;
    drop(conn);

    state.sessions.drop_device(id);
    let pairings = state.pairings.close_opened_by(id);
    tracing::info!(
        account = %auth.account.id, device = %id, tokens, pairings,
        "device revoked"
    );
    Ok(StatusCode::NO_CONTENT)
}
