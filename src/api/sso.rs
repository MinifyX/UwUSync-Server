//! Signing in with UwUAuth, and what this server says about itself to the
//! suite. See `docs/sso.md`.
//!
//! The device does the browser part: it listens on its own loopback address,
//! opens the system browser at the address [`authorize`] hands it, and brings
//! back what UwUAuth sent there. This server is the OpenID Connect client —
//! it holds the client secret, exchanges the code, and checks the ID token.
//! What the device gets is a ticket: for a few minutes and one use, "this is
//! UwUAuth's person so-and-so", which stands in for an invite or an
//! enrolment token. The master password still opens the vault, and only the
//! device ever knows it.
//!
//! Two PKCE pairs are in play. The device's, between it and this server, so
//! only the device that started a login can finish it. And this server's own,
//! towards UwUAuth, as any confidential client would.

use super::{who, Peer};
use crate::db::{accounts, sso as people};
use crate::oidc::{self, ClientAuth, Expected, Refused};
use crate::sso::{self as store, Pending};
use crate::state::AppState;
use crate::{b64, limits, ApiError, Result};
use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::Json;
use serde_json::{json, Map, Value};
use uwussh_proto::api::{SsoFinish, SsoStart, SsoStarted, SsoTicket};

/// The scopes this server asks UwUAuth for: who, and their name and address.
pub const SCOPES: &str = "openid email profile";

/// Longer than this, a `code` from UwUAuth is not one.
const MAX_CODE: usize = 2048;

/// The pairing, or "not here".
fn pairing(state: &AppState) -> Result<people::Pairing> {
    people::pairing(&state.db.lock())?.ok_or(ApiError::SsoOff)
}

/// Where to send the browser.
pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    request: Request,
) -> Result<Json<SsoStarted>> {
    let who = who(&state, &headers, peer);
    state.limits.check(&who, &limits::SSO)?;
    let request: SsoStart = super::body(&state, request).await?;
    if !store::loopback_callback(&request.redirect_uri) {
        return Err(ApiError::Invalid(format!(
            "the redirect has to be http://127.0.0.1:<port>{}",
            store::CALLBACK_PATH
        )));
    }
    if !store::pkce_shaped(&request.code_challenge) || request.code_challenge.len() != 43 {
        return Err(ApiError::Invalid("an S256 code challenge".into()));
    }
    let pairing = pairing(&state)?;
    let discovery = oidc::discover(&state.oidc, &pairing.issuer)
        .await
        .map_err(|error| upstream("UwUAuth's discovery document", error))?;

    let verifier = b64::encode(crate::random_bytes::<32>());
    let nonce = b64::encode(crate::random_bytes::<16>());
    let now = state.clock.now_ms();
    let expires_ms = now + store::LOGIN_TTL_MS;
    let login_state = state.sso.begin(
        Pending {
            challenge: request.code_challenge,
            redirect_uri: request.redirect_uri.clone(),
            verifier: verifier.clone(),
            nonce: nonce.clone(),
            issuer: pairing.issuer.clone(),
            generation: pairing.generation(),
            expires_ms,
        },
        now,
    );
    let query = [
        ("response_type", "code"),
        ("client_id", pairing.client_id.as_str()),
        ("redirect_uri", request.redirect_uri.as_str()),
        ("scope", SCOPES),
        ("state", login_state.as_str()),
        ("nonce", nonce.as_str()),
        ("code_challenge", store::s256(&verifier).as_str()),
        ("code_challenge_method", "S256"),
    ]
    .iter()
    .map(|(key, value)| format!("{key}={}", oidc::form_encode(value)))
    .collect::<Vec<_>>()
    .join("&");
    let endpoint = &discovery.authorization_endpoint;
    let separator = if endpoint.contains('?') { '&' } else { '?' };
    Ok(Json(SsoStarted {
        url: format!("{endpoint}{separator}{query}"),
        state: login_state,
        expires_ms,
    }))
}

/// What came back to the device's loopback address, for a ticket.
pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Peer,
    request: Request,
) -> Result<Json<SsoTicket>> {
    let who = who(&state, &headers, peer);
    state.limits.check(&who, &limits::SSO)?;
    let request: SsoFinish = super::body(&state, request).await?;
    let now = state.clock.now_ms();

    // Taken out once the device's PKCE verifier matches, and then whatever
    // happens next: a state is answered once. A wrong verifier leaves the
    // login to the device that holds the right one.
    let verified = |login: &store::Pending| {
        store::pkce_shaped(&request.code_verifier)
            && crate::db::constant_time_eq(
                store::s256(&request.code_verifier).as_bytes(),
                login.challenge.as_bytes(),
            )
    };
    let login = state
        .sso
        .take_if(&request.state, now, verified)
        .ok_or(ApiError::Unauthorized)?;
    if request.code.is_empty() || request.code.len() > MAX_CODE {
        return Err(ApiError::Invalid("a code from UwUAuth".into()));
    }
    let pairing = pairing(&state)?;
    if pairing.issuer != login.issuer || pairing.generation() != login.generation {
        // Paired anew while the browser was open.
        return Err(ApiError::Unauthorized);
    }
    // RFC 9207: an answer that names its issuer has to name this one, or it
    // came from somewhere else.
    if let Some(iss) = &request.iss {
        if iss.trim_end_matches('/') != pairing.issuer.trim_end_matches('/') {
            return Err(ApiError::Unauthorized);
        }
    }

    let discovery = oidc::discover(&state.oidc, &pairing.issuer)
        .await
        .map_err(|error| upstream("UwUAuth's discovery document", error))?;
    let answer = oidc::exchange(
        &discovery,
        &ClientAuth {
            client_id: &pairing.client_id,
            client_secret: Some(&pairing.client_secret),
        },
        &request.code,
        &login.redirect_uri,
        Some(&login.verifier),
    )
    .await
    .map_err(|error| {
        tracing::warn!(%error, "UwUAuth did not take a code");
        ApiError::Unauthorized
    })?;
    let id_token = answer
        .id_token
        .ok_or_else(|| ApiError::Upstream("UwUAuth answered without an ID token".into()))?;
    let expected = Expected {
        issuer: &pairing.issuer,
        client_id: &pairing.client_id,
        nonce: &login.nonce,
    };
    let seconds = (crate::now_ms() / 1000) as i64;
    let keys = oidc::keys(&state.oidc, &discovery, false)
        .await
        .map_err(|error| upstream("UwUAuth's keys", error))?;
    let claims = match oidc::check_id_token(&id_token, &keys, &expected, seconds) {
        Err(Refused::UnknownKey) => {
            // UwUAuth may have a new key since the last fetch.
            let keys = oidc::keys(&state.oidc, &discovery, true)
                .await
                .map_err(|error| upstream("UwUAuth's keys", error))?;
            oidc::check_id_token(&id_token, &keys, &expected, seconds)
        }
        other => other,
    }
    .map_err(|refused| {
        tracing::warn!(?refused, "an ID token from UwUAuth was refused");
        ApiError::Unauthorized
    })?;

    let person = person_for(&state, &pairing.issuer, &claims)?;
    let (ticket, expires_ms) = state.sso.issue(person.id, &pairing.generation(), now);
    let needs_account_key = match person.account_id {
        Some(account) => accounts::header(&state.db.lock(), account)?
            .map(|header| header.needs_account_key)
            .unwrap_or(false),
        None => false,
    };
    tracing::info!(person = %person.id, has_account = person.account_id.is_some(), "signed in with UwUAuth");
    Ok(Json(SsoTicket {
        ticket,
        expires_ms,
        has_account: person.account_id.is_some(),
        needs_account_key,
        display_name: person.display_name,
        user_name: Some(person.user_name),
    }))
}

/// The person an ID token names, kept or updated — or refused, when UwUAuth
/// has said they may not come in.
fn person_for(
    state: &AppState,
    issuer: &str,
    claims: &Map<String, Value>,
) -> Result<people::SsoUser> {
    let text = |name: &str| {
        claims
            .get(name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty() && value.len() <= 256)
            .map(str::to_string)
    };
    let subject = text("sub").ok_or(ApiError::Unauthorized)?;
    // An address only names someone once the issuer vouches for it.
    let email = if claims.get("email_verified") == Some(&Value::Bool(true)) {
        text("email")
    } else {
        None
    };
    let user_name = email
        .or_else(|| text("preferred_username"))
        .unwrap_or_else(|| subject.clone());
    let display_name = text("name");
    let conn = state.db.lock();
    match people::by_subject(&conn, issuer, &subject)? {
        Some(person) if !person.active => Err(ApiError::Disabled),
        Some(mut person) => {
            if person.user_name != user_name || person.display_name != display_name {
                person.user_name = user_name;
                person.display_name = display_name;
                people::update(&conn, &person)?;
            }
            Ok(person)
        }
        // Not pushed over SCIM (yet): UwUAuth let them sign in to this app,
        // which is what it decides.
        None => Ok(people::insert(
            &conn,
            issuer,
            &subject,
            &user_name,
            display_name.as_deref(),
            true,
        )?),
    }
}

fn upstream(what: &str, error: String) -> ApiError {
    tracing::warn!(%error, "{what}");
    ApiError::Upstream(format!("{what} could not be fetched"))
}

/// Who this is, for UwUAuth and for a device that is about to connect:
/// whether there is signing in with UwUAuth here.
pub async fn server(State(state): State<AppState>) -> Result<Json<Value>> {
    Ok(Json(server_info(&state)?))
}

fn server_info(state: &AppState) -> Result<Value> {
    let paired = people::pairing(&state.db.lock())?;
    Ok(json!({
        "product": "UwUSync",
        "version": env!("CARGO_PKG_VERSION"),
        "url": state.config.base_url(),
        "schema": uwussh_proto::SCHEMA_VERSION,
        "sso": paired.is_some(),
        "scim": paired.as_ref().is_some_and(|paired| paired.scim_token_hash.is_some()),
    }))
}

/// The suite's discovery document: which UwU servers are here, and the
/// UwUAuth this one signs in with.
pub async fn well_known(State(state): State<AppState>) -> Result<Json<Value>> {
    let info = server_info(&state)?;
    let mut servers = vec![json!({
        "product": "UwUSync",
        "url": state.config.base_url(),
        "info": "/uwu/v1/server",
    })];
    if let Some(paired) = people::pairing(&state.db.lock())? {
        servers.push(json!({
            "product": "UwUAuth",
            "url": paired.url,
            "issuer": paired.issuer,
        }));
    }
    Ok(Json(json!({
        "uwusuite": 1,
        "servers": servers,
        "sso": info["sso"],
    })))
}

/// The person a ticket names, if it still does: there, still let in by
/// UwUAuth, and from the UwUAuth this server is paired with now. The ticket
/// is not used up by this.
pub fn ticket_person(
    state: &AppState,
    conn: &rusqlite::Connection,
    ticket: &str,
    now: u64,
) -> Result<people::SsoUser> {
    let paired = people::pairing(conn)?.ok_or(ApiError::SsoOff)?;
    let id = state
        .sso
        .peek(ticket, &paired.generation(), now)
        .ok_or(ApiError::Unauthorized)?;
    let person = people::by_id(conn, id)?.ok_or(ApiError::Unauthorized)?;
    if person.issuer != paired.issuer {
        return Err(ApiError::Unauthorized);
    }
    if !person.active {
        state.sso.forget_person(person.id);
        return Err(ApiError::Disabled);
    }
    Ok(person)
}
