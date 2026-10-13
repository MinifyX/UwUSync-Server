//! What goes wrong, and what the client is told about it.
//!
//! Two rules. The body carries a short machine-readable `error` and a sentence
//! for a log, never a stack trace and never anything about another account. And
//! nothing here distinguishes "no such account" from "wrong credential": a
//! server that answers differently is a server that answers questions nobody
//! asked.

use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

pub type Result<T> = std::result::Result<T, ApiError>;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    Invalid(String),
    #[error("not allowed")]
    Unauthorized,
    #[error("registration is closed on this server")]
    RegistrationClosed,
    /// A proof of the master password that did not check out, from a device
    /// that is signed in. Not 401: that means "sign in again", and a device
    /// would do exactly that and ask a second time.
    #[error("that is not the master password")]
    WrongPassword,
    #[error("this server has as many accounts as it takes")]
    ServerFull,
    #[error("no such thing")]
    NotFound,
    #[error("too large: {0}")]
    TooLarge(String),
    #[error("too many requests, try again later")]
    RateLimited,
    #[error("this server speaks schema {known}, not {found}")]
    Schema { found: u32, known: u32 },
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("{0}")]
    Internal(String),
    /// A body that is not what the endpoint takes, read after its limits were
    /// checked — answered the way axum's own extractor answers it.
    #[error("{0}")]
    Body(#[from] JsonRejection),
    /// Something a team does not allow. See [`TeamError`].
    #[error("{0}")]
    Team(#[from] TeamError),
}

/// What a team refuses, each with a name of its own: a client decides by the
/// name what to do next — ask again with the epoch it was told, pull first,
/// show the person that they are still waiting to be let in.
///
/// A team somebody is no member of is not in here. That is `not-found`,
/// whether there is such a team or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TeamError {
    #[error("teams are switched off on this server")]
    Disabled,
    #[error("this server lets nobody create a team")]
    CreationClosed,
    #[error("your role in this team does not allow that")]
    Forbidden,
    #[error("your membership has not been confirmed yet")]
    Pending,
    #[error("that code is not valid, or not any more")]
    InvalidInvite,
    #[error("this account is in as many teams as this server allows")]
    TeamLimit,
    #[error("this team has as many members as this server allows")]
    TeamFull,
    #[error("this team has as many open invites as it may; revoke one first")]
    TooManyInvites,
    #[error("this account has no team identity yet")]
    NoIdentity,
    #[error("this account has a team identity already")]
    IdentityExists,
    #[error("the member's team identity is not the one that was named")]
    IdentityChanged,
    #[error("this account is in the team already")]
    AlreadyMember,
    #[error("a team keeps at least one owner")]
    LastOwner,
    #[error("the keys do not name exactly the active members")]
    MembersMismatch,
    #[error("there are records newer than the cursor that was named")]
    StaleCursor,
    #[error("that member is not waiting to be confirmed")]
    NotPending,
    #[error("that member has not been confirmed yet")]
    NotActive,
    /// With the epoch the team is at, so the client need not ask.
    #[error("the team is at epoch {current}")]
    StaleEpoch { current: u64 },
}

impl TeamError {
    fn code(&self) -> (StatusCode, &'static str) {
        use StatusCode as S;
        match self {
            Self::Disabled => (S::FORBIDDEN, "teams-disabled"),
            Self::CreationClosed => (S::FORBIDDEN, "team-creation-closed"),
            Self::Forbidden => (S::FORBIDDEN, "forbidden"),
            Self::Pending => (S::FORBIDDEN, "membership-pending"),
            Self::InvalidInvite => (S::FORBIDDEN, "invalid-invite"),
            Self::TeamLimit => (S::FORBIDDEN, "team-limit"),
            Self::TeamFull => (S::FORBIDDEN, "team-full"),
            Self::TooManyInvites => (S::FORBIDDEN, "too-many-invites"),
            Self::NoIdentity => (S::CONFLICT, "no-identity"),
            Self::IdentityExists => (S::CONFLICT, "identity-exists"),
            Self::IdentityChanged => (S::CONFLICT, "identity-changed"),
            Self::AlreadyMember => (S::CONFLICT, "already-member"),
            Self::LastOwner => (S::CONFLICT, "last-owner"),
            Self::MembersMismatch => (S::CONFLICT, "members-mismatch"),
            Self::StaleCursor => (S::CONFLICT, "stale-cursor"),
            Self::NotPending => (S::CONFLICT, "not-pending"),
            Self::NotActive => (S::CONFLICT, "not-active"),
            Self::StaleEpoch { .. } => (S::CONFLICT, "stale-epoch"),
        }
    }
}

#[derive(Serialize)]
struct Body {
    error: &'static str,
    message: String,
    /// Only with `stale-epoch`: the epoch the team is at.
    #[serde(skip_serializing_if = "Option::is_none")]
    epoch: Option<u64>,
}

impl ApiError {
    fn code(&self) -> (StatusCode, &'static str) {
        match self {
            Self::Invalid(_) => (StatusCode::BAD_REQUEST, "invalid"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::RegistrationClosed => (StatusCode::FORBIDDEN, "registration-closed"),
            Self::WrongPassword => (StatusCode::FORBIDDEN, "wrong-password"),
            Self::ServerFull => (StatusCode::FORBIDDEN, "server-full"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not-found"),
            Self::TooLarge(_) => (StatusCode::PAYLOAD_TOO_LARGE, "too-large"),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate-limited"),
            Self::Schema { .. } => (StatusCode::BAD_REQUEST, "schema"),
            Self::Database(_) | Self::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
            Self::Body(rejection) => (rejection.status(), "invalid"),
            Self::Team(refusal) => refusal.code(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Self::Body(rejection) = self {
            return rejection.into_response();
        }
        let (status, error) = self.code();
        // What went wrong inside stays inside: it goes to the log, and the
        // client gets the kind of error, not the detail.
        let message = match &self {
            Self::Database(inner) => {
                tracing::error!(%inner, "database error");
                "something went wrong".to_string()
            }
            Self::Internal(inner) => {
                tracing::error!(%inner, "internal error");
                "something went wrong".to_string()
            }
            other => other.to_string(),
        };
        let epoch = match &self {
            Self::Team(TeamError::StaleEpoch { current }) => Some(*current),
            _ => None,
        };
        let body = Body {
            error,
            message,
            epoch,
        };
        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_internal_reaches_the_client() {
        let error = ApiError::Database(rusqlite::Error::QueryReturnedNoRows);
        let (status, code) = error.code();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(code, "internal");
    }

    #[test]
    fn a_wrong_credential_and_a_missing_account_look_the_same() {
        // Both paths end in `Unauthorized`; there is no variant that says
        // "this account exists, the secret was wrong".
        let (status, code) = ApiError::Unauthorized.code();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(code, "unauthorized");
    }
}
