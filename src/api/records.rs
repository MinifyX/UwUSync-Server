//! The mailbox: take records, hand records back, and say when there is news.

use crate::auth::Authenticated;
use crate::connections::Holding;
use crate::db::{devices, records};
use crate::limits;
use crate::state::AppState;
use crate::wire::{PushRequest, PushResponse, Reader};
use crate::{ApiError, Result};
use axum::body::Body;
use axum::extract::{Query, Request, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_core::Stream;
use serde::Deserialize;
use std::convert::Infallible;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;
use tokio_stream::wrappers::ReceiverStream;
use uwussh_proto::{MAX_BATCH, SCHEMA_VERSION};

#[derive(Debug, Deserialize)]
pub struct PullQuery {
    #[serde(default)]
    pub since: u64,
    pub limit: Option<usize>,
    /// Set by clients that know manifests. One from before them fails to
    /// read a whole page with a record kind it has never heard of, so it
    /// gets none.
    /// Clients send `manifests=1`.
    #[serde(default)]
    pub manifests: u8,
    /// Set by clients that know the command assistant's kinds (UwUSSH 0.3).
    /// Those also skip a kind they have never heard of, so they get every
    /// kind there is; anyone else gets none of the assistant's. Clients send
    /// `assist=1`.
    #[serde(default)]
    pub assist: u8,
}

impl PullQuery {
    fn reader(&self) -> Reader {
        Reader {
            manifests: self.manifests != 0,
            assist: self.assist != 0,
        }
    }
}

/// Everything after a cursor. The device's own records come back too — it
/// costs one pass and lets a device check that what the server stored is what
/// it sent.
///
/// A page is up to 11 MiB, and it is held until the client has read it — so
/// it counts as one of the account's pulls until then, not only until it is
/// made.
pub async fn pull(
    auth: Authenticated,
    State(state): State<AppState>,
    Query(query): Query<PullQuery>,
) -> Result<Response> {
    state.limits.check_account(auth.account.id, &limits::PULL)?;
    let going = state.limits.start(auth.account.id, &limits::PULLS)?;
    let limit = query.limit.unwrap_or(MAX_BATCH).min(MAX_BATCH);
    let page = {
        let conn = state.db.lock();
        let page = records::pull(&conn, &auth.account, query.since, limit, query.reader())?;
        // How far this device has read decides what the server may forget —
        // so never further than there is: a device with a cursor from another
        // server, or from before a restore, must not let tombstones go it
        // never saw.
        devices::seen(&conn, auth.device.id, page.cursor.0.min(auth.account.seq))?;
        page
    };
    Ok(Json(page)
        .into_response()
        .map(|body| Body::new(Holding::new(body, going))))
}

/// Offer records. Counted before the body is read: it may be 16 MiB.
pub async fn push(
    auth: Authenticated,
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<PushResponse>> {
    state.limits.check_account(auth.account.id, &limits::PUSH)?;
    let _going = state.limits.start(auth.account.id, &limits::PUSHES)?;
    let request: PushRequest = super::body(&state, request).await?;
    if request.schema != SCHEMA_VERSION {
        return Err(ApiError::Schema {
            found: request.schema,
            known: SCHEMA_VERSION,
        });
    }

    let response = {
        let mut conn = state.db.lock();
        records::push_within(
            &mut conn,
            &auth.account,
            auth.device.id,
            &request.envelopes,
            state.config.quota,
        )?
    };
    if !response.accepted.is_empty() {
        state.events.announce(auth.account.id, response.cursor.0);
    }
    Ok(Json(response))
}

/// How often an open event stream asks whether its token is still good.
const RECHECK: Duration = Duration::from_secs(30);

/// "There is something new from sequence N." Nothing else is ever pushed out:
/// the device pulls, the same way it would have anyway. The event names no
/// kind, so it needs no filtering: a device woken for records it does not
/// read pulls a page without them, and the cursor still moves past them.
///
/// A stream lasts as long as the token it was opened with. Every half minute
/// it asks whether that token is still good, and ends when it is not — a
/// revoked device must not go on hearing when the account changes, and an
/// expired token is the device's cue to sign in again and reconnect.
pub async fn events(
    auth: Authenticated,
    State(state): State<AppState>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, Infallible>>>> {
    let guard = state
        .events
        .open_stream(auth.device.id)
        .ok_or(ApiError::RateLimited)?;
    let mut receiver = state.events.subscribe(auth.account.id);
    let (sender, stream) = tokio::sync::mpsc::channel(16);
    let token = auth.token;
    let device = auth.device.id;
    let state = state.clone();

    tokio::spawn(async move {
        let _open = guard;
        let mut recheck = tokio::time::interval(RECHECK);
        recheck.tick().await;
        loop {
            tokio::select! {
                news = receiver.recv() => match news {
                    Ok(seq) => {
                        let event = Event::default().event("records").data(seq.to_string());
                        if sender.send(Ok(event)).await.is_err() {
                            return;
                        }
                    }
                    // Missed a few: the next one says the same thing better.
                    Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => return,
                },
                _ = recheck.tick() => {
                    if sender.is_closed() || !still_in(&state, &token, device) {
                        return;
                    }
                }
            }
        }
    });

    // A keep-alive every half minute, so a proxy in between does not decide
    // the connection is idle and drop it.
    Ok(Sse::new(ReceiverStream::new(stream)).keep_alive(KeepAlive::new().interval(RECHECK)))
}

/// Whether a stream's token is still good and its device still in. Both: a
/// device revoked from the command line is revoked by another process, whose
/// word reaches this one through the database and not through its tokens.
fn still_in(state: &AppState, token: &str, device: uuid::Uuid) -> bool {
    state.sessions.get(token).is_some()
        && matches!(devices::get(&state.db.lock(), device), Ok(Some(found)) if !found.revoked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::authenticate;
    use crate::db::{accounts, Db};
    use crate::Config;
    use axum::http::HeaderMap;
    use axum::response::IntoResponse;

    /// A signed-in device and the headers it sends.
    fn signed_in(state: &AppState) -> (uuid::Uuid, HeaderMap) {
        let conn = state.db.lock();
        let account = accounts::create(&conn, &accounts::tests::header(), b"key").unwrap();
        let device = devices::add(&conn, account.id, "laptop", &[1; 32]).unwrap();
        drop(conn);
        let (token, _) = state.sessions.issue(account.id, device.id, 3_600_000);
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        (device.id, headers)
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_ends_once_its_device_is_shut_out() {
        let state = AppState::new(Db::open_in_memory().unwrap(), Config::default());
        let (device, headers) = signed_in(&state);
        let auth = authenticate(&state, &headers).unwrap();
        let body = events(auth, State(state.clone()))
            .await
            .unwrap()
            .into_response()
            .into_body();

        state.sessions.drop_device(device);
        // Time runs on by itself here: the stream notices at its next look.
        let ended = tokio::time::timeout(RECHECK * 3, axum::body::to_bytes(body, usize::MAX)).await;
        assert!(ended.is_ok(), "the stream of a revoked device ends");
        assert!(
            state.events.open_stream(device).is_some(),
            "and its place is free again"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_ends_when_its_device_is_revoked_from_elsewhere() {
        let state = AppState::new(Db::open_in_memory().unwrap(), Config::default());
        let (device, headers) = signed_in(&state);
        let auth = authenticate(&state, &headers).unwrap();
        let account = auth.account.id;
        let body = events(auth, State(state.clone()))
            .await
            .unwrap()
            .into_response()
            .into_body();
        // As `uwusync-server revoke` does it: the database, and no token.
        devices::revoke(&state.db.lock(), account, device).unwrap();
        let ended = tokio::time::timeout(RECHECK * 3, axum::body::to_bytes(body, usize::MAX)).await;
        assert!(ended.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_with_a_good_token_stays_open() {
        let state = AppState::new(Db::open_in_memory().unwrap(), Config::default());
        let (_, headers) = signed_in(&state);
        let auth = authenticate(&state, &headers).unwrap();
        let body = events(auth, State(state.clone()))
            .await
            .unwrap()
            .into_response()
            .into_body();
        let ended = tokio::time::timeout(RECHECK * 5, axum::body::to_bytes(body, usize::MAX)).await;
        assert!(ended.is_err(), "still open after several looks");
    }

    #[tokio::test]
    async fn a_page_counts_as_a_pull_until_it_has_been_read() {
        let state = AppState::new(Db::open_in_memory().unwrap(), Config::default());
        let (_, headers) = signed_in(&state);
        let ask = || {
            let auth = authenticate(&state, &headers).unwrap();
            let query = PullQuery {
                since: 0,
                limit: None,
                manifests: 1,
                assist: 1,
            };
            pull(auth, State(state.clone()), Query(query))
        };

        // Answered, and never read: each one is still held.
        let mut unread = Vec::new();
        for _ in 0..limits::PULLS.max {
            unread.push(ask().await.unwrap().into_body());
        }
        assert!(matches!(ask().await, Err(ApiError::RateLimited)));

        // One read to its end makes room, and so does one given up on.
        axum::body::to_bytes(unread.pop().unwrap(), usize::MAX)
            .await
            .unwrap();
        let another = ask().await.unwrap();
        assert!(matches!(ask().await, Err(ApiError::RateLimited)));
        drop(another);
        assert!(ask().await.is_ok());
    }

    /// A push as a client sends it, with a record of each kind named.
    async fn push_kinds(state: &AppState, headers: &HeaderMap, kinds: &[&str]) -> Response {
        let auth = authenticate(state, headers).unwrap();
        let envelopes: Vec<serde_json::Value> = kinds
            .iter()
            .map(|kind| {
                serde_json::json!({
                    "id": uuid::Uuid::now_v7(),
                    "vault_id": auth.account.vault_id,
                    "kind": kind,
                    "updated_at": uwussh_proto::Hlc::new(1_700_000_000_000, 0, 1),
                    // 24 bytes of nonce, three of sealed record.
                    "nonce": "A".repeat(32),
                    "blob": "AQID",
                })
            })
            .collect();
        let body = serde_json::json!({ "schema": SCHEMA_VERSION, "envelopes": envelopes });
        let request = Request::builder()
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        match push(auth, State(state.clone()), request).await {
            Ok(answer) => answer.into_response(),
            Err(error) => error.into_response(),
        }
    }

    async fn pull_as(state: &AppState, headers: &HeaderMap, since: u64, assist: u8) -> Vec<u8> {
        let auth = authenticate(state, headers).unwrap();
        let query = PullQuery {
            since,
            limit: None,
            manifests: 1,
            assist,
        };
        let body = pull(auth, State(state.clone()), Query(query))
            .await
            .unwrap()
            .into_body();
        axum::body::to_bytes(body, usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    #[tokio::test]
    async fn the_assistants_kinds_are_taken_and_held_back_from_old_clients() {
        let state = AppState::new(Db::open_in_memory().unwrap(), Config::default());
        let (_, headers) = signed_in(&state);
        let answer = push_kinds(
            &state,
            &headers,
            &["host", "assist_config", "assist_cache", "assist_cache"],
        )
        .await;
        assert_eq!(answer.status(), axum::http::StatusCode::OK);

        // UwUSSH 0.2 reads the page with the protocol crate as it is pinned
        // here — strictly, as 0.2 does — and gets the host and the end.
        let old: uwussh_proto::PullResponse =
            serde_json::from_slice(&pull_as(&state, &headers, 0, 0).await).unwrap();
        assert_eq!(old.envelopes.len(), 1);
        assert_eq!(old.envelopes[0].kind, uwussh_proto::EntityKind::Host);
        assert_eq!(old.cursor.0, 4);
        assert!(!old.has_more);

        // Synced before the assistant's records came: a page that is empty
        // and still moves the cursor to the end.
        let caught_up: uwussh_proto::PullResponse =
            serde_json::from_slice(&pull_as(&state, &headers, 1, 0).await).unwrap();
        assert!(caught_up.envelopes.is_empty());
        assert_eq!(caught_up.cursor.0, 4);

        // A client that asks gets every one, under its own kind.
        let new: crate::wire::PullResponse =
            serde_json::from_slice(&pull_as(&state, &headers, 0, 1).await).unwrap();
        let kinds: Vec<&str> = new.envelopes.iter().map(|env| env.kind.as_str()).collect();
        assert_eq!(
            kinds,
            ["host", "assist_config", "assist_cache", "assist_cache"]
        );
        assert_eq!(new.cursor.0, 4);
    }

    #[tokio::test]
    async fn a_kind_that_is_no_name_is_refused_and_nothing_is_stored() {
        let state = AppState::new(Db::open_in_memory().unwrap(), Config::default());
        let (_, headers) = signed_in(&state);
        let answer = push_kinds(&state, &headers, &["host", "Robert'); DROP TABLE"]).await;
        assert!(answer.status().is_client_error(), "{}", answer.status());
        let page: crate::wire::PullResponse =
            serde_json::from_slice(&pull_as(&state, &headers, 0, 1).await).unwrap();
        assert!(page.envelopes.is_empty());
        assert_eq!(page.cursor.0, 0);
    }
}
