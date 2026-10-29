//! Signing in with UwUAuth, between the two requests it takes, and the ticket
//! it ends in. See `docs/sso.md`.
//!
//! Both live in memory only. A restart forgets them, which costs a person one
//! more click in the browser and nothing else: neither opens a vault.
//!
//! - A **login in progress** is keyed by its `state`, hashed, and holds what
//!   the second request has to match: the device's PKCE challenge, its
//!   loopback address, and this server's own verifier and nonce towards
//!   UwUAuth.
//! - A **ticket** is what a finished login gives the device: for a few
//!   minutes and one use, "this is UwUAuth's person so-and-so". It stands in
//!   for an invite or an enrolment token, never for the master password.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// How long a login may take in the browser.
pub const LOGIN_TTL_MS: u64 = 10 * 60 * 1000;

/// How long a ticket is good for once the browser is done.
pub const TICKET_TTL_MS: u64 = 5 * 60 * 1000;

/// Logins in progress at once, on the whole server. Each is a few hundred
/// bytes; the bound is there so nobody can make the server remember without
/// end. The oldest goes first.
pub const MAX_LOGINS: usize = 1024;

/// Tickets at once, likewise.
pub const MAX_TICKETS: usize = 1024;

/// Wrong master passwords with one ticket before it is gone: a ticket is not a
/// licence to guess, as an enrolment token is not.
pub const TICKET_TRIES: u32 = 5;

/// A login between `authorize` and `token`.
#[derive(Debug, Clone)]
pub struct Pending {
    /// The device's PKCE challenge, S256.
    pub challenge: String,
    /// Where the browser was sent back to: the device's loopback address.
    pub redirect_uri: String,
    /// This server's own PKCE verifier towards UwUAuth.
    pub verifier: String,
    pub nonce: String,
    /// The pairing it was started with: a login that outlives a new pairing
    /// is not finished against the new one.
    pub issuer: String,
    pub client_id: String,
    pub expires_ms: u64,
}

/// A finished login: who, until when, and how many wrong passwords it saw.
#[derive(Debug, Clone)]
struct Ticket {
    person: Uuid,
    expires_ms: u64,
    failures: u32,
}

#[derive(Default)]
struct Inner {
    logins: HashMap<[u8; 32], Pending>,
    tickets: HashMap<[u8; 32], Ticket>,
}

#[derive(Clone, Default)]
pub struct SsoStore {
    inner: Arc<Mutex<Inner>>,
}

fn key(secret: &str) -> [u8; 32] {
    crate::sha256(secret.as_bytes())
}

impl SsoStore {
    /// Keep a login under a fresh `state`, and hand the state back.
    pub fn begin(&self, pending: Pending, now: u64) -> String {
        let state = crate::b64::encode(crate::random_bytes::<32>());
        let mut inner = self.inner.lock();
        inner.logins.retain(|_, login| login.expires_ms > now);
        if inner.logins.len() >= MAX_LOGINS {
            if let Some(oldest) = inner
                .logins
                .iter()
                .min_by_key(|(_, login)| login.expires_ms)
                .map(|(key, _)| *key)
            {
                inner.logins.remove(&oldest);
            }
        }
        inner.logins.insert(key(&state), pending);
        state
    }

    /// The login under `state`, taken out: whatever happens next, a state is
    /// answered once.
    pub fn take(&self, state: &str, now: u64) -> Option<Pending> {
        let mut inner = self.inner.lock();
        inner
            .logins
            .remove(&key(state))
            .filter(|login| login.expires_ms > now)
    }

    /// A ticket for `person`, and when it runs out.
    pub fn issue(&self, person: Uuid, now: u64) -> (String, u64) {
        let ticket = crate::b64::encode(crate::random_bytes::<32>());
        let expires_ms = now + TICKET_TTL_MS;
        let mut inner = self.inner.lock();
        inner.tickets.retain(|_, ticket| ticket.expires_ms > now);
        if inner.tickets.len() >= MAX_TICKETS {
            if let Some(oldest) = inner
                .tickets
                .iter()
                .min_by_key(|(_, ticket)| ticket.expires_ms)
                .map(|(key, _)| *key)
            {
                inner.tickets.remove(&oldest);
            }
        }
        inner.tickets.insert(
            key(&ticket),
            Ticket {
                person,
                expires_ms,
                failures: 0,
            },
        );
        (ticket, expires_ms)
    }

    /// Whose ticket this is, without using it up.
    pub fn peek(&self, ticket: &str, now: u64) -> Option<Uuid> {
        if ticket.is_empty() || ticket.len() > 128 {
            return None;
        }
        let inner = self.inner.lock();
        inner
            .tickets
            .get(&key(ticket))
            .filter(|found| found.expires_ms > now)
            .map(|found| found.person)
    }

    /// Use a ticket up. Whose it was, if it was still there.
    pub fn spend(&self, ticket: &str, now: u64) -> Option<Uuid> {
        let mut inner = self.inner.lock();
        inner
            .tickets
            .remove(&key(ticket))
            .filter(|found| found.expires_ms > now)
            .map(|found| found.person)
    }

    /// A wrong master password with this ticket. Whether that used it up.
    pub fn failed(&self, ticket: &str) -> bool {
        let mut inner = self.inner.lock();
        let hashed = key(ticket);
        let Some(found) = inner.tickets.get_mut(&hashed) else {
            return true;
        };
        found.failures += 1;
        if found.failures >= TICKET_TRIES {
            inner.tickets.remove(&hashed);
            return true;
        }
        false
    }

    /// Every ticket of a person: UwUAuth just said they may not come in.
    pub fn forget_person(&self, person: Uuid) {
        self.inner
            .lock()
            .tickets
            .retain(|_, ticket| ticket.person != person);
    }

    /// Everything: the pairing went, or changed.
    pub fn clear(&self) {
        let mut inner = self.inner.lock();
        inner.logins.clear();
        inner.tickets.clear();
    }
}

/// A PKCE verifier or challenge as RFC 7636 has them: 43 to 128 characters of
/// the unreserved set.
pub fn pkce_shaped(text: &str) -> bool {
    (43..=128).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

/// The S256 challenge of a verifier.
pub fn s256(verifier: &str) -> String {
    crate::b64::encode(crate::sha256(verifier.as_bytes()))
}

/// The one place a device may have UwUAuth send the browser back to: its own
/// loopback listener, by address — never `localhost`, which a hosts file can
/// point elsewhere (RFC 8252 §8.3).
pub const CALLBACK_PATH: &str = "/uwusync/callback";

/// Whether `uri` is `http://127.0.0.1:<port>/uwusync/callback` and nothing else.
pub fn loopback_callback(uri: &str) -> bool {
    let Some(rest) = uri.strip_prefix("http://127.0.0.1:") else {
        return false;
    };
    let Some((port, path)) = rest.split_once('/') else {
        return false;
    };
    !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|port| port != 0)
        && format!("/{path}") == CALLBACK_PATH
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(expires_ms: u64) -> Pending {
        Pending {
            challenge: "c".repeat(43),
            redirect_uri: "http://127.0.0.1:4000/uwusync/callback".into(),
            verifier: "v".repeat(43),
            nonce: "n".into(),
            issuer: "https://auth.example.com".into(),
            client_id: "sync".into(),
            expires_ms,
        }
    }

    #[test]
    fn a_state_is_answered_once_and_only_in_time() {
        let store = SsoStore::default();
        let state = store.begin(pending(1_000), 0);
        assert!(store.take("other", 0).is_none());
        assert!(store.take(&state, 0).is_some());
        assert!(store.take(&state, 0).is_none(), "once");
        let late = store.begin(pending(1_000), 0);
        assert!(store.take(&late, 1_000).is_none(), "in time");
    }

    #[test]
    fn a_ticket_is_one_use_and_a_few_wrong_passwords() {
        let store = SsoStore::default();
        let person = Uuid::now_v7();
        let (ticket, expires) = store.issue(person, 0);
        assert_eq!(expires, TICKET_TTL_MS);
        assert_eq!(store.peek(&ticket, 0), Some(person));
        for _ in 1..TICKET_TRIES {
            assert!(!store.failed(&ticket));
        }
        assert!(store.failed(&ticket), "the last try uses it up");
        assert_eq!(store.peek(&ticket, 0), None);

        let (ticket, _) = store.issue(person, 0);
        assert_eq!(store.peek(&ticket, TICKET_TTL_MS), None, "ran out");
        assert_eq!(store.spend(&ticket, 1), Some(person));
        assert_eq!(store.spend(&ticket, 1), None);

        let (ticket, _) = store.issue(person, 0);
        store.forget_person(person);
        assert_eq!(store.peek(&ticket, 0), None);
    }

    #[test]
    fn the_store_stays_bounded() {
        let store = SsoStore::default();
        for at in 0..(MAX_LOGINS as u64 + 10) {
            store.begin(pending(10_000 + at), 0);
        }
        assert_eq!(store.inner.lock().logins.len(), MAX_LOGINS);
        for _ in 0..(MAX_TICKETS + 10) {
            store.issue(Uuid::now_v7(), 0);
        }
        assert_eq!(store.inner.lock().tickets.len(), MAX_TICKETS);
    }

    #[test]
    fn only_the_loopback_callback_is_taken() {
        assert!(loopback_callback("http://127.0.0.1:53124/uwusync/callback"));
        for wrong in [
            "http://localhost:53124/uwusync/callback",
            "https://127.0.0.1:53124/uwusync/callback",
            "http://127.0.0.1/uwusync/callback",
            "http://127.0.0.1:0/uwusync/callback",
            "http://127.0.0.1:99999/uwusync/callback",
            "http://127.0.0.1:53124/uwusync/callback?x=1",
            "http://127.0.0.1:53124/uwusync/callback#x",
            "http://127.0.0.1:53124/elsewhere",
            "http://127.0.0.1:53124@203.0.113.9/uwusync/callback",
            "http://127.0.0.1.example.com:1/uwusync/callback",
        ] {
            assert!(!loopback_callback(wrong), "{wrong}");
        }
    }

    #[test]
    fn pkce_is_rfc_7636() {
        // BASE64URL(SHA256(verifier)) without padding, as
        // `openssl dgst -sha256 -binary | base64` (URL alphabet) has it.
        assert_eq!(
            s256("dBjftJeZ4CVP-mB92K1uGbcdS6wDBqiAN6vbE6MDfL4"),
            "JHJs8stILK3XBJwIEP37z-URA-gVnXwWhYIrBfX2Kuw"
        );
        assert!(pkce_shaped("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
        assert!(!pkce_shaped("short"));
        assert!(!pkce_shaped(&"a/".repeat(30)));
    }
}
