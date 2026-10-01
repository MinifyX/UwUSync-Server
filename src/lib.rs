//! UwUSync Server: the sync server behind UwUSSH and UwURDP.
//!
//! It is a **dumb, encrypted mailbox**. It hands out sequence numbers, keeps
//! the newest version of every record, pages through them from a cursor, and
//! refuses a write whose `base_seq` is not the version it holds. It cannot read
//! a record, so it cannot merge one either — everything clever happens on the
//! devices.
//!
//! What it does enforce needs no key: how large a record may be, how many fit
//! in one request, who may ask at all, and how often. Those are in [`limits`]
//! and [`auth`].
//!
//! The wire format, the clock and the conflict rule come from `uwussh-proto`,
//! the same crate the client uses. That is deliberate: a schema change is one
//! edit in one place instead of two that drift apart. The one exception is the
//! record kind, which [`wire`] takes as any name: a kind the clients add needs
//! no new server.

pub mod api;
pub mod auth;
pub mod config;
pub mod connections;
pub mod db;
pub mod error;
pub mod health;
pub mod limits;
pub mod pairing;
pub mod state;
pub mod tls;
pub mod updates;
pub mod wire;

pub use config::Config;
pub use error::{ApiError, Result};
pub use state::AppState;

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        .unwrap_or(0)
}

/// Base64 without padding, for everything that travels as text: keys,
/// verifiers, tokens, invite codes.
pub mod b64 {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    pub fn decode(text: &str) -> Option<Vec<u8>> {
        URL_SAFE_NO_PAD.decode(text.trim()).ok()
    }
}

/// The alphabet invite codes and pairing codes are written in: Crockford's
/// without the letters that look like digits, because a code gets read aloud
/// and typed in.
pub(crate) const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTVWXYZ23456789";

/// Random bytes from the operating system.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut bytes = [0u8; N];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// SHA-256, for the things the server stores instead of the secret itself:
/// the login verifier, invite codes, enrolment tokens.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}
