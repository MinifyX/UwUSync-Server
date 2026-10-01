//! Records as they travel, with the kind as a name the server does not have
//! to know.
//!
//! The JSON is exactly `uwussh-proto`'s — same fields, same base64, same
//! cursor — with one difference: `kind` is any short snake_case name, not
//! only one of the kinds the pinned protocol crate knows. The server cannot
//! read a record anyway; the kind is a label it keeps and hands back. So a
//! client that adds a kind (the command assistant's settings and answers in
//! UwUSSH 0.3, say) needs no new server to sync it.
//!
//! What a newer kind does need is a reader that can take it. Every build
//! before UwUSSH 0.3 fails on a whole page as soon as one record has a kind it
//! has never heard of, so who gets which kind is decided per pull by what the
//! client says it reads ([`Reader`]).

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use uuid::Uuid;
use uwussh_proto::{Accepted, EntityKind, Hlc, SyncCursor};

/// The longest kind name taken. The longest today is 16 characters.
const MAX_KIND_LEN: usize = 32;

/// A record's kind, as the name the wire carries (`host`, `assist_cache`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Kind(String);

impl Kind {
    pub const MANIFEST: &'static str = "manifest";
    /// The command assistant's settings (`EntityKind::AssistConfig`, 10).
    pub const ASSIST_CONFIG: &'static str = "assist_config";
    /// One slot of the command assistant's answer cache
    /// (`EntityKind::AssistCache`, 11).
    pub const ASSIST_CACHE: &'static str = "assist_cache";

    /// The kinds every client reads: those UwUSSH 0.2 knows, without the
    /// manifest, which has a flag of its own. Written out instead of taken
    /// from the protocol crate, so that a newer pin cannot quietly widen what
    /// old clients are sent.
    pub const EVERYONE: [&'static str; 9] = [
        "host",
        "group",
        "identity",
        "key",
        "snippet",
        "port_forward",
        "known_host",
        "terminal_profile",
        "secret",
    ];

    /// A kind by name, if it is shaped like one: a lowercase letter, then up
    /// to 31 more of lowercase letters, digits and underscores.
    pub fn parse(name: &str) -> Option<Self> {
        let mut bytes = name.bytes();
        let first = bytes.next()?;
        let shaped = name.len() <= MAX_KIND_LEN
            && first.is_ascii_lowercase()
            && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        shaped.then(|| Self(name.to_string()))
    }

    /// A kind as the database holds it: checked by [`Self::parse`] on the
    /// way in, or written by an older server from the protocol crate's names.
    pub(crate) fn stored(name: String) -> Self {
        Self(name)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether a client that reads what `reader` says may be sent this kind.
    ///
    /// The kinds of 0.2 go to everyone and manifests to whoever asks for them.
    /// Everything else — the assistant's kinds, and any kind added after
    /// them — only goes to clients that send `assist=1`: those skip a kind
    /// they do not know instead of failing the page.
    pub fn readable_by(&self, reader: Reader) -> bool {
        if Self::EVERYONE.contains(&self.as_str()) {
            true
        } else if self.0 == Self::MANIFEST {
            reader.manifests
        } else {
            reader.assist
        }
    }
}

impl From<EntityKind> for Kind {
    fn from(kind: EntityKind) -> Self {
        let name = serde_json::to_value(kind)
            .ok()
            .and_then(|value| value.as_str().map(str::to_string))
            .unwrap_or_default();
        Self(name)
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for Kind {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Kind {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let name = String::deserialize(d)?;
        Self::parse(&name).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "a record kind is a short snake_case name, not {name:?}"
            ))
        })
    }
}

/// What a pulling client says it can read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Reader {
    /// `manifests=1`: UwUSSH 0.2 and later.
    pub manifests: bool,
    /// `assist=1`: UwUSSH 0.3 and later, which also skips kinds it does not
    /// know.
    pub assist: bool,
}

impl Reader {
    /// A client that reads every kind there is.
    pub const ALL: Self = Self {
        manifests: true,
        assist: true,
    };
}

/// One sealed record, as `uwussh_proto::Envelope` with an open-ended kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub kind: Kind,
    pub updated_at: Hlc,
    #[serde(default)]
    pub base_seq: u64,
    #[serde(default)]
    pub deleted: bool,
    #[serde(with = "padded_base64")]
    pub nonce: Vec<u8>,
    #[serde(with = "padded_base64")]
    pub blob: Vec<u8>,
    #[serde(default)]
    pub seq: Option<u64>,
}

impl From<uwussh_proto::Envelope> for Envelope {
    fn from(envelope: uwussh_proto::Envelope) -> Self {
        Self {
            id: envelope.id,
            vault_id: envelope.vault_id,
            kind: envelope.kind.into(),
            updated_at: envelope.updated_at,
            base_seq: envelope.base_seq,
            deleted: envelope.deleted,
            nonce: envelope.nonce,
            blob: envelope.blob,
            seq: envelope.seq,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushRequest {
    pub schema: u32,
    pub envelopes: Vec<Envelope>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PushResponse {
    #[serde(default)]
    pub accepted: Vec<Accepted>,
    #[serde(default)]
    pub conflicts: Vec<Envelope>,
    pub cursor: SyncCursor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullResponse {
    pub envelopes: Vec<Envelope>,
    pub cursor: SyncCursor,
    pub has_more: bool,
}

/// Standard base64 with padding, as the protocol crate writes it. Reading is
/// as forgiving about padding and trailing bits as the protocol crate is.
mod padded_base64 {
    use super::*;

    const LENIENT: GeneralPurpose = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    );

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        LENIENT.decode(text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proto_envelope(kind: EntityKind) -> uwussh_proto::Envelope {
        uwussh_proto::Envelope {
            id: Uuid::now_v7(),
            vault_id: Uuid::now_v7(),
            kind,
            updated_at: Hlc::new(1_700_000_000_000, 3, 7),
            base_seq: 4,
            deleted: true,
            nonce: vec![7; 24],
            blob: vec![1, 2, 3, 4, 5],
            seq: Some(9),
        }
    }

    #[test]
    fn the_json_is_the_protocol_crates_both_ways() {
        for kind in EntityKind::ALL {
            let theirs = proto_envelope(kind);
            let ours = Envelope::from(theirs.clone());
            assert_eq!(
                serde_json::to_value(&ours).unwrap(),
                serde_json::to_value(&theirs).unwrap(),
                "{kind:?}"
            );
            let back: uwussh_proto::Envelope =
                serde_json::from_value(serde_json::to_value(&ours).unwrap()).unwrap();
            assert_eq!(back, theirs);
            let read: Envelope =
                serde_json::from_value(serde_json::to_value(&theirs).unwrap()).unwrap();
            assert_eq!(read, ours);
        }
    }

    #[test]
    fn a_kind_the_protocol_crate_does_not_know_is_kept_as_it_is() {
        let mut json = serde_json::to_value(proto_envelope(EntityKind::Host)).unwrap();
        json["kind"] = Kind::ASSIST_CACHE.into();
        let read: Envelope = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(read.kind.as_str(), "assist_cache");
        assert_eq!(serde_json::to_value(&read).unwrap(), json);
    }

    #[test]
    fn a_kind_is_a_short_snake_case_name_and_nothing_else() {
        for good in ["host", "assist_config", "k9", &"a".repeat(MAX_KIND_LEN)] {
            assert!(Kind::parse(good).is_some(), "{good}");
        }
        for bad in [
            "",
            "Host",
            "9lives",
            "_x",
            "a-b",
            "a b",
            "kïnd",
            &"a".repeat(MAX_KIND_LEN + 1),
        ] {
            assert!(Kind::parse(bad).is_none(), "{bad}");
            let mut json = serde_json::to_value(proto_envelope(EntityKind::Host)).unwrap();
            json["kind"] = bad.into();
            assert!(serde_json::from_value::<Envelope>(json).is_err(), "{bad}");
        }
    }

    #[test]
    fn who_reads_which_kind() {
        let old = Reader::default();
        let manifests = Reader {
            manifests: true,
            assist: false,
        };
        for name in Kind::EVERYONE {
            let kind = Kind::parse(name).unwrap();
            // Every one of them is a kind the pinned protocol knows.
            assert!(serde_json::from_value::<EntityKind>(name.into()).is_ok());
            assert!(kind.readable_by(old));
        }
        let manifest = Kind::from(EntityKind::Manifest);
        assert!(!manifest.readable_by(old));
        assert!(manifest.readable_by(manifests));
        for later in [Kind::ASSIST_CONFIG, Kind::ASSIST_CACHE, "hologram"] {
            let kind = Kind::parse(later).unwrap();
            assert!(!kind.readable_by(manifests), "{later}");
            assert!(kind.readable_by(Reader::ALL), "{later}");
        }
    }
}
