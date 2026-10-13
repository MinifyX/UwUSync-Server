//! Everything the server reads from its environment, and nothing else.
//!
//! No config file: a container gets its settings from environment variables,
//! and a setting that lives in two places is a setting that disagrees with
//! itself.

use std::net::SocketAddr;
use std::path::PathBuf;

/// Whether the server brings its own certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// Make one, keep the key, and say what its fingerprint is. The client
    /// pins that, the way it pins an SSH host key.
    Auto,
    /// Speak plain HTTP, because something in front does the TLS.
    Off,
}

impl TlsMode {
    fn parse(value: &str) -> Option<Self> {
        Some(match value.trim().to_ascii_lowercase().as_str() {
            "auto" | "on" | "1" | "true" => Self::Auto,
            "off" | "0" | "false" | "proxy" => Self::Off,
            _ => return None,
        })
    }
}

/// Who may create an account on this server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registration {
    /// Anyone who can reach the server. For a server on a tailnet, say.
    Open,
    /// Only with a code from `uwusync-server invite`. The default, and what the
    /// first start prints one of.
    Invite,
    /// Nobody. For a server whose devices are all enrolled.
    Closed,
}

impl Registration {
    fn parse(value: &str) -> Option<Self> {
        Some(match value.trim().to_ascii_lowercase().as_str() {
            "open" => Self::Open,
            "invite" => Self::Invite,
            "closed" => Self::Closed,
            _ => return None,
        })
    }
}

/// Who may start a team on this server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeamCreation {
    /// Every account. The default.
    All,
    /// Nobody: the teams there are stay, and no new one comes.
    None,
}

impl TeamCreation {
    fn parse(value: &str) -> Option<Self> {
        Some(match value.trim().to_ascii_lowercase().as_str() {
            "all" => Self::All,
            "none" => Self::None,
            _ => return None,
        })
    }
}

/// The most members any setting lets a team have. A rotation names every one
/// of them in one request.
pub const TEAM_MEMBERS_CEILING: u64 = 1000;

/// What the operator decides about teams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Teams {
    /// Off: every team endpoint but the one that says so refuses. What teams
    /// hold stays in the database, untouched, until they are switched on
    /// again or deleted from the command line.
    pub enabled: bool,
    pub creation: TeamCreation,
    /// Teams one account may be in, counting those it only waits to be let
    /// into.
    pub max_per_account: u64,
    /// Members one team may have, counting those who wait.
    pub max_members: u64,
}

impl Default for Teams {
    fn default() -> Self {
        Self {
            enabled: true,
            creation: TeamCreation::All,
            max_per_account: 10,
            max_members: 50,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Where the database and, later, the certificate live. One volume.
    pub data_dir: PathBuf,
    pub listen: SocketAddr,
    /// How devices reach this server — `nas.lan:8443`. The server cannot know
    /// it (it listens on every address), and it goes into the setup code, so
    /// a server behind a name or a proxy is told.
    pub public: Option<String>,
    pub registration: Registration,
    pub tls: TlsMode,
    /// Trust `X-Forwarded-For` for the address rate limits are counted per.
    /// Only ever true behind a proxy that sets it, or anyone can pretend to be
    /// someone else.
    pub trust_forwarded: bool,
    /// How long a device's session token lives before it signs again.
    pub session_secs: u64,
    /// Ask GitHub once a day whether there is a newer release, and say so in
    /// the log. The only connection the server opens on its own.
    pub update_check: bool,
    /// The image tag this machine follows (`latest`, `beta`, `edge` or a
    /// version), which decides what counts as an update.
    pub channel: Option<String>,
    /// How many accounts this server takes, whoever asks.
    pub max_accounts: u64,
    /// What one account may hold — and one team, which gets the same — and
    /// what all of them together may.
    pub quota: crate::db::records::Quota,
    pub teams: Teams,
    /// Connections open at once, from everybody.
    pub max_connections: usize,
    /// Connections open at once from one address (an IPv6 /64 counts as one).
    /// Zero for no limit. Not applied behind a proxy, where every connection
    /// comes from the proxy.
    pub max_connections_per_address: usize,
    /// The cheapest key derivation a vault header may ask for. Not read from
    /// the environment: a floor an operator can lower is one a mistake lowers
    /// too. Tests lower it, because they derive keys by the dozen.
    pub kdf_floor: crate::db::accounts::KdfFloor,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            listen: "0.0.0.0:8443".parse().expect("a literal address"),
            public: None,
            registration: Registration::Invite,
            tls: TlsMode::Auto,
            trust_forwarded: false,
            session_secs: 60 * 60,
            update_check: true,
            channel: None,
            max_accounts: 100,
            quota: crate::db::records::Quota::default(),
            teams: Teams::default(),
            max_connections: 512,
            max_connections_per_address: 32,
            kdf_floor: crate::db::accounts::KdfFloor::default(),
        }
    }
}

impl Config {
    /// Read the environment. A variable that is set but unusable is an error
    /// rather than a default quietly taking over — a server that listens
    /// somewhere else than asked is worse than one that refuses to start.
    pub fn from_env() -> Result<Self, String> {
        let mut config = Config::default();

        if let Some(dir) = var("UWUSYNC_DATA") {
            config.data_dir = PathBuf::from(dir);
        }
        if let Some(listen) = var("UWUSYNC_LISTEN") {
            config.listen = listen
                .parse()
                .map_err(|_| format!("UWUSYNC_LISTEN is not an address: {listen}"))?;
        }
        config.public = var("UWUSYNC_PUBLIC");
        if let Some(registration) = var("UWUSYNC_REGISTRATION") {
            config.registration = Registration::parse(&registration).ok_or_else(|| {
                format!("UWUSYNC_REGISTRATION must be open, invite or closed: {registration}")
            })?;
        }
        if let Some(tls) = var("UWUSYNC_TLS") {
            config.tls = TlsMode::parse(&tls)
                .ok_or_else(|| format!("UWUSYNC_TLS must be auto or off: {tls}"))?;
        }
        if let Some(trust) = var("UWUSYNC_TRUST_FORWARDED") {
            config.trust_forwarded = switch(&trust)
                .ok_or_else(|| format!("UWUSYNC_TRUST_FORWARDED must be on or off: {trust}"))?;
        }
        if let Some(secs) = var("UWUSYNC_SESSION_SECS") {
            config.session_secs = secs
                .parse()
                .map_err(|_| format!("UWUSYNC_SESSION_SECS is not a number: {secs}"))?;
        }
        if let Some(check) = var("UWUSYNC_UPDATE_CHECK") {
            config.update_check = switch(&check)
                .ok_or_else(|| format!("UWUSYNC_UPDATE_CHECK must be on or off: {check}"))?;
        }
        config.channel = var("UWUSYNC_CHANNEL");
        if let Some(max) = var("UWUSYNC_MAX_ACCOUNTS") {
            config.max_accounts = number("UWUSYNC_MAX_ACCOUNTS", &max)?;
        }
        if let Some(records) = var("UWUSYNC_ACCOUNT_MAX_RECORDS") {
            config.quota.records = number("UWUSYNC_ACCOUNT_MAX_RECORDS", &records)?;
        }
        if let Some(megabytes) = var("UWUSYNC_ACCOUNT_MAX_MB") {
            config.quota.bytes = number("UWUSYNC_ACCOUNT_MAX_MB", &megabytes)?
                .checked_mul(1024 * 1024)
                .ok_or("UWUSYNC_ACCOUNT_MAX_MB is more than any disk")?;
        }
        if let Some(megabytes) = var("UWUSYNC_SERVER_MAX_MB") {
            config.quota.server_bytes = number("UWUSYNC_SERVER_MAX_MB", &megabytes)?
                .checked_mul(1024 * 1024)
                .ok_or("UWUSYNC_SERVER_MAX_MB is more than any disk")?;
        }
        if let Some(teams) = var("UWUSYNC_TEAMS") {
            config.teams.enabled = switch(&teams)
                .ok_or_else(|| format!("UWUSYNC_TEAMS must be on or off: {teams}"))?;
        }
        if let Some(creation) = var("UWUSYNC_TEAM_CREATION") {
            config.teams.creation = TeamCreation::parse(&creation)
                .ok_or_else(|| format!("UWUSYNC_TEAM_CREATION must be all or none: {creation}"))?;
        }
        if let Some(max) = var("UWUSYNC_MAX_TEAMS_PER_ACCOUNT") {
            config.teams.max_per_account = number("UWUSYNC_MAX_TEAMS_PER_ACCOUNT", &max)?;
        }
        if let Some(max) = var("UWUSYNC_MAX_TEAM_MEMBERS") {
            config.teams.max_members = number("UWUSYNC_MAX_TEAM_MEMBERS", &max)?;
            if config.teams.max_members == 0 || config.teams.max_members > TEAM_MEMBERS_CEILING {
                return Err(format!(
                    "UWUSYNC_MAX_TEAM_MEMBERS must be between 1 and {TEAM_MEMBERS_CEILING}: {max}"
                ));
            }
        }
        if let Some(max) = var("UWUSYNC_MAX_CONNECTIONS") {
            config.max_connections = number("UWUSYNC_MAX_CONNECTIONS", &max)? as usize;
            if config.max_connections == 0 {
                return Err("UWUSYNC_MAX_CONNECTIONS of 0 would let nobody in".into());
            }
        }
        if let Some(max) = var("UWUSYNC_MAX_CONNECTIONS_PER_IP") {
            config.max_connections_per_address =
                number("UWUSYNC_MAX_CONNECTIONS_PER_IP", &max)? as usize;
        }
        Ok(config)
    }

    /// `uwusync.db` — or `uwussh.db`, from before the server was called
    /// UwUSync, when that is the one there is. It keeps that name rather than
    /// being renamed: a rollback to a version from before would not find it
    /// under the new one, and start again empty.
    pub fn database(&self) -> PathBuf {
        let current = self.data_dir.join("uwusync.db");
        let legacy = self.data_dir.join("uwussh.db");
        if !current.exists() && legacy.exists() {
            legacy
        } else {
            current
        }
    }

    pub fn backups(&self) -> PathBuf {
        self.data_dir.join("backups")
    }

    /// How a device writes this server down: the scheme follows whether the
    /// server does its own TLS, unless the address already says.
    pub fn base_url(&self) -> String {
        let scheme = match self.tls {
            TlsMode::Auto => "https",
            TlsMode::Off => "http",
        };
        match &self.public {
            Some(public) if public.contains("://") => public.trim_end_matches('/').to_string(),
            Some(public) => format!("{scheme}://{public}"),
            None => format!("{scheme}://{}", self.listen),
        }
    }
}

/// A setting, under its name — or under the one it had while the server was
/// UwUSSH Server (`UWUSSH_` for `UWUSYNC_`), so an `.env` from then still
/// counts. The new name wins where both are set.
fn var(name: &str) -> Option<String> {
    let read = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    read(name).or_else(|| read(&legacy_name(name)?))
}

const LEGACY_PREFIX: &str = "UWUSSH_";

fn legacy_name(name: &str) -> Option<String> {
    name.strip_prefix("UWUSYNC_")
        .map(|rest| format!("{LEGACY_PREFIX}{rest}"))
}

/// The settings that are only set under their old `UWUSSH_` name, for a
/// word in the log that they have a new one.
pub fn legacy_variables() -> Vec<String> {
    let mut names: Vec<String> = std::env::vars_os()
        .filter_map(|(name, _)| name.into_string().ok())
        .filter(|name| {
            name.strip_prefix(LEGACY_PREFIX)
                .is_some_and(|rest| std::env::var_os(format!("UWUSYNC_{rest}")).is_none())
        })
        .collect();
    names.sort();
    names
}

fn number(name: &str, value: &str) -> Result<u64, String> {
    value
        .trim()
        .parse()
        .map_err(|_| format!("{name} is not a number: {value}"))
}

fn switch(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "on" | "1" | "true" | "yes" => Some(true),
        "off" | "0" | "false" | "no" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_the_documented_ones() {
        let config = Config::default();
        assert_eq!(config.listen.port(), 8443);
        assert_eq!(config.registration, Registration::Invite);
        assert_eq!(config.tls, TlsMode::Auto, "secure without being asked");
        assert!(!config.trust_forwarded, "off unless a proxy is in front");
        assert!(config.update_check);
        assert_eq!(config.database().file_name().unwrap(), "uwusync.db");
        assert_eq!(config.quota.server_bytes, 2048 * 1024 * 1024);
        assert_eq!(config.max_connections, 512);
        assert_eq!(config.max_connections_per_address, 32);
        assert_eq!(config.kdf_floor.memory_kib, 19456);
        assert_eq!(config.kdf_floor.time_cost, 2);
        assert!(config.teams.enabled);
        assert_eq!(config.teams.creation, TeamCreation::All);
        assert_eq!(config.teams.max_per_account, 10);
        assert_eq!(config.teams.max_members, 50);
    }

    #[test]
    fn the_address_a_device_writes_down_says_how_to_reach_it() {
        let plain = Config {
            tls: TlsMode::Off,
            public: Some("nas.lan:8443".into()),
            ..Config::default()
        };
        assert_eq!(plain.base_url(), "http://nas.lan:8443");

        let secure = Config {
            public: Some("nas.lan:8443".into()),
            ..Config::default()
        };
        assert_eq!(secure.base_url(), "https://nas.lan:8443");
        assert_eq!(Config::default().base_url(), "https://0.0.0.0:8443");

        let proxied = Config {
            tls: TlsMode::Off,
            public: Some("https://uwusync.example.com/".into()),
            ..Config::default()
        };
        assert_eq!(proxied.base_url(), "https://uwusync.example.com");
    }

    #[test]
    fn a_setting_keeps_its_name_from_before() {
        assert_eq!(
            legacy_name("UWUSYNC_PUBLIC").as_deref(),
            Some("UWUSSH_PUBLIC")
        );
        assert_eq!(legacy_name("RUST_LOG"), None);
    }

    #[test]
    fn a_database_from_before_the_new_name_is_used_where_it_is() {
        let dir = std::env::temp_dir().join(format!("uwusync-legacy-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = Config {
            data_dir: dir.clone(),
            ..Config::default()
        };
        assert_eq!(config.database(), dir.join("uwusync.db"), "a new server");
        std::fs::write(dir.join("uwussh.db"), b"x").unwrap();
        assert_eq!(config.database(), dir.join("uwussh.db"), "one from before");
        std::fs::write(dir.join("uwusync.db"), b"x").unwrap();
        assert_eq!(
            config.database(),
            dir.join("uwusync.db"),
            "the new one wins"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_switch_is_on_or_off_and_nothing_else() {
        assert_eq!(switch("OFF"), Some(false));
        assert_eq!(switch("on"), Some(true));
        assert_eq!(switch("0"), Some(false));
        assert_eq!(switch("later"), None);
    }

    #[test]
    fn registration_only_takes_the_three_words() {
        assert_eq!(Registration::parse("OPEN"), Some(Registration::Open));
        assert_eq!(Registration::parse("closed"), Some(Registration::Closed));
        assert_eq!(Registration::parse("maybe"), None);
    }
}
