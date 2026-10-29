//! `uwusync-server` — run it, or ask it something.
//!
//! With no arguments it serves. The other commands are the ones you reach for
//! from a shell on the box: make an invite, see the devices, shut one out, take
//! a backup.

use axum_server::tls_rustls::RustlsConfig;
use axum_server::Handle;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;
use uwusync_server::api;
use uwusync_server::config::TlsMode;
use uwusync_server::db::{accounts, devices, invites, records, teams, with_suffix, Db};
use uwusync_server::{connections, date, health, now_ms, tls, updates, uwuauth, AppState, Config};

#[derive(Parser)]
#[command(
    name = "uwusync-server",
    version,
    about = "Sync server for UwUSSH and UwURDP"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Serve. The default.
    Serve,
    /// Make an invite code for a new account.
    Invite,
    /// List the accounts on this server, and how many devices each has.
    Accounts,
    /// List the devices of an account.
    Devices { account: Uuid },
    /// Shut a device out.
    Revoke { device: Uuid },
    /// List the teams on this server: id, name, members, records, created.
    Teams,
    /// Delete a team with everything it holds. Its members keep their
    /// accounts and their own vaults.
    TeamDelete { team: Uuid },
    /// Make a member of a team an owner — for a team that has none left.
    TeamOwner { team: Uuid, account: Uuid },
    /// Print the fingerprint of this server certificate, which is what a
    /// device pins.
    Fingerprint,
    /// Write a consistent copy of the database.
    Backup {
        /// Where to write it. The default is a dated file under `backups`.
        #[arg(long)]
        to: Option<PathBuf>,
    },
    /// Put a backup back. Without a name, list the backups there are. Only
    /// while the server is stopped:
    /// `docker compose stop && docker compose run --rm uwusync restore <name>`
    Restore {
        /// A file under `backups`, or a path.
        backup: Option<PathBuf>,
    },
    /// Ask the running server whether it is well. The container's health
    /// check: the image has no shell and no curl, so the server asks itself.
    Health,
    /// Sign in with UwUAuth: pair with it, see the pairing, or end it.
    Uwuauth {
        #[command(subcommand)]
        command: Uwuauth,
    },
    /// Make a new certificate key, because the old one is lost for good.
    /// Every device pinned the old one and has to be set up again.
    NewKey,
}

#[derive(Subcommand)]
enum Uwuauth {
    /// Pair with UwUAuth, with a pairing code made there. Needs
    /// UWUSYNC_PUBLIC at an https address.
    Pair {
        /// UwUAuth's address, `https://auth.example.com` — or leave it out
        /// and give the code with the address in it (`<address>#pair=<code>`).
        url: String,
        /// The pairing code, when the address is given on its own.
        code: Option<String>,
    },
    /// Show the pairing.
    Status,
    /// Forget the pairing. Accounts and devices stay.
    Unpair,
}

fn main() -> Result<(), String> {
    use std::io::IsTerminal;
    // Everything this server writes is its own: the database and its log, the
    // backups, the certificate key. Nobody else on the machine reads them.
    #[cfg(unix)]
    // SAFETY: umask only sets this process's file mode mask; it cannot fail
    // and touches no memory.
    unsafe {
        libc::umask(0o077);
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "uwusync_server=info,tower_http=warn".into()),
        )
        // The log goes to stderr, so what a command prints on stdout — a
        // fingerprint, a list of backups — is only that. Colours for a person
        // at a terminal, none for `docker compose logs` and whatever reads it:
        // install.sh looks for the setup code there.
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();
    // `ring` rather than the default provider: it needs no C toolchain beyond
    // a compiler, so this builds the same everywhere.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    let config = Config::from_env()?;
    let command = cli.command.unwrap_or(Command::Serve);
    // Asked every half minute, so it touches nothing but the network — not
    // even the database.
    if let Command::Health = command {
        return health::probe(&config);
    }
    // Opening the database would be using it, and a restore needs it unused.
    if let Command::Restore { backup } = command {
        return restore(&config, backup);
    }
    let db = Db::open(&config.database()).map_err(|error| format!("database: {error}"))?;

    match command {
        Command::Health | Command::Restore { .. } => unreachable!("answered above"),
        Command::NewKey => {
            if tls::public_key_of(&config.data_dir)
                .map_err(|error| error.to_string())?
                .is_some()
            {
                return Err("there is a certificate key; this is for when it is gone".into());
            }
            let fingerprint =
                tls::fingerprint_of(&config.data_dir, true).map_err(|error| error.to_string())?;
            println!("{fingerprint}");
            println!("A new key. Every device has to be set up again: remove the server in");
            println!("UwUSSH or UwURDP under Settings → Sync and connect with a new setup code.");
            Ok(())
        }
        Command::Serve => serve(db, config),
        Command::Uwuauth { command } => {
            let said = match command {
                Uwuauth::Pair { url, code } => {
                    let (url, code) = match code {
                        Some(code) => (Some(url), code),
                        None => (None, url),
                    };
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|error| error.to_string())?
                        .block_on(uwuauth::pair(&config, &db, url.as_deref(), &code))?
                }
                Uwuauth::Status => uwuauth::status(&db)?,
                Uwuauth::Unpair => uwuauth::unpair(&db)?,
            };
            println!("{said}");
            Ok(())
        }
        Command::Invite => {
            let code = {
                let conn = db.lock();
                invites::create_invite(&conn, invites::INVITE_TTL_MS)
                    .map_err(|error| error.to_string())?
            };
            let fingerprint = match config.tls {
                TlsMode::Auto => Some(
                    tls::fingerprint_of(&config.data_dir, !has_accounts(&db))
                        .map_err(|error| error.to_string())?,
                ),
                TlsMode::Off => None,
            };
            println!("Invite code: {code}");
            println!(
                "Setup code:  {}",
                setup_code(&config, &code, fingerprint.as_deref())
            );
            println!("Good for a week, and for one account.");
            Ok(())
        }
        Command::Accounts => {
            let conn = db.lock();
            let mut stmt = conn
                .prepare("SELECT id, created_ms FROM accounts ORDER BY created_ms")
                .map_err(|error| error.to_string())?;
            let rows: Vec<(String, i64)> = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(|error| error.to_string())?
                .collect::<rusqlite::Result<_>>()
                .map_err(|error| error.to_string())?;
            if rows.is_empty() {
                println!("No accounts yet. `uwusync-server invite` makes the first one possible.");
            }
            for (id, created) in rows {
                let account = Uuid::parse_str(&id).unwrap_or(Uuid::nil());
                let count = devices::live_count(&conn, account).unwrap_or(0);
                println!("{id}  {} device(s)  since {}", count, date(created as u64));
            }
            Ok(())
        }
        Command::Devices { account } => {
            let conn = db.lock();
            for device in devices::list(&conn, account).map_err(|error| error.to_string())? {
                let state = match device.revoked_ms {
                    Some(when) => format!("revoked {}", date(when)),
                    None => match device.last_seen_ms {
                        Some(when) => format!("last seen {}", date(when)),
                        None => "never here".to_string(),
                    },
                };
                println!("{}  {}  {state}", device.id, device.name);
            }
            Ok(())
        }
        Command::Revoke { device } => {
            let conn = db.lock();
            let found = devices::get(&conn, device)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| format!("no device {device}"))?;
            let revoked = devices::revoke(&conn, found.account_id, device)
                .map_err(|error| error.to_string())?;
            // What it made goes with it, as it does through the API. Its event
            // stream in the running server notices within half a minute.
            invites::drop_enrolments_of(&conn, device).map_err(|error| error.to_string())?;
            println!(
                "{}",
                if revoked {
                    "Revoked. It stops syncing at once — but rotate the keys and passwords it held."
                } else {
                    "It was already revoked."
                }
            );
            Ok(())
        }
        Command::Teams => {
            let teams = teams::all(&db.lock()).map_err(|error| error.to_string())?;
            if teams.is_empty() {
                println!("No teams.");
            }
            for team in teams {
                println!(
                    "{}  {:?}  {} member(s)  {} record(s)  since {}{}",
                    team.id,
                    team.name,
                    team.members,
                    team.records,
                    date(team.created_ms),
                    if team.owners == 0 {
                        "  (no owner: see team-owner)"
                    } else {
                        ""
                    }
                );
            }
            Ok(())
        }
        Command::TeamDelete { team } => {
            let gone = teams::delete_any(&db.lock(), team).map_err(|error| error.to_string())?;
            if !gone {
                return Err(format!("no team {team}"));
            }
            println!("Deleted, with its records. Its members' devices drop it at their next sync.");
            Ok(())
        }
        Command::TeamOwner { team, account } => {
            let made =
                teams::make_owner(&db.lock(), team, account).map_err(|error| error.to_string())?;
            if !made {
                return Err(format!(
                    "account {account} is not a member of team {team} who has its key"
                ));
            }
            println!("That member owns the team now.");
            Ok(())
        }
        Command::Fingerprint => {
            match config.tls {
                TlsMode::Auto => {
                    let fingerprint = tls::fingerprint_of(&config.data_dir, !has_accounts(&db))
                        .map_err(|error| error.to_string())?;
                    println!("{fingerprint}");
                    println!("{}", config.base_url());
                    println!("A device pins this on the first connection, like an SSH host key.");
                }
                TlsMode::Off => {
                    println!("UWUSYNC_TLS is off: the certificate belongs to whatever is in front.")
                }
            }
            Ok(())
        }
        Command::Backup { to } => {
            let path = to.unwrap_or_else(|| backup_path(&config));
            room_for_backup(&config, &path)?;
            db.backup_to(&path).map_err(|error| error.to_string())?;
            println!("Written to {}", path.display());
            Ok(())
        }
    }
}

#[tokio::main]
async fn serve(db: Db, config: Config) -> Result<(), String> {
    // The certificate first: its fingerprint belongs in the setup code, and a
    // key that cannot be written is a reason not to start at all.
    let identity = match config.tls {
        TlsMode::Auto => Some(
            tls::load(
                &config.data_dir,
                &tls::names_for(config.public.as_deref()),
                !has_accounts(&db),
            )
            .map_err(|error| format!("certificate: {error}"))?,
        ),
        TlsMode::Off => None,
    };
    let fingerprint = identity
        .as_ref()
        .map(|identity| identity.fingerprint.clone());

    // A server nobody can join is not much use, so the first start says how.
    if accounts::count(&db.lock()).unwrap_or(0) == 0
        && invites::count_open_invites(&db.lock()).unwrap_or(0) == 0
    {
        let code = {
            let conn = db.lock();
            invites::create_invite(&conn, invites::INVITE_TTL_MS)
                .map_err(|error| error.to_string())?
        };
        // As a field of its own: install.sh takes the first `setup_code=` in
        // the log, and nothing a stranger can make the server log looks like
        // that — this line is written before anybody can connect.
        tracing::info!(
            setup_code = %setup_code(&config, &code, fingerprint.as_deref()),
            "no accounts yet: paste this setup code into UwUSSH or UwURDP under Settings → Sync. It is good for a week"
        );
    }

    let listen = config.listen;
    let url = config.base_url();
    let limits = connections::Limits::from_config(&config);
    let state = AppState::new(db, config);
    maintenance(state.clone());
    updates::spawn(state.config.clone());
    tracing::info!(version = updates::build().version, "UwUSync Server");
    let legacy = uwusync_server::config::legacy_variables();
    if !legacy.is_empty() {
        tracing::info!(
            variables = %legacy.join(" "),
            "these settings still have their names from UwUSSH Server; they work, \
             and update.sh renames them to UWUSYNC_…"
        );
    }

    // Every connection is an open file, and the server takes hundreds.
    match connections::raise_open_files() {
        Some(files) if files < limits.max as u64 + 64 => tracing::warn!(
            files,
            connections = limits.max,
            "this process may open fewer files than the server takes connections; \
             raise the limit (ulimit -n) or lower UWUSYNC_MAX_CONNECTIONS"
        ),
        _ => {}
    }

    let tls = match &identity {
        Some(identity) => Some(
            RustlsConfig::from_pem(
                identity.cert_pem.clone().into_bytes(),
                identity.key_pem.clone().into_bytes(),
            )
            .await
            .map_err(|error| format!("certificate: {error}"))?,
        ),
        None => None,
    };
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .and_then(|listener| listener.into_std())
        .map_err(|error| format!("cannot listen on {listen}: {error}"))?;

    // An event stream never ends by itself, and a graceful shutdown waits for
    // every connection — so after the grace period it stops waiting.
    let handle = Handle::new();
    tokio::spawn({
        let handle = handle.clone();
        async move {
            shutdown().await;
            handle.graceful_shutdown(Some(GRACE));
        }
    });
    match &identity {
        Some(identity) => {
            tracing::info!(%listen, %url, fingerprint = %identity.fingerprint, "UwUSync server ready")
        }
        None => tracing::warn!(
            %listen, %url,
            "serving plain HTTP — put a reverse proxy with a certificate in front"
        ),
    }
    connections::serve(listener, api::router(state), tls, limits, handle)
        .await
        .map_err(|error| error.to_string())
}

/// How long open connections get to finish once the server is told to stop.
/// Docker waits ten seconds before it stops asking.
const GRACE: Duration = Duration::from_secs(5);

/// Ctrl-C at a terminal, SIGTERM from `docker stop`. The second matters more:
/// a process that is PID 1 in a container and has no handler for it does not
/// stop at all, and gets killed ten seconds later.
async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("stopping");
}

/// Backups kept: a week of nights, the ones before updates counted in. Each
/// is a whole copy of the database, so this number times the database is
/// what they take on disk.
const BACKUPS_KEPT: usize = 7;

/// Once a day: a backup, and a sweep of what nobody needs any more. And every
/// few minutes, the session tokens that ran out.
fn maintenance(state: AppState) {
    tokio::spawn({
        let sessions = state.sessions.clone();
        async move {
            let mut every = tokio::time::interval(Duration::from_secs(5 * 60));
            loop {
                every.tick().await;
                sessions.sweep();
            }
        }
    });
    tokio::spawn(async move {
        let day = Duration::from_secs(24 * 60 * 60);
        // Not at once on start: a server that is restarted in a loop should
        // not write a backup every time.
        tokio::time::sleep(Duration::from_secs(60 * 10)).await;
        loop {
            let db = state.db.clone();
            let config = state.config.clone();
            let done = tokio::task::spawn_blocking(move || {
                let path = backup_path(&config);
                if let Err(error) = room_for_backup(&config, &path) {
                    tracing::warn!("no backup tonight: {error}");
                } else if let Err(error) = db.backup_to(&path) {
                    tracing::warn!(%error, "backup failed");
                } else {
                    keep_newest(&config.backups(), BACKUPS_KEPT);
                }
                purge(&db);
            })
            .await;
            if done.is_err() {
                tracing::warn!("maintenance did not finish");
            }
            tokio::time::sleep(day).await;
        }
    });
}

/// Tombstones every device has read and that are older than a season, and
/// codes that are long expired.
///
/// One account at a time, letting go of the database in between: requests
/// keep being answered while a server with many accounts tidies up.
fn purge(db: &Db) {
    const NINETY_DAYS_MS: u64 = 90 * 24 * 60 * 60 * 1000;
    let _ = invites::purge(&db.lock());
    let _ = teams::purge(&db.lock(), now_ms());
    let ids: Vec<String> = match db
        .lock()
        .prepare("SELECT id FROM accounts")
        .and_then(|mut stmt| stmt.query_map([], |row| row.get(0))?.collect())
    {
        Ok(ids) => ids,
        Err(error) => {
            tracing::warn!(%error, "could not read the accounts");
            return;
        }
    };
    for id in ids {
        let Ok(id) = Uuid::parse_str(&id) else {
            continue;
        };
        let conn = db.lock();
        let Ok(Some(account)) = accounts::get(&conn, id) else {
            continue;
        };
        let below = devices::lowest_cursor(&conn, id).unwrap_or(0);
        let before = now_ms().saturating_sub(NINETY_DAYS_MS);
        match records::purge_tombstones(&conn, &account, before, below) {
            Ok(0) => {}
            Ok(gone) => tracing::info!(%id, gone, "tombstones forgotten"),
            Err(error) => tracing::warn!(%error, "could not purge tombstones"),
        }
    }
    // Teams the same way, one at a time.
    let teams = match teams::all(&db.lock()) {
        Ok(teams) => teams,
        Err(error) => {
            tracing::warn!(%error, "could not read the teams");
            return;
        }
    };
    for team in teams {
        let before = now_ms().saturating_sub(NINETY_DAYS_MS);
        match teams::purge_tombstones(&db.lock(), team.id, before) {
            Ok(0) => {}
            Ok(gone) => tracing::info!(team = %team.id, gone, "tombstones forgotten"),
            Err(error) => tracing::warn!(%error, "could not purge a team's tombstones"),
        }
    }
}

/// Whether a backup to `path` leaves the disk with room to spare. A backup
/// is about as large as the database, and one that fills the disk takes the
/// database down with it: the next write has nowhere to go. So it is only
/// written when what is free afterwards is still a twentieth of the disk, and
/// at least 256 MiB.
fn room_for_backup(config: &Config, path: &std::path::Path) -> Result<(), String> {
    let database = config.database();
    let size = |path: &std::path::Path| std::fs::metadata(path).map_or(0, |meta| meta.len());
    let need = size(&database) + size(&with_suffix(&database, "-wal"));
    // The directory it goes into may not be there yet; the disk it will be
    // on is that of the nearest one that is.
    let Some((free, total)) = path.ancestors().skip(1).find_map(disk_space) else {
        return Ok(());
    };
    enough_room(free, total, need).then_some(()).ok_or_else(|| {
        format!(
            "{} MiB free, and a backup of about {} MiB would leave less than the disk needs \
             to keep going. Make room, or copy the backups under backups/ elsewhere and \
             remove old ones",
            free / (1024 * 1024),
            need.div_ceil(1024 * 1024)
        )
    })
}

/// Whether `need` bytes fit into `free` with a margin left over.
fn enough_room(free: u64, total: u64, need: u64) -> bool {
    let margin = (total / 20).max(256 * 1024 * 1024);
    free >= need.saturating_add(margin)
}

/// Free and total bytes of the file system `path` is on, for whoever may
/// write there — or nothing, where that is not known.
#[cfg(unix)]
#[allow(clippy::unnecessary_cast)]
fn disk_space(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: statvfs reads a NUL-terminated path and writes one struct,
    // both of which live on this stack for the length of the call; the
    // struct is plain data, for which all zeroes is a valid value.
    let stat = unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(path.as_ptr(), &mut stat) != 0 {
            return None;
        }
        stat
    };
    let unit = stat.f_frsize as u64;
    Some((stat.f_bavail as u64 * unit, stat.f_blocks as u64 * unit))
}

#[cfg(not(unix))]
fn disk_space(_path: &std::path::Path) -> Option<(u64, u64)> {
    None
}

/// Keep the newest `keep` backups and remove the rest.
fn keep_newest(dir: &std::path::Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension().is_some_and(|ext| ext == "db")
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| backup_stamp(name).is_some())
        })
        .collect();
    files.sort_by(|a, b| stamp_of(a).cmp(&stamp_of(b)));
    for old in files.iter().rev().skip(keep) {
        let _ = std::fs::remove_file(old);
    }
}

/// Whether anybody has an account here — and so has pinned this server's key.
fn has_accounts(db: &Db) -> bool {
    accounts::count(&db.lock()).map_or(true, |count| count > 0)
}

/// `uwusync-server restore [name]`.
fn restore(config: &Config, backup: Option<PathBuf>) -> Result<(), String> {
    let Some(backup) = backup else {
        let backups = list_backups(&config.backups());
        if backups.is_empty() {
            println!("No backups in {} yet.", config.backups().display());
        }
        for (name, bytes) in backups {
            println!("{name}  {} KiB", bytes.div_ceil(1024));
        }
        return Ok(());
    };
    // A bare name means one of the backups; anything else is a path.
    let path = if backup.components().count() == 1 && !backup.exists() {
        config.backups().join(&backup)
    } else {
        backup
    };
    let database = config.database();
    let aside = with_suffix(&database, &format!(".before-restore-{}", stamp(now_ms())));
    uwusync_server::db::restore(&path, &database, &aside)?;
    println!("Restored from {}.", path.display());
    if aside.exists() {
        println!("What was there before is kept as {}.", aside.display());
    }
    println!("Start the server again: docker compose up -d");
    Ok(())
}

/// The backups under `dir`, oldest first, with their sizes.
fn list_backups(dir: &std::path::Path) -> Vec<(String, u64)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut backups: Vec<(String, u64)> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_string();
            backup_stamp(&name)?;
            let bytes = entry.metadata().map(|meta| meta.len()).unwrap_or(0);
            Some((name, bytes))
        })
        .collect();
    backups.sort_by(|(a, _), (b, _)| backup_stamp(a).cmp(&backup_stamp(b)));
    backups
}

/// When a backup was written, from its name: `uwusync-<when>.db`, or
/// `uwussh-<when>.db` from before the server was called UwUSync. Nothing for
/// a file that is not a backup.
fn backup_stamp(name: &str) -> Option<&str> {
    name.strip_prefix("uwusync-")
        .or_else(|| name.strip_prefix("uwussh-"))?
        .strip_suffix(".db")
}

fn stamp_of(path: &std::path::Path) -> Option<&str> {
    backup_stamp(path.file_name()?.to_str()?)
}

/// Where a backup goes unless told otherwise: `backups/uwusync-<when>.db`, to
/// the second — the nightly one and one taken before an update can fall on
/// the same day, and `VACUUM INTO` will not write over a file.
fn backup_path(config: &Config) -> PathBuf {
    config
        .backups()
        .join(format!("uwusync-{}.db", stamp(now_ms())))
}

/// One setup code to paste: where the server is, its certificate fingerprint,
/// and the invite. The fingerprint is the part that matters — the first device
/// pins it the way an SSH client pins a host key, and passes it on to every
/// device that pairs with it afterwards.
fn setup_code(config: &Config, invite: &str, fingerprint: Option<&str>) -> String {
    let mut body = serde_json::json!({ "u": config.base_url(), "i": invite });
    if let Some(fingerprint) = fingerprint {
        body["f"] = serde_json::json!(fingerprint);
    }
    format!("uwu1_{}", uwusync_server::b64::encode(body.to_string()))
}

/// `YYYY-MM-DD-HHMMSS`, in UTC. Sorts the way it reads.
fn stamp(ms: u64) -> String {
    let seconds = (ms / 1000) % 86_400;
    format!(
        "{}-{:02}{:02}{:02}",
        date(ms),
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_date_is_the_date() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(1_700_000_000_000), "2023-11-14");
        assert_eq!(date(1_789_000_000_000), "2026-09-10");
    }

    #[test]
    fn a_stamp_is_the_date_and_the_time() {
        assert_eq!(stamp(0), "1970-01-01-000000");
        // 2023-11-14 22:13:20 UTC
        assert_eq!(stamp(1_700_000_000_000), "2023-11-14-221320");
        let mut stamps = [stamp(1_700_000_000_000), stamp(1_699_999_999_000)];
        stamps.sort();
        assert_eq!(stamps[0], "2023-11-14-221319", "and it sorts by time");
    }

    fn decode(code: &str) -> serde_json::Value {
        assert!(code.starts_with("uwu1_"), "{code}");
        let decoded = uwusync_server::b64::decode(&code["uwu1_".len()..]).unwrap();
        serde_json::from_slice(&decoded).unwrap()
    }

    #[test]
    fn a_setup_code_carries_the_address_the_fingerprint_and_the_invite() {
        let config = Config {
            public: Some("nas.lan:8443".into()),
            ..Config::default()
        };
        let parsed = decode(&setup_code(
            &config,
            "ABCDE-FGHJK-MNPQR",
            Some("SHA256:abc"),
        ));
        assert_eq!(parsed["u"], "https://nas.lan:8443");
        assert_eq!(parsed["f"], "SHA256:abc");
        assert_eq!(parsed["i"], "ABCDE-FGHJK-MNPQR");
    }

    #[test]
    fn without_its_own_certificate_there_is_nothing_to_pin() {
        let config = Config {
            tls: TlsMode::Off,
            public: Some("https://uwusync.example.com".into()),
            ..Config::default()
        };
        let parsed = decode(&setup_code(&config, "X", None));
        assert_eq!(parsed["u"], "https://uwusync.example.com");
        assert!(parsed.get("f").is_none(), "{parsed}");
    }

    #[test]
    fn a_setup_code_falls_back_to_where_the_server_listens() {
        let parsed = decode(&setup_code(&Config::default(), "X", None));
        assert_eq!(parsed["u"], "https://0.0.0.0:8443");
    }

    #[test]
    fn a_backup_is_written_only_with_room_to_spare() {
        const MIB: u64 = 1024 * 1024;
        // A 32 GiB disk: the margin is a twentieth of it.
        let disk = 32 * 1024 * MIB;
        assert!(enough_room(10 * 1024 * MIB, disk, 100 * MIB));
        assert!(
            !enough_room(1700 * MIB, disk, 100 * MIB),
            "under the margin after"
        );
        // A small disk still keeps 256 MiB.
        assert!(!enough_room(300 * MIB, 1024 * MIB, 50 * MIB));
        assert!(enough_room(400 * MIB, 1024 * MIB, 50 * MIB));
        assert!(!enough_room(disk, disk, u64::MAX), "no overflow");
    }

    #[test]
    fn only_the_newest_backups_are_kept() {
        let dir = std::env::temp_dir().join(format!("uwusync-backups-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        // Two from before the new name, three after.
        for day in 1..=2 {
            std::fs::write(dir.join(format!("uwussh-2026-09-0{day}-030000.db")), b"x").unwrap();
        }
        for day in 3..=5 {
            std::fs::write(dir.join(format!("uwusync-2026-09-0{day}-030000.db")), b"x").unwrap();
        }
        std::fs::write(dir.join("notes.txt"), b"x").unwrap();

        keep_newest(&dir, 2);

        let mut left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect();
        left.sort();
        assert_eq!(
            left,
            vec![
                "notes.txt",
                "uwusync-2026-09-04-030000.db",
                "uwusync-2026-09-05-030000.db"
            ]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn backups_from_before_the_new_name_still_count() {
        assert_eq!(
            backup_stamp("uwussh-2026-09-01-030000.db"),
            Some("2026-09-01-030000")
        );
        assert_eq!(
            backup_stamp("uwusync-2026-09-02-030000.db"),
            Some("2026-09-02-030000")
        );
        assert_eq!(backup_stamp("notes.db"), None);
        assert_eq!(backup_stamp("uwusync-x.txt"), None);
        let dir = std::env::temp_dir().join(format!("uwusync-listed-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("uwusync-2026-09-22-030000.db"), b"x").unwrap();
        std::fs::write(dir.join("uwussh-2026-09-21-030000.db"), b"x").unwrap();
        let names: Vec<String> = list_backups(&dir)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(
            names,
            vec![
                "uwussh-2026-09-21-030000.db",
                "uwusync-2026-09-22-030000.db"
            ],
            "oldest first, whatever they are called"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
