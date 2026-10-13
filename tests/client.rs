//! The real client against the real server.
//!
//! Every other test here speaks the protocol by hand, which proves the server
//! does what it says — but not that the client agrees. This one runs the
//! actual crates from the client repository: its store, its vault, its sync
//! engine, its transport. What is checked is the one thing neither side can
//! check alone: that a host saved on one device, with a password in the vault,
//! turns up on a second device that joined the account — and that the server
//! carried it without being able to read any of it.
//!
//! The server runs on a runtime of its own thread, and the client work happens
//! on this one, blocking. That is how the app will run it too: sync belongs on
//! its own thread, not in the runtime that drives a terminal.

use std::net::SocketAddr;
use std::sync::mpsc;
use uwussh_proto::api::{CreateAccount, EnrolDevice, NewDevice};
use uwussh_store::{AuthMethod, HostDraft, PasswordChange, SecretText, Store};
use uwussh_sync::{from_wire, sync_once, to_wire, Server};
use uwussh_vault::{AccountKey, KdfParams};
use uwusync_server::config::Registration;
use uwusync_server::db::accounts::KdfFloor;
use uwusync_server::db::Db;
use uwusync_server::{api, b64, random_bytes, AppState, Config};

const PASSWORD: &[u8] = b"correct horse battery staple";
/// The cheap parameters, because these tests run on every commit and the real
/// ones take 64 MiB a call.
const KDF: KdfParams = KdfParams::INSECURE_FOR_TESTS;

/// A server on a port of its own, on a runtime of its own thread.
struct Running {
    url: String,
    state: AppState,
}

fn start() -> Running {
    start_with(Registration::Open)
}

fn start_with(registration: Registration) -> Running {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ready, started) = mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("a runtime");
        runtime.block_on(async move {
            let config = Config {
                registration,
                // The cheap parameters above are below what the server takes
                // from a real client.
                kdf_floor: KdfFloor {
                    memory_kib: KDF.memory_kib,
                    time_cost: KDF.time_cost,
                },
                ..Config::default()
            };
            let state = AppState::new(Db::open_in_memory().expect("a database"), config);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("a port");
            let address = listener.local_addr().expect("an address");
            ready
                .send((address, state.clone()))
                .expect("the test is there");
            axum::serve(
                listener,
                api::router(state).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("serving");
        });
    });
    let (address, state) = started.recv().expect("the server starts");
    Running {
        // Plain HTTP, which the client allows for localhost and nothing else.
        url: format!("http://{address}"),
        state,
    }
}

/// A device's signing key: the seed, and the public half the server enrols.
///
/// The seed is made here and handed to the client, which signs with its own
/// version of ed25519 — so this also shows the two versions in the two
/// repositories producing signatures the other accepts.
fn device_key() -> ([u8; 32], String) {
    let seed = random_bytes::<32>();
    let public = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    (seed, b64::encode(public))
}

fn host(name: &str, address: &str) -> HostDraft {
    HostDraft {
        id: None,
        name: name.into(),
        address: address.into(),
        port: 22,
        username: "uwu".into(),
        auth: AuthMethod::Password,
        key_path: None,
        group_path: None,
        workspace: None,
        key_id: None,
        password: PasswordChange::Keep,
    }
}

fn names(store: &Store) -> Vec<String> {
    let mut names: Vec<String> = store
        .list_hosts()
        .unwrap()
        .into_iter()
        .map(|host| host.name)
        .collect();
    names.sort();
    names
}

#[test]
fn a_host_saved_on_one_device_turns_up_on_the_one_that_joined() {
    let running = start();
    let account_key = AccountKey::generate();

    // ── The first device ───────────────────────────────────────────────────
    let first = Store::open_in_memory().unwrap();
    first
        .create_synced_vault(PASSWORD, &account_key, KDF)
        .unwrap();
    let header = first.vault_header().unwrap().unwrap();
    let login_key = header.login_key(PASSWORD, Some(&account_key)).unwrap();

    let mut prox = host("prox-1", "10.0.0.12");
    prox.group_path = Some("Homelab".into());
    prox.password = PasswordChange::Set {
        value: SecretText::new("hunter2"),
    };
    let saved = first.save_host(prox).unwrap();

    let (seed, public_key) = device_key();
    let server = Server::connect(&running.url, None).unwrap();
    let admitted = server
        .create_account(&CreateAccount {
            invite: String::new(),
            vault: to_wire(&header),
            auth_key: b64::encode(*login_key),
            device: NewDevice {
                name: "LVDesk1".into(),
                public_key,
            },
        })
        .unwrap();
    let server = server.as_device(admitted.account_id, admitted.device_id, &seed);

    let up = sync_once(&first, &server).unwrap();
    assert!(up.pushed >= 4, "host, login, group and password: {up:?}");
    assert_eq!(up.apply.rejected, 0);

    // What the server holds: ciphertext, and nothing that reads as a hostname.
    let held = running.state.db.lock();
    let blobs: Vec<Vec<u8>> = held
        .prepare("SELECT blob FROM records")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    drop(held);
    assert!(blobs.len() >= 4);
    for blob in &blobs {
        let text = String::from_utf8_lossy(blob).to_string();
        for secret in ["prox-1", "10.0.0.12", "hunter2", "Homelab"] {
            assert!(!text.contains(secret), "{secret} must not be readable");
        }
    }

    // ── The second device joins ────────────────────────────────────────────
    let enrolment = server.enrolment_token().unwrap();

    let second = Store::open_in_memory().unwrap();
    let joining = Server::connect(&running.url, None).unwrap();
    // Before it can prove anything, it needs the salt and the costs — and is
    // told that the account key is wanted as well.
    let params = joining.vault_params(&enrolment.token).unwrap();
    assert_eq!(params.vault_id, header.vault_id);
    assert!(
        params.needs_account_key,
        "so a missing kit is not blamed on the password"
    );

    let (seed, public_key) = device_key();
    let admitted = joining
        .enrol(&EnrolDevice {
            enrolment: enrolment.token.clone(),
            auth_key: b64::encode(*login_key),
            device: NewDevice {
                name: "LVLaptop".into(),
                public_key,
            },
        })
        .unwrap();
    let joining = joining.as_device(admitted.account_id, admitted.device_id, &seed);

    // Now it may have the wrapped key, and opens it with the password and the
    // account key the pairing would have carried.
    let downloaded = from_wire(&joining.vault().unwrap()).unwrap();
    assert_eq!(downloaded, header, "the header came back as it was written");
    let key = downloaded
        .unlock_with(PASSWORD, Some(&account_key))
        .unwrap()
        .export_key();
    second.adopt_vault(&downloaded, key).unwrap();

    let down = sync_once(&second, &joining).unwrap();
    assert_eq!(down.apply.rejected, 0, "{down:?}");
    let hosts = second.list_hosts().unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].id, saved.id);
    assert_eq!(hosts[0].address, "10.0.0.12");
    assert_eq!(hosts[0].group_path.as_deref(), Some("Homelab"));
    assert_eq!(
        second.reveal_host_password(saved.id).unwrap().as_slice(),
        b"hunter2",
        "the password opens on the device that joined"
    );

    // ── And back the other way ─────────────────────────────────────────────
    second.save_host(host("nas", "10.0.0.9")).unwrap();
    sync_once(&second, &joining).unwrap();
    sync_once(&first, &server).unwrap();
    assert_eq!(names(&first), vec!["nas", "prox-1"]);
    assert_eq!(names(&second), vec!["nas", "prox-1"]);

    // A device that has signed in can do it again with its key alone, which
    // is what every pass after the first hour does.
    assert!(server.sign_in().is_ok());
    assert_eq!(sync_once(&first, &server).unwrap().apply.rejected, 0);
}

#[test]
fn the_relay_carries_what_the_two_devices_say_to_each_other() {
    let running = start();
    let account_key = AccountKey::generate();
    let first = Store::open_in_memory().unwrap();
    first
        .create_synced_vault(PASSWORD, &account_key, KDF)
        .unwrap();
    let header = first.vault_header().unwrap().unwrap();
    let login_key = header.login_key(PASSWORD, Some(&account_key)).unwrap();

    let (seed, public_key) = device_key();
    let server = Server::connect(&running.url, None).unwrap();
    let admitted = server
        .create_account(&CreateAccount {
            invite: String::new(),
            vault: to_wire(&header),
            auth_key: b64::encode(*login_key),
            device: NewDevice {
                name: "LVDesk1".into(),
                public_key,
            },
        })
        .unwrap();
    let server = server.as_device(admitted.account_id, admitted.device_id, &seed);

    // The device that is in opens a session; the joining one needs no account.
    let session = server.open_pairing().unwrap();
    assert_eq!(session.id.len(), 5, "a code somebody reads out loud");
    let joining = Server::connect(&running.url, None).unwrap();

    // Side a signs in as the device that opened it; side b holds its side
    // with a secret it made up.
    let claim = Some("the joining device's own secret");
    server
        .pair_send(&session.id, "a", None, b"spake from a")
        .unwrap();
    assert!(
        server
            .pair_receive(&session.id, "a", None, 0, false)
            .unwrap()
            .is_empty(),
        "a device does not hear itself"
    );
    assert_eq!(
        joining
            .pair_receive(&session.id, "b", claim, 0, false)
            .unwrap(),
        vec![b"spake from a".to_vec()]
    );

    joining
        .pair_send(&session.id, "b", claim, b"spake from b")
        .unwrap();
    server
        .pair_send(&session.id, "a", None, b"the sealed account key")
        .unwrap();
    assert_eq!(
        joining
            .pair_receive(&session.id, "b", claim, 1, false)
            .unwrap(),
        vec![b"the sealed account key".to_vec()],
        "and only what it has not seen yet"
    );

    // Somebody else who learned the id speaks for neither side.
    let stranger = Server::connect(&running.url, None).unwrap();
    assert!(stranger
        .pair_send(&session.id, "a", None, b"me too")
        .is_err());
    assert!(stranger
        .pair_receive(&session.id, "b", Some("a guess"), 0, false)
        .is_err());

    server.close_pairing(&session.id).unwrap();
    assert!(joining
        .pair_receive(&session.id, "b", claim, 0, false)
        .is_err());
}

#[test]
fn a_client_pointed_at_the_wrong_thing_says_so_rather_than_trying() {
    // Plain HTTP to anywhere but this machine is refused before a socket is
    // opened, because what travels here is a login key.
    assert!(Server::connect("http://nas.lan:8443", None).is_err());
    assert!(Server::connect("https://nas.lan:8443", None).is_ok());

    // And a device with no token does not send a request it knows will fail.
    let running = start();
    let stranger = Server::connect(&running.url, None).unwrap();
    assert!(stranger.devices().is_err());
}

// ── The whole thing, as a person does it ────────────────────────────────────

/// Sealing for this device, as the operating system would. A test has no
/// DPAPI, and what matters here is that the same bytes come back.
fn protect(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    Ok(bytes.iter().map(|byte| byte ^ 0x5a).collect())
}

fn unprotect(bytes: &[u8]) -> std::io::Result<zeroize::Zeroizing<Vec<u8>>> {
    Ok(zeroize::Zeroizing::new(
        bytes.iter().map(|byte| byte ^ 0x5a).collect(),
    ))
}

/// The setup code the server prints, built the way `uwusync-server invite`
/// builds it.
fn setup_code(running: &Running) -> uwussh_sync::Setup {
    let invite = {
        let conn = running.state.db.lock();
        uwusync_server::db::invites::create_invite(&conn, 60_000).unwrap()
    };
    let body = serde_json::json!({ "u": running.url, "i": invite }).to_string();
    let code = format!("uwu1_{}", b64::encode(body));
    uwussh_sync::parse_setup(&code).expect("the server's own code")
}

#[test]
fn a_second_device_joins_by_reading_out_three_words() {
    let running = start_with(Registration::Invite);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);

    // ── The first device: a setup code, a master password, and that is all ──
    let first = std::sync::Arc::new(Store::open_in_memory().unwrap());
    // It already has a host, from before there was ever a server.
    first.create_vault_with(PASSWORD, KDF).unwrap();
    let mut prox = host("prox-1", "10.0.0.12");
    prox.password = PasswordChange::Set {
        value: SecretText::new("hunter2"),
    };
    let saved = first.save_host(prox).unwrap();

    let setup = setup_code(&running);
    let (server, paired) =
        uwussh_sync::create_account(&first, &setup, PASSWORD, "LVDesk1", protect).unwrap();
    let kit = paired.recovery.expect("the recovery kit, shown once");
    assert_eq!(
        first.reveal_host_password(saved.id).unwrap().as_slice(),
        b"hunter2",
        "turning sync on wrapped one key again and re-encrypted nothing"
    );
    assert!(
        first.vault_needs_account_key().unwrap(),
        "and the vault now wants the kit as well"
    );
    sync_once(&first, &server).unwrap();

    // ── The code, as it goes on screen ─────────────────────────────────────
    let offer = uwussh_sync::flow::offer_pairing(&first, &server).unwrap();
    let spoken = offer.offer.spoken.clone();
    let (id, words) = uwussh_sync::pairing::parse_spoken(&spoken).expect("a code to read out");
    // The joining device is told the address and the fingerprint by the
    // pasteable form; typing the spoken code needs the address as well, which
    // is what the interface asks for.
    let pasted = uwussh_sync::pairing::parse_offer(&offer.offer.pasteable).unwrap();
    assert_eq!(pasted.id, id);
    assert_eq!(pasted.words, words);

    // ── The second device: the code and the master password ────────────────
    let second = std::sync::Arc::new(Store::open_in_memory().unwrap());
    let joining = {
        let second = second.clone();
        let target = pasted.clone();
        std::thread::spawn(move || {
            uwussh_sync::join(&second, &target, PASSWORD, "LVLaptop", protect, deadline)
        })
    };

    let joined =
        uwussh_sync::flow::wait_for_device(&first, &server, &offer, unprotect, deadline).unwrap();
    assert_eq!(joined.device_name, "LVLaptop");

    let (other, paired) = joining.join().unwrap().unwrap();
    assert!(
        paired.recovery.is_none(),
        "only the device that made the key shows a kit"
    );
    assert_eq!(
        Some(paired.account_id),
        first.sync_state().unwrap().account_id,
        "both devices are in the same account"
    );

    // It has the vault, and the vault wants the kit — which it has, because
    // the handshake carried it.
    assert!(second.vault_needs_account_key().unwrap());
    sync_once(&second, &other).unwrap();
    let hosts = second.list_hosts().unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].address, "10.0.0.12");
    assert_eq!(
        second.reveal_host_password(saved.id).unwrap().as_slice(),
        b"hunter2",
        "and the password opens on a device that was only ever told three words"
    );

    // Locked and opened again with what this device keeps: no kit typed.
    second.lock_vault();
    let key = uwussh_sync::flow::account_key(&second, unprotect)
        .unwrap()
        .expect("the account key this device kept");
    second.unlock_vault_with(PASSWORD, Some(&key)).unwrap();
    assert_eq!(
        second.reveal_host_password(saved.id).unwrap().as_slice(),
        b"hunter2"
    );
    // And the kit from the other device is the same key.
    assert_eq!(key.to_code(), kit.to_code());

    // Signing in again from scratch, the way tomorrow's first pass does.
    let returning = uwussh_sync::reconnect(&second, unprotect).unwrap();
    assert_eq!(sync_once(&second, &returning).unwrap().apply.rejected, 0);

    // The account has two devices, and each can see them.
    assert_eq!(server.devices().unwrap().len(), 2);
    assert_eq!(other.devices().unwrap().len(), 2);
}

#[test]
fn a_device_that_heard_the_wrong_words_gets_nothing() {
    let running = start_with(Registration::Invite);
    // Short: the handshake fails on the first answer, and the other side is
    // only waiting for something that will never come.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let first = std::sync::Arc::new(Store::open_in_memory().unwrap());
    let setup = setup_code(&running);
    let (server, _) =
        uwussh_sync::create_account(&first, &setup, PASSWORD, "LVDesk1", protect).unwrap();

    let offer = uwussh_sync::flow::offer_pairing(&first, &server).unwrap();
    let mut wrong = uwussh_sync::pairing::parse_offer(&offer.offer.pasteable).unwrap();
    wrong.words = "tiger-tiger-tiger".into();

    let second = std::sync::Arc::new(Store::open_in_memory().unwrap());
    let joining = {
        let second = second.clone();
        std::thread::spawn(move || {
            uwussh_sync::join(&second, &wrong, PASSWORD, "LVLaptop", protect, deadline)
        })
    };
    assert!(
        uwussh_sync::flow::wait_for_device(&first, &server, &offer, unprotect, deadline).is_err(),
        "the handover must not happen"
    );
    assert!(joining.join().unwrap().is_err());

    // The account still has one device, and the other store is untouched.
    assert_eq!(server.devices().unwrap().len(), 1);
    assert!(second.vault_header().unwrap().is_none());
}

// ── Teams ───────────────────────────────────────────────────────────────────
//
// The client's side of teams was written against a server it made up. These
// run it against this one: its member key, its wraps, its rotation and its
// mailbox, over HTTP, with nothing spoken by hand except where the point is
// what the server says to a client that tries what its own store refuses.

use uuid::Uuid;
use uwussh_store::{KeymapDraft, SpaceHostDraft, Spaces, TeamRole};
use uwussh_sync::team::TeamApi;
use uwussh_sync::{MemberState, TeamPass, Teams};

/// One device of one account, with its folder of spaces.
struct Member {
    folder: std::path::PathBuf,
    spaces: Spaces,
    server: Server,
    account: Uuid,
    /// The account key, on the device that made it.
    kit: Option<AccountKey>,
}

impl Drop for Member {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.folder);
    }
}

fn spaces() -> (std::path::PathBuf, Spaces) {
    let folder = std::env::temp_dir().join(format!("uwusync-teams-{}", Uuid::now_v7()));
    let spaces = Spaces::open(&folder.join("uwussh.db")).unwrap();
    (folder, spaces)
}

impl Member {
    /// A new account on the server, as the app makes one.
    fn new(running: &Running, device: &str) -> Self {
        let (folder, spaces) = spaces();
        spaces.main().create_vault_with(PASSWORD, KDF).unwrap();
        let setup = setup_code(running);
        let (server, paired) =
            uwussh_sync::create_account(&spaces.main(), &setup, PASSWORD, device, protect).unwrap();
        Self {
            folder,
            spaces,
            server,
            account: paired.account_id,
            kit: paired.recovery,
        }
    }

    /// Another device of the same account, enrolled with the master password.
    fn second(&self, running: &Running, device: &str) -> Self {
        let kit = self.kit.as_ref().expect("the first device's kit");
        let header = self.spaces.main().vault_header().unwrap().unwrap();
        let login_key = header.login_key(PASSWORD, Some(kit)).unwrap();
        let enrolment = self.server.enrolment_token().unwrap();
        let (seed, public_key) = device_key();
        let joining = Server::connect(&running.url, None).unwrap();
        let admitted = joining
            .enrol(&EnrolDevice {
                enrolment: enrolment.token,
                auth_key: b64::encode(*login_key),
                device: NewDevice {
                    name: device.into(),
                    public_key,
                },
            })
            .unwrap();
        let server = joining.as_device(admitted.account_id, admitted.device_id, &seed);
        let downloaded = from_wire(&server.vault().unwrap()).unwrap();
        let key = downloaded
            .unlock_with(PASSWORD, Some(kit))
            .unwrap()
            .export_key();
        let (folder, spaces) = spaces();
        spaces.main().adopt_vault(&downloaded, key).unwrap();
        Self {
            folder,
            spaces,
            server,
            account: self.account,
            kit: None,
        }
    }

    fn teams<R>(&self, f: impl FnOnce(&Teams<'_, Server>) -> R) -> R {
        let main = self.spaces.main_id();
        f(&Teams::new(&self.spaces, &main, &self.server))
    }

    /// What every sync of the server does: the account's own mailbox, then
    /// its teams.
    fn pass(&self) -> TeamPass {
        let own = sync_once(&self.spaces.main(), &self.server).unwrap();
        assert_eq!(own.apply.rejected, 0, "{own:?}");
        self.teams(|teams| teams.pass()).unwrap()
    }

    fn fingerprint(&self) -> String {
        self.pass().status.fingerprint.expect("a member key")
    }

    fn space(&self, team: Uuid) -> Option<uwussh_store::SpaceHandle> {
        self.spaces.team_space(&self.spaces.main_id(), team)
    }

    fn add(
        &self,
        team: Uuid,
        name: &str,
        password: Option<&str>,
    ) -> Result<Uuid, uwussh_store::StoreError> {
        let mut draft = host(name, "192.0.2.10");
        if let Some(password) = password {
            draft.password = PasswordChange::Set {
                value: SecretText::new(password),
            };
        }
        self.spaces
            .save_host(SpaceHostDraft {
                draft,
                space: Some(self.space(team).expect("the team's space").id),
            })
            .map(|saved| saved.host.id)
    }

    /// The names of the hosts the team has on this device.
    fn hosts(&self, team: Uuid) -> Vec<String> {
        self.space(team)
            .map_or_else(Vec::new, |space| names(&space.store))
    }

    fn password(&self, team: Uuid, host: Uuid) -> Vec<u8> {
        let space = self.space(team).expect("the team's space");
        space
            .store
            .reveal_host_password(host)
            .unwrap()
            .as_slice()
            .to_vec()
    }
}

/// `owner` invites, `newcomer` joins and waits, and `owner` lets them in
/// after comparing the fingerprint the newcomer's own device shows.
fn admit(owner: &Member, team: Uuid, newcomer: &Member, role: TeamRole) {
    let invite = owner.teams(|teams| teams.invite(team, role)).unwrap();
    let joined = newcomer
        .teams(|teams| teams.join(&invite.code.expect("a code, once"), "Somebody"))
        .unwrap();
    assert_eq!((joined.id, joined.state), (team, MemberState::Pending));

    // Waiting: the team's name, and nothing of what is in it.
    let waiting = newcomer.pass();
    assert_eq!(waiting.status.teams[0].state, MemberState::Pending);
    assert!(newcomer.space(team).is_none());
    assert_eq!(
        team_error(newcomer.server.pull(team, 0, 10)),
        "membership-pending"
    );

    let seen = newcomer.fingerprint();
    let listed = owner.teams(|teams| teams.members(team)).unwrap();
    let theirs = listed
        .iter()
        .find(|member| member.account_id == newcomer.account)
        .expect("the newcomer, listed");
    assert_eq!(theirs.fingerprint, seen, "what both sides compare");
    assert_eq!(
        team_error(owner.teams(|teams| teams.confirm(team, newcomer.account, "0000-0000"))),
        "identity-changed",
        "and nothing is wrapped for a key nobody compared"
    );
    owner
        .teams(|teams| teams.confirm(team, newcomer.account, &seen))
        .unwrap();
    let pass = newcomer.pass();
    assert!(pass.spaces_changed);
    assert_eq!(pass.status.teams[0].state, MemberState::Active);
}

fn team_error<T: std::fmt::Debug>(result: Result<T, uwussh_sync::TeamError>) -> String {
    match result {
        Err(error) => error.code().unwrap_or("none").to_string(),
        Ok(value) => panic!("should have been refused: {value:?}"),
    }
}

fn team_epoch(running: &Running, team: Uuid) -> (u64, bool) {
    running
        .state
        .db
        .lock()
        .query_row(
            "SELECT epoch, needs_rotation FROM teams WHERE id = ?1",
            [team.to_string()],
            |row| Ok((row.get::<_, i64>(0)? as u64, row.get(1)?)),
        )
        .unwrap()
}

#[test]
fn what_one_member_saves_in_a_team_the_other_reads_and_the_server_does_not() {
    let running = start_with(Registration::Invite);
    let (olive, ben) = (
        Member::new(&running, "LVDesk1"),
        Member::new(&running, "Bens"),
    );

    let status = olive.pass().status;
    assert!(status.supported && status.enabled && status.may_create);
    assert!(status.fingerprint.is_none() && status.teams.is_empty());

    let made = olive.teams(|teams| teams.create("Ops", "Olive")).unwrap();
    let team = made.id;
    assert_eq!(
        (made.role, made.state),
        (TeamRole::Owner, MemberState::Active)
    );
    // Made with a key nobody opens, and given its real one at once.
    assert_eq!(team_epoch(&running, team), (2, false));

    admit(&olive, team, &ben, TeamRole::Editor);
    let bastion = olive.add(team, "bastion", Some("hunter2")).unwrap();
    assert!(olive.pass().records_changed);
    assert!(ben.pass().records_changed);
    assert_eq!(ben.hosts(team), ["bastion"]);
    assert_eq!(ben.password(team, bastion), b"hunter2");

    // And back: an editor writes.
    ben.add(team, "db", None).unwrap();
    ben.pass();
    olive.pass();
    assert_eq!(olive.hosts(team), ["bastion", "db"]);

    // What the server holds of it reads as nothing.
    let blobs: Vec<Vec<u8>> = {
        let held = running.state.db.lock();
        let mut rows = held.prepare("SELECT blob FROM team_records").unwrap();
        let blobs = rows.query_map([], |row| row.get(0)).unwrap();
        blobs.collect::<rusqlite::Result<_>>().unwrap()
    };
    assert!(
        blobs.len() >= 4,
        "two hosts, a password and whatever else the team keeps"
    );
    for blob in &blobs {
        let text = String::from_utf8_lossy(blob).to_string();
        for secret in ["bastion", "192.0.2.10", "hunter2"] {
            assert!(!text.contains(secret), "{secret} must not be readable");
        }
    }

    // ── The accounts' own vaults go on as before ───────────────────────────
    let mut own = host("nas", "192.0.2.9");
    own.password = PasswordChange::Set {
        value: SecretText::new("swordfish"),
    };
    let nas = olive.spaces.main().save_host(own).unwrap().id;
    let keys = KeymapDraft {
        bindings: [("terminal:clear".to_string(), Vec::new())].into(),
        texts: Vec::new(),
    };
    olive.spaces.main().save_keymap("other", keys).unwrap();
    olive.pass();

    // Another device of the account gets its own vault with the keymap, and
    // opens the team with the member key the server kept sealed for it.
    let laptop = olive.second(&running, "LVLaptop");
    let pass = laptop.pass();
    assert_eq!(pass.status.fingerprint, olive.pass().status.fingerprint);
    assert_eq!(names(&laptop.spaces.main()), ["nas"]);
    assert_eq!(
        laptop
            .spaces
            .main()
            .reveal_host_password(nas)
            .unwrap()
            .as_slice(),
        b"swordfish"
    );
    let keymap = laptop.spaces.main().keymap("other").unwrap();
    assert!(keymap.bindings.contains_key("terminal:clear"));
    assert_eq!(laptop.hosts(team), ["bastion", "db"]);
    assert_eq!(laptop.password(team, bastion), b"hunter2");
    // What the account wrote down about the team — which key it has, whose
    // key was compared — came with the account's own records.
    let (desk, lap) = (olive.spaces.main(), laptop.spaces.main());
    let noted = desk
        .team_key_record(team)
        .unwrap()
        .expect("the team's key, noted");
    assert_eq!(noted.epoch, 2);
    assert_eq!(lap.team_key_record(team).unwrap(), Some(noted));
    let pin = desk
        .team_pin(team, ben.account)
        .unwrap()
        .expect("Ben's key, compared");
    assert_eq!(lap.team_pin(team, ben.account).unwrap(), Some(pin));
    let listed = laptop.teams(|teams| teams.members(team)).unwrap();
    assert!(
        listed.iter().all(|member| member.confirmed == Some(true)),
        "{listed:?}"
    );

    // Nothing crossed over, in either direction, on either account.
    ben.pass();
    assert!(names(&ben.spaces.main()).is_empty());
    assert!(ben
        .spaces
        .main()
        .keymap("other")
        .unwrap()
        .bindings
        .is_empty());
    assert_eq!(names(&olive.spaces.main()), ["nas"]);
    assert_eq!(olive.hosts(team), ["bastion", "db"]);
    let (own_kinds, team_kinds): (i64, i64) = running
        .state
        .db
        .lock()
        .query_row(
            "SELECT (SELECT count(*) FROM records WHERE id = ?1),
                    (SELECT count(*) FROM team_records WHERE id = ?1)",
            [uwussh_store::keymap_id("other").unwrap().to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((own_kinds, team_kinds), (1, 0));
}

#[test]
fn a_reader_reads_and_is_refused_a_write_by_the_store_and_by_the_server() {
    let running = start_with(Registration::Invite);
    let (olive, rita) = (
        Member::new(&running, "LVDesk1"),
        Member::new(&running, "Ritas"),
    );
    let team = olive
        .teams(|teams| teams.create("Ops", "Olive"))
        .unwrap()
        .id;
    admit(&olive, team, &rita, TeamRole::Reader);
    olive.add(team, "bastion", None).unwrap();
    olive.pass();
    rita.pass();
    assert_eq!(rita.hosts(team), ["bastion"]);

    // The client does not try…
    assert!(rita.space(team).unwrap().read_only);
    assert!(rita.add(team, "mine", None).is_err());
    let before = running
        .state
        .db
        .lock()
        .query_row("SELECT seq FROM teams", [], |row| row.get::<_, i64>(0))
        .unwrap();
    rita.pass();

    // …and one that did is told no: here, a record of the team's own, sent
    // back as it came.
    let (epoch, _) = team_epoch(&running, team);
    let page = rita.server.pull(team, 0, 10).unwrap();
    assert_eq!((page.epoch, page.role), (epoch, TeamRole::Reader));
    let mut edit = page.page.envelopes[0].clone();
    edit.base_seq = edit.seq.unwrap_or(0);
    assert_eq!(
        team_error(rita.server.push(team, epoch, vec![edit.clone()])),
        "forbidden"
    );
    let after = running
        .state
        .db
        .lock()
        .query_row("SELECT seq FROM teams", [], |row| row.get::<_, i64>(0))
        .unwrap();
    assert_eq!(before, after);
    // Nor does a reader invite, or confirm, or rotate.
    assert_eq!(
        team_error(rita.teams(|teams| teams.invite(team, TeamRole::Editor))),
        "forbidden"
    );

    // Made an editor, the same device writes — and the owner's push under a
    // key that is not the team's is the other refusal a client acts on.
    olive
        .teams(|teams| teams.set_role(team, rita.account, TeamRole::Editor))
        .unwrap();
    assert!(rita.pass().spaces_changed);
    rita.add(team, "mine", None).unwrap();
    rita.pass();
    olive.pass();
    assert_eq!(olive.hosts(team), ["bastion", "mine"]);
    match olive.server.push(team, epoch - 1, vec![edit]) {
        Err(uwussh_sync::TeamError::Refused {
            code, epoch: now, ..
        }) => {
            assert_eq!((code.as_str(), now), ("stale-epoch", Some(epoch)));
        }
        other => panic!("an old epoch must be refused: {other:?}"),
    }
}

#[test]
fn a_removed_member_reads_nothing_more_and_who_stays_reads_everything() {
    let running = start_with(Registration::Invite);
    let (olive, ben, cleo) = (
        Member::new(&running, "LVDesk1"),
        Member::new(&running, "Bens"),
        Member::new(&running, "Cleos"),
    );
    let team = olive
        .teams(|teams| teams.create("Ops", "Olive"))
        .unwrap()
        .id;
    admit(&olive, team, &ben, TeamRole::Editor);
    admit(&olive, team, &cleo, TeamRole::Editor);
    let bastion = olive.add(team, "bastion", Some("hunter2")).unwrap();
    olive.add(team, "db", None).unwrap();
    olive.pass();
    ben.pass();
    cleo.pass();
    assert_eq!(ben.hosts(team), ["bastion", "db"]);
    // Cleo has an edit nobody has seen when the key changes.
    cleo.add(team, "cleo's", None).unwrap();
    let old_key = cleo.space(team).unwrap().store.team_key().unwrap();
    let (old_epoch, _) = team_epoch(&running, team);

    // ── Out, and a new key in the same breath ──────────────────────────────
    let removal = olive
        .teams(|teams| teams.remove(team, ben.account))
        .unwrap();
    assert!(removal.rotated, "the owner confirmed everybody who stays");
    let known = removal.hosts;
    assert_eq!(known.len(), 1, "the login Ben may still know: {known:?}");
    assert_eq!((known[0].id, known[0].name.as_str()), (bastion, "bastion"));
    assert_eq!(team_epoch(&running, team), (old_epoch + 1, false));
    let kept: i64 = running
        .state
        .db
        .lock()
        .query_row(
            "SELECT count(*) FROM team_records WHERE deleted = 0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        kept >= 3,
        "everything is there again, under the new key: {kept}"
    );

    // Ben: the server knows no such team for him, with the token he has and
    // the key he kept, and his device lets go of it.
    assert_eq!(team_error(ben.server.pull(team, 0, 10)), "not-found");
    assert_eq!(team_error(ben.server.members(team)), "not-found");
    assert!(ben.server.teams().unwrap().is_empty());
    let pass = ben.pass();
    assert!(pass.spaces_changed && pass.status.teams.is_empty());
    assert!(ben.space(team).is_none());

    // Written after the rotation.
    let fresh = olive.add(team, "after", Some("tr0ub4dor")).unwrap();
    olive.pass();

    // Cleo follows: the new key, everything from before, what came after,
    // and her own edit sealed again and sent.
    cleo.pass();
    let space = cleo.space(team).unwrap();
    assert_eq!(
        space.store.team_state().unwrap().unwrap().epoch,
        old_epoch + 1
    );
    assert_ne!(*old_key, *space.store.team_key().unwrap());
    assert_eq!(cleo.hosts(team), ["after", "bastion", "cleo's", "db"]);
    assert_eq!(cleo.password(team, bastion), b"hunter2");
    assert_eq!(cleo.password(team, fresh), b"tr0ub4dor");
    olive.pass();
    assert_eq!(olive.hosts(team), ["after", "bastion", "cleo's", "db"]);

    // The accounts' own vaults never noticed.
    for member in [&olive, &ben, &cleo] {
        member
            .spaces
            .main()
            .save_host(host("own", "192.0.2.20"))
            .unwrap();
        member.pass();
        assert_eq!(names(&member.spaces.main()), ["own"]);
    }
    let own: i64 = running
        .state
        .db
        .lock()
        .query_row(
            "SELECT count(DISTINCT account_id) FROM records",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(own, 3);
}

#[test]
fn an_admin_gives_the_team_a_new_key_only_after_comparing_who_stays() {
    let running = start_with(Registration::Invite);
    let (olive, ada, cleo, dan) = (
        Member::new(&running, "LVDesk1"),
        Member::new(&running, "Adas"),
        Member::new(&running, "Cleos"),
        Member::new(&running, "Dans"),
    );
    let team = olive
        .teams(|teams| teams.create("Ops", "Olive"))
        .unwrap()
        .id;
    admit(&olive, team, &ada, TeamRole::Admin);
    admit(&olive, team, &cleo, TeamRole::Editor);
    admit(&olive, team, &dan, TeamRole::Editor);
    let bastion = olive.add(team, "bastion", Some("hunter2")).unwrap();
    for member in [&olive, &ada, &cleo, &dan] {
        member.pass();
    }
    assert_eq!(dan.hosts(team), ["bastion"]);
    let (old_epoch, _) = team_epoch(&running, team);
    // Read off the two devices now: Olive's own next pass would give the
    // team its key itself, she compared everybody.
    let (seen_olive, seen_cleo) = (olive.fingerprint(), cleo.fingerprint());

    // Ada was let in by Olive and has compared nobody's key herself. She
    // may take Dan out — the server says so — but hands no key to people
    // she only knows from the server's list.
    let removal = ada.teams(|teams| teams.remove(team, dan.account)).unwrap();
    assert!(!removal.rotated);
    assert_eq!(removal.hosts.len(), 1);
    assert_eq!(team_epoch(&running, team), (old_epoch, true));
    assert_eq!(team_error(dan.server.pull(team, 0, 10)), "not-found");

    let waiting = ada.pass();
    let info = &waiting.status.teams[0];
    assert!(info.needs_rotation);
    let attention = info.attention.as_ref().expect("why there is no new key");
    assert_eq!(
        attention.kind,
        uwussh_sync::AttentionKind::MemberUnconfirmed
    );
    assert_eq!(team_epoch(&running, team), (old_epoch, true));
    // Meanwhile the team works as it did.
    assert_eq!(ada.hosts(team), ["bastion"]);
    // That a key is owed, her device keeps with the team's space.
    let state = ada.space(team).unwrap().store.team_state().unwrap();
    assert!(state.unwrap().rotation_owed);

    // She compares, one after the other; the server hears nothing of it.
    let listed = ada.teams(|teams| teams.members(team)).unwrap();
    assert_eq!(listed.len(), 3);
    for member in &listed {
        assert_eq!(member.confirmed, Some(member.me), "{member:?}");
    }
    for (other, seen) in [(&olive, &seen_olive), (&cleo, &seen_cleo)] {
        ada.teams(|teams| teams.confirm(team, other.account, seen))
            .unwrap();
        assert_eq!(team_epoch(&running, team), (old_epoch, true));
    }

    // Her next pass gives the team its key.
    let pass = ada.pass();
    assert!(
        pass.status.teams[0].attention.is_none(),
        "{:?}",
        pass.status
    );
    assert!(!pass.status.teams[0].needs_rotation);
    assert_eq!(team_epoch(&running, team), (old_epoch + 1, false));
    let after = ada.add(team, "after", Some("tr0ub4dor")).unwrap();
    ada.pass();

    let state = ada.space(team).unwrap().store.team_state().unwrap();
    assert!(!state.unwrap().rotation_owed);
    // Which key the team has now, and whom she compared, went up with her
    // own records: a second device of hers knows both.
    let tablet = ada.second(&running, "AdasTablet");
    sync_once(&tablet.spaces.main(), &tablet.server).unwrap();
    let (desk, other) = (ada.spaces.main(), tablet.spaces.main());
    let noted = desk.team_key_record(team).unwrap().expect("the key, noted");
    assert_eq!(noted.epoch, old_epoch + 1);
    assert_eq!(other.team_key_record(team).unwrap(), Some(noted));
    assert!(!other.team_owes_key(team).unwrap());
    for member in [&olive, &cleo] {
        let pin = desk.team_pin(team, member.account).unwrap();
        assert!(pin.is_some());
        assert_eq!(other.team_pin(team, member.account).unwrap(), pin);
    }

    // Everybody who is left reads on, under a key an admin made.
    for member in [&olive, &cleo] {
        member.pass();
        let space = member.space(team).unwrap();
        assert_eq!(
            space.store.team_state().unwrap().unwrap().epoch,
            old_epoch + 1
        );
        assert_eq!(member.hosts(team), ["after", "bastion"]);
        assert_eq!(member.password(team, bastion), b"hunter2");
        assert_eq!(member.password(team, after), b"tr0ub4dor");
    }
    // And Dan's device lets go.
    assert!(dan.pass().status.teams.is_empty());
    assert!(dan.space(team).is_none());
}
