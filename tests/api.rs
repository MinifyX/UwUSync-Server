//! The server over real HTTP, driven the way a device drives it.
//!
//! Each test starts a server on a port of its own with a database in memory,
//! then speaks the actual protocol: create an account, sign a challenge, push,
//! pull, join a second device, revoke one. What is checked is both halves of
//! the job — that a device which does everything right gets its records
//! across, and that one which does not gets nowhere.

use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use std::net::SocketAddr;
use uuid::Uuid;
use uwussh_proto::{EntityKind, Envelope, Hlc, PullResponse, PushResponse, SCHEMA_VERSION};
use uwusync_server::api;
use uwusync_server::config::Registration;
use uwusync_server::db::Db;
use uwusync_server::{AppState, Config};

/// A server on a port of its own, with nothing on disk.
struct Server {
    base: String,
    state: AppState,
    client: reqwest::Client,
}

async fn start(registration: Registration) -> Server {
    start_with(Config {
        registration,
        ..Config::default()
    })
    .await
}

async fn start_with(config: Config) -> Server {
    // The client crate brings in a rustls that expects its provider to be
    // chosen, and cargo unifies features across the test binary. Choosing it
    // here is what the server itself does when it serves.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let state = AppState::new(Db::open_in_memory().unwrap(), config);
    let app = api::router(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    Server {
        base: format!("http://{address}"),
        state,
        client: reqwest::Client::new(),
    }
}

impl Server {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn invite(&self) -> String {
        let conn = self.state.db.lock();
        uwusync_server::db::invites::create_invite(&conn, 60_000).unwrap()
    }

    /// The vault header a device uploads. Its contents are opaque here — the
    /// server never opens it, which is the point.
    fn vault(vault_id: Uuid) -> serde_json::Value {
        json!({
            "vaultId": vault_id,
            "kdfMemoryKib": 65536,
            "kdfTimeCost": 3,
            "kdfParallelism": 4,
            "salt": "c2FsdHktc2FsdHktc2FsdA",
            "wrappedNonce": "bm9uY2Utbm9uY2Utbm9uY2U",
            "wrappedBlob": "d3JhcHBlZC12YXVsdC1rZXk",
        })
    }
}

/// A device: its key, its ids, and its token.
struct Device {
    signing: SigningKey,
    account: Uuid,
    id: Uuid,
    token: String,
    vault_id: Uuid,
}

/// The login key a device derives from the master password and the account
/// key. Here it is just the password's stand-in — the server only ever sees
/// these 32 bytes and stores their hash.
fn login_key(password: &str) -> String {
    let mut key = [0u8; 32];
    for (slot, byte) in key.iter_mut().zip(password.bytes().cycle()) {
        *slot = byte;
    }
    uwusync_server::b64::encode(key)
}

impl Device {
    fn new_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    async fn create_account(server: &Server, invite: &str, password: &str, seed: u8) -> Device {
        let signing = Self::new_key(seed);
        let vault_id = Uuid::now_v7();
        let response = server
            .client
            .post(server.url("/v1/accounts"))
            .json(&json!({
                "invite": invite,
                "vault": Server::vault(vault_id),
                "authKey": login_key(password),
                "device": {
                    "name": "LVDesk1",
                    "publicKey": uwusync_server::b64::encode(signing.verifying_key().to_bytes()),
                },
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{:?}", response.text().await);
        let body: serde_json::Value = response.json().await.unwrap();
        Device {
            signing,
            account: body["accountId"].as_str().unwrap().parse().unwrap(),
            id: body["deviceId"].as_str().unwrap().parse().unwrap(),
            token: body["token"].as_str().unwrap().to_string(),
            vault_id,
        }
    }

    /// Sign in again with the device key: challenge, signature, token.
    async fn login(&mut self, server: &Server) -> reqwest::StatusCode {
        let challenge: serde_json::Value = server
            .client
            .post(server.url("/v1/session/challenge"))
            .json(&json!({ "deviceId": self.id }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let challenge =
            uwusync_server::b64::decode(challenge["challenge"].as_str().unwrap()).unwrap();
        let material = uwusync_server::auth::session_material(self.account, self.id, &challenge);
        let signature = self.signing.sign(&material).to_bytes();

        let response = server
            .client
            .post(server.url("/v1/session"))
            .json(&json!({
                "deviceId": self.id,
                "signature": uwusync_server::b64::encode(signature),
            }))
            .send()
            .await
            .unwrap();
        let status = response.status();
        if status == 200 {
            let body: serde_json::Value = response.json().await.unwrap();
            self.token = body["token"].as_str().unwrap().to_string();
        }
        status
    }

    fn envelope(&self, id: Uuid, base_seq: u64, blob: &[u8]) -> Envelope {
        Envelope {
            id,
            vault_id: self.vault_id,
            kind: EntityKind::Host,
            updated_at: Hlc::new(1_700_000_000_000, 0, 1),
            base_seq,
            deleted: false,
            nonce: vec![7; 24],
            blob: blob.to_vec(),
            seq: None,
        }
    }

    async fn push(&self, server: &Server, envelopes: &[Envelope]) -> PushResponse {
        let response = server
            .client
            .post(server.url("/v1/records"))
            .bearer_auth(&self.token)
            .json(&json!({ "schema": SCHEMA_VERSION, "envelopes": envelopes }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{:?}", response.text().await);
        response.json().await.unwrap()
    }

    async fn pull(&self, server: &Server, since: u64) -> PullResponse {
        let response = server
            .client
            .get(server.url(&format!("/v1/records?since={since}")))
            .bearer_auth(&self.token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{:?}", response.text().await);
        response.json().await.unwrap()
    }
}

#[tokio::test]
async fn a_device_creates_an_account_and_gets_its_records_across() {
    let server = start(Registration::Invite).await;
    let invite = server.invite().await;
    let device = Device::create_account(&server, &invite, "master", 1).await;

    let id = Uuid::now_v7();
    let pushed = device
        .push(&server, &[device.envelope(id, 0, b"sealed host")])
        .await;
    assert_eq!(pushed.accepted.len(), 1);
    assert_eq!(pushed.accepted[0].seq, 1);

    let page = device.pull(&server, 0).await;
    assert_eq!(page.envelopes.len(), 1);
    assert_eq!(page.envelopes[0].id, id);
    assert_eq!(page.envelopes[0].blob, b"sealed host".to_vec());
    assert!(!page.has_more);

    // And the device can sign in again tomorrow with the key it enrolled.
    let mut device = device;
    assert_eq!(device.login(&server).await, 200);
    assert_eq!(device.pull(&server, 0).await.envelopes.len(), 1);
}

#[tokio::test]
async fn a_second_device_joins_with_a_token_and_the_master_password() {
    let server = start(Registration::Invite).await;
    let invite = server.invite().await;
    let first = Device::create_account(&server, &invite, "master", 1).await;
    let id = Uuid::now_v7();
    first
        .push(&server, &[first.envelope(id, 0, b"from the first")])
        .await;

    // The device that is already in makes a one-time token. In the real flow
    // it travels to the other device through the pairing channel.
    let enrolment: serde_json::Value = server
        .client
        .post(server.url("/v1/devices/invite"))
        .bearer_auth(&first.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = enrolment["token"].as_str().unwrap().to_string();

    // Before it can prove anything, the joining device needs the salt and the
    // costs — and gets nothing it could attack offline.
    let params: serde_json::Value = server
        .client
        .post(server.url("/v1/vault/params"))
        .json(&json!({ "enrolment": token }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(params["salt"], "c2FsdHktc2FsdHktc2FsdA");
    assert!(params.get("wrappedBlob").is_none(), "{params}");

    let second_key = Device::new_key(2);
    let second_public = uwusync_server::b64::encode(second_key.verifying_key().to_bytes());
    let join = |password: &'static str| {
        let body = json!({
            "enrolment": token,
            "authKey": login_key(password),
            "device": { "name": "LVLaptop", "publicKey": second_public },
        });
        server
            .client
            .post(server.url("/v1/devices/enrol"))
            .json(&body)
            .send()
    };

    // The wrong master password gets nowhere — and does not burn the token.
    assert_eq!(join("wrong").await.unwrap().status(), 401);

    let response = join("master").await.unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    let second = Device {
        signing: second_key,
        account: body["accountId"].as_str().unwrap().parse().unwrap(),
        id: body["deviceId"].as_str().unwrap().parse().unwrap(),
        token: body["token"].as_str().unwrap().to_string(),
        vault_id: first.vault_id,
    };
    assert_eq!(second.account, first.account);

    // Now it may have the wrapped key, and everything the first device wrote.
    let header: serde_json::Value = server
        .client
        .get(server.url("/v1/vault"))
        .bearer_auth(&second.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(header["wrappedBlob"], "d3JhcHBlZC12YXVsdC1rZXk");

    let page = second.pull(&server, 0).await;
    assert_eq!(page.envelopes.len(), 1);
    assert_eq!(page.envelopes[0].blob, b"from the first".to_vec());

    // The token was spent: nobody joins twice with it.
    assert_eq!(join("master").await.unwrap().status(), 401);

    // And both devices show up in the list.
    let devices: serde_json::Value = server
        .client
        .get(server.url("/v1/devices"))
        .bearer_auth(&first.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(devices.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn two_devices_editing_one_record_meet_the_version_check() {
    let server = start(Registration::Invite).await;
    let invite = server.invite().await;
    let first = Device::create_account(&server, &invite, "master", 1).await;

    let id = Uuid::now_v7();
    first.push(&server, &[first.envelope(id, 0, b"one")]).await;
    first.push(&server, &[first.envelope(id, 1, b"two")]).await;

    // A device still believing version 1 is current is refused, and told what
    // the server holds instead.
    let response = first
        .push(&server, &[first.envelope(id, 1, b"three")])
        .await;
    assert!(response.accepted.is_empty());
    assert_eq!(response.conflicts.len(), 1);
    assert_eq!(response.conflicts[0].blob, b"two".to_vec());
    assert_eq!(response.conflicts[0].seq, Some(2));

    // Based on that, it goes through.
    let response = first
        .push(&server, &[first.envelope(id, 2, b"three")])
        .await;
    assert_eq!(response.accepted.len(), 1);
}

#[tokio::test]
async fn nothing_reaches_anyone_who_did_not_sign() {
    let server = start(Registration::Invite).await;
    let invite = server.invite().await;
    let device = Device::create_account(&server, &invite, "master", 1).await;

    for token in ["", "not-a-token", &format!("{}x", device.token)] {
        let response = server
            .client
            .get(server.url("/v1/records"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401, "with token {token:?}");
    }
    let response = server
        .client
        .get(server.url("/v1/records"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401, "and with no token at all");

    // A signature by the wrong key is no signature.
    let mut impostor = Device {
        signing: Device::new_key(9),
        account: device.account,
        id: device.id,
        token: String::new(),
        vault_id: device.vault_id,
    };
    assert_eq!(impostor.login(&server).await, 401);

    // Nor is one for a challenge that was already answered.
    let challenge: serde_json::Value = server
        .client
        .post(server.url("/v1/session/challenge"))
        .json(&json!({ "deviceId": device.id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let raw = uwusync_server::b64::decode(challenge["challenge"].as_str().unwrap()).unwrap();
    let material = uwusync_server::auth::session_material(device.account, device.id, &raw);
    let signature = uwusync_server::b64::encode(device.signing.sign(&material).to_bytes());
    let replay = json!({ "deviceId": device.id, "signature": signature });

    let first = server
        .client
        .post(server.url("/v1/session"))
        .json(&replay)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);
    let again = server
        .client
        .post(server.url("/v1/session"))
        .json(&replay)
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 401, "a challenge is answered once");
}

#[tokio::test]
async fn a_revoked_device_is_out_at_once() {
    let server = start(Registration::Invite).await;
    let invite = server.invite().await;
    let first = Device::create_account(&server, &invite, "master", 1).await;

    // A second device, so the first is not the last one standing.
    let enrolment: serde_json::Value = server
        .client
        .post(server.url("/v1/devices/invite"))
        .bearer_auth(&first.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let second_key = Device::new_key(2);
    let body: serde_json::Value = server
        .client
        .post(server.url("/v1/devices/enrol"))
        .json(&json!({
            "enrolment": enrolment["token"],
            "authKey": login_key("master"),
            "device": {
                "name": "LVLaptop",
                "publicKey": uwusync_server::b64::encode(second_key.verifying_key().to_bytes()),
            },
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut second = Device {
        signing: second_key,
        account: first.account,
        id: body["deviceId"].as_str().unwrap().parse().unwrap(),
        token: body["token"].as_str().unwrap().to_string(),
        vault_id: first.vault_id,
    };
    assert_eq!(second.pull(&server, 0).await.envelopes.len(), 0);

    assert_eq!(
        revoke(&server, &first, second.id, Some("master")).await,
        204
    );

    // The token it was holding is worthless from this moment.
    let response = server
        .client
        .get(server.url("/v1/records"))
        .bearer_auth(&second.token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    // And it cannot sign in again either.
    assert_eq!(second.login(&server).await, 401);

    // The last device standing cannot shut itself out: nobody would be left.
    assert_eq!(revoke(&server, &first, first.id, None).await, 400);
}

/// Revoke `target`, signed in as `by`, with the master password or without.
async fn revoke(
    server: &Server,
    by: &Device,
    target: Uuid,
    password: Option<&str>,
) -> reqwest::StatusCode {
    let body = match password {
        Some(password) => json!({ "currentAuthKey": login_key(password) }),
        None => json!({}),
    };
    server
        .client
        .post(server.url(&format!("/v1/devices/{target}/revoke")))
        .bearer_auth(&by.token)
        .json(&body)
        .send()
        .await
        .unwrap()
        .status()
}

/// An enrolment token made by `by`.
async fn enrolment_token(server: &Server, by: &Device) -> String {
    let enrolment: serde_json::Value = server
        .client
        .post(server.url("/v1/devices/invite"))
        .bearer_auth(&by.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    enrolment["token"].as_str().unwrap().to_string()
}

/// Join `first`'s account as a device with key `seed`.
async fn join(server: &Server, token: &str, password: &str, seed: u8) -> reqwest::Response {
    let key = Device::new_key(seed);
    server
        .client
        .post(server.url("/v1/devices/enrol"))
        .json(&json!({
            "enrolment": token,
            "authKey": login_key(password),
            "device": {
                "name": format!("device {seed}"),
                "publicKey": uwusync_server::b64::encode(key.verifying_key().to_bytes()),
            },
        }))
        .send()
        .await
        .unwrap()
}

async fn second_device(server: &Server, first: &Device, seed: u8) -> Device {
    let token = enrolment_token(server, first).await;
    let response = join(server, &token, "master", seed).await;
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    Device {
        signing: Device::new_key(seed),
        account: first.account,
        id: body["deviceId"].as_str().unwrap().parse().unwrap(),
        token: body["token"].as_str().unwrap().to_string(),
        vault_id: first.vault_id,
    }
}

#[tokio::test]
async fn shutting_another_device_out_takes_the_master_password() {
    let server = start(Registration::Open).await;
    let first = Device::create_account(&server, "", "master", 1).await;
    let second = second_device(&server, &first, 2).await;
    let third = second_device(&server, &first, 3).await;

    // A stolen laptop has its token, and that is all it has.
    assert_eq!(revoke(&server, &second, first.id, None).await, 403);
    assert_eq!(
        revoke(&server, &second, first.id, Some("a guess")).await,
        403
    );
    assert_eq!(
        first.pull(&server, 0).await.envelopes.len(),
        0,
        "and the owner's device is still in"
    );
    // Guessing on is slowed down for that laptop alone: it cannot use up the
    // tries of the owner's devices, and so cannot keep itself from being
    // revoked.
    let mut slowed = false;
    for _ in 0..12 {
        if revoke(&server, &second, first.id, Some("another guess")).await == 429 {
            slowed = true;
            break;
        }
    }
    assert!(slowed, "ten wrong proofs an hour from one device");

    // The owner, with the password, can shut the laptop out.
    assert_eq!(
        revoke(&server, &first, second.id, Some("master")).await,
        204
    );
    // And a device may always take itself out.
    assert_eq!(revoke(&server, &third, third.id, None).await, 204);
}

#[tokio::test]
async fn a_revoked_device_takes_its_tokens_and_pairings_along() {
    let server = start(Registration::Open).await;
    let first = Device::create_account(&server, "", "master", 1).await;
    let second = second_device(&server, &first, 2).await;

    // Before it is shut out, it makes a token and opens a pairing.
    let token = enrolment_token(&server, &second).await;
    let opened: serde_json::Value = server
        .client
        .post(server.url("/v1/pair"))
        .bearer_auth(&second.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let pairing = opened["id"].as_str().unwrap().to_string();

    assert_eq!(
        revoke(&server, &first, second.id, Some("master")).await,
        204
    );

    assert_eq!(
        join(&server, &token, "master", 9).await.status(),
        401,
        "its token died with it"
    );
    let gone = server
        .client
        .get(server.url(&format!("/v1/pair/{pairing}?side=b")))
        .header("x-uwussh-pair-claim", "somebody")
        .send()
        .await
        .unwrap();
    assert_eq!(gone.status(), 404, "and so did its pairing");
}

#[tokio::test]
async fn an_enrolment_token_is_no_licence_to_guess_the_password() {
    let server = start(Registration::Open).await;
    let first = Device::create_account(&server, "", "master", 1).await;
    let token = enrolment_token(&server, &first).await;
    // A typo or two is fine...
    assert_eq!(join(&server, &token, "mastr", 2).await.status(), 401);
    // ...but five wrong passwords use the token up, the right one included.
    for _ in 0..4 {
        assert_eq!(join(&server, &token, "guess", 2).await.status(), 401);
    }
    assert_eq!(join(&server, &token, "master", 2).await.status(), 401);
}

#[tokio::test]
async fn open_registration_counts_every_account_it_makes() {
    let server = start(Registration::Open).await;
    for seed in 0..5 {
        Device::create_account(&server, "", "master", seed).await;
    }
    let response = server
        .client
        .post(server.url("/v1/accounts"))
        .json(&json!({
            "invite": "",
            "vault": Server::vault(Uuid::now_v7()),
            "authKey": login_key("master"),
            "device": { "name": "x", "publicKey": uwusync_server::b64::encode([7u8; 32]) },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        429,
        "five an hour from one address, not more"
    );
}

#[tokio::test]
async fn a_full_server_takes_no_more_accounts_and_keeps_the_invite() {
    let server = start_with(Config {
        registration: Registration::Invite,
        max_accounts: 1,
        ..Config::default()
    })
    .await;
    let first = server.invite().await;
    Device::create_account(&server, &first, "master", 1).await;

    let second = server.invite().await;
    let response = server
        .client
        .post(server.url("/v1/accounts"))
        .json(&json!({
            "invite": second,
            "vault": Server::vault(Uuid::now_v7()),
            "authKey": login_key("master"),
            "device": { "name": "x", "publicKey": uwusync_server::b64::encode([8u8; 32]) },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "server-full");
    let open = uwusync_server::db::invites::count_open_invites(&server.state.db.lock()).unwrap();
    assert_eq!(open, 1, "the invite was not spent on a refusal");
}

#[tokio::test]
async fn a_push_of_several_mebibytes_gets_through() {
    // The records are the one endpoint that takes more than a few kilobytes,
    // and the limit it has is the one it says, not a framework's default.
    let server = start(Registration::Open).await;
    let device = Device::create_account(&server, "", "master", 1).await;
    let big = vec![3u8; uwussh_proto::MAX_BLOB_BYTES];
    let batch: Vec<Envelope> = (0..12)
        .map(|_| device.envelope(Uuid::now_v7(), 0, &big))
        .collect();
    let pushed = device.push(&server, &batch).await;
    assert_eq!(pushed.accepted.len(), 12);

    // Everything else stays small.
    let response = server
        .client
        .post(server.url("/v1/session/challenge"))
        .header("content-type", "application/json")
        .body(format!(
            "{{\"deviceId\":\"{}\",\"pad\":\"{}\"}}",
            device.id,
            "x".repeat(100 * 1024)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 413);
}

#[tokio::test]
async fn a_request_over_its_limit_is_turned_away_before_its_body_is_read() {
    let server = start(Registration::Open).await;
    let device = Device::create_account(&server, "", "master", 1).await;
    for seed in 2..=5 {
        Device::create_account(&server, "", "master", seed).await;
    }
    // Five accounts this hour from this address. The sixth request is refused
    // for that, not for what its body says: the body is never read.
    let response = server
        .client
        .post(server.url("/v1/accounts"))
        .header("content-type", "application/json")
        .body("not even json")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 429);

    // The same for pushes, whose bodies may be 16 MiB: a push that is one
    // too many is counted before it is read, whatever it holds.
    let mut statuses = Vec::new();
    for _ in 0..=uwusync_server::limits::PUSH.max {
        let response = server
            .client
            .post(server.url("/v1/records"))
            .bearer_auth(&device.token)
            .header("content-type", "application/json")
            .body("not even json")
            .send()
            .await
            .unwrap();
        statuses.push(response.status());
    }
    assert_eq!(statuses[0], 400, "read and refused for what it says");
    assert_eq!(statuses.last().copied().unwrap(), 429);
}

#[tokio::test]
async fn an_account_holds_what_the_server_allows_and_no_more() {
    let server = start_with(Config {
        registration: Registration::Open,
        quota: uwusync_server::db::records::Quota {
            records: 3,
            bytes: 1024 * 1024,
            ..Default::default()
        },
        ..Config::default()
    })
    .await;
    let device = Device::create_account(&server, "", "master", 1).await;
    let three: Vec<Envelope> = (0..3)
        .map(|_| device.envelope(Uuid::now_v7(), 0, b"a host"))
        .collect();
    device.push(&server, &three).await;

    let response = server
        .client
        .post(server.url("/v1/records"))
        .bearer_auth(&device.token)
        .json(&json!({
            "schema": SCHEMA_VERSION,
            "envelopes": [device.envelope(Uuid::now_v7(), 0, b"one more")],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 413);
    assert_eq!(device.pull(&server, 0).await.envelopes.len(), 3);
}

#[tokio::test]
async fn records_of_one_account_never_reach_another() {
    let server = start(Registration::Open).await;
    let mine = Device::create_account(&server, "", "master", 1).await;
    let theirs = Device::create_account(&server, "", "other", 2).await;
    theirs
        .push(&server, &[theirs.envelope(Uuid::now_v7(), 0, b"theirs")])
        .await;

    assert!(mine.pull(&server, 0).await.envelopes.is_empty());

    // Nor can one account's device push into the other's vault.
    let mut stranger = mine.envelope(Uuid::now_v7(), 0, b"mine");
    stranger.vault_id = theirs.vault_id;
    let response = server
        .client
        .post(server.url("/v1/records"))
        .bearer_auth(&mine.token)
        .json(&json!({ "schema": SCHEMA_VERSION, "envelopes": [stranger] }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);

    // And the device list is the account's own.
    let devices: serde_json::Value = server
        .client
        .get(server.url("/v1/devices"))
        .bearer_auth(&mine.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(devices.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn an_invite_lets_exactly_one_account_in() {
    let server = start(Registration::Invite).await;
    let invite = server.invite().await;
    Device::create_account(&server, &invite, "master", 1).await;

    for code in [invite.as_str(), "MADE-UPCO-DEXX", ""] {
        let response = server
            .client
            .post(server.url("/v1/accounts"))
            .json(&json!({
                "invite": code,
                "vault": Server::vault(Uuid::now_v7()),
                "authKey": login_key("master"),
                "device": { "name": "another", "publicKey": uwusync_server::b64::encode([3u8; 32]) },
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401, "with {code:?}");
    }
}

#[tokio::test]
async fn a_closed_server_takes_no_new_accounts() {
    let server = start(Registration::Closed).await;
    // The same answer every time, and none of them counted: a closed server
    // has nothing to slow down, and nothing to fill its limiter with.
    for _ in 0..=uwusync_server::limits::ACCOUNTS.max {
        let response = server
            .client
            .post(server.url("/v1/accounts"))
            .json(&json!({
                "vault": Server::vault(Uuid::now_v7()),
                "authKey": login_key("master"),
                "device": { "name": "x", "publicKey": uwusync_server::b64::encode([4u8; 32]) },
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
    }
}

#[tokio::test]
async fn a_client_from_another_schema_is_turned_away_before_anything_is_stored() {
    let server = start(Registration::Open).await;
    let device = Device::create_account(&server, "", "master", 1).await;

    let response = server
        .client
        .post(server.url("/v1/records"))
        .bearer_auth(&device.token)
        .json(&json!({
            "schema": SCHEMA_VERSION + 1,
            "envelopes": [device.envelope(Uuid::now_v7(), 0, b"from the future")],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "schema");
    assert!(device.pull(&server, 0).await.envelopes.is_empty());
}

#[tokio::test]
async fn changing_the_master_password_takes_the_old_one() {
    let server = start(Registration::Open).await;
    let device = Device::create_account(&server, "", "master", 1).await;

    let change = |current: &'static str, next: &'static str, vault: Uuid| {
        server
            .client
            .put(server.url("/v1/vault/key"))
            .bearer_auth(&device.token)
            .json(&json!({
                "currentAuthKey": login_key(current),
                "vault": Server::vault(vault),
                "authKey": login_key(next),
            }))
            .send()
    };

    assert_eq!(
        change("not the password", "new", device.vault_id)
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        change("master", "new", Uuid::now_v7())
            .await
            .unwrap()
            .status(),
        400,
        "and it stays the same vault"
    );
    assert_eq!(
        change("master", "new", device.vault_id)
            .await
            .unwrap()
            .status(),
        204
    );

    // The new password is the one that counts now — which the next device to
    // join finds out.
    let enrolment: serde_json::Value = server
        .client
        .post(server.url("/v1/devices/invite"))
        .bearer_auth(&device.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let join = |password: &'static str| {
        server
            .client
            .post(server.url("/v1/devices/enrol"))
            .json(&json!({
                "enrolment": enrolment["token"],
                "authKey": login_key(password),
                "device": { "name": "next", "publicKey": uwusync_server::b64::encode([5u8; 32]) },
            }))
            .send()
    };
    assert_eq!(join("master").await.unwrap().status(), 401);
    assert_eq!(join("new").await.unwrap().status(), 200);
}

#[tokio::test]
async fn a_vault_too_cheap_to_guess_against_is_not_taken() {
    let server = start(Registration::Open).await;
    let mut cheap = Server::vault(Uuid::now_v7());
    cheap["kdfMemoryKib"] = json!(1024);
    cheap["kdfTimeCost"] = json!(1);
    let response = server
        .client
        .post(server.url("/v1/accounts"))
        .json(&json!({
            "vault": cheap,
            "authKey": login_key("master"),
            "device": { "name": "x", "publicKey": uwusync_server::b64::encode([6u8; 32]) },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(
        response.text().await.unwrap().contains("too cheap"),
        "and says why"
    );
    assert_eq!(
        uwusync_server::db::accounts::count(&server.state.db.lock()).unwrap(),
        0
    );

    // Nor as a new password on an account that is fine.
    let device = Device::create_account(&server, "", "master", 1).await;
    let mut cheap = Server::vault(device.vault_id);
    cheap["kdfTimeCost"] = json!(1);
    let response = server
        .client
        .put(server.url("/v1/vault/key"))
        .bearer_auth(&device.token)
        .json(&json!({
            "currentAuthKey": login_key("master"),
            "vault": cheap,
            "authKey": login_key("new"),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn a_device_hears_that_there_is_something_new() {
    let server = start(Registration::Open).await;
    let listener = Device::create_account(&server, "", "master", 1).await;

    let mut stream = server
        .client
        .get(server.url("/v1/events"))
        .bearer_auth(&listener.token)
        .send()
        .await
        .unwrap();
    assert_eq!(stream.status(), 200);

    // Wait until the stream is really subscribed, then push.
    for _ in 0..100 {
        if server.state.events.listeners(listener.account) > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    listener
        .push(
            &server,
            &[listener.envelope(Uuid::now_v7(), 0, b"new host")],
        )
        .await;

    let chunk = tokio::time::timeout(std::time::Duration::from_secs(5), stream.chunk())
        .await
        .expect("an event within five seconds")
        .unwrap()
        .expect("some bytes");
    let text = String::from_utf8_lossy(&chunk).to_string();
    assert!(text.contains("event: records"), "{text}");
    assert!(text.contains("data: 1"), "{text}");
}

#[tokio::test]
async fn the_health_check_says_nothing_about_the_accounts() {
    let server = start(Registration::Open).await;
    Device::create_account(&server, "", "master", 1).await;

    let body: serde_json::Value = server
        .client
        .get(server.url("/healthz"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["schema"], SCHEMA_VERSION);
    assert_eq!(body.as_object().unwrap().len(), 2, "{body}");
}

#[tokio::test]
async fn guessing_is_slowed_down() {
    let server = start(Registration::Open).await;
    let device = Device::create_account(&server, "", "master", 1).await;

    // The session bucket allows thirty tries a minute per address.
    let mut refused = false;
    for _ in 0..40 {
        let response = server
            .client
            .post(server.url("/v1/session"))
            .json(&json!({ "deviceId": device.id, "signature": uwusync_server::b64::encode([0u8; 64]) }))
            .send()
            .await
            .unwrap();
        if response.status() == 429 {
            refused = true;
            break;
        }
    }
    assert!(refused, "a guesser must run into a wall");
}

#[tokio::test]
async fn asking_for_made_up_devices_does_not_lock_out_the_real_ones() {
    let server = start(Registration::Open).await;
    let mut device = Device::create_account(&server, "", "master", 1).await;
    // From the very address the device signs in from, as every IPv6 client
    // does behind Docker's proxy: more challenges than a device may ask for
    // in a minute, each for a device that is not there.
    for _ in 0..=uwusync_server::limits::SESSION.max {
        let response = server
            .client
            .post(server.url("/v1/session/challenge"))
            .json(&json!({ "deviceId": Uuid::new_v4() }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }
    assert_eq!(device.login(&server).await, 200);
}

#[tokio::test]
async fn a_device_cannot_be_kept_from_signing_in_from_elsewhere() {
    let server = start_with(Config {
        registration: Registration::Open,
        trust_forwarded: true,
        ..Config::default()
    })
    .await;
    let mut device = Device::create_account(&server, "", "master", 1).await;
    // Somebody who knows the device's id uses up every try it has — at the
    // address they ask from.
    let mut refused = false;
    for _ in 0..=uwusync_server::limits::SESSION.max {
        let response = server
            .client
            .post(server.url("/v1/session"))
            .header("x-forwarded-for", "192.0.2.66")
            .json(&json!({ "deviceId": device.id, "signature": uwusync_server::b64::encode([0u8; 64]) }))
            .send()
            .await
            .unwrap();
        if response.status() == 429 {
            refused = true;
        }
    }
    assert!(refused);
    assert_eq!(
        device.login(&server).await,
        200,
        "the device itself, from its own address"
    );
}

// ── Pairing ──────────────────────────────────────────────────────────────────
//
// The server carries messages between two devices and understands none of
// them. What is checked here is that it carries them to the right side, that
// it cannot be used for anything else, and that a session is over when it is
// over.

#[tokio::test]
async fn two_devices_hand_a_secret_through_the_relay() {
    let server = start(Registration::Open).await;
    let first = Device::create_account(&server, "", "master", 1).await;

    let opened: serde_json::Value = server
        .client
        .post(server.url("/v1/pair"))
        .bearer_auth(&first.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = opened["id"].as_str().unwrap().to_string();
    assert_eq!(id.len(), 5, "a code somebody reads out loud");

    // Side a is the device that opened it, signed in; side b has no account
    // yet and holds its side with a secret it made up.
    let speaking_as = |side: &str, request: reqwest::RequestBuilder| match side {
        "a" => request.bearer_auth(&first.token),
        _ => request.header("x-uwussh-pair-claim", "the joining device's secret"),
    };
    let post = |side: &'static str, message: &'static [u8]| {
        speaking_as(
            side,
            server
                .client
                .post(server.url(&format!("/v1/pair/{id}")))
                .json(&json!({ "side": side, "message": uwusync_server::b64::encode(message) })),
        )
        .send()
    };
    let read = |side: &'static str, after: usize| {
        speaking_as(
            side,
            server
                .client
                .get(server.url(&format!("/v1/pair/{id}?side={side}&after={after}"))),
        )
        .send()
    };

    // The handshake: one message each way, then the sealed payload.
    assert_eq!(post("a", b"spake from a").await.unwrap().status(), 204);

    let mine: serde_json::Value = read("a", 0).await.unwrap().json().await.unwrap();
    assert!(
        mine["messages"].as_array().unwrap().is_empty(),
        "a device does not read its own message back"
    );

    let theirs: serde_json::Value = read("b", 0).await.unwrap().json().await.unwrap();
    assert_eq!(
        theirs["messages"][0],
        uwusync_server::b64::encode(b"spake from a")
    );
    assert_eq!(theirs["next"], 1);

    assert_eq!(post("b", b"spake from b").await.unwrap().status(), 204);
    assert_eq!(
        post("a", b"sealed account key").await.unwrap().status(),
        204
    );

    let theirs: serde_json::Value = read("b", 1).await.unwrap().json().await.unwrap();
    assert_eq!(
        theirs["messages"][0],
        uwusync_server::b64::encode(b"sealed account key"),
        "and only what it has not seen yet"
    );

    // Somebody who only knows the id speaks for neither side.
    let as_a = server
        .client
        .post(server.url(&format!("/v1/pair/{id}")))
        .json(&json!({ "side": "a", "message": uwusync_server::b64::encode(b"me too") }))
        .send()
        .await
        .unwrap();
    assert_eq!(as_a.status(), 401, "side a without the opener's token");
    let as_b = server
        .client
        .get(server.url(&format!("/v1/pair/{id}?side=b&after=0")))
        .header("x-uwussh-pair-claim", "a different secret")
        .send()
        .await
        .unwrap();
    assert_eq!(as_b.status(), 401, "side b is taken");

    // Finished: the device that opened it says so.
    let closed = server
        .client
        .delete(server.url(&format!("/v1/pair/{id}")))
        .bearer_auth(&first.token)
        .send()
        .await
        .unwrap();
    assert_eq!(closed.status(), 204);
    assert_eq!(read("b", 0).await.unwrap().status(), 404);
}

#[tokio::test]
async fn a_waiting_device_is_woken_when_the_other_speaks() {
    let server = start(Registration::Open).await;
    let first = Device::create_account(&server, "", "master", 1).await;
    let opened: serde_json::Value = server
        .client
        .post(server.url("/v1/pair"))
        .bearer_auth(&first.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = opened["id"].as_str().unwrap().to_string();

    let waiting = server
        .client
        .get(server.url(&format!("/v1/pair/{id}?side=b&after=0&wait=true")))
        .header("x-uwussh-pair-claim", "waiting")
        .send();
    let speaking = async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        server
            .client
            .post(server.url(&format!("/v1/pair/{id}")))
            .bearer_auth(&first.token)
            .json(&json!({ "side": "a", "message": uwusync_server::b64::encode(b"at last") }))
            .send()
            .await
            .unwrap()
    };

    let (answer, _) =
        tokio::time::timeout(std::time::Duration::from_secs(5), both(waiting, speaking))
            .await
            .expect("the wait ends when the message arrives");

    let body: serde_json::Value = answer.unwrap().json().await.unwrap();
    assert_eq!(body["messages"][0], uwusync_server::b64::encode(b"at last"));
}

/// `tokio::join!` as a function, so both halves can be put under one timeout.
async fn both<A: std::future::Future, B: std::future::Future>(
    a: A,
    b: B,
) -> (A::Output, B::Output) {
    tokio::join!(a, b)
}

#[tokio::test]
async fn the_relay_is_a_handshake_and_not_storage() {
    let server = start(Registration::Open).await;
    let first = Device::create_account(&server, "", "master", 1).await;
    let opened: serde_json::Value = server
        .client
        .post(server.url("/v1/pair"))
        .bearer_auth(&first.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = opened["id"].as_str().unwrap().to_string();
    let post = |message: String| {
        server
            .client
            .post(server.url(&format!("/v1/pair/{id}")))
            .bearer_auth(&first.token)
            .json(&json!({ "side": "a", "message": message }))
            .send()
    };

    assert_eq!(
        post(uwusync_server::b64::encode(vec![0u8; 9 * 1024]))
            .await
            .unwrap()
            .status(),
        413,
        "a handshake message is small"
    );
    assert_eq!(post(String::new()).await.unwrap().status(), 400);
    assert_eq!(
        post("not base64 at all !!".into()).await.unwrap().status(),
        400
    );

    for _ in 0..4 {
        assert_eq!(
            post(uwusync_server::b64::encode(b"fine"))
                .await
                .unwrap()
                .status(),
            204
        );
    }
    assert_eq!(
        post(uwusync_server::b64::encode(b"one too many"))
            .await
            .unwrap()
            .status(),
        400,
        "and there are only so many of them"
    );

    // A side nobody named is not a side.
    let bad_side = server
        .client
        .post(server.url(&format!("/v1/pair/{id}")))
        .json(&json!({ "side": "c", "message": uwusync_server::b64::encode(b"x") }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_side.status(), 400);
}

#[tokio::test]
async fn a_session_nobody_opened_is_not_there_and_not_everyones_to_close() {
    let server = start(Registration::Open).await;
    let mine = Device::create_account(&server, "", "master", 1).await;
    let theirs = Device::create_account(&server, "", "other", 2).await;

    // Opening one needs a device that is already in.
    let anonymous = server
        .client
        .post(server.url("/v1/pair"))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status(), 401);

    let opened: serde_json::Value = server
        .client
        .post(server.url("/v1/pair"))
        .bearer_auth(&mine.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = opened["id"].as_str().unwrap().to_string();

    // Another account cannot close it, and is not told that it exists.
    let stranger = server
        .client
        .delete(server.url(&format!("/v1/pair/{id}")))
        .bearer_auth(&theirs.token)
        .send()
        .await
        .unwrap();
    assert_eq!(stranger.status(), 404);

    let unknown = server
        .client
        .get(server.url("/v1/pair/ZZZZZ?side=b"))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 404);

    // It is still there for the account that opened it.
    assert_eq!(
        server
            .client
            .get(server.url(&format!("/v1/pair/{id}?side=b")))
            .header("x-uwussh-pair-claim", "the joining device")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
}

/// Teams: a vault several accounts share, and every rule the server keeps
/// about one. The keys here are stand-ins — the server never opens one.
mod teams {
    use super::*;
    use serde_json::Value;
    use uwusync_server::config::{TeamCreation, Teams};

    const WEEK_MS: u64 = 7 * 24 * 60 * 60 * 1000;

    /// 32 bytes that stand for a public key.
    fn key(seed: u8) -> String {
        uwusync_server::b64::encode([seed; 32])
    }

    /// Bytes that stand for a team key wrapped to somebody.
    fn wrapped(text: &str) -> String {
        uwusync_server::b64::encode(text.as_bytes())
    }

    async fn call(
        server: &Server,
        device: &Device,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let mut request = server
            .client
            .request(method, server.url(path))
            .bearer_auth(&device.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let text = response.text().await.unwrap();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    async fn get(server: &Server, device: &Device, path: &str) -> (u16, Value) {
        call(server, device, reqwest::Method::GET, path, None).await
    }

    async fn post(server: &Server, device: &Device, path: &str, body: Value) -> (u16, Value) {
        call(server, device, reqwest::Method::POST, path, Some(body)).await
    }

    async fn patch(server: &Server, device: &Device, path: &str, body: Value) -> (u16, Value) {
        call(server, device, reqwest::Method::PATCH, path, Some(body)).await
    }

    async fn delete(server: &Server, device: &Device, path: &str) -> (u16, Value) {
        call(server, device, reqwest::Method::DELETE, path, None).await
    }

    /// What a refusal looks like: its status and its `error`.
    fn refused(answer: &(u16, Value)) -> (u16, &str) {
        (answer.0, answer.1["error"].as_str().unwrap_or(""))
    }

    /// An account with a team identity. Its public key is its seed, 32 times.
    async fn member(server: &Server, seed: u8) -> Device {
        let device = Device::create_account(server, "", "master", seed).await;
        let answer = call(
            server,
            &device,
            reqwest::Method::PUT,
            "/v1/teams/identity",
            Some(json!({ "public_key": key(seed), "sealed_private": wrapped("sealed") })),
        )
        .await;
        assert_eq!(answer.0, 200, "{answer:?}");
        device
    }

    async fn open() -> Server {
        start(Registration::Open).await
    }

    async fn with_teams(teams: Teams) -> Server {
        start_with(Config {
            registration: Registration::Open,
            teams,
            ..Config::default()
        })
        .await
    }

    async fn team(server: &Server, owner: &Device) -> Uuid {
        let answer = post(
            server,
            owner,
            "/v1/teams",
            json!({ "name": "Ops", "display_name": "Olive", "wrapped_key": wrapped("for the owner") }),
        )
        .await;
        assert_eq!(answer.0, 200, "{answer:?}");
        answer.1["id"].as_str().unwrap().parse().unwrap()
    }

    async fn invite(server: &Server, by: &Device, team: Uuid, role: &str) -> String {
        let answer = post(
            server,
            by,
            &format!("/v1/teams/{team}/invites"),
            json!({ "role": role }),
        )
        .await;
        assert_eq!(answer.0, 200, "{answer:?}");
        answer.1["code"].as_str().unwrap().to_string()
    }

    async fn join(server: &Server, device: &Device, code: &str) -> (u16, Value) {
        post(
            server,
            device,
            "/v1/teams/join",
            json!({ "code": code, "display_name": "Newcomer" }),
        )
        .await
    }

    async fn confirm(
        server: &Server,
        by: &Device,
        team: Uuid,
        whom: &Device,
        seed: u8,
        epoch: u64,
    ) -> (u16, Value) {
        post(
            server,
            by,
            &format!("/v1/teams/{team}/members/{}/confirm", whom.account),
            json!({ "epoch": epoch, "public_key": key(seed), "wrapped_key": wrapped("for them") }),
        )
        .await
    }

    /// Invite, redeem, confirm: `whom` is in the team as `role`.
    async fn admit(
        server: &Server,
        owner: &Device,
        team: Uuid,
        whom: &Device,
        seed: u8,
        role: &str,
    ) {
        let code = invite(server, owner, team, role).await;
        let joined = join(server, whom, &code).await;
        assert_eq!(joined.0, 200, "{joined:?}");
        assert_eq!(joined.1["state"], "pending");
        let confirmed = confirm(server, owner, team, whom, seed, 1).await;
        assert_eq!(confirmed.0, 204, "{confirmed:?}");
    }

    fn record(team: Uuid, id: Uuid, base_seq: u64, blob: &[u8]) -> Envelope {
        Envelope {
            id,
            vault_id: team,
            kind: EntityKind::Host,
            updated_at: Hlc::new(1_700_000_000_000, 0, 1),
            base_seq,
            deleted: false,
            nonce: vec![7; 24],
            blob: blob.to_vec(),
            seq: None,
        }
    }

    async fn push(
        server: &Server,
        device: &Device,
        team: Uuid,
        epoch: u64,
        envelopes: &[Envelope],
    ) -> (u16, Value) {
        post(
            server,
            device,
            &format!("/v1/teams/{team}/records"),
            json!({ "schema": SCHEMA_VERSION, "epoch": epoch, "envelopes": envelopes }),
        )
        .await
    }

    async fn pull(server: &Server, device: &Device, team: Uuid, cursor: u64) -> (u16, Value) {
        get(
            server,
            device,
            &format!("/v1/teams/{team}/records?cursor={cursor}"),
        )
        .await
    }

    async fn mine(server: &Server, device: &Device) -> Vec<Value> {
        let answer = get(server, device, "/v1/teams").await;
        assert_eq!(answer.0, 200, "{answer:?}");
        answer.1.as_array().unwrap().clone()
    }

    #[tokio::test]
    async fn a_team_is_read_by_those_let_in_and_by_nobody_else() {
        let server = open().await;
        let owner = member(&server, 1).await;
        let newcomer = member(&server, 2).await;
        let stranger = member(&server, 3).await;

        let policy = get(&server, &owner, "/v1/teams/policy").await;
        assert_eq!(
            policy.1,
            json!({
                "enabled": true, "may_create": true,
                "max_teams_per_account": 10, "max_members_per_team": 50,
            })
        );

        let team = team(&server, &owner).await;
        let listed = mine(&server, &owner).await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["role"], "owner");
        assert_eq!(listed[0]["state"], "active");
        assert_eq!(listed[0]["epoch"], 1);
        assert_eq!(listed[0]["wrapped_key"], wrapped("for the owner"));
        assert_eq!(listed[0]["needs_rotation"], false);
        assert_eq!(listed[0]["members"], 1);

        let id = Uuid::now_v7();
        let pushed = push(&server, &owner, team, 1, &[record(team, id, 0, b"sealed")]).await;
        assert_eq!(pushed.0, 200, "{pushed:?}");
        assert_eq!(pushed.1["accepted"][0]["seq"], 1);
        // The owner's own vault is beside it, untouched.
        assert!(owner.pull(&server, 0).await.envelopes.is_empty());

        // Redeeming an invite makes a member who waits — and reads nothing.
        let code = invite(&server, &owner, team, "editor").await;
        let joined = join(&server, &newcomer, &code).await;
        assert_eq!(
            joined.1,
            json!({ "team_id": team, "name": "Ops", "role": "editor", "state": "pending" })
        );
        let waiting = mine(&server, &newcomer).await;
        assert_eq!(waiting[0]["state"], "pending");
        assert_eq!(waiting[0]["wrapped_key"], Value::Null);
        let records = format!("/v1/teams/{team}/records");
        let members = format!("/v1/teams/{team}/members");
        assert_eq!(
            refused(&pull(&server, &newcomer, team, 0).await),
            (403, "membership-pending")
        );
        assert_eq!(
            refused(&get(&server, &newcomer, &members).await),
            (403, "membership-pending")
        );
        assert_eq!(
            refused(
                &push(
                    &server,
                    &newcomer,
                    team,
                    1,
                    &[record(team, Uuid::now_v7(), 0, b"x")]
                )
                .await
            ),
            (403, "membership-pending")
        );

        // The owner sees who waits, and the key to compare.
        let seen = get(&server, &owner, &members).await.1;
        assert_eq!(seen.as_array().unwrap().len(), 2);
        assert_eq!(seen[1]["account_id"], newcomer.account.to_string());
        assert_eq!(seen[1]["display_name"], "Newcomer");
        assert_eq!(seen[1]["role"], "editor");
        assert_eq!(seen[1]["state"], "pending");
        assert_eq!(seen[1]["public_key"], key(2));

        // A key for another epoch, or wrapped to another key than the
        // member's, is not stored.
        let stale = confirm(&server, &owner, team, &newcomer, 2, 2).await;
        assert_eq!(refused(&stale), (409, "stale-epoch"));
        assert_eq!(stale.1["epoch"], 1);
        assert_eq!(
            refused(&confirm(&server, &owner, team, &newcomer, 9, 1).await),
            (409, "identity-changed")
        );
        // Nobody confirms themselves in.
        assert_eq!(
            refused(&confirm(&server, &newcomer, team, &newcomer, 2, 1).await),
            (403, "membership-pending")
        );
        assert_eq!(confirm(&server, &owner, team, &newcomer, 2, 1).await.0, 204);
        assert_eq!(
            refused(&confirm(&server, &owner, team, &newcomer, 2, 1).await),
            (409, "not-pending")
        );

        let page = pull(&server, &newcomer, team, 0).await;
        assert_eq!(page.0, 200, "{page:?}");
        assert_eq!(page.1["envelopes"][0]["id"], id.to_string());
        assert_eq!(page.1["cursor"], 1);
        assert_eq!(page.1["has_more"], false);
        assert_eq!(page.1["epoch"], 1);
        assert_eq!(page.1["role"], "editor");
        assert_eq!(page.1["needs_rotation"], false);
        assert_eq!(
            mine(&server, &newcomer).await[0]["wrapped_key"],
            wrapped("for them")
        );

        // A newer version needs the version it is based on, as everywhere.
        let conflict = push(&server, &newcomer, team, 1, &[record(team, id, 0, b"mine")]).await;
        assert_eq!(conflict.1["conflicts"][0]["id"], id.to_string());
        let newer = push(&server, &newcomer, team, 1, &[record(team, id, 1, b"mine")]).await;
        assert_eq!(newer.1["accepted"][0]["seq"], 2);
        // And a record is the team's only if it says so.
        let foreign = record(newcomer.vault_id, Uuid::now_v7(), 0, b"x");
        assert_eq!(push(&server, &newcomer, team, 1, &[foreign]).await.0, 400);

        // To anybody else there is no such team — as there is no team at
        // all under an id that is none.
        let nowhere = Uuid::now_v7();
        for path in [
            records.clone(),
            members.clone(),
            format!("/v1/teams/{team}/invites"),
            format!("/v1/teams/{nowhere}/records"),
            "/v1/teams/not-an-id/records".to_string(),
        ] {
            assert_eq!(
                refused(&get(&server, &stranger, &path).await),
                (404, "not-found"),
                "{path}"
            );
        }
        assert_eq!(
            refused(
                &push(
                    &server,
                    &stranger,
                    team,
                    1,
                    &[record(team, Uuid::now_v7(), 0, b"x")]
                )
                .await
            ),
            (404, "not-found")
        );
        assert_eq!(
            refused(
                &patch(
                    &server,
                    &stranger,
                    &format!("/v1/teams/{team}"),
                    json!({ "name": "Mine" })
                )
                .await
            ),
            (404, "not-found")
        );
        assert_eq!(
            refused(&delete(&server, &stranger, &format!("/v1/teams/{team}")).await),
            (404, "not-found")
        );
        assert_eq!(
            refused(&confirm(&server, &stranger, team, &stranger, 3, 1).await),
            (404, "not-found")
        );
        assert_eq!(
            refused(
                &post(
                    &server,
                    &stranger,
                    &format!("/v1/teams/{team}/rotate"),
                    json!({ "epoch": 2, "keys": [{ "account_id": stranger.account, "wrapped_key": wrapped("k") }] }),
                )
                .await
            ),
            (404, "not-found")
        );
        assert!(mine(&server, &stranger).await.is_empty());

        // Without a token there is nothing here at all.
        for path in ["/v1/teams/policy", "/v1/teams", "/v1/teams/identity"] {
            let response = server.client.get(server.url(path)).send().await.unwrap();
            assert_eq!(response.status(), 401, "{path}");
        }
    }

    #[tokio::test]
    async fn each_role_does_what_it_may_and_no_more() {
        let server = open().await;
        let owner = member(&server, 1).await;
        let admin = member(&server, 2).await;
        let editor = member(&server, 3).await;
        let reader = member(&server, 4).await;
        let waiting = member(&server, 5).await;
        let team = team(&server, &owner).await;
        admit(&server, &owner, team, &admin, 2, "admin").await;
        admit(&server, &owner, team, &editor, 3, "editor").await;
        // An admin lets people in as well as an owner does.
        admit(&server, &admin, team, &reader, 4, "reader").await;
        let code = invite(&server, &admin, team, "reader").await;
        assert_eq!(join(&server, &waiting, &code).await.0, 200);

        let at = |device: &Device| format!("/v1/teams/{team}/members/{}", device.account);
        let this = format!("/v1/teams/{team}");
        let one = || [record(team, Uuid::now_v7(), 0, b"sealed")];

        // Records: a reader reads, an editor writes too.
        assert_eq!(
            refused(&push(&server, &reader, team, 1, &one()).await),
            (403, "forbidden")
        );
        assert_eq!(push(&server, &editor, team, 1, &one()).await.0, 200);
        assert_eq!(pull(&server, &reader, team, 0).await.1["role"], "reader");
        assert_eq!(
            pull(&server, &reader, team, 0).await.1["envelopes"]
                .as_array()
                .unwrap()
                .len(),
            1
        );

        // Everything about the team itself is for those who manage it.
        for lesser in [&editor, &reader] {
            let invites = format!("{this}/invites");
            let answers = [
                post(&server, lesser, &invites, json!({ "role": "reader" })).await,
                get(&server, lesser, &invites).await,
                patch(&server, lesser, &this, json!({ "name": "Theirs" })).await,
                patch(&server, lesser, &at(&reader), json!({ "role": "admin" })).await,
                delete(&server, lesser, &at(&waiting)).await,
                confirm(&server, lesser, team, &waiting, 5, 1).await,
                post(
                    &server,
                    lesser,
                    &format!("{this}/rotate"),
                    json!({ "epoch": 2, "keys": [] }),
                )
                .await,
                delete(&server, lesser, &this).await,
            ];
            for answer in &answers {
                assert_eq!(refused(answer), (403, "forbidden"), "{answer:?}");
            }
            // But every member sees who is in it.
            assert_eq!(
                get(&server, lesser, &format!("{this}/members")).await.0,
                200
            );
        }

        // An admin manages — up to the owners, and the team's existence.
        let renamed = patch(&server, &admin, &this, json!({ "name": "  Operations " })).await;
        assert_eq!(renamed.1["name"], "Operations");
        assert_eq!(
            patch(&server, &admin, &at(&reader), json!({ "role": "editor" }))
                .await
                .0,
            204
        );
        for answer in [
            patch(&server, &admin, &at(&editor), json!({ "role": "owner" })).await,
            patch(&server, &admin, &at(&owner), json!({ "role": "admin" })).await,
            delete(&server, &admin, &at(&owner)).await,
            delete(&server, &admin, &this).await,
        ] {
            assert_eq!(refused(&answer), (403, "forbidden"), "{answer:?}");
        }
        // Nobody is invited as an owner, and a role is one of the four.
        let invites = format!("{this}/invites");
        assert_eq!(
            post(&server, &owner, &invites, json!({ "role": "owner" }))
                .await
                .0,
            400
        );
        assert!(
            post(&server, &owner, &invites, json!({ "role": "king" }))
                .await
                .0
                >= 400
        );

        // A team keeps an owner: the only one neither steps down nor leaves.
        assert_eq!(
            refused(&patch(&server, &owner, &at(&owner), json!({ "role": "admin" })).await),
            (409, "last-owner")
        );
        assert_eq!(
            refused(&delete(&server, &owner, &at(&owner)).await),
            (409, "last-owner")
        );
        // And an owner is made from a member who has the key.
        assert_eq!(
            refused(&patch(&server, &owner, &at(&waiting), json!({ "role": "owner" })).await),
            (409, "not-active")
        );
        assert_eq!(
            patch(&server, &owner, &at(&admin), json!({ "role": "owner" }))
                .await
                .0,
            204
        );
        assert_eq!(
            patch(&server, &owner, &at(&owner), json!({ "role": "admin" }))
                .await
                .0,
            204
        );
        assert_eq!(mine(&server, &owner).await[0]["role"], "admin");
        assert_eq!(
            refused(&delete(&server, &admin, &at(&admin)).await),
            (409, "last-owner"),
            "the new owner is the only one now"
        );

        // Only an owner deletes the team, and its records go with it.
        assert_eq!(
            refused(&delete(&server, &owner, &this).await),
            (403, "forbidden")
        );
        assert_eq!(delete(&server, &admin, &this).await.0, 204);
        for device in [&owner, &admin, &editor, &reader, &waiting] {
            assert!(mine(&server, device).await.is_empty());
            assert_eq!(
                refused(&pull(&server, device, team, 0).await),
                (404, "not-found")
            );
        }
        let left: i64 = server
            .state
            .db
            .lock()
            .query_row(
                "SELECT (SELECT count(*) FROM team_records) + (SELECT count(*) FROM team_members)
                      + (SELECT count(*) FROM team_invites) + (SELECT count(*) FROM teams)",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(left, 0);
    }

    #[tokio::test]
    async fn a_removed_member_is_out_at_once_and_a_rotation_moves_the_team_on() {
        let server = open().await;
        let owner = member(&server, 1).await;
        let editor = member(&server, 2).await;
        let reader = member(&server, 3).await;
        let waiting = member(&server, 4).await;
        let team = team(&server, &owner).await;
        admit(&server, &owner, team, &editor, 2, "editor").await;
        admit(&server, &owner, team, &reader, 3, "reader").await;
        let code = invite(&server, &owner, team, "editor").await;
        assert_eq!(join(&server, &waiting, &code).await.0, 200);
        let two = [
            record(team, Uuid::now_v7(), 0, b"one"),
            record(team, Uuid::now_v7(), 0, b"two"),
        ];
        assert_eq!(push(&server, &editor, team, 1, &two).await.0, 200);

        // Taken out: from this request on there is no team for them.
        let gone = delete(
            &server,
            &owner,
            &format!("/v1/teams/{team}/members/{}", editor.account),
        )
        .await;
        assert_eq!(gone.0, 204, "{gone:?}");
        assert_eq!(
            refused(&pull(&server, &editor, team, 0).await),
            (404, "not-found")
        );
        assert_eq!(
            refused(
                &push(
                    &server,
                    &editor,
                    team,
                    1,
                    &[record(team, Uuid::now_v7(), 0, b"x")]
                )
                .await
            ),
            (404, "not-found")
        );
        assert!(mine(&server, &editor).await.is_empty());
        // They knew the key, so the team wants a new one — and says so.
        assert_eq!(mine(&server, &owner).await[0]["needs_rotation"], true);
        assert_eq!(
            pull(&server, &reader, team, 0).await.1["needs_rotation"],
            true
        );

        let rotate = format!("/v1/teams/{team}/rotate");
        let for_ = |device: &Device| json!({ "account_id": device.account, "wrapped_key": wrapped("new") });
        let both = json!([for_(&owner), for_(&reader)]);

        // Not a reader's to do.
        assert_eq!(
            refused(
                &post(
                    &server,
                    &reader,
                    &rotate,
                    json!({ "epoch": 2, "keys": both })
                )
                .await
            ),
            (403, "forbidden")
        );
        // The next epoch, and no other.
        for epoch in [1, 3] {
            let answer = post(
                &server,
                &owner,
                &rotate,
                json!({ "epoch": epoch, "keys": both }),
            )
            .await;
            assert_eq!(refused(&answer), (409, "stale-epoch"), "{epoch}");
            assert_eq!(answer.1["epoch"], 1);
        }
        // Exactly the members who have the key: nobody left out, nobody
        // slipped in — not the one who was removed, not the one who waits —
        // and nobody twice.
        for keys in [
            json!([for_(&owner)]),
            json!([for_(&owner), for_(&reader), for_(&editor)]),
            json!([for_(&owner), for_(&reader), for_(&waiting)]),
            json!([for_(&owner), for_(&reader), for_(&reader)]),
            json!([]),
        ] {
            let answer = post(
                &server,
                &owner,
                &rotate,
                json!({ "epoch": 2, "keys": keys }),
            )
            .await;
            assert_eq!(refused(&answer), (409, "members-mismatch"), "{keys}");
        }
        // With a cursor: only if nothing was pushed since.
        assert_eq!(
            refused(
                &post(
                    &server,
                    &owner,
                    &rotate,
                    json!({ "epoch": 2, "keys": both, "cursor": 1 })
                )
                .await
            ),
            (409, "stale-cursor")
        );
        // None of that changed anything.
        assert_eq!(
            pull(&server, &reader, team, 0).await.1["envelopes"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        let rotated = post(
            &server,
            &owner,
            &rotate,
            json!({ "epoch": 2, "keys": both, "cursor": 2 }),
        )
        .await;
        assert_eq!(rotated.0, 200, "{rotated:?}");
        assert_eq!(rotated.1["epoch"], 2);
        assert_eq!(rotated.1["needs_rotation"], false);
        assert_eq!(rotated.1["wrapped_key"], wrapped("new"));

        // The old epoch's records are gone, its key is no use for writing,
        // and the numbers go on from where they were.
        let page = pull(&server, &reader, team, 0).await.1;
        assert!(page["envelopes"].as_array().unwrap().is_empty());
        assert_eq!(page["epoch"], 2);
        assert_eq!(
            mine(&server, &reader).await[0]["wrapped_key"],
            wrapped("new")
        );
        let late = push(
            &server,
            &owner,
            team,
            1,
            &[record(team, Uuid::now_v7(), 0, b"old key")],
        )
        .await;
        assert_eq!(refused(&late), (409, "stale-epoch"));
        assert_eq!(late.1["epoch"], 2);
        let again = push(
            &server,
            &owner,
            team,
            2,
            &[record(team, two[0].id, 0, b"new key")],
        )
        .await;
        assert_eq!(again.1["accepted"][0]["seq"], 3);
        let after = pull(&server, &reader, team, 2).await.1;
        assert_eq!(after["envelopes"].as_array().unwrap().len(), 1);
        assert_eq!(after["cursor"], 3);

        // Who waited still waits, and is let in with the new epoch's key.
        assert_eq!(mine(&server, &waiting).await[0]["state"], "pending");
        assert_eq!(
            refused(&confirm(&server, &owner, team, &waiting, 4, 1).await),
            (409, "stale-epoch")
        );
        assert_eq!(confirm(&server, &owner, team, &waiting, 4, 2).await.0, 204);

        // Leaving is removing oneself, and calls for a rotation the same.
        let left = delete(
            &server,
            &reader,
            &format!("/v1/teams/{team}/members/{}", reader.account),
        )
        .await;
        assert_eq!(left.0, 204);
        assert_eq!(
            refused(&pull(&server, &reader, team, 0).await),
            (404, "not-found")
        );
        assert_eq!(mine(&server, &owner).await[0]["needs_rotation"], true);
        assert_eq!(mine(&server, &owner).await[0]["members"], 2);
    }

    #[tokio::test]
    async fn an_invite_is_good_for_a_week_and_for_one_member() {
        let server = open().await;
        let owner = member(&server, 1).await;
        let first = member(&server, 2).await;
        let second = member(&server, 3).await;
        let team = team(&server, &owner).await;
        let other_team = {
            let answer = post(
                &server,
                &first,
                "/v1/teams",
                json!({ "name": "Other", "display_name": "First", "wrapped_key": wrapped("k") }),
            )
            .await;
            answer.1["id"].as_str().unwrap().to_string()
        };
        let invites = format!("/v1/teams/{team}/invites");

        // What is listed is that there is one, never its code.
        let made = post(&server, &owner, &invites, json!({ "role": "reader" }))
            .await
            .1;
        let code = made["code"].as_str().unwrap().to_string();
        let now = server.state.clock.now_ms();
        let expires = made["expires_ms"].as_u64().unwrap();
        assert!(expires > now + WEEK_MS - 60_000 && expires <= now + WEEK_MS);
        let listed = get(&server, &owner, &invites).await.1;
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert_eq!(listed[0]["id"], made["id"]);
        assert_eq!(listed[0]["role"], "reader");
        assert_eq!(listed[0]["created_by"], owner.account.to_string());
        assert!(listed[0].get("code").is_none());
        let stored: Vec<u8> = server
            .state
            .db
            .lock()
            .query_row("SELECT code_hash FROM team_invites", [], |row| row.get(0))
            .unwrap();
        assert_eq!(stored.len(), 32, "a hash, not the code");

        // Somebody already in gains nothing by it, and does not use it up.
        assert_eq!(
            refused(&join(&server, &owner, &code).await),
            (409, "already-member")
        );
        // It is typed as it is read: case and dashes do not matter.
        let typed = code.replace('-', " ").to_lowercase();
        assert_eq!(join(&server, &first, &typed).await.0, 200);
        // Once.
        assert_eq!(
            refused(&join(&server, &second, &code).await),
            (403, "invalid-invite")
        );
        assert!(get(&server, &owner, &invites)
            .await
            .1
            .as_array()
            .unwrap()
            .is_empty());

        // An invite of this team is not another team's to take back.
        let kept = post(&server, &owner, &invites, json!({ "role": "reader" }))
            .await
            .1;
        let theirs = format!(
            "/v1/teams/{other_team}/invites/{}",
            kept["id"].as_str().unwrap()
        );
        assert_eq!(
            refused(&delete(&server, &first, &theirs).await),
            (404, "not-found")
        );
        // Taken back, it lets nobody in.
        let own = format!("{invites}/{}", kept["id"].as_str().unwrap());
        assert_eq!(delete(&server, &owner, &own).await.0, 204);
        assert_eq!(
            refused(&delete(&server, &owner, &own).await),
            (404, "not-found")
        );
        assert_eq!(
            refused(&join(&server, &second, kept["code"].as_str().unwrap()).await),
            (403, "invalid-invite")
        );

        // A week later it has run out — and looks like any wrong code.
        let late = invite(&server, &owner, team, "editor").await;
        server.state.clock.advance(WEEK_MS - 60_000);
        assert_eq!(
            get(&server, &owner, &invites)
                .await
                .1
                .as_array()
                .unwrap()
                .len(),
            1
        );
        server.state.clock.advance(60_001);
        assert!(get(&server, &owner, &invites)
            .await
            .1
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(
            refused(&join(&server, &second, &late).await),
            (403, "invalid-invite")
        );
        assert_eq!(
            refused(&join(&server, &second, "AAAAA-BBBBB-CCCCC").await),
            (403, "invalid-invite")
        );
        assert!(mine(&server, &second).await.is_empty());

        // One that works still does, after those tries.
        let good = invite(&server, &owner, team, "editor").await;
        assert_eq!(join(&server, &second, &good).await.0, 200);
    }

    #[tokio::test]
    async fn guessing_codes_is_slowed_down_and_invites_do_not_pile_up() {
        let server = open().await;
        let owner = member(&server, 1).await;
        let guesser = member(&server, 2).await;
        let team = team(&server, &owner).await;

        let mut statuses = Vec::new();
        for _ in 0..11 {
            statuses.push(join(&server, &guesser, "AAAAA-BBBBB-CCCCC").await.0);
        }
        assert_eq!(statuses[..10], [403; 10]);
        assert_eq!(statuses[10], 429);
        // Also for a code that would have worked.
        let code = invite(&server, &owner, team, "reader").await;
        assert_eq!(
            refused(&join(&server, &guesser, &code).await),
            (429, "rate-limited")
        );

        let invites = format!("/v1/teams/{team}/invites");
        for _ in 1..20 {
            invite(&server, &owner, team, "reader").await;
        }
        assert_eq!(
            refused(&post(&server, &owner, &invites, json!({ "role": "reader" })).await),
            (403, "too-many-invites")
        );
    }

    #[tokio::test]
    async fn the_operator_decides_whether_who_and_how_many() {
        // Off: the policy says so, and nothing else answers.
        let off = with_teams(Teams {
            enabled: false,
            ..Teams::default()
        })
        .await;
        let device = Device::create_account(&off, "", "master", 1).await;
        let policy = get(&off, &device, "/v1/teams/policy").await;
        assert_eq!(policy.0, 200);
        assert_eq!(policy.1["enabled"], false);
        assert_eq!(policy.1["may_create"], false);
        let team = Uuid::now_v7();
        let identity = json!({ "public_key": key(1), "sealed_private": wrapped("s") });
        for answer in [
            get(&off, &device, "/v1/teams").await,
            get(&off, &device, "/v1/teams/identity").await,
            call(
                &off,
                &device,
                reqwest::Method::PUT,
                "/v1/teams/identity",
                Some(identity),
            )
            .await,
            post(&off, &device, "/v1/teams", json!({})).await,
            post(&off, &device, "/v1/teams/join", json!({})).await,
            get(&off, &device, &format!("/v1/teams/{team}/members")).await,
            get(&off, &device, &format!("/v1/teams/{team}/invites")).await,
            post(
                &off,
                &device,
                &format!("/v1/teams/{team}/rotate"),
                json!({}),
            )
            .await,
            pull(&off, &device, team, 0).await,
            push(&off, &device, team, 1, &[]).await,
            delete(&off, &device, &format!("/v1/teams/{team}")).await,
        ] {
            assert_eq!(refused(&answer), (403, "teams-disabled"), "{answer:?}");
        }

        // Nobody may create one: the rest still works.
        let closed = with_teams(Teams {
            creation: TeamCreation::None,
            ..Teams::default()
        })
        .await;
        let device = member(&closed, 1).await;
        let policy = get(&closed, &device, "/v1/teams/policy").await.1;
        assert_eq!(
            (&policy["enabled"], &policy["may_create"]),
            (&json!(true), &json!(false))
        );
        let answer = post(
            &closed,
            &device,
            "/v1/teams",
            json!({ "name": "Ops", "display_name": "Olive", "wrapped_key": wrapped("k") }),
        )
        .await;
        assert_eq!(refused(&answer), (403, "team-creation-closed"));
        assert!(mine(&closed, &device).await.is_empty());

        // One team per account, two members per team.
        let small = with_teams(Teams {
            max_per_account: 1,
            max_members: 2,
            ..Teams::default()
        })
        .await;
        let owner = member(&small, 1).await;
        let second = member(&small, 2).await;
        let third = member(&small, 3).await;
        let busy = member(&small, 4).await;
        let policy = get(&small, &owner, "/v1/teams/policy").await.1;
        assert_eq!(policy["max_teams_per_account"], 1);
        assert_eq!(policy["max_members_per_team"], 2);
        let team = self::team(&small, &owner).await;
        let another = post(
            &small,
            &owner,
            "/v1/teams",
            json!({ "name": "More", "display_name": "Olive", "wrapped_key": wrapped("k") }),
        )
        .await;
        assert_eq!(refused(&another), (403, "team-limit"));
        // Joining counts as well as creating, also while waiting.
        self::team(&small, &busy).await;
        let code = invite(&small, &owner, team, "reader").await;
        assert_eq!(
            refused(&join(&small, &busy, &code).await),
            (403, "team-limit")
        );
        // The code that could not be used is still good.
        assert_eq!(join(&small, &second, &code).await.0, 200);
        let code = invite(&small, &owner, team, "reader").await;
        assert_eq!(
            refused(&join(&small, &third, &code).await),
            (403, "team-full")
        );
        let out = format!("/v1/teams/{team}/members/{}", second.account);
        assert_eq!(delete(&small, &owner, &out).await.0, 204);
        // Nobody who had the key went: no rotation is called for.
        assert_eq!(mine(&small, &owner).await[0]["needs_rotation"], false);
        assert_eq!(join(&small, &third, &code).await.0, 200);
    }

    #[tokio::test]
    async fn a_member_key_is_set_once_and_replacing_it_means_waiting_again() {
        let server = open().await;
        let owner = member(&server, 1).await;
        let other = Device::create_account(&server, "", "master", 2).await;
        let put = |device: &'static str, body: Value| {
            let server = &server;
            let (owner, other) = (&owner, &other);
            async move {
                let device = if device == "owner" { owner } else { other };
                call(
                    server,
                    device,
                    reqwest::Method::PUT,
                    "/v1/teams/identity",
                    Some(body),
                )
                .await
            }
        };

        // Without one there is no creating and no joining.
        assert_eq!(
            refused(&get(&server, &other, "/v1/teams/identity").await),
            (404, "not-found")
        );
        let team = team(&server, &owner).await;
        let code = invite(&server, &owner, team, "admin").await;
        assert_eq!(
            refused(&join(&server, &other, &code).await),
            (409, "no-identity")
        );
        let answer = post(
            &server,
            &other,
            "/v1/teams",
            json!({ "name": "Ops", "display_name": "Otto", "wrapped_key": wrapped("k") }),
        )
        .await;
        assert_eq!(refused(&answer), (409, "no-identity"));

        // A key is 32 bytes, and what is sealed is bounded.
        for body in [
            json!({ "public_key": wrapped("short"), "sealed_private": wrapped("s") }),
            json!({ "public_key": key(2), "sealed_private": "" }),
            json!({ "public_key": key(2), "sealed_private": "not base64!" }),
            json!({ "public_key": key(2), "sealed_private": uwusync_server::b64::encode(vec![1u8; 1025]) }),
        ] {
            assert_eq!(put("other", body.clone()).await.0, 400, "{body}");
        }
        let stored = put(
            "other",
            json!({ "public_key": key(2), "sealed_private": wrapped("sealed") }),
        )
        .await;
        assert_eq!(stored.0, 200, "{stored:?}");
        let read = get(&server, &other, "/v1/teams/identity").await.1;
        assert_eq!(read["public_key"], key(2));
        assert_eq!(read["sealed_private"], wrapped("sealed"));
        // Nobody reads another account's: there is no route that would.

        // The first one stays unless the client says it means it.
        let second = json!({ "public_key": key(9), "sealed_private": wrapped("other") });
        assert_eq!(
            refused(&put("other", second).await),
            (409, "identity-exists")
        );
        assert_eq!(
            get(&server, &other, "/v1/teams/identity").await.1["public_key"],
            key(2)
        );

        assert_eq!(join(&server, &other, &code).await.0, 200);
        assert_eq!(confirm(&server, &owner, team, &other, 2, 1).await.0, 204);
        assert_eq!(pull(&server, &other, team, 0).await.0, 200);

        // Sealing the same key anew is the device's to do with its token.
        let resealed = put(
            "other",
            json!({ "public_key": key(2), "sealed_private": wrapped("resealed"), "replace": true }),
        )
        .await;
        assert_eq!(resealed.0, 200, "{resealed:?}");
        assert_eq!(mine(&server, &other).await[0]["state"], "active");

        // Another key is the account holder's to put there, not a device's:
        // not without the master password, and not with a wrong one.
        for proof in [None, Some("a guess")] {
            let mut body = json!({ "public_key": key(9), "sealed_private": wrapped("other"), "replace": true });
            if let Some(password) = proof {
                body["current_auth_key"] = json!(login_key(password));
            }
            assert_eq!(
                refused(&put("other", body).await),
                (403, "wrong-password"),
                "{proof:?}"
            );
        }
        let malformed = put(
            "other",
            json!({ "public_key": key(9), "sealed_private": wrapped("other"), "replace": true,
                    "current_auth_key": "short" }),
        )
        .await;
        assert_eq!(refused(&malformed), (400, "invalid"));
        assert_eq!(
            get(&server, &other, "/v1/teams/identity").await.1["public_key"],
            key(2)
        );
        assert_eq!(mine(&server, &other).await[0]["state"], "active");
        assert_eq!(pull(&server, &other, team, 0).await.0, 200);

        // Replaced: what was wrapped to the old key is dropped, and the
        // member waits until somebody has checked the new one.
        let replaced = put(
            "other",
            json!({ "public_key": key(9), "sealed_private": wrapped("other"), "replace": true,
                    "current_auth_key": login_key("master") }),
        )
        .await;
        assert_eq!(replaced.0, 200, "{replaced:?}");
        let waiting = mine(&server, &other).await;
        assert_eq!(waiting[0]["state"], "pending");
        assert_eq!(waiting[0]["wrapped_key"], Value::Null);
        assert_eq!(waiting[0]["role"], "admin");
        assert_eq!(
            refused(&pull(&server, &other, team, 0).await),
            (403, "membership-pending")
        );
        assert_eq!(
            refused(
                &post(
                    &server,
                    &other,
                    &format!("/v1/teams/{team}/invites"),
                    json!({ "role": "reader" })
                )
                .await
            ),
            (403, "membership-pending")
        );
        let members = get(&server, &owner, &format!("/v1/teams/{team}/members"))
            .await
            .1;
        assert_eq!(members[1]["state"], "pending");
        assert_eq!(members[1]["public_key"], key(9));
        // A key wrapped to the old one is refused; to the new one, taken.
        assert_eq!(
            refused(&confirm(&server, &owner, team, &other, 2, 1).await),
            (409, "identity-changed")
        );
        assert_eq!(confirm(&server, &owner, team, &other, 9, 1).await.0, 204);
        assert_eq!(pull(&server, &other, team, 0).await.0, 200);
    }

    #[tokio::test]
    async fn a_team_holds_what_the_server_allows_and_what_is_sent_is_bounded() {
        let server = start_with(Config {
            registration: Registration::Open,
            quota: uwusync_server::db::records::Quota {
                records: 2,
                bytes: 1024 * 1024,
                ..Default::default()
            },
            ..Config::default()
        })
        .await;
        let owner = member(&server, 1).await;
        let team = team(&server, &owner).await;
        let other = {
            let answer = post(
                &server,
                &owner,
                "/v1/teams",
                json!({ "name": "Other", "display_name": "Olive", "wrapped_key": wrapped("k") }),
            )
            .await;
            answer.1["id"].as_str().unwrap().parse::<Uuid>().unwrap()
        };

        // Each team counts for itself, and beside the account's own vault.
        let two = |team: Uuid| {
            [
                record(team, Uuid::now_v7(), 0, b"one"),
                record(team, Uuid::now_v7(), 0, b"two"),
            ]
        };
        assert_eq!(push(&server, &owner, team, 1, &two(team)).await.0, 200);
        assert_eq!(push(&server, &owner, other, 1, &two(other)).await.0, 200);
        owner
            .push(
                &server,
                &[
                    owner.envelope(Uuid::now_v7(), 0, b"own"),
                    owner.envelope(Uuid::now_v7(), 0, b"own"),
                ],
            )
            .await;
        let more = push(
            &server,
            &owner,
            team,
            1,
            &[record(team, Uuid::now_v7(), 0, b"three")],
        )
        .await;
        assert_eq!(refused(&more), (413, "too-large"));
        assert_eq!(
            pull(&server, &owner, team, 0).await.1["envelopes"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        // A record of one team does not get into another by its address.
        let misfiled = push(
            &server,
            &owner,
            other,
            1,
            &[record(team, Uuid::now_v7(), 0, b"x")],
        )
        .await;
        assert_eq!(misfiled.0, 400);
        // Pages are the mailbox's pages.
        let page = get(
            &server,
            &owner,
            &format!("/v1/teams/{team}/records?cursor=0&limit=1"),
        )
        .await
        .1;
        assert_eq!(page["envelopes"].as_array().unwrap().len(), 1);
        assert_eq!(page["has_more"], true);
        assert_eq!(page["cursor"], 1);
        let rest = get(
            &server,
            &owner,
            &format!("/v1/teams/{team}/records?since=1"),
        )
        .await
        .1;
        assert_eq!(rest["envelopes"].as_array().unwrap().len(), 1);
        assert_eq!(rest["has_more"], false);

        // Names and keys: not empty, not long, nothing unprintable.
        let long = "x".repeat(81);
        for body in [
            json!({ "name": "", "display_name": "Olive", "wrapped_key": wrapped("k") }),
            json!({ "name": "   ", "display_name": "Olive", "wrapped_key": wrapped("k") }),
            json!({ "name": long, "display_name": "Olive", "wrapped_key": wrapped("k") }),
            json!({ "name": "Ops\u{7}", "display_name": "Olive", "wrapped_key": wrapped("k") }),
            json!({ "name": "Ops", "display_name": "x".repeat(61), "wrapped_key": wrapped("k") }),
            json!({ "name": "Ops", "display_name": "Olive", "wrapped_key": "" }),
            json!({ "name": "Ops", "display_name": "Olive",
                    "wrapped_key": uwusync_server::b64::encode(vec![1u8; 513]) }),
        ] {
            assert_eq!(
                refused(&post(&server, &owner, "/v1/teams", body.clone()).await),
                (400, "invalid"),
                "{body}"
            );
        }
        assert_eq!(
            refused(
                &patch(
                    &server,
                    &owner,
                    &format!("/v1/teams/{team}"),
                    json!({ "name": "x".repeat(81) })
                )
                .await
            ),
            (400, "invalid")
        );
        // What is not what the endpoint takes is refused, not crashed on.
        for body in [json!([]), json!({ "name": 7 }), json!(null)] {
            let answer = post(&server, &owner, "/v1/teams", body).await;
            assert!((400..500).contains(&answer.0), "{answer:?}");
        }
        let answer = post(
            &server,
            &owner,
            &format!("/v1/teams/{team}/rotate"),
            json!({ "epoch": 2, "keys": [{ "account_id": "nobody", "wrapped_key": "k" }] }),
        )
        .await;
        assert!((400..500).contains(&answer.0), "{answer:?}");
        assert_eq!(mine(&server, &owner).await.len(), 2);
    }

    #[tokio::test]
    async fn an_invite_lasts_as_long_as_its_maker_may_invite() {
        let server = open().await;
        let owner = member(&server, 1).await;
        let admin = member(&server, 2).await;
        let newcomer = member(&server, 3).await;
        let team = team(&server, &owner).await;
        admit(&server, &owner, team, &admin, 2, "admin").await;
        let at = format!("/v1/teams/{team}/members/{}", admin.account);
        let invites = format!("/v1/teams/{team}/invites");
        let kept = invite(&server, &owner, team, "reader").await;

        // Made by an admin who is then an editor: it lets nobody in.
        let made = invite(&server, &admin, team, "admin").await;
        assert_eq!(
            get(&server, &owner, &invites)
                .await
                .1
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            patch(&server, &owner, &at, json!({ "role": "editor" }))
                .await
                .0,
            204
        );
        assert_eq!(
            refused(&join(&server, &newcomer, &made).await),
            (403, "invalid-invite")
        );
        assert_eq!(
            get(&server, &owner, &invites)
                .await
                .1
                .as_array()
                .unwrap()
                .len(),
            1
        );

        // Made by an admin who is then taken out: the same.
        assert_eq!(
            patch(&server, &owner, &at, json!({ "role": "admin" }))
                .await
                .0,
            204
        );
        let made = invite(&server, &admin, team, "admin").await;
        assert_eq!(delete(&server, &owner, &at).await.0, 204);
        assert_eq!(
            refused(&join(&server, &newcomer, &made).await),
            (403, "invalid-invite")
        );

        // Anybody else's are as good as they were.
        assert_eq!(
            get(&server, &owner, &invites)
                .await
                .1
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(join(&server, &newcomer, &kept).await.0, 200);
    }

    #[tokio::test]
    async fn a_deleted_record_is_forgotten_once_every_reading_device_has_seen_it() {
        use uwusync_server::db::teams as stored;
        let server = open().await;
        let owner = member(&server, 1).await;
        let reader = member(&server, 2).await;
        let never = member(&server, 3).await;
        let team = team(&server, &owner).await;
        admit(&server, &owner, team, &reader, 2, "reader").await;
        // A member whose device never reads the team holds nothing back.
        admit(&server, &owner, team, &never, 3, "reader").await;

        let id = Uuid::now_v7();
        assert_eq!(
            push(&server, &owner, team, 1, &[record(team, id, 0, b"sealed")])
                .await
                .0,
            200
        );
        assert_eq!(pull(&server, &reader, team, 0).await.1["cursor"], 1);
        let mut gone = record(team, id, 1, b"gone");
        gone.deleted = true;
        let pushed = push(&server, &owner, team, 1, &[gone]).await;
        assert_eq!(pushed.1["accepted"][0]["seq"], 2, "{pushed:?}");
        assert_eq!(pull(&server, &owner, team, 0).await.1["cursor"], 2);

        let later = server.state.clock.now_ms() + WEEK_MS;
        let purge =
            |before: u64| stored::purge_tombstones(&server.state.db.lock(), team, before).unwrap();
        // The reader's device has the record and not yet the marker.
        assert_eq!(
            stored::lowest_cursor(&server.state.db.lock(), team).unwrap(),
            1
        );
        assert_eq!(purge(later), 0);
        assert_eq!(
            pull(&server, &reader, team, 1).await.1["envelopes"][0]["deleted"],
            true
        );
        // Seen by all, but not old yet.
        assert_eq!(purge(0), 0);
        assert_eq!(purge(later), 1);
        assert!(pull(&server, &never, team, 0).await.1["envelopes"]
            .as_array()
            .unwrap()
            .is_empty());
        let held: (i64, i64) = server
            .state
            .db
            .lock()
            .query_row("SELECT record_count, record_bytes FROM teams", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(held, (0, 0));

        // The operator's delete takes the whole team or nothing.
        assert!(stored::delete_any(&server.state.db.lock(), team).unwrap());
        assert!(!stored::delete_any(&server.state.db.lock(), team).unwrap());
        let left: i64 = server
            .state
            .db
            .lock()
            .query_row(
                "SELECT (SELECT count(*) FROM team_cursors) + (SELECT count(*) FROM team_members)
                      + (SELECT count(*) FROM team_invites) + (SELECT count(*) FROM teams)",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(left, 0);
        assert_eq!(
            refused(&pull(&server, &owner, team, 0).await),
            (404, "not-found")
        );
    }

    /// Read the stream until `wanted` has come by.
    async fn hears(stream: &mut reqwest::Response, wanted: &str) {
        let mut heard = String::new();
        let found = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !heard.contains(wanted) {
                let chunk = stream
                    .chunk()
                    .await
                    .unwrap()
                    .expect("the stream stays open");
                heard.push_str(&String::from_utf8_lossy(&chunk));
            }
        })
        .await;
        assert!(found.is_ok(), "expected {wanted:?}, heard {heard:?}");
    }

    #[tokio::test]
    async fn a_member_hears_when_a_team_changes() {
        let server = open().await;
        let owner = member(&server, 1).await;
        let reader = member(&server, 2).await;
        let team = team(&server, &owner).await;
        admit(&server, &owner, team, &reader, 2, "reader").await;

        let mut stream = server
            .client
            .get(server.url("/v1/events"))
            .bearer_auth(&reader.token)
            .send()
            .await
            .unwrap();
        assert_eq!(stream.status(), 200);
        while server.state.events.listeners(reader.account) == 0 {
            tokio::task::yield_now().await;
        }
        let event = format!("event: team\ndata: {team}");

        // Records.
        push(
            &server,
            &owner,
            team,
            1,
            &[record(team, Uuid::now_v7(), 0, b"new")],
        )
        .await;
        hears(&mut stream, &event).await;
        // The key.
        let rotated = post(
            &server,
            &owner,
            &format!("/v1/teams/{team}/rotate"),
            json!({ "epoch": 2, "keys": [
                { "account_id": owner.account, "wrapped_key": wrapped("n") },
                { "account_id": reader.account, "wrapped_key": wrapped("n") },
            ] }),
        )
        .await;
        assert_eq!(rotated.0, 200, "{rotated:?}");
        hears(&mut stream, &event).await;
        // Being taken out: the last thing they hear about it.
        let out = format!("/v1/teams/{team}/members/{}", reader.account);
        assert_eq!(delete(&server, &owner, &out).await.0, 204);
        hears(&mut stream, &event).await;
    }

    #[tokio::test]
    async fn a_stream_that_missed_events_is_told_to_look_at_every_team() {
        let server = open().await;
        let owner = member(&server, 1).await;
        let team = team(&server, &owner).await;
        let mut stream = server
            .client
            .get(server.url("/v1/events"))
            .bearer_auth(&owner.token)
            .send()
            .await
            .unwrap();
        while server.state.events.listeners(owner.account) == 0 {
            tokio::task::yield_now().await;
        }
        // More at once than a stream holds, with no chance to read between.
        for _ in 0..40 {
            server.state.events.announce_team(&[owner.account], team);
        }
        hears(&mut stream, "event: team\ndata: *\n").await;
        // And what it still held follows.
        hears(&mut stream, &format!("event: team\ndata: {team}")).await;
    }

    /// UwUAuth deleting a person who alone owns a team with others in it
    /// would leave the team to nobody: refused, until someone else owns it.
    #[tokio::test]
    async fn uwuauth_cannot_delete_the_only_owner_of_a_team() {
        use super::sso::{create_with, device_of, scim, scim_user, ticket, Provider, SCIM_TOKEN};
        let provider = Provider::start().await;
        let server = open().await;
        provider.pair(&server);
        let person = scim_user(&server, "owner-1").await;
        let id = person["id"].as_str().unwrap().to_string();
        let signed = ticket(&server, &provider, "owner-1").await;
        let created = create_with(&server, signed["ticket"].as_str().unwrap(), 21).await;
        assert_eq!(created.0, 200, "{created:?}");
        let owner = device_of(&created.1, 21);
        let identity = call(
            &server,
            &owner,
            reqwest::Method::PUT,
            "/v1/teams/identity",
            Some(json!({ "public_key": key(21), "sealed_private": wrapped("sealed") })),
        )
        .await;
        assert_eq!(identity.0, 200, "{identity:?}");
        let team = team(&server, &owner).await;
        let other = member(&server, 22).await;
        admit(&server, &owner, team, &other, 22, "editor").await;

        let path = format!("/scim/v2/Users/{id}");
        let refused = scim(&server, reqwest::Method::DELETE, &path, SCIM_TOKEN, None).await;
        assert_eq!(refused.0, 409, "{refused:?}");
        assert_eq!(mine(&server, &other).await.len(), 1);

        // With an admin who can take over, it goes through — and the team
        // has an owner afterwards.
        let promoted = patch(
            &server,
            &owner,
            &format!("/v1/teams/{team}/members/{}", other.account),
            json!({ "role": "admin" }),
        )
        .await;
        assert!(promoted.0 < 300, "{promoted:?}");
        let deleted = scim(&server, reqwest::Method::DELETE, &path, SCIM_TOKEN, None).await;
        assert_eq!(deleted.0, 204, "{deleted:?}");
        let teams = mine(&server, &other).await;
        assert_eq!(teams.len(), 1);
        assert_eq!(teams[0]["role"], "owner", "{teams:?}");
    }
}

/// Signing in with UwUAuth, against a stand-in for it: an OpenID provider on
/// a port of its own that signs ID tokens with a key made for the test, and
/// answers pairing the way UwUAuth does. And SCIM, as UwUAuth drives it.
mod sso {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
    use serde_json::Value;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use uwusync_server::db::sso::{self as people, Pairing};
    use uwusync_server::sso::s256;

    pub(super) const CLIENT_ID: &str = "uwusync-test";
    const CLIENT_SECRET: &str = "client-secret-for-tests";
    pub(super) const SCIM_TOKEN: &str = "scim-token-for-tests";
    const REDIRECT: &str = "http://127.0.0.1:4000/uwusync/callback";

    /// What the provider hands out for one `code`: the claims, and the PKCE
    /// challenge the server sent with it.
    #[derive(Default)]
    struct Codes {
        codes: HashMap<String, (Value, String)>,
        /// Pairing requests, as they arrived.
        paired: Vec<Value>,
    }

    pub(super) struct Provider {
        pub(super) issuer: String,
        codes: Arc<Mutex<Codes>>,
    }

    fn signing_key() -> EcdsaKeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap()
    }

    fn sign(key: &EcdsaKeyPair, claims: &Value) -> String {
        let header = uwusync_server::b64::encode(
            json!({ "alg": "ES256", "kid": "k1", "typ": "JWT" }).to_string(),
        );
        let payload = uwusync_server::b64::encode(claims.to_string());
        let signed = format!("{header}.{payload}");
        let signature = key.sign(&SystemRandom::new(), signed.as_bytes()).unwrap();
        format!(
            "{signed}.{}",
            uwusync_server::b64::encode(signature.as_ref())
        )
    }

    impl Provider {
        pub(super) async fn start() -> Provider {
            use axum::extract::State as S;
            use axum::routing::{get, post};

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let issuer = format!("http://{}", listener.local_addr().unwrap());
            let key = Arc::new(signing_key());
            let codes = Arc::new(Mutex::new(Codes::default()));

            #[derive(Clone)]
            struct Fake {
                issuer: String,
                key: Arc<EcdsaKeyPair>,
                codes: Arc<Mutex<Codes>>,
            }
            let fake = Fake {
                issuer: issuer.clone(),
                key: key.clone(),
                codes: codes.clone(),
            };
            let app = axum::Router::new()
                .route(
                    "/.well-known/openid-configuration",
                    get(|S(fake): S<Fake>| async move {
                        axum::Json(json!({
                            "issuer": fake.issuer,
                            "authorization_endpoint": format!("{}/authorize", fake.issuer),
                            "token_endpoint": format!("{}/token", fake.issuer),
                            "jwks_uri": format!("{}/jwks", fake.issuer),
                        }))
                    }),
                )
                .route(
                    "/jwks",
                    get(|S(fake): S<Fake>| async move {
                        let point = fake.key.public_key().as_ref().to_vec();
                        axum::Json(json!({ "keys": [{
                            "kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
                            "x": uwusync_server::b64::encode(&point[1..33]),
                            "y": uwusync_server::b64::encode(&point[33..65]),
                        }]}))
                    }),
                )
                .route(
                    "/token",
                    post(
                        |S(fake): S<Fake>, headers: axum::http::HeaderMap, form: String| async move {
                            use axum::response::IntoResponse;
                            let form: HashMap<String, String> = form
                                .split('&')
                                .filter_map(|pair| pair.split_once('='))
                                .map(|(key, value)| (key.to_string(), decode(value)))
                                .collect();
                            let basic = headers
                                .get("authorization")
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or_default()
                                .to_string();
                            let expected = format!(
                                "Basic {}",
                                base64_standard(&format!("{CLIENT_ID}:{CLIENT_SECRET}"))
                            );
                            let bad = (
                                axum::http::StatusCode::BAD_REQUEST,
                                axum::Json(json!({ "error": "invalid_grant" })),
                            )
                                .into_response();
                            if basic != expected || form["redirect_uri"] != REDIRECT {
                                return bad;
                            }
                            let Some((claims, challenge)) =
                                fake.codes.lock().unwrap().codes.remove(&form["code"])
                            else {
                                return bad;
                            };
                            if s256(&form["code_verifier"]) != challenge {
                                return bad;
                            }
                            axum::Json(json!({
                                "id_token": sign(&fake.key, &claims),
                                "access_token": "an-access-token",
                                "token_type": "Bearer",
                            }))
                            .into_response()
                        },
                    ),
                )
                .route(
                    "/uwu/v1/server",
                    get(|S(fake): S<Fake>| async move {
                        axum::Json(json!({
                            "product": "UwUAuth", "pairing": 1, "issuer": fake.issuer,
                        }))
                    }),
                )
                .route(
                    "/uwu/v1/pair",
                    post(
                        |S(fake): S<Fake>, axum::Json(body): axum::Json<Value>| async move {
                            use axum::response::IntoResponse;
                            if body["code"] != "PAIR-CODE" {
                                return (
                                    axum::http::StatusCode::BAD_REQUEST,
                                    axum::Json(json!({ "error": "invalid_code" })),
                                )
                                    .into_response();
                            }
                            fake.codes.lock().unwrap().paired.push(body);
                            axum::Json(json!({
                                "issuer": fake.issuer,
                                "clientId": CLIENT_ID,
                                "clientSecret": CLIENT_SECRET,
                                "scopes": ["openid", "email", "profile"],
                                "scimToken": SCIM_TOKEN,
                                "appId": "app-1",
                                "manageUrl": format!("{}/admin/apps/app-1", fake.issuer),
                            }))
                            .into_response()
                        },
                    ),
                )
                .with_state(fake);
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            Provider { issuer, codes }
        }

        /// Pair `server` with this provider, straight in its database.
        pub(super) fn pair(&self, server: &Server) {
            people::set_pairing(
                &server.state.db.lock(),
                &Pairing {
                    url: self.issuer.clone(),
                    issuer: self.issuer.clone(),
                    client_id: CLIENT_ID.into(),
                    client_secret: CLIENT_SECRET.into(),
                    scim_token_hash: Some(uwusync_server::sha256(SCIM_TOKEN.as_bytes()).to_vec()),
                    app_id: Some("app-1".into()),
                    manage_url: None,
                    paired_ms: 1,
                },
            )
            .unwrap();
        }

        /// The browser half: what UwUAuth does after the person signed in
        /// as `sub` — a code for the claims, bound to the server's challenge
        /// and nonce from the address it was sent to.
        fn signs_in(&self, url: &str, sub: &str, email: &str) -> (String, String) {
            let url = reqwest::Url::parse(url).unwrap();
            assert!(url
                .as_str()
                .starts_with(&format!("{}/authorize?", self.issuer)));
            let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
            assert_eq!(query["client_id"], CLIENT_ID);
            assert_eq!(query["redirect_uri"], REDIRECT);
            assert_eq!(query["code_challenge_method"], "S256");
            assert_eq!(query["scope"], "openid email profile");
            let now = uwusync_server::now_ms() / 1000;
            let claims = json!({
                "iss": self.issuer, "aud": CLIENT_ID, "sub": sub, "email": email,
                "name": "Mia Example", "nonce": query["nonce"],
                "iat": now, "exp": now + 300,
            });
            let code = uwusync_server::b64::encode(uwusync_server::random_bytes::<16>());
            self.codes
                .lock()
                .unwrap()
                .codes
                .insert(code.clone(), (claims, query["code_challenge"].clone()));
            (code, query["state"].clone())
        }
    }

    fn decode(value: &str) -> String {
        let value = value.replace('+', " ");
        let mut out = Vec::new();
        let bytes = value.as_bytes();
        let mut at = 0;
        while at < bytes.len() {
            if bytes[at] == b'%' && at + 2 < bytes.len() {
                out.push(u8::from_str_radix(&value[at + 1..at + 3], 16).unwrap());
                at += 3;
            } else {
                out.push(bytes[at]);
                at += 1;
            }
        }
        String::from_utf8(out).unwrap()
    }

    fn base64_standard(text: &str) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(text)
    }

    async fn post_json(server: &Server, path: &str, body: Value) -> (u16, Value) {
        let response = server
            .client
            .post(server.url(path))
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let text = response.text().await.unwrap();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    /// The whole device half of a sign-in: a ticket, or the refusal.
    pub(super) async fn sign_in(
        server: &Server,
        provider: &Provider,
        sub: &str,
        email: &str,
    ) -> (u16, Value) {
        let verifier = uwusync_server::b64::encode(uwusync_server::random_bytes::<32>());
        let started = post_json(
            server,
            "/v1/sso/authorize",
            json!({ "redirectUri": REDIRECT, "codeChallenge": s256(&verifier) }),
        )
        .await;
        assert_eq!(started.0, 200, "{started:?}");
        let (code, state) = provider.signs_in(started.1["url"].as_str().unwrap(), sub, email);
        assert_eq!(state, started.1["state"]);
        post_json(
            server,
            "/v1/sso/token",
            json!({ "state": state, "code": code, "codeVerifier": verifier, "iss": provider.issuer }),
        )
        .await
    }

    pub(super) async fn ticket(server: &Server, provider: &Provider, sub: &str) -> Value {
        let answer = sign_in(server, provider, sub, &format!("{sub}@example.com")).await;
        assert_eq!(answer.0, 200, "{answer:?}");
        answer.1
    }

    /// An account made with a ticket instead of an invite.
    pub(super) async fn create_with(server: &Server, ticket: &str, seed: u8) -> (u16, Value) {
        let signing = Device::new_key(seed);
        post_json(
            server,
            "/v1/accounts",
            json!({
                "ssoTicket": ticket,
                "vault": Server::vault(Uuid::now_v7()),
                "authKey": login_key("master"),
                "device": {
                    "name": "LVDesk1",
                    "publicKey": uwusync_server::b64::encode(signing.verifying_key().to_bytes()),
                },
            }),
        )
        .await
    }

    pub(super) fn device_of(answer: &Value, seed: u8) -> Device {
        Device {
            signing: Device::new_key(seed),
            account: answer["accountId"].as_str().unwrap().parse().unwrap(),
            id: answer["deviceId"].as_str().unwrap().parse().unwrap(),
            token: answer["token"].as_str().unwrap().to_string(),
            vault_id: Uuid::nil(),
        }
    }

    async fn enrol_with(server: &Server, ticket: &str, password: &str, seed: u8) -> (u16, Value) {
        let signing = Device::new_key(seed);
        post_json(
            server,
            "/v1/devices/enrol",
            json!({
                "ssoTicket": ticket,
                "authKey": login_key(password),
                "device": {
                    "name": format!("device {seed}"),
                    "publicKey": uwusync_server::b64::encode(signing.verifying_key().to_bytes()),
                },
            }),
        )
        .await
    }

    pub(super) async fn scim(
        server: &Server,
        method: reqwest::Method,
        path: &str,
        token: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let mut request = server
            .client
            .request(method, server.url(path))
            .bearer_auth(token);
        if let Some(body) = body {
            request = request
                .header("content-type", "application/scim+json")
                .body(body.to_string());
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        if status != 204 {
            let kind = response
                .headers()
                .get("content-type")
                .map(|value| value.to_str().unwrap().to_string());
            assert_eq!(kind.as_deref(), Some("application/scim+json"), "{status}");
        }
        let text = response.text().await.unwrap();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    pub(super) async fn scim_user(server: &Server, sub: &str) -> Value {
        let created = scim(
            server,
            reqwest::Method::POST,
            "/scim/v2/Users",
            SCIM_TOKEN,
            Some(json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": format!("{sub}@example.com"),
                "externalId": sub,
                "displayName": "Mia Example",
                "active": true,
            })),
        )
        .await;
        assert_eq!(created.0, 201, "{created:?}");
        created.1
    }

    async fn patch_active(server: &Server, id: &str, active: bool) -> (u16, Value) {
        scim(
            server,
            reqwest::Method::PATCH,
            &format!("/scim/v2/Users/{id}"),
            SCIM_TOKEN,
            Some(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{ "op": "replace", "value": { "active": active } }],
            })),
        )
        .await
    }

    #[tokio::test]
    async fn signing_in_with_uwuauth_makes_an_account_and_joins_devices_to_it() {
        let provider = Provider::start().await;
        // An invite-only server: the ticket stands in for the invite.
        let server = start(Registration::Invite).await;
        provider.pair(&server);

        let first = ticket(&server, &provider, "person-1").await;
        assert_eq!(first["hasAccount"], false);
        assert_eq!(first["userName"], "person-1@example.com");
        assert_eq!(first["displayName"], "Mia Example");
        let ticket_text = first["ticket"].as_str().unwrap();
        let created = create_with(&server, ticket_text, 1).await;
        assert_eq!(created.0, 200, "{created:?}");
        let mut device = device_of(&created.1, 1);
        assert_eq!(device.login(&server).await, 200);
        // One use.
        assert_eq!(create_with(&server, ticket_text, 2).await.0, 401);

        // The same person again, on another device: they have an account now,
        // and a second one is not made for them.
        let again = ticket(&server, &provider, "person-1").await;
        assert_eq!(again["hasAccount"], true);
        let again = again["ticket"].as_str().unwrap();
        let refused = create_with(&server, again, 3).await;
        assert_eq!(refused.0, 409, "{refused:?}");

        // The vault parameters with the ticket, then the master password.
        let params = post_json(&server, "/v1/vault/params", json!({ "ssoTicket": again })).await;
        assert_eq!(params.0, 200, "{params:?}");
        // A wrong one costs a try and not the ticket…
        assert_eq!(enrol_with(&server, again, "wrong", 4).await.0, 401);
        // …the right one lets the device in, and the ticket is spent.
        let joined = enrol_with(&server, again, "master", 4).await;
        assert_eq!(joined.0, 200, "{joined:?}");
        assert_eq!(joined.1["accountId"], device.account.to_string());
        assert_eq!(enrol_with(&server, again, "master", 5).await.0, 401);

        // Somebody else gets an account of their own.
        let other = ticket(&server, &provider, "person-2").await;
        assert_eq!(other["hasAccount"], false);
        let made = create_with(&server, other["ticket"].as_str().unwrap(), 6).await;
        assert_eq!(made.0, 200);
        assert_ne!(made.1["accountId"], device.account.to_string());
    }

    #[tokio::test]
    async fn a_ticket_is_only_for_the_one_who_started_the_login() {
        let provider = Provider::start().await;
        let server = start(Registration::Invite).await;

        // Not paired: no signing in.
        let off = post_json(
            &server,
            "/v1/sso/authorize",
            json!({ "redirectUri": REDIRECT, "codeChallenge": s256(&"v".repeat(43)) }),
        )
        .await;
        assert_eq!(off.0, 404, "{off:?}");
        provider.pair(&server);

        // Only the device's own loopback listener is a place to come back to.
        for redirect in [
            "http://localhost:4000/uwusync/callback",
            "https://sync.example.com/uwusync/callback",
            "http://127.0.0.1:4000/elsewhere",
        ] {
            let answer = post_json(
                &server,
                "/v1/sso/authorize",
                json!({ "redirectUri": redirect, "codeChallenge": s256(&"v".repeat(43)) }),
            )
            .await;
            assert_eq!(answer.0, 400, "{redirect}");
        }

        let verifier = "v".repeat(43);
        let started = post_json(
            &server,
            "/v1/sso/authorize",
            json!({ "redirectUri": REDIRECT, "codeChallenge": s256(&verifier) }),
        )
        .await;
        let (code, state) =
            provider.signs_in(started.1["url"].as_str().unwrap(), "p", "p@example.com");
        // Somebody who saw the code and the state but not the verifier.
        let stolen = post_json(
            &server,
            "/v1/sso/token",
            json!({ "state": state, "code": code, "codeVerifier": "w".repeat(43) }),
        )
        .await;
        assert_eq!(stolen.0, 401);
        // And the state is gone with that: it is answered once.
        let late = post_json(
            &server,
            "/v1/sso/token",
            json!({ "state": state, "code": code, "codeVerifier": verifier }),
        )
        .await;
        assert_eq!(late.0, 401);

        // An answer that names another issuer came from somewhere else.
        let started = post_json(
            &server,
            "/v1/sso/authorize",
            json!({ "redirectUri": REDIRECT, "codeChallenge": s256(&verifier) }),
        )
        .await;
        let (code, state) =
            provider.signs_in(started.1["url"].as_str().unwrap(), "p", "p@example.com");
        let mixed = post_json(
            &server,
            "/v1/sso/token",
            json!({ "state": state, "code": code, "codeVerifier": verifier,
                    "iss": "https://auth.example.net" }),
        )
        .await;
        assert_eq!(mixed.0, 401);

        // A made-up ticket is no invite.
        assert_eq!(create_with(&server, "made-up", 1).await.0, 401);
        // And unpaired, a ticket from before is worth nothing.
        let ticket = ticket(&server, &provider, "p").await;
        people::unpair(&server.state.db.lock()).unwrap();
        assert_eq!(
            create_with(&server, ticket["ticket"].as_str().unwrap(), 1)
                .await
                .0,
            404
        );
    }

    #[tokio::test]
    async fn the_server_says_what_it_is_and_whom_it_signs_in_with() {
        let provider = Provider::start().await;
        let server = start(Registration::Invite).await;
        let info: Value = server
            .client
            .get(server.url("/uwu/v1/server"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(info["product"], "UwUSync");
        assert_eq!(info["sso"], false);
        provider.pair(&server);
        let suite: Value = server
            .client
            .get(server.url("/.well-known/uwusuite"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(suite["sso"], true);
        assert_eq!(suite["servers"][1]["product"], "UwUAuth");
        assert_eq!(suite["servers"][1]["issuer"], provider.issuer);
        // Nothing secret in either.
        assert!(!suite.to_string().contains(CLIENT_SECRET));
    }

    #[tokio::test]
    async fn pairing_takes_a_code_from_uwuauth_and_keeps_what_it_answers() {
        let provider = Provider::start().await;
        let server = start_with(Config {
            public: Some("https://sync.example.com".into()),
            ..Config::default()
        })
        .await;
        let wrong = uwusync_server::uwuauth::pair(
            &server.state.config,
            &server.state.db,
            Some(&provider.issuer),
            "WRONG",
        )
        .await;
        assert!(wrong.unwrap_err().contains("does not know this code"));

        let said = uwusync_server::uwuauth::pair(
            &server.state.config,
            &server.state.db,
            None,
            &format!("{}/#pair=PAIR-CODE", provider.issuer),
        )
        .await
        .unwrap();
        assert!(said.contains("Paired"), "{said}");
        let asked = provider.codes.lock().unwrap().paired.pop().unwrap();
        assert_eq!(asked["app"]["product"], "UwUSync");
        assert_eq!(
            asked["app"]["redirectUris"],
            json!(["http://127.0.0.1/uwusync/callback"])
        );
        assert_eq!(
            asked["app"]["scim"]["baseUrl"],
            "https://sync.example.com/scim/v2"
        );
        let kept = people::pairing(&server.state.db.lock()).unwrap().unwrap();
        assert_eq!(kept.issuer, provider.issuer);
        assert_eq!(kept.client_secret, CLIENT_SECRET);
        assert!(people::scim_token_matches(&server.state.db.lock(), SCIM_TOKEN).unwrap());
        // And it signs in at once.
        let ticket = ticket(&server, &provider, "paired").await;
        assert_eq!(ticket["hasAccount"], false);

        // Without an https address of its own, it does not pair.
        let plain = start(Registration::Invite).await;
        let refused = uwusync_server::uwuauth::pair(
            &plain.state.config,
            &plain.state.db,
            Some(&provider.issuer),
            "PAIR-CODE",
        )
        .await;
        assert!(refused.is_err());
    }

    #[tokio::test]
    async fn scim_is_for_uwuauth_and_its_token_only() {
        let provider = Provider::start().await;
        let server = start(Registration::Invite).await;
        // Unpaired, no token is right.
        let answer = scim(
            &server,
            reqwest::Method::GET,
            "/scim/v2/Users",
            SCIM_TOKEN,
            None,
        )
        .await;
        assert_eq!(answer.0, 401);
        provider.pair(&server);
        let config = scim(
            &server,
            reqwest::Method::GET,
            "/scim/v2/ServiceProviderConfig",
            SCIM_TOKEN,
            None,
        )
        .await;
        assert_eq!(config.0, 200);
        assert_eq!(config.1["patch"]["supported"], true);
        // Guessing is slowed down — and the slowdown is for the guesser.
        let mut statuses = Vec::new();
        for _ in 0..12 {
            statuses.push(
                scim(
                    &server,
                    reqwest::Method::GET,
                    "/scim/v2/Users",
                    "guess",
                    None,
                )
                .await
                .0,
            );
        }
        assert_eq!(statuses[0], 401);
        assert_eq!(*statuses.last().unwrap(), 429);
    }

    #[tokio::test]
    async fn scim_keeps_people_and_turning_one_off_shuts_their_devices_out() {
        let provider = Provider::start().await;
        let server = start(Registration::Invite).await;
        provider.pair(&server);

        // Pushed before they ever signed in: pending, found by their `sub`.
        let pushed = scim_user(&server, "person-1").await;
        let id = pushed["id"].as_str().unwrap().to_string();
        assert_eq!(pushed["externalId"], "person-1");
        assert_eq!(pushed["active"], true);
        let duplicate = scim(
            &server,
            reqwest::Method::POST,
            "/scim/v2/Users",
            SCIM_TOKEN,
            Some(json!({ "userName": "other@example.com", "externalId": "person-1" })),
        )
        .await;
        assert_eq!(duplicate.0, 409);
        let missing = scim(
            &server,
            reqwest::Method::POST,
            "/scim/v2/Users",
            SCIM_TOKEN,
            Some(json!({ "userName": "nobody@example.com" })),
        )
        .await;
        assert_eq!(missing.0, 400);
        let found = scim(
            &server,
            reqwest::Method::GET,
            "/scim/v2/Users?filter=userName%20eq%20%22person-1%40example.com%22",
            SCIM_TOKEN,
            None,
        )
        .await;
        assert_eq!(found.1["totalResults"], 1);
        assert_eq!(found.1["Resources"][0]["id"], id);

        let ticket = ticket(&server, &provider, "person-1").await;
        let created = create_with(&server, ticket["ticket"].as_str().unwrap(), 1).await;
        assert_eq!(created.0, 200, "{created:?}");
        let mut device = device_of(&created.1, 1);
        // Still one person.
        let all = scim(
            &server,
            reqwest::Method::GET,
            "/scim/v2/Users",
            SCIM_TOKEN,
            None,
        )
        .await;
        assert_eq!(all.1["totalResults"], 1);

        // The account's external id is not UwUAuth's to move.
        let moved = scim(
            &server,
            reqwest::Method::PATCH,
            &format!("/scim/v2/Users/{id}"),
            SCIM_TOKEN,
            Some(json!({ "Operations": [{ "op": "replace", "path": "externalId", "value": "person-9" }] })),
        )
        .await;
        assert_eq!(moved.0, 400, "{moved:?}");

        // Off: every device is out at once, and signing in is refused.
        let off = patch_active(&server, &id, false).await;
        assert_eq!(off.0, 200, "{off:?}");
        assert_eq!(off.1["active"], false);
        let pull = server
            .client
            .get(server.url("/v1/records?since=0"))
            .bearer_auth(&device.token)
            .send()
            .await
            .unwrap();
        assert_eq!(pull.status(), 401);
        assert_ne!(device.login(&server).await, 200);
        let refused = sign_in(&server, &provider, "person-1", "person-1@example.com").await;
        assert_eq!(refused.0, 403, "{refused:?}");

        // On again: the account is still there, and joining it takes the
        // master password as ever.
        assert_eq!(patch_active(&server, &id, true).await.0, 200);
        let again = super::sso::ticket(&server, &provider, "person-1").await;
        assert_eq!(again["hasAccount"], true);
        let joined = enrol_with(&server, again["ticket"].as_str().unwrap(), "master", 2).await;
        assert_eq!(joined.0, 200, "{joined:?}");
        assert_eq!(joined.1["accountId"], device.account.to_string());

        // Deleted: the account goes with them.
        let gone = scim(
            &server,
            reqwest::Method::DELETE,
            &format!("/scim/v2/Users/{id}"),
            SCIM_TOKEN,
            None,
        )
        .await;
        assert_eq!(gone.0, 204);
        let joined = device_of(&joined.1, 2);
        let pull = server
            .client
            .get(server.url("/v1/records?since=0"))
            .bearer_auth(&joined.token)
            .send()
            .await
            .unwrap();
        assert_eq!(pull.status(), 401);
        assert!(
            uwusync_server::db::accounts::header(&server.state.db.lock(), device.account)
                .unwrap()
                .is_none()
        );
        let after = scim(
            &server,
            reqwest::Method::GET,
            &format!("/scim/v2/Users/{id}"),
            SCIM_TOKEN,
            None,
        )
        .await;
        assert_eq!(after.0, 404);
        // Signing in again makes a new, empty account — not the old one.
        let fresh = super::sso::ticket(&server, &provider, "person-1").await;
        assert_eq!(fresh["hasAccount"], false);
    }

    #[tokio::test]
    async fn groups_are_taken_and_forgotten() {
        let provider = Provider::start().await;
        let server = start(Registration::Invite).await;
        provider.pair(&server);
        let group = scim(
            &server,
            reqwest::Method::POST,
            "/scim/v2/Groups",
            SCIM_TOKEN,
            Some(json!({ "displayName": "Ops", "members": [] })),
        )
        .await;
        assert_eq!(group.0, 201);
        let id = group.1["id"].as_str().unwrap();
        let patched = scim(
            &server,
            reqwest::Method::PATCH,
            &format!("/scim/v2/Groups/{id}"),
            SCIM_TOKEN,
            Some(json!({ "Operations": [{ "op": "add", "path": "members", "value": [] }] })),
        )
        .await;
        assert_eq!(patched.0, 204);
        let list = scim(
            &server,
            reqwest::Method::GET,
            "/scim/v2/Groups",
            SCIM_TOKEN,
            None,
        )
        .await;
        assert_eq!(list.1["totalResults"], 0);
        let deleted = scim(
            &server,
            reqwest::Method::DELETE,
            &format!("/scim/v2/Groups/{id}"),
            SCIM_TOKEN,
            None,
        )
        .await;
        assert_eq!(deleted.0, 204);
    }
}
